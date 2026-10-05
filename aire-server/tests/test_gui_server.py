from pathlib import Path
import hashlib
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aire.agent.cli import main, resolve_binary
from aire.api.server import GuiApplication, GuiError, GuiModelConfig, create_server
from aire.knowledge.database import BinaryKnowledgeStore
from test_agent_runner import AgentModel
from test_retrieval import fixture


class GuiServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.database = root / 'analysis.sqlite'
        self.sessions = root / 'sessions'
        index, functions = fixture()
        index.binary.program_name = 'aire_test_binary'
        index.binary.architecture = 'x86:LE:64:default'
        index.binary.sha256 = 'a' * 64
        functions['a'].decompiled_text = 'void start() { shared(); }'
        functions['a'].assembly = 'CALL 10'
        with BinaryKnowledgeStore(self.database) as store:
            store.save_program_index(index)
        self.app = GuiApplication(self.database, session_dir=self.sessions,
                                  model_config=GuiModelConfig(model='mock'),
                                  client_factory=lambda: AgentModel())

    def test_bootstrap_sessions_tools_and_chat_use_existing_backend(self):
        before = self.database.read_bytes()
        bootstrap = self.app.bootstrap()
        self.assertEqual(bootstrap['selected_binary_id'], 'b')
        self.assertEqual(bootstrap['binary_metadata']['counts']['functions'], 7)
        self.assertIn('get_decompiled_text', bootstrap['tool_names'])

        created = self.app.new_session('b')
        session_id = created['session_id']
        functions = self.app.run_tool(session_id, 'list_functions', {'limit': 10, 'offset': 0})
        self.assertTrue(functions['ok'])
        self.app.select_function(session_id, 'start')
        decompiled = self.app.run_tool(session_id, 'get_decompiled_text', {'function': 'it', 'max_chars': 2000})
        self.assertTrue(decompiled['ok'])
        self.assertIn('void start()', decompiled['data']['text'])

        events = []
        result = self.app.run_chat(session_id, 'Show me the most important functions.', on_event=events.append)
        self.assertEqual(result.status, 'completed')
        self.assertIn('Connectivity ranking', result.answer)
        self.assertTrue(events)
        transcript = self.app.session(session_id)
        self.assertEqual([m['role'] for m in transcript['messages']], ['user', 'assistant'])
        self.assertEqual(self.app.sessions.list('b')[0]['session_id'], session_id)
        reopened = GuiApplication(self.database, session_dir=self.sessions)
        self.assertEqual(reopened.session(session_id)['messages'], transcript['messages'])
        self.assertEqual(reopened.session(session_id)['current_function_id'], 'b:a')
        self.assertEqual(self.database.read_bytes(), before)

    def test_http_serves_static_frontend_and_json_api(self):
        server = create_server(self.app, '127.0.0.1', 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_address[1]}'

        with urlopen(base + '/', timeout=3) as response:
            html = response.read().decode('utf-8')
            self.assertIn('How can I help you today?', html)
            self.assertIn("default-src 'self'", response.headers['Content-Security-Policy'])

        for asset, content_type in [('app.css', 'text/css'), ('app.js', 'javascript')]:
            with urlopen(base + '/' + asset, timeout=3) as response:
                self.assertIn(content_type, response.headers['Content-Type'])
                self.assertTrue(response.read())

        with urlopen(base + '/api/bootstrap', timeout=3) as response:
            payload = json.loads(response.read())
            self.assertEqual(payload['selected_binary_id'], 'b')

        body = json.dumps({'binary_id': 'b'}).encode('utf-8')
        request = Request(base + '/api/sessions', data=body, method='POST',
                          headers={'Content-Type': 'application/json'})
        with urlopen(request, timeout=3) as response:
            created = json.loads(response.read())
            self.assertRegex(created['session_id'], r'^[0-9a-f]{32}$')

        session_id = created['session_id']
        requests = [
            ('/api/tool', {'session_id': session_id, 'tool': 'list_functions', 'arguments': {}}, 'items'),
            (f'/api/sessions/{session_id}/select-function', {'function': 'start'}, 'selected_function'),
            ('/api/tool', {'session_id': session_id, 'tool': 'get_decompiled_text',
                           'arguments': {'function': 'it'}}, 'text'),
        ]
        for endpoint, payload, expected in requests:
            request = Request(base + endpoint, data=json.dumps(payload).encode(),
                              headers={'Content-Type': 'application/json'})
            with urlopen(request, timeout=3) as response:
                result = json.loads(response.read())
                self.assertIn(expected, result.get('data', result))

        with urlopen(base + f'/api/sessions/{session_id}', timeout=3) as response:
            self.assertEqual(json.loads(response.read())['current_function_id'], 'b:a')

        request = Request(base + '/api/sessions', data=b'{broken',
                          headers={'Content-Type': 'application/json'})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()

        body = json.dumps({'session_id': created['session_id'],
                           'question': 'Show me the most important functions.'}).encode('utf-8')
        request = Request(base + '/api/chat', data=body, method='POST',
                          headers={'Content-Type': 'application/json'})
        with urlopen(request, timeout=5) as response:
            packets = [json.loads(line) for line in response.read().splitlines() if line.strip()]
        self.assertTrue(any(packet['type'] == 'event' for packet in packets))
        result = next(packet['data'] for packet in packets if packet['type'] == 'result')
        self.assertEqual(result['status'], 'completed')
        self.assertIn('Connectivity ranking', result['answer'])

        with urlopen(base + '/api/sessions?binary_id=b', timeout=3) as response:
            self.assertEqual(json.loads(response.read())['sessions'][0]['session_id'], session_id)

    def test_tools_preserve_binary_scope_and_reject_mutations(self):
        other, _ = fixture('other')
        with BinaryKnowledgeStore(self.database) as store:
            store.save_program_index(other)
        before = self.database.read_bytes()
        session_id = self.app.new_session('b')['session_id']
        self.assertFalse(self.app.run_tool(session_id, 'get_function', {'function': 'other:a'})['ok'])
        self.assertFalse(self.app.run_tool(session_id, 'save_program_index', {})['ok'])
        with self.assertRaises(GuiError):
            self.app.select_function(session_id, 'other:a')
        for name, arguments in [('get_artifacts', {'kind': 'STRING'}),
                                ('get_artifacts', {'kind': 'IMPORT'}),
                                ('get_callers', {'function': 'start'}),
                                ('get_callees', {'function': 'start'}),
                                ('security_findings', {})]:
            self.assertTrue(self.app.run_tool(session_id, name, arguments)['ok'], name)
        self.assertEqual(self.database.read_bytes(), before)

    def test_binary_selection_preserves_cli_identity_name_and_hash_resolution(self):
        target = Path(self.directory.name) / 'fixture.bin'
        target.write_bytes(b'static fixture, never executed')
        index, _ = fixture()
        index.binary.program_name = 'fixture.bin'
        index.binary.path = str(target)
        index.binary.sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        with BinaryKnowledgeStore(self.database) as store:
            store.save_program_index(index)
            for selector in ['b', 'fixture.bin', str(target)]:
                self.assertEqual(resolve_binary(store, selector).binary_id, 'b')
        for selector in ['b', 'fixture.bin', str(target)]:
            app = GuiApplication(self.database, initial_binary=selector, session_dir=self.sessions)
            self.assertEqual(app.initial_binary_id, 'b')
        target.write_bytes(b'changed file must not match by name')
        with self.assertRaises(ValueError):
            GuiApplication(self.database, initial_binary=str(target), session_dir=self.sessions)

    def test_cli_gui_dispatch_keeps_session_and_model_options(self):
        with patch('aire.api.server.serve', return_value=0) as serve:
            self.assertEqual(main(['gui', 'b', '--database', str(self.database),
                                   '--session-dir', str(self.sessions), '--no-browser',
                                   '--model', 'mock', '--port', '0'], output=lambda _: None), 0)
        app = serve.call_args.args[0]
        self.assertEqual(app.initial_binary_id, 'b')
        self.assertEqual(app.model_config.model, 'mock')
        self.assertFalse(serve.call_args.kwargs['open_browser'])

    def test_missing_database_is_never_created(self):
        missing = Path(self.directory.name) / 'missing.sqlite'
        with self.assertRaises(GuiError):
            GuiApplication(missing, session_dir=self.sessions)
        self.assertFalse(missing.exists())

    def test_non_loopback_bind_is_rejected(self):
        with self.assertRaises(GuiError):
            create_server(self.app, '0.0.0.0', 8765)


if __name__ == '__main__':
    unittest.main()
