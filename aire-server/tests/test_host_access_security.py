"""Host-access security review regressions (GUI opened from the Windows host browser).

Threat model: the GUI runs in the host OS browser via a VirtualBox NAT port forward,
so any web page in another tab and any local host process can send requests to
localhost. All inputs are synthetic; no binary is executed and no model is loaded.
See docs/HOST_ACCESS_SECURITY_REVIEW.md.

The real-browser XSS test needs Firefox and runs only with AIRE_RUN_BROWSER_TESTS=1
(it is reported as a skip otherwise, which is not a pass).
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aire.agent import cli
from aire.ai.ollama_client import GenerationResult, OllamaClient
from aire.api.binary_library import REPOSITORY, redact_paths
from aire.api.server import AireRequestHandler, GuiApplication, GuiError, GuiModelConfig, create_server
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import ArtifactRecord
from test_chat import catalog_from_prompt
from test_retrieval import fixture

TOKEN = 'T' * 43
XSS = '<img src=x onerror=alert(1) class=aire-xss>'


class _PayloadModel:
    """Valid structured model output whose free text is an XSS payload."""
    model, num_ctx = 'mock', 4096

    def generate(self, prompt, **kwargs):
        if 'current_function_id' in prompt:
            return GenerationResult(json.dumps({'action': 'answer'}), 'mock', 0)
        catalog = catalog_from_prompt(prompt)
        # Cite code-bearing evidence so the unchanged grounding validator accepts the answer.
        ids = [i['id'] for i in catalog if i['kind'] == 'EDGE'][:2] or [i['id'] for i in catalog][:1]
        return GenerationResult(json.dumps({
            'summary': {'claim': 'Model says ' + XSS, 'evidence_ids': ids}, 'fact_ids': ids,
            'interpretations': [{'claim': 'Interpretation ' + XSS, 'confidence': 'low', 'evidence_ids': ids}],
            'uncertainties': ['Uncertainty ' + XSS]}), 'mock', 0)

    def health(self):
        return {}


def _database(root, payload=False):
    index, functions = fixture()
    index.binary.sha256 = 'a' * 64
    if payload:
        functions['a'].current_name = 'start' + XSS
        functions['a'].decompiled_text = 'void start() { /* ' + XSS + ' */ }'
        index.artifacts.append(ArtifactRecord('b:s1', 'b', 'STRING', '5000', 'string ' + XSS))
        index.artifacts.append(ArtifactRecord('b:i1', 'b', 'IMPORT', None, 'import ' + XSS))
    database = Path(root) / 'analysis.sqlite'
    with BinaryKnowledgeStore(database) as store:
        store.save_program_index(index)
    return database


class _Server:
    def __init__(self, test, app, **options):
        self.server = create_server(app, '127.0.0.1', 0, **options)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.origin = f'http://127.0.0.1:{self.port}'

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            all_headers = {'Content-Type': 'application/json'} if body is not None else {}
            all_headers.update(headers or {})
            connection.putrequest(method, path, skip_host='Host' in all_headers, skip_accept_encoding=True)
            for key, value in all_headers.items():
                connection.putheader(key, value)
            data = body.encode() if isinstance(body, str) else body
            if data is not None:
                connection.putheader('Content-Length', str(len(data)))
            connection.endheaders(data)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()


class HostAccessHttpTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.app = GuiApplication(_database(self.root), session_dir=self.root / 'sessions',
                                  upload_dir=self.root / 'uploads', model_config=GuiModelConfig(model='mock'),
                                  client_factory=_PayloadModel)
        self.addCleanup(self.app.library.close)

    def auth(self, server, **extra):
        return {'X-AIRE-Token': TOKEN, **extra}

    # B4 ----------------------------------------------------------------
    def test_host_header_allowlist_is_exact(self):
        server = _Server(self, self.app, token=TOKEN, public_ports=(18080,))
        port = server.port
        for good in (f'localhost:{port}', f'127.0.0.1:{port}', f'LOCALHOST:{port}', 'localhost:18080',
                     '127.0.0.1:18080'):
            self.assertEqual(server.request('GET', '/api/binaries', headers=self.auth(server, Host=good))[0], 200, good)
        for bad in ('evil.example', f'evil.example:{port}', f'127.0.0.1.evil.example:{port}', f'127.0.0.2:{port}',
                    f'[::1]:{port}', f'0x7f000001:{port}', f'localhost:{port + 1}', 'localhost', '127.0.0.1',
                    f'localhost.:{port}', f'user@localhost:{port}', f'localhost:{port}/x', ''):
            status, headers, _ = server.request('GET', '/api/binaries', headers=self.auth(server, Host=bad))
            self.assertEqual(status, 403, bad)
            # Static files too: a rebinding page must not even read the frontend.
            self.assertEqual(server.request('GET', '/', headers={'Host': bad})[0], 403, bad)

    # B5 ----------------------------------------------------------------
    def test_foreign_or_missing_origin_rejected_on_state_changing_endpoints(self):
        server = _Server(self, self.app, token=TOKEN)
        cookie = {'Cookie': f'{server.server.cookie_name}={TOKEN}'}
        session = json.loads(server.request('POST', '/api/sessions', json.dumps({'binary_id': 'b'}),
                                            {**cookie, 'Origin': server.origin})[2])['session_id']
        endpoints = [('/api/sessions', {'binary_id': 'b'}), ('/api/chat', {'session_id': session, 'question': 'x'}),
                     ('/api/tool', {'session_id': session, 'tool': 'list_functions', 'arguments': {}}),
                     (f'/api/sessions/{session}/select-function', {'function': 'start'}),
                     ('/api/analysis', {'fixture_id': 'none'})]
        for path, body in endpoints:
            for origin in ('http://evil.example', 'null', f'http://localhost:{server.port}',
                           f'https://127.0.0.1:{server.port}', f'http://127.0.0.1:{server.port + 1}', None):
                headers = {**cookie, **({'Origin': origin} if origin else {})}
                status, _, data = server.request('POST', path, json.dumps(body), headers)
                self.assertEqual(status, 403, (path, origin, data))
        status, _, _ = server.request('POST', '/api/uploads', b'MZ', {**cookie, 'Origin': 'http://evil.example',
                                      'Content-Type': 'application/octet-stream'})
        self.assertEqual(status, 403)
        # A same-origin browser request and a header-token client (no Origin) are accepted.
        self.assertEqual(server.request('POST', '/api/sessions', json.dumps({'binary_id': 'b'}),
                                        {**cookie, 'Origin': server.origin})[0], 201)
        self.assertEqual(server.request('POST', '/api/sessions', json.dumps({'binary_id': 'b'}),
                                        self.auth(server))[0], 201)

    def test_cross_site_fetch_metadata_rejected_for_reads(self):
        server = _Server(self, self.app, token=TOKEN)
        for site in ('cross-site', 'same-site'):
            self.assertEqual(server.request('GET', '/api/bootstrap',
                                            headers=self.auth(server, **{'Sec-Fetch-Site': site}))[0], 403, site)
        for site in ('same-origin', 'none'):
            self.assertEqual(server.request('GET', '/api/bootstrap',
                                            headers=self.auth(server, **{'Sec-Fetch-Site': site}))[0], 200, site)

    # B6 ----------------------------------------------------------------
    def test_cross_origin_preflight_refused_and_no_cors_headers(self):
        server = _Server(self, self.app, token=TOKEN)
        status, headers, _ = server.request('OPTIONS', '/api/chat', headers={
            'Origin': 'http://evil.example', 'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type'})
        self.assertGreaterEqual(status, 400)
        self.assertFalse([h for h in headers if h.lower().startswith('access-control-')], headers)
        for path in ('/', '/app.js', '/api/bootstrap'):
            _, headers, _ = server.request('GET', path, headers=self.auth(server, Origin='http://evil.example'))
            self.assertFalse([h for h in headers if h.lower().startswith('access-control-')], (path, headers))

    # B7 ----------------------------------------------------------------
    def test_simple_form_content_types_rejected(self):
        server = _Server(self, self.app, token=TOKEN)
        for content_type in ('text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x'):
            status, _, data = server.request('POST', '/api/sessions', '{"binary_id":"b"}',
                                             self.auth(server, **{'Content-Type': content_type}))
            self.assertEqual(status, 400, content_type)
            self.assertIn('application/json', json.loads(data)['message'])

    # B8 ----------------------------------------------------------------
    def test_per_launch_token_required_for_api(self):
        server = _Server(self, self.app, token=TOKEN)
        self.assertEqual(server.request('GET', '/api/bootstrap')[0], 401)
        self.assertEqual(server.request('GET', '/api/bootstrap', headers={'X-AIRE-Token': 'x' * 43})[0], 401)
        self.assertEqual(server.request('GET', '/api/bootstrap',
                                        headers={'Cookie': f'{server.server.cookie_name}={"x" * 43}'})[0], 401)
        self.assertEqual(server.request('POST', '/api/sessions', json.dumps({'binary_id': 'b'}),
                                        {'Origin': server.origin})[0], 401)
        self.assertEqual(server.request('GET', '/api/bootstrap', headers=self.auth(server))[0], 200)
        # The static frontend itself is public code; it reports the 401 to the user.
        self.assertEqual(server.request('GET', '/')[0], 200)
        # Token exchange: wrong token refused; right token sets an HttpOnly SameSite=Strict cookie.
        self.assertEqual(server.request('GET', '/?token=' + 'x' * 43)[0], 401)
        status, headers, _ = server.request('GET', '/?token=' + TOKEN)
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/')
        cookie = headers['Set-Cookie']
        for flag in ('HttpOnly', 'SameSite=Strict', 'Path=/'):
            self.assertIn(flag, cookie)
        pair = cookie.split(';', 1)[0]
        self.assertEqual(server.request('GET', '/api/bootstrap', headers={'Cookie': pair})[0], 200)

    def test_token_never_written_to_request_log(self):
        server = _Server(self, self.app, token=TOKEN)
        lines = []
        with patch.object(AireRequestHandler, 'log_date_time_string', return_value='t'), \
                patch('sys.stderr') as stderr:
            stderr.write.side_effect = lines.append
            server.request('GET', '/?token=' + TOKEN)
            server.request('GET', '/?token=' + TOKEN + '&x=1')
        self.assertTrue(lines)
        self.assertNotIn(TOKEN, ''.join(lines))
        self.assertIn('token=<redacted>', ''.join(lines))

    def test_head_requests_use_the_same_gate(self):
        server = _Server(self, self.app, token=TOKEN)
        self.assertEqual(server.request('HEAD', '/', headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(server.request('HEAD', '/api/bootstrap', headers=self.auth(server))[0], 405)
        self.assertEqual(server.request('HEAD', '/app.js')[0], 200)

    # C10 ---------------------------------------------------------------
    def test_security_headers_on_static_and_api(self):
        server = _Server(self, self.app, token=TOKEN)
        for path, headers in (('/', {}), ('/app.js', {}), ('/api/bootstrap', self.auth(server)),
                              ('/api/bootstrap', {})):
            _, response, _ = server.request('GET', path, headers=headers)
            csp = response['Content-Security-Policy']
            for directive in ("default-src 'self'", "script-src 'self'", "object-src 'none'", "base-uri 'none'",
                              "frame-ancestors 'none'"):
                self.assertIn(directive, csp, path)
            self.assertNotIn('unsafe-inline', csp)
            self.assertNotIn('unsafe-eval', csp)
            self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(response['Referrer-Policy'], 'no-referrer')
            self.assertEqual(response['Cache-Control'], 'no-store')

    # D11 ---------------------------------------------------------------
    def test_static_route_path_traversal_rejected(self):
        server = _Server(self, self.app, token=TOKEN)
        secret = Path(__file__).resolve().parents[1] / 'src/aire/api/server.py'
        marker = b'class AireRequestHandler'
        self.assertIn(marker, secret.read_bytes())
        for path in ('/../server.py', '/%2e%2e/server.py', '/%2E%2E%2Fserver.py', '/..%2fserver.py',
                     '/..%5cserver.py', '/static/../../server.py', '//' + str(secret).lstrip('/'),
                     '/' + str(secret), '/%2f' + str(secret).lstrip('/').replace('/', '%2f'),
                     '/....//server.py', '/%252e%252e/server.py', '/../../../../etc/passwd'):
            status, _, data = server.request('GET', path)
            self.assertIn(status, (400, 404), path)
            self.assertNotIn(marker, data, path)
            self.assertNotIn(b'root:', data, path)

    # D14 ---------------------------------------------------------------
    def test_client_errors_redact_absolute_paths(self):
        home = str(Path.home())
        self.assertNotIn(home, redact_paths(f'[Errno 2] No such file: {home}/aire/x.exe'))
        self.assertIn('~/other/x.exe', redact_paths(f'{home}/other/x.exe'))
        self.assertEqual(redact_paths(f'{REPOSITORY}/a.exe'), '<repo>/a.exe')
        server = _Server(self, self.app, token=TOKEN)
        with patch.object(GuiApplication, 'list_binaries', side_effect=ValueError(f'broken {home}/secret/db')):
            status, _, data = server.request('GET', '/api/binaries', headers=self.auth(server))
        self.assertEqual(status, 400)
        self.assertNotIn(home.encode(), data)
        with patch.object(GuiApplication, 'list_binaries', side_effect=RuntimeError(f'trace {home}/x')):
            status, _, data = server.request('GET', '/api/binaries', headers=self.auth(server))
        self.assertEqual(status, 500)
        self.assertNotIn(home.encode(), data)
        self.assertNotIn(b'Traceback', data)

    # E18 ---------------------------------------------------------------
    def test_session_files_are_owner_only_regardless_of_umask(self):
        old = os.umask(0o002)
        try:
            session_id = self.app.new_session('b')['session_id']
            self.app.sessions.append_exchange(session_id, 'question', 'answer', 'completed')
        finally:
            os.umask(old)
        for suffix in ('.agent.json', '.transcript.json'):
            mode = (self.root / 'sessions' / (session_id + suffix)).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, suffix)

    # F20 ---------------------------------------------------------------
    def test_chat_concurrency_is_bounded(self):
        server = _Server(self, self.app, token=TOKEN)
        slots = server.server.chat_slots
        held = 0
        while slots.acquire(blocking=False):
            held += 1
        try:
            self.assertGreater(held, 0)
            status, _, data = server.request('POST', '/api/chat', json.dumps({'session_id': '0' * 32, 'question': 'x'}),
                                             self.auth(server))
            self.assertEqual(status, 429, data)
        finally:
            for _ in range(held):
                slots.release()

    def test_body_size_limit(self):
        server = _Server(self, self.app, token=TOKEN)
        status, _, _ = server.request('POST', '/api/sessions', b'{' + b' ' * 1_000_001 + b'}', self.auth(server))
        self.assertEqual(status, 400)


class BindPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.app = GuiApplication(_database(root), session_dir=root / 's', upload_dir=root / 'u',
                                  client_factory=_PayloadModel)
        self.addCleanup(self.app.library.close)

    def test_wildcard_and_public_binds_refused_even_with_opt_in(self):
        for host in ('0.0.0.0', '::', '0', '8.8.8.8', '224.0.0.1', '169.254.1.1', 'fd00::1', 'example.com',
                     '255.255.255.255'):
            for opt_in in (False, True):
                with self.subTest(host=host, opt_in=opt_in), self.assertRaises(GuiError):
                    create_server(self.app, host, 0, token=TOKEN, allow_non_loopback=opt_in)

    def test_nat_address_requires_opt_in_and_token(self):
        with self.assertRaisesRegex(GuiError, 'loopback'):
            create_server(self.app, '10.0.2.15', 0, token=TOKEN)
        with self.assertRaisesRegex(GuiError, 'token'):
            create_server(self.app, '10.0.2.15', 0, allow_non_loopback=True)

    def test_nat_address_binds_only_that_interface_when_present(self):
        try:
            probe = socket.socket()
            probe.bind(('10.0.2.15', 0))
            probe.close()
        except OSError:
            self.skipTest('10.0.2.15 is not a local interface address on this machine')
        server = create_server(self.app, '10.0.2.15', 0, token=TOKEN, allow_non_loopback=True, public_ports=(18080,))
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_address[0], '10.0.2.15')
        self.assertEqual(server.allowed_ports, {server.server_address[1], 18080})

    def test_serve_warns_and_prints_tokenized_urls(self):
        lines = []
        with patch('aire.api.server.AireHttpServer.serve_forever', side_effect=KeyboardInterrupt), \
                patch('aire.api.server.webbrowser.open') as browser:
            with self.assertLogs('aire.gui', 'WARNING') as logs:
                try:
                    from aire.api.server import serve
                    serve(self.app, host='10.0.2.15', port=0, open_browser=True, output=lines.append,
                          allow_non_loopback=True, public_port=18080)
                except GuiError:
                    self.skipTest('10.0.2.15 is not a local interface address on this machine')
                except OSError:
                    self.skipTest('10.0.2.15 is not bindable here')
        text = '\n'.join(lines)
        self.assertIn('WARNING: listening on non-loopback address 10.0.2.15', text)
        self.assertIn('http://127.0.0.1:18080/?token=', text)
        self.assertTrue(logs.output)
        browser.assert_not_called()  # the VM browser cannot use a NAT-only bind

    def test_loopback_serve_generates_a_fresh_token(self):
        tokens = []
        for _ in range(2):
            lines = []
            with patch('aire.api.server.AireHttpServer.serve_forever', side_effect=KeyboardInterrupt):
                from aire.api.server import serve
                serve(self.app, host='127.0.0.1', port=0, open_browser=False, output=lines.append)
            url = next(line for line in lines if line.startswith('Local URL: '))
            tokens.append(url.split('token=', 1)[1])
        self.assertNotEqual(tokens[0], tokens[1])
        self.assertTrue(all(len(t) >= 40 for t in tokens))


class OllamaHostPolicyTests(unittest.TestCase):
    def test_virtualbox_host_requires_explicit_opt_in(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            with self.assertRaises(ValueError):
                OllamaClient(host='http://10.0.2.2:11434')
            self.assertEqual(OllamaClient(host='http://10.0.2.2:11434', allow_remote_host=True).host,
                             'http://10.0.2.2:11434')
            with self.assertRaises(ValueError):
                OllamaClient(host='http://10.0.2.2:11434', allow_remote_host='1')  # bool only

    def test_ipv4_mapped_loopback_rejected_without_opt_in(self):
        for host in ('http://[::ffff:127.0.0.1]', 'http://[::ffff:7f00:1]:11434', 'http://[::ffff:10.0.2.2]'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                OllamaClient(host=host)

    def test_gui_client_gets_opt_in_only_from_launch_config(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        database = _database(root)
        closed = GuiApplication(database, session_dir=root / 's', upload_dir=root / 'u',
                                model_config=GuiModelConfig(host='http://10.0.2.2:11434', model='m'))
        self.addCleanup(closed.library.close)
        with self.assertRaises(ValueError):
            closed._client()
        opened = GuiApplication(database, session_dir=root / 's', upload_dir=root / 'u',
                                model_config=GuiModelConfig(host='http://10.0.2.2:11434', model='m',
                                                            allow_remote_host=True))
        self.addCleanup(opened.library.close)
        self.assertEqual(opened._client().host, 'http://10.0.2.2:11434')
        # No API request can change it: the config is immutable and no route reads such a field.
        with self.assertRaises(Exception):
            closed.model_config.allow_remote_host = True
        server = _Server(self, closed, token=TOKEN)
        session = json.loads(server.request('POST', '/api/sessions', json.dumps(
            {'binary_id': 'b', 'allow_remote_host': True, 'ollama_host': 'http://10.0.2.2:11434'}),
            {'X-AIRE-Token': TOKEN})[2])
        self.assertIn('session_id', session)
        self.assertFalse(closed.model_config.allow_remote_host)
        static = (Path(__file__).resolve().parents[1] / 'src/aire/api/server.py').read_text()
        self.assertNotIn("body.get('allow_remote", static)
        self.assertNotIn("body.get('ollama", static)

    def test_cli_flag_and_environment_set_the_opt_in(self):
        captured = {}

        def fake_serve(application, **options):
            captured['config'] = application.model_config
            captured['options'] = options
            application.library.close()
            return 0
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        database = _database(root)
        base = ['gui', '--database', str(database), '--session-dir', str(root / 's'), '--upload-dir', str(root / 'u'),
                '--no-browser', '--no-prewarm', '--ollama-host', 'http://10.0.2.2:11434']
        with patch('aire.api.server.serve', fake_serve), patch.dict(os.environ, {}, clear=False):
            os.environ.pop('AIRE_OLLAMA_ALLOW_REMOTE', None)
            os.environ.pop('AIRE_GUI_PUBLIC_PORT', None)
            cli.main(base, output=lambda _: None)
            self.assertFalse(captured['config'].allow_remote_host)
            self.assertFalse(captured['options']['allow_non_loopback'])
            cli.main(base + ['--allow-remote-ollama', '--bind', '10.0.2.15', '--allow-non-loopback-bind',
                             '--public-port', '18080'], output=lambda _: None)
            self.assertTrue(captured['config'].allow_remote_host)
            self.assertEqual(captured['options']['host'], '10.0.2.15')
            self.assertTrue(captured['options']['allow_non_loopback'])
            self.assertEqual(captured['options']['public_port'], 18080)
            os.environ['AIRE_OLLAMA_ALLOW_REMOTE'] = '1'
            os.environ['AIRE_GUI_PUBLIC_PORT'] = '18081'
            cli.main(base, output=lambda _: None)
            self.assertTrue(captured['config'].allow_remote_host)
            self.assertEqual(captured['options']['public_port'], 18081)


@unittest.skipUnless(os.environ.get('AIRE_RUN_BROWSER_TESTS') == '1' and shutil.which('firefox'),
                     'real-browser XSS test: set AIRE_RUN_BROWSER_TESTS=1 (needs Firefox)')
class BrowserXssTests(unittest.TestCase):
    """Payloads in a function name, string/import artifacts, decompiled text and model
    output render as literal text in headless Firefox; no injected element or script runs."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.app = GuiApplication(_database(root, payload=True), session_dir=root / 's', upload_dir=root / 'u',
                                  model_config=GuiModelConfig(model='mock'), client_factory=_PayloadModel)
        self.addCleanup(self.app.library.close)
        self.server = _Server(self, self.app, token=TOKEN)

    def _firefox(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        snap_common = Path.home() / 'snap/firefox/common'  # snap Firefox has a private /tmp
        profile_root = Path(tempfile.mkdtemp(prefix='aire-xss-', dir=snap_common if snap_common.is_dir() else None))
        self.addCleanup(shutil.rmtree, profile_root, True)
        profile = profile_root / 'profile'
        profile.mkdir()
        (profile / 'user.js').write_text(f'user_pref("marionette.port", {port});\n'
                                         'user_pref("browser.shell.checkDefaultBrowser", false);\n')
        log = (profile_root / 'firefox.log').open('w')
        self.addCleanup(log.close)
        process = subprocess.Popen(['firefox', '--headless', '--no-remote', '--marionette', '--profile', str(profile)],
                                   stdout=log, stderr=log)

        def stop():
            process.terminate()
            try:
                process.wait(20)
            except subprocess.TimeoutExpired:
                process.kill()
        self.addCleanup(stop)
        for _ in range(200):
            try:
                sock = socket.create_connection(('127.0.0.1', port), timeout=2)
                break
            except OSError:
                time.sleep(.3)
        else:
            self.fail('Firefox Marionette did not start')
        self.addCleanup(sock.close)
        sock.settimeout(60)

        def receive():
            prefix = b''
            while not prefix.endswith(b':'):
                prefix += sock.recv(1)
            remaining, data = int(prefix[:-1]), b''
            while len(data) < remaining:
                data += sock.recv(remaining - len(data))
            return json.loads(data)
        receive()
        counter = [0]

        def command(name, parameters=None):
            counter[0] += 1
            data = json.dumps([0, counter[0], name, parameters or {}]).encode()
            sock.sendall(str(len(data)).encode() + b':' + data)
            result = receive()
            if result[2]:
                raise RuntimeError(result[2])
            return result[3]
        return command

    def test_payloads_render_as_literal_text(self):
        command = self._firefox()

        def script(code):
            result = command('WebDriver:ExecuteScript', {'script': code, 'args': [], 'newSandbox': False})
            return result.get('value') if isinstance(result, dict) else result

        def wait(code, timeout=60):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = script(code)
                if value:
                    return value
                time.sleep(.1)
            self.fail('Timed out: ' + code + '\nBODY: ' + str(script('return document.body.innerText'))[:1500])

        command('WebDriver:NewSession', {'capabilities': {}})
        # Real token login flow: tokenized URL -> HttpOnly cookie -> API calls succeed.
        command('WebDriver:Navigate', {'url': self.server.origin + '/?token=' + TOKEN})
        wait('return document.querySelector("#binarySelect") && document.querySelector("#binarySelect").options.length > 0')
        self.assertEqual(script('return document.cookie'), '')  # HttpOnly: not readable by page script
        self.assertEqual(script('return location.search'), '')  # token removed from the address bar
        # Record any dialog or injected-handler execution (CSP should block it anyway).
        script('window.__aire_alerts = []; window.alert = m => window.__aire_alerts.push(String(m));')
        literal = 'return document.body.innerText.includes(' + json.dumps(XSS) + ')'
        injected = 'return document.querySelectorAll(".aire-xss, img[onerror]").length'

        script('document.querySelector("#investigateBtn").click()')  # opens Functions list
        wait('return document.querySelector("#toolResult .tool-row")')
        wait(literal)
        self.assertEqual(script(injected), 0, 'function name')
        for view in ('strings', 'imports'):
            script(f'document.querySelector("[data-tool-view={view}]").click()')
            wait(f'return document.querySelector("#toolResult h4").textContent.toLowerCase().startsWith("{view[:-1]}")')
            wait(literal)
            self.assertEqual(script(injected), 0, view)
        # Select the payload function by clicking its row, then show its decompiled text.
        script('document.querySelector("[data-tool-view=functions]").click()')
        wait('return [...document.querySelectorAll("#toolResult button.tool-row")].some(b => b.textContent.startsWith("start<img"))')
        script('[...document.querySelectorAll("#toolResult button.tool-row")].find(b => b.textContent.startsWith("start<img")).click()')
        wait('return !document.querySelector("#selectedFunctionChip").classList.contains("hidden")')
        self.assertTrue(script('return document.querySelector("#selectedFunctionChip").textContent.includes(' +
                               json.dumps(XSS) + ')'))
        script('document.querySelector("[data-tool-view=decompiled]").click()')
        wait('return document.querySelector("#toolResult pre.code-view")')
        wait(literal)
        self.assertEqual(script(injected), 0, 'decompiled text')
        # Model output through the real chat composer and streaming renderer.
        script('const i = document.querySelector("#chatInput") ; i.value = "Explain start";'
               'i.closest("form").requestSubmit();')
        wait('return document.querySelector(".message-row.assistant .analysis-footer")', timeout=90)
        wait('return document.querySelector(".message-row.assistant .answer-body").innerText.includes("Model says <img")')
        self.assertEqual(script(injected), 0, 'model output')
        self.assertEqual(script('return window.__aire_alerts.length'), 0)
        # The stored transcript re-renders the same way (Recent conversations).
        script('document.querySelector("[data-nav=recent]").click()')
        wait('return document.querySelector(".recent-card")')
        self.assertEqual(script(injected), 0, 'recent list')
        self.assertEqual(script('return window.__aire_alerts.length'), 0)


if __name__ == '__main__':
    unittest.main()
