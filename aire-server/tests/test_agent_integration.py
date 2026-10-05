"""Opt-in real fixture indexing; live agent inference is separately opt-in."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from aire.agent.runner import AgentLimits, AgentRunner
from aire.agent.session import AgentSession
from aire.agent.tools import AgentTools
from aire.ai.ollama_client import OllamaClient
from aire.knowledge.database import BinaryKnowledgeStore
from aire.pyghidra.indexer import index_binary
from test_agent_runner import AgentModel, tool

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/fixtures/simple_elf'
QUESTIONS = ['What does this binary do?', 'Show me the most important functions.',
             'Why is process_input important?', 'What calls it?',
             'Explain this function using both decompiled code and assembly.']


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class AgentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='aire_m8_')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.database = Path(os.environ.get('AIRE_AGENT_DATABASE', str(Path(cls.directory.name) / 'analysis.sqlite')))
        cls.indices, cls.hashes, cls.reports = {}, {}, {}
        with BinaryKnowledgeStore(cls.database) as store:
            for kind, name in [('debug', 'aire_test_binary'), ('stripped', 'aire_test_binary_stripped')]:
                path = FIXTURE / name
                cls.hashes[kind] = hashlib.sha256(path.read_bytes()).hexdigest()
                cls.indices[kind] = index_binary(path)
                store.save_program_index(cls.indices[kind])
                if hashlib.sha256(path.read_bytes()).hexdigest() != cls.hashes[kind]:
                    raise AssertionError('Fixture changed')

    @classmethod
    def tearDownClass(cls):
        for kind, name in [('debug', 'aire_test_binary'), ('stripped', 'aire_test_binary_stripped')]:
            if hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest() != cls.hashes[kind]:
                raise AssertionError('Fixture changed during agent validation')
        if os.environ.get('AIRE_AGENT_REPORT'):
            Path(os.environ['AIRE_AGENT_REPORT']).write_text(json.dumps(cls.reports, indent=2, ensure_ascii=True))

    def test_debug_and_stripped_deterministic(self):
        debug = next(f for f in self.indices['debug'].functions if f.current_name == 'process_input')
        with BinaryKnowledgeStore(self.database) as store:
            before = store._db.total_changes
            for kind, index in self.indices.items():
                overview_model = AgentModel([{'action': 'answer'}])
                overview = AgentRunner(store, overview_model,
                    limits=AgentLimits(evidence_chars=6000)).run(
                    AgentSession(index.binary.binary_id), 'What does this binary do?')
                self.assertEqual(overview.status, 'completed', overview.answer)
                self.assertEqual(overview.response.target, None)
                self.assertTrue(overview.response.evidence_bundle.metadata['priority_function_ids'])
                self.assertTrue(any(f.function.decompiled_text or f.function.assembly
                    for f in overview.response.evidence_bundle.functions))
                self.assertTrue(any(c['kind'] == 'FUNC' and
                    (c['data']['function']['decompiled_text'] or c['data']['function']['assembly'])
                    for c in (json.loads(line) for line in overview_model.calls[0].splitlines()
                              if line.startswith('{"data":'))))
                self.assertTrue(any(c['kind'] == 'EDGE' for c in
                    (json.loads(line) for line in overview_model.calls[0].splitlines()
                     if line.startswith('{"data":'))))
                self.assertTrue(any(e.event_type == 'evidence_found' for e in overview.events))
                selector = 'process_input' if kind == 'debug' else debug.address
                session = AgentSession(index.binary.binary_id)
                model = AgentModel([tool('get_function', function=selector), tool('get_callees', function='it')])
                result = AgentRunner(store, model).run(session, 'Explain this function')
                self.assertEqual(result.status, 'completed', result.answer)
                self.assertEqual(result.response.evidence_bundle.functions[0].function.address, debug.address)
                self.assertTrue(result.tool_results[1]['ok'])
                if kind == 'stripped':
                    self.assertNotEqual(result.response.evidence_bundle.functions[0].function.current_name, 'process_input')
                followup = AgentRunner(store, AgentModel([tool('get_callers', function='it')])).run(session, 'What calls it?')
                self.assertEqual(followup.status, 'completed')
                self.assertTrue(followup.tool_results[0]['data']['items'])
            self.assertEqual(store._db.total_changes, before)

    @unittest.skipUnless(os.environ.get('AIRE_RUN_AGENT_LIVE_TESTS') == '1', 'Opt-in agent Ollama validation')
    def test_live_demo(self):
        client = OllamaClient(timeout_seconds=120)
        self.assertIn(client.model, client.list_models(), 'Selected model must already be installed')
        index = self.indices['debug']
        session = AgentSession(index.binary.binary_id)
        reports = []
        with BinaryKnowledgeStore(self.database) as store:
            before = store._db.total_changes
            runner = AgentRunner(store, client, limits=AgentLimits(max_iterations=3, max_tool_calls=5,
                timeout_seconds=240, evidence_chars=6000))
            for question in QUESTIONS:
                print('\nM8 live request: ' + question, flush=True)
                result = runner.run(session, question, on_event=lambda e: print(
                    e.event_type + ': ' + e.message + (' [' + e.tool_name + ']' if e.tool_name else ''), flush=True))
                reports.append({'question': question, 'model': client.model, 'num_ctx': client.num_ctx,
                    'status': result.status, 'selected_function': session.current_function_id,
                    'answer': result.answer, 'tools': [r['tool'] for r in result.tool_results],
                    'events': [e.to_dict() for e in result.events],
                    'sizes': result.response.sizes if result.response else None})
                print('M8 live status: ' + result.status, flush=True)
                self.reports['live'] = reports
                if os.environ.get('AIRE_AGENT_REPORT'):
                    Path(os.environ['AIRE_AGENT_REPORT']).write_text(json.dumps(self.reports, indent=2))
            self.assertEqual(store._db.total_changes, before)
        # Validation records inference limitations; infrastructure remains deterministic.
        self.assertEqual(len(reports), 5)
