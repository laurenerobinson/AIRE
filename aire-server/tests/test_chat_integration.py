"""Real static simple-ELF M1–M5 checks; live model cases are separately opt-in.

Never builds, executes, patches, or saves the target program. A fake model tests
M5 infrastructure independently of local Ollama availability.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from aire.ai.chat import AireChatService, render_response
from aire.ai.ollama_client import OllamaClient, OllamaConnectionError, OllamaTimeoutError
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.retrieval import ProgramQueryService
from aire.pyghidra.indexer import index_binary
from test_chat import FakeModel

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/fixtures/simple_elf'
BINARIES = {'debug': FIXTURE / 'aire_test_binary', 'stripped': FIXTURE / 'aire_test_binary_stripped'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class ChatIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = {kind: digest(path) for kind, path in BINARIES.items()}
        cls.directory = tempfile.TemporaryDirectory(prefix='aire_m5_')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.db_path = Path(cls.directory.name) / 'analysis.sqlite'
        cls.indices = {}
        cls.reports = {}
        try:
            with BinaryKnowledgeStore(cls.db_path) as store:
                for kind, path in BINARIES.items():
                    cls.indices[kind] = index_binary(path)
                    store.save_program_index(cls.indices[kind])
        finally:
            for kind, path in BINARIES.items():
                if digest(path) != cls.before[kind]:
                    raise AssertionError(f'{kind} fixture changed during static indexing')
        cls.debug_target = next(f for f in cls.indices['debug'].functions if f.current_name == 'process_input')
        cls.expected_names = {'validate_input', 'transform_input'}
        cls.expected_addresses = {f.address for f in cls.indices['debug'].functions if f.current_name in cls.expected_names}
        ground_truth = (FIXTURE / 'GROUND_TRUTH.md').read_text()
        for path in ('main -> process_input -> validate_input -> calculate_checksum',
                     'main -> process_input -> transform_input -> calculate_checksum'):
            if path not in ground_truth:
                raise AssertionError('Integration expectations need review against fixture ground truth')

    @classmethod
    def tearDownClass(cls):
        output = os.environ.get('AIRE_CHAT_REPORT')
        if output:
            Path(output).write_text(json.dumps(cls.reports, indent=2, sort_keys=True))
        for kind, path in BINARIES.items():
            if digest(path) != cls.before[kind]:
                raise AssertionError(f'{kind} fixture was modified')

    def run_question(self, kind, client, *, live=False):
        index = self.indices[kind]
        with BinaryKnowledgeStore(self.db_path) as store:
            query = ProgramQueryService(store)
            target = query.resolve_function(index.binary.binary_id,
                'process_input' if kind == 'debug' else self.debug_target.address,
                by='name' if kind == 'debug' else 'address')
            edges = query.get_callees(index.binary.binary_id, target)
            self.assertEqual({e.callee.address for e in edges}, self.expected_addresses)
            if kind == 'debug':
                self.assertEqual({e.callee.current_name for e in edges}, self.expected_names)
            else:
                self.assertNotEqual(target.current_name, 'process_input')
            # Explicit test-only resource budget; all grounding assertions below
            # remain identical. Static/fake-provider coverage keeps its defaults.
            resource_options = {}
            if live and 'AIRE_CHAT_TEST_CONTEXT_CHARS' in os.environ:
                resource_options['max_total_context_chars'] = int(os.environ['AIRE_CHAT_TEST_CONTEXT_CHARS'])
            response = AireChatService(store, client).ask(index.binary.binary_id,
                'What functions does this function interact with? Select the direct call relationships as facts.',
                target.function_id, target_by='id', debug=live,
                max_functions=6, max_artifacts=6, max_edges=8, **resource_options)
            bundle = response.evidence_bundle
            self.assertEqual(bundle.metadata['resolved_target_id'], target.function_id)
            self.assertIn(target.function_id, [f.function.function_id for f in bundle.functions])
            self.assertTrue(bundle.functions[0].function.decompiled_text)
            self.assertTrue(bundle.functions[0].function.assembly)
            self.assertTrue(response.summary.claim)
            self.assertEqual(response.context_truncated, bool(response.context_truncations))
            self.assertTrue(set(bundle.truncations).issubset(set(response.context_truncations)))
            known_sources = {(p.source_table, p.source_id) for p in bundle.provenance}
            for citation in response.citations.values():
                self.assertIn((citation.provenance.source_table, citation.provenance.source_id), known_sources)
                self.assertEqual(citation.provenance.binary_id, index.binary.binary_id)
            for claim in [response.summary] + response.facts + response.interpretations:
                self.assertTrue(claim.evidence_ids)
                self.assertTrue(set(claim.evidence_ids).issubset(response.citations))
            for fact in response.facts:
                self.assertEqual(fact.claim, response.citations[fact.evidence_ids[0]].fact)
            for interpretation in response.interpretations:
                self.assertIn(interpretation.confidence, ('low', 'medium', 'high'))
            # Ground truth scoring uses exact stored edge identities, not prose wording.
            selected_sources = {response.citations[identity].provenance.source_id
                                for fact in response.facts for identity in fact.evidence_ids}
            expected_edges = [item for item in bundle.edges if item.caller.function_id == target.function_id]
            supported = [item for item in expected_edges if item.provenance.source_id in selected_sources]
            self.assertEqual(len(expected_edges), 2)
            self.assertEqual({item.callee.address for item in supported}, self.expected_addresses,
                             'Answer must select both supplied direct-callee facts for this relationship question')
            self.assertEqual(store._db.total_changes, 0)
            label = kind + ('_live' if live else '_fake_model')
            report = {
                'mode': 'live Ollama' if live else 'real static evidence + fake model; NOT live inference',
                'model': response.model, 'question': response.question, 'target_address': target.address,
                'target_name': target.current_name, 'summary': response.summary.claim,
                'facts': [fact.claim for fact in response.facts],
                'interpretations': [claim.claim for claim in response.interpretations],
                'citation_count': len(response.citations), 'citations_valid': True,
                'ground_truth_direct_callee_matches': len(supported),
                'context_truncated': response.context_truncated,
                'sizes': response.sizes, 'timing_seconds': response.timing,
                'sha256_before': self.before[kind], 'sha256_after': digest(BINARIES[kind]),
            }
            self.reports[label] = report
            print('\nM5: ' + json.dumps(report, sort_keys=True), flush=True)
            self.assertEqual(report['sha256_before'], report['sha256_after'])
            self.assertIn('model interpretation', render_response(response))

    def test_debug_deterministic_pipeline(self):
        self.run_question('debug', FakeModel())

    def test_stripped_deterministic_pipeline(self):
        self.run_question('stripped', FakeModel())

    def local_client(self, kind):
        client = OllamaClient()
        try:
            models = client.list_models()
        except (OllamaConnectionError, OllamaTimeoutError) as exc:
            self.reports[kind + '_live'] = {'status': 'skipped', 'reason': str(exc)}
            self.skipTest(str(exc))
        model = client.model or (models[0] if models else None)
        if not model or model not in models:
            reason = f'No installed selected model: {model!r}; available models: {models}. No model pulled.'
            self.reports[kind + '_live'] = {'status': 'skipped', 'reason': reason}
            self.skipTest(reason)
        return OllamaClient(host=client.host, model=model)

    @unittest.skipUnless(os.environ.get('AIRE_RUN_OLLAMA_TESTS') == '1', 'Opt-in local Ollama inference')
    def test_debug_live_ollama(self):
        self.run_question('debug', self.local_client('debug'), live=True)

    @unittest.skipUnless(os.environ.get('AIRE_RUN_OLLAMA_TESTS') == '1', 'Opt-in local Ollama inference')
    def test_stripped_live_ollama(self):
        self.run_question('stripped', self.local_client('stripped'), live=True)


if __name__ == '__main__':
    unittest.main()
