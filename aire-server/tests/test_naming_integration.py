"""Opt-in static stripped-fixture naming; one separately opted-in live target.

The indexing child exits before inference so its JVM cannot contend with Ollama.
The analyzed executables are never run. Ground truth is never sent to the model.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aire.ai.chat import AireChatService
from aire.ai.chat_models import ChatError
from aire.ai.naming import NamingService, NamingOptions
from aire.ai.ollama_client import OllamaClient
from aire.knowledge.database import BinaryKnowledgeStore
from test_naming import NamingModel, output

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures/simple_elf'
PATHS = [FIXTURES / 'aire_test_binary', FIXTURES / 'aire_test_binary_stripped']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra naming integration')
class NamingIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = [digest(p) for p in PATHS]
        cls.directory = tempfile.TemporaryDirectory(prefix='aire_m6_')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.path = Path(cls.directory.name) / 'analysis.sqlite'
        # A distinct Python/JVM lifetime, using the real M1 and M2 APIs.
        code = '''import sys
from pathlib import Path
from aire.pyghidra.indexer import index_binary
from aire.knowledge.database import BinaryKnowledgeStore
with BinaryKnowledgeStore(sys.argv[1]) as store:
    for path in sys.argv[2:]:
        store.save_program_index(index_binary(Path(path)))
'''
        try:
            subprocess.run([sys.executable, '-c', code, str(cls.path), *map(str, PATHS)], check=True)
        finally:
            if cls.before != [digest(p) for p in PATHS]:
                raise AssertionError('Fixture modified during indexing')
        with BinaryKnowledgeStore(cls.path) as store:
            debug = store.load_program_index(cls.before[0])
            stripped = store.load_program_index(cls.before[1])
        truth = (FIXTURES / 'GROUND_TRUTH.md').read_text()
        if 'Gate transformation on successful validation' not in truth:
            raise AssertionError('Review evaluation against ground truth')
        cls.debug = next(f for f in debug.functions if f.current_name == 'process_input')
        cls.target = next(f for f in stripped.functions if f.address == cls.debug.address)
        if cls.target.current_name == cls.debug.current_name:
            raise AssertionError('Stripped target leaks ground-truth name')
        cls.reports = {}

    @classmethod
    def tearDownClass(cls):
        if cls.before != [digest(p) for p in PATHS]:
            raise AssertionError('Fixture modified during naming')
        if os.environ.get('AIRE_NAMING_REPORT'):
            Path(os.environ['AIRE_NAMING_REPORT']).write_text(json.dumps(cls.reports, indent=2))

    def run_naming(self, client, live=False):
        with BinaryKnowledgeStore(self.path) as store:
            stored_before = store.load_program_index(self.before[1])
            file_before = digest(self.path)
            changes_before = store._db.total_changes
            # No writes allowed even if a future service regression attempts one.
            store._db.execute('PRAGMA query_only=ON')
            service = NamingService(store, AireChatService(store, client))
            options = NamingOptions(max_candidates=2, max_suggestions_per_function=2,
                                    max_context_chars=5000, include_assembly=False)
            original = client.generate
            prompts = []
            def checked(prompt, **kwargs):
                prompts.append(prompt)
                for forbidden in ('process_input', 'validate_input', 'transform_input', 'GROUND_TRUTH.md'):
                    self.assertNotIn(forbidden, prompt)
                self.assertIn('UNTRUSTED ANALYZED DATA', prompt)
                print(f'Naming preflight: prompt={len(prompt)+len(kwargs["system"])} characters, '
                      f'num_ctx={getattr(client, "num_ctx", "fake")}', flush=True)
                return original(prompt, **kwargs)
            try:
                with patch.object(client, 'generate', side_effect=checked):
                    result = service.suggest_names(self.before[1], self.target.function_id, options)
            finally:
                # Integrity is required on rejected/failed responses too.
                self.assertEqual(store._db.total_changes, changes_before)
                self.assertEqual(store.load_program_index(self.before[1]), stored_before)
                self.assertEqual(digest(self.path), file_before)
                self.assertEqual([digest(p) for p in PATHS], self.before)
            self.assertEqual(result.function_address, self.debug.address)
            self.assertEqual(result.current_name, self.target.current_name)
            self.assertLessEqual(len(result.suggestions), 2)
            self.assertLessEqual(result.sizes['context_characters'], 5000)
            self.assertTrue(result.context_truncated)
            # Live abstention is valid and explicitly distinguishable from a suggestion.
            if not live:
                self.assertTrue(result.suggestions)
            for s in result.suggestions:
                self.assertTrue(s.evidence_ids)
                self.assertTrue(set(s.evidence_ids) <= result.citations.keys())
                for identity in s.evidence_ids:
                    self.assertEqual(result.citations[identity].provenance.binary_id, self.before[1])
        self.reports['live' if live else 'fake'] = {
            'mode': 'real local inference' if live else 'fake provider; no semantic model evaluation',
            'ground_truth': self.debug.current_name, 'address': self.debug.address,
            'sha256_before': self.before, 'sha256_after': [digest(p) for p in PATHS],
            'database_unchanged': True, 'ground_truth_absent_from_prompt': True,
            'result': result.to_dict()}

    def test_stripped_fake_naming(self):
        self.run_naming(NamingModel())

    def test_rejected_output_leaves_analysis_unchanged(self):
        # Addresses in names stay invalid even when every citation is real.
        invalid = lambda prompt: output(prompt, 'analyze_004012f8')
        with self.assertRaisesRegex(ChatError, 'address-bearing'):
            self.run_naming(NamingModel([invalid, invalid]))

    @unittest.skipUnless(os.environ.get('AIRE_RUN_NAMING_LIVE_TESTS') == '1', 'Opt-in one-function Ollama naming')
    def test_stripped_live_naming(self):
        # Once explicitly enabled, service/model errors fail rather than mask as skips.
        client = OllamaClient()
        self.assertEqual(client.model, 'qwen2.5-coder:1.5b')
        self.assertEqual(client.num_ctx, 4096)
        self.assertEqual(client.host, 'http://127.0.0.1:11434')
        self.assertIn(client.model, client.list_models())
        self.run_naming(client, live=True)


if __name__ == '__main__':
    unittest.main()
