"""Real Ghidra → cached SQLite snapshot; opt in with AIRE_RUN_GHIDRA_TESTS=1."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
from aire.profiling import AnalysisProfile

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'tests/binaries/aire_test_stripped'


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class AnalysisCacheIntegrationTests(unittest.TestCase):
    def test_real_miss_then_reopened_cache_hit(self):
        before = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        try:
            with tempfile.TemporaryDirectory(prefix='aire-analysis-cache-') as directory:
                database = Path(directory) / 'analysis.sqlite'
                with BinaryKnowledgeStore(database) as store:
                    with AnalysisProfile() as profile:
                        fresh = analyze_binary(BINARY, store)
                    self.assertFalse(fresh.cache_hit)
                    self.assertGreater(len(fresh.program_index.functions), 80)
                    self.assertTrue(fresh.program_index.metadata['input_sha256_unchanged'])
                    self.assertEqual(profile.counts['projects_created'], 1)
                    self.assertEqual(profile.counts['executable_imports'], 1)
                    self.assertEqual(profile.counts['analyze_calls'], 1)
                    self.assertEqual(profile.counts['database_saves'], 1)
                    self.assertEqual(profile.counts['sha256_reads'], 4)
                    self.assertEqual(profile.counts['decompile_attempts'],
                                     sum(not function.is_external for function in fresh.program_index.functions))
                    self.assertEqual(profile.to_dict()['repeated_decompilations'], {})
                    self.assertAlmostEqual(sum(profile.seconds.values()), profile.total_seconds)
                with BinaryKnowledgeStore(database) as store:
                    with patch('aire.analysis.cache.index_binary', side_effect=AssertionError('Cache indexed')):
                        with patch('aire.pyghidra.indexer._start_runtime', side_effect=AssertionError('Cache started Ghidra')):
                            cached = analyze_binary(BINARY, store)
                self.assertTrue(cached.cache_hit)
                self.assertEqual(cached.program_index, fresh.program_index)
                self.assertEqual(cached.program_index.binary.binary_id, before)
                self.assertGreater(fresh.elapsed_seconds, 0)
                self.assertGreater(cached.elapsed_seconds, 0)
        finally:
            self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
