"""Real M1 → SQLite → reopened ProgramIndex, enabled with AIRE_RUN_GHIDRA_TESTS=1."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from aire.knowledge.database import BinaryKnowledgeStore
from aire.pyghidra.indexer import index_binary

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'tests/binaries/aire_test_stripped'


def counts(index):
    artifacts = Counter(a.type for a in index.artifacts)
    return {'functions': len(index.functions),
            'decompiled_functions': sum(bool(f.decompiled_text) for f in index.functions),
            'strings': artifacts['STRING'], 'imports': artifacts['IMPORT'],
            'exports': artifacts['EXPORT'], 'call_edges': len(index.function_edges),
            'warnings': len(index.warnings)}


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class DatabaseIntegrationTests(unittest.TestCase):
    def test_real_round_trip(self):
        before = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        try:
            original = index_binary(BINARY)
            self.assertGreater(len(original.functions), 80)
            self.assertTrue(any(f.decompiled_text for f in original.functions))
            self.assertTrue(any(f.assembly for f in original.functions))
            self.assertTrue(any(a.type == 'STRING' for a in original.artifacts))
            self.assertTrue(any(a.type == 'IMPORT' for a in original.artifacts))
            self.assertTrue(original.function_edges)
            with tempfile.TemporaryDirectory(prefix='aire_m2_') as directory:
                path = Path(directory) / 'analysis.sqlite'
                with BinaryKnowledgeStore(path) as store:
                    tick = time.perf_counter()
                    store.save_program_index(original)
                    save_seconds = time.perf_counter() - tick
                with BinaryKnowledgeStore(path) as store:
                    tick = time.perf_counter()
                    loaded = store.load_program_index(original.binary.binary_id)
                    load_seconds = time.perf_counter() - tick
                    self.assertEqual(store._db.execute('PRAGMA foreign_key_check').fetchall(), [])
                size = path.stat().st_size
                # Equality includes every field, all text/metrics, list ordering,
                # datetimes/booleans, warnings, and all metadata (not just counts).
                self.assertEqual(loaded, original)
                self.assertEqual(loaded.to_dict(), original.to_dict())
                self.assertEqual(counts(loaded), counts(original))
                report = {'original': counts(original), 'loaded': counts(loaded),
                          'save_seconds': save_seconds, 'load_seconds': load_seconds,
                          'database_bytes': size, 'sha256_before': before,
                          'sha256_after': hashlib.sha256(BINARY.read_bytes()).hexdigest()}
                print('\nM2 round-trip: ' + json.dumps(report, sort_keys=True), flush=True)
                report_path = os.environ.get('AIRE_DATABASE_REPORT')
                if report_path:
                    Path(report_path).write_text(json.dumps(report, indent=2))
        finally:
            self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
