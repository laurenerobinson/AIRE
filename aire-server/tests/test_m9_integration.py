"""Opt-in real PyGhidra checks for M9 (set AIRE_RUN_GHIDRA_TESTS=1).

* CNG crypto PEs: crypto_evidence must find every ground-truth crypto function
  at its exact address with its documented APIs, and main's CALL relationships.
* Damaged-but-loadable PEs (validator level 'partial') must index without
  raising and leave inputs unchanged.
* Parallel decompilation output must equal the serial path on a real binary.
Targets are only read; nothing is executed.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.analysis.cache import analyze_binary
from aire.api.binary_library import REPOSITORY
from aire.knowledge.database import BinaryKnowledgeStore
from aire.pyghidra.indexer import index_binary
from aire.security.crypto_evidence import crypto_evidence

M9 = REPOSITORY / 'tests/fixtures/m9'
RUN = os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1'


def _facts(index):
    data = index.to_dict()
    data['binary'].pop('analyzed_at')
    for key in list(data['metadata']):
        if key.endswith('_seconds') or key == 'decompile_workers':
            data['metadata'].pop(key)
    for key in ('Analysis Times.Times', 'Date Created'):
        data['program_info'].pop(key, None)
    return data


@unittest.skipUnless(RUN, 'set AIRE_RUN_GHIDRA_TESTS=1 for real PyGhidra integration')
class M9GhidraIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.store = BinaryKnowledgeStore(Path(cls.directory.name) / 'm9.sqlite')
        cls.truth = json.loads((M9 / 'crypto_pe/GROUND_TRUTH.json').read_text())['programs']

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.directory.cleanup()

    def test_crypto_evidence_matches_ground_truth(self):
        for program, truth in self.truth.items():
            with self.subTest(program):
                path = REPOSITORY / truth['binary']
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), truth['sha256'])
                result = analyze_binary(path, self.store)
                report = crypto_evidence(self.store._db, result.binary_id)
                found = {row['address']: row for row in report['functions']}
                expected = {s['address']: (name, s) for name, s in truth['functions'].items() if s.get('apis')}
                self.assertEqual(set(found), set(expected), 'crypto functions differ from ground truth')
                for address, (name, spec) in expected.items():
                    self.assertTrue(set(spec['apis']) <= set(found[address]['apis']), name)
                    for call in found[address]['callsites']:
                        self.assertIn(call['source_table'], ('binary_references', 'function_edges'))
                main = truth['functions']['main']
                for callee in main['calls']:
                    address = truth['functions'][callee]['address']
                    if address in found:
                        self.assertIn(main['address'], {c['address'] for c in found[address]['callers']},
                                      f'main -> {callee}')
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), truth['sha256'])

    def test_partial_corrupt_pes_index_without_crashing(self):
        rows = {r['name']: r for r in json.loads((M9 / 'corrupt_pe/EXPECTED.json').read_text())['fixtures']}
        for name in ('corrupt_section_overlap', 'corrupt_import_thunks_invalid'):
            with self.subTest(name):
                path = M9 / rows[name]['binary_path']
                result = analyze_binary(path, self.store)
                self.assertFalse(result.cache_hit)
                self.assertTrue(result.program_index.functions)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), rows[name]['binary_sha256'])

    def test_parallel_decompilation_equals_serial_on_real_binary(self):
        path = M9 / 'crypto_pe/aes_gcm.exe'
        with patch.dict(os.environ, {'AIRE_DECOMPILE_WORKERS': '1'}):
            serial = index_binary(path)
        with patch.dict(os.environ, {'AIRE_DECOMPILE_WORKERS': '4'}):
            parallel = index_binary(path)
        self.assertEqual(serial.metadata['decompile_workers'], 1)
        self.assertEqual(parallel.metadata['decompile_workers'], 4)
        self.assertEqual(_facts(serial), _facts(parallel))


    def test_injected_decompiler_freeze_is_retried_and_recovered(self):
        # SIGSTOPs the native decompiler processes mid-extraction (simulated
        # host freeze); facts must equal a clean run after serial retries.
        import subprocess, sys
        script = REPOSITORY / 'scripts/verify_m9_retry_real.py'
        result = subprocess.run([sys.executable, str(script), str(M9 / 'crypto_pe/sha256_hash.exe')],
                                capture_output=True, text=True, timeout=900, env=os.environ)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        report = json.loads(result.stdout)
        self.assertTrue(report['decompile_retry']['timed_out'])
        self.assertEqual(report['decompile_retry']['recovered'], report['decompile_retry']['timed_out'])
        self.assertTrue(report['facts_identical_to_clean_run'])


    def test_prewarmed_worker_serves_first_job_without_jvm_start(self):
        import time
        from aire.api.binary_library import BinaryLibrary
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / 'p.sqlite'
            with BinaryKnowledgeStore(database):
                pass
            library = BinaryLibrary(database, directory=Path(tmp) / 'uploads')
            try:
                self.assertTrue(library.prewarm())
                deadline = time.monotonic() + 300
                while library.analyzer_status()['status'] in ('warming', 'running'):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.5)
                self.assertEqual(library.analyzer_status()['status'], 'ready', library.analyzer_status())
                job = library.start(fixture_id='local:simple-elf')
                while library.job(job['job_id'])['status'] not in ('completed', 'failed'):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.2)
                row = library.job(job['job_id'])
                self.assertEqual(row['status'], 'completed', row.get('error'))
                self.assertFalse(row['cache_hit'])
                self.assertEqual(row['profile']['counts']['launcher_start_calls'], 0)
            finally:
                library.close()


    def test_m10_phase1_matches_objdump_on_elf(self):
        # M10: structured facts + semantics vs an independent disassembler.
        import shutil, sys
        if shutil.which('objdump') is None:
            self.skipTest('objdump not installed')
        sys.path.insert(0, str(REPOSITORY / 'scripts'))
        from evaluate_m10 import evaluate_phase1
        path = REPOSITORY / 'tests/fixtures/simple_elf/aire_test_binary'
        result = analyze_binary(path, self.store)
        binary = next(b for b in self.store.list_binaries() if b.binary_id == result.binary_id)
        report = evaluate_phase1(self.store, binary, path)
        self.assertEqual(report['mismatches'], {})
        self.assertEqual(report['rates']['relations'], 1.0)
        self.assertGreater(report['counts']['relations'], 10)


if __name__ == '__main__':
    unittest.main()
