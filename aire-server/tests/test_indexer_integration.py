"""Opt in with AIRE_RUN_GHIDRA_TESTS=1; never executes the controlled fixture."""
import hashlib
import json
import os
from pathlib import Path
import unittest

from aire.pyghidra.indexer import index_binary
from aire.pyghidra.options import IndexOptions

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'tests/binaries/aire_test_stripped'


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class GhidraIntegrationTests(unittest.TestCase):
    def test_controlled_binary(self):
        before = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        index = index_binary(BINARY)
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), before)
        self.assertTrue(index.metadata['analysis_completed'])
        self.assertTrue(index.metadata['input_sha256_unchanged'])
        self.assertIn('Executable and Linking Format', index.binary.format)
        self.assertEqual(index.binary.architecture, 'x86:LE:64:default')
        self.assertEqual(index.binary.compiler_spec, 'gcc')
        self.assertEqual(int(index.binary.image_base, 16), 0x100000)
        self.assertGreater(len(index.functions), 80)
        self.assertEqual(len(index.functions), index.metadata['ghidra_function_count'])
        names = {f.current_name for f in index.functions}
        self.assertTrue({'socket', 'write', 'memset', 'EVP_EncryptUpdate', 'EVP_EncryptInit_ex'} <= names)
        self.assertTrue(any(f.decompiled_text for f in index.functions))
        self.assertTrue(any(f.assembly for f in index.functions))
        self.assertTrue(any(a.type == 'STRING' for a in index.artifacts))
        self.assertTrue(any(a.type == 'IMPORT' for a in index.artifacts))
        self.assertTrue(any(a.type == 'EXPORT' for a in index.artifacts))
        self.assertTrue(index.function_edges)
        known = {f.function_id for f in index.functions}
        for edge in index.function_edges:
            self.assertIn(edge.caller_function_id, known)
            self.assertIn(edge.callee_function_id, known)
        for function in index.functions:
            self.assertLessEqual(len(function.assembly or ''), 20000)
            self.assertLessEqual(len((function.assembly or '').splitlines()), 200)
        addresses = {int(f.address, 16) for f in index.functions if not f.is_external}
        for line in (ROOT / 'tests/ground_truth/FUNCTION_MAP.txt').read_text().splitlines():
            if line.startswith('0x'):
                self.assertIn(int(line.split()[0], 16) + 0x100000, addresses)
        report = os.environ.get('AIRE_INDEX_REPORT')
        if report:
            Path(report).write_text(json.dumps(index.to_dict(), indent=2))
        second = index_binary(BINARY, IndexOptions(decompile=False, include_assembly=False))
        self.assertEqual([f.function_id for f in index.functions], [f.function_id for f in second.functions])
        self.assertEqual({a.artifact_id for a in index.artifacts}, {a.artifact_id for a in second.artifacts})
        self.assertTrue(all(f.decompiled_text is None and f.assembly is None for f in second.functions))
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
