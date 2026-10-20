"""Real static ELF/PE indexing; opt in with AIRE_RUN_GHIDRA_TESTS=1.

Only index_binary reads the targets. Neither professor binary is executed or
modified. AIRE_FORMAT_REPORT_DIR optionally preserves full indexes and hashes.
"""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import unittest

from aire.knowledge.models import ProgramIndex
from aire.pyghidra.indexer import index_binary


ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    'simple_elf': (
        ROOT / 'tests/fixtures/simple_elf/aire_test_binary',
        'Executable and Linking Format', 64,
    ),
    'professor_pe': (
        ROOT / 'professor_samples/function_overloading/original/FunctionOverloading.exe',
        'Portable Executable', 32,
    ),
    'professor_elf': (
        ROOT / 'professor_samples/function_overloading_elf/original/FunctionOverloading',
        'Executable and Linking Format', 64,
    ),
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_facts(index):
    """Compare extracted facts across loads, excluding timestamps/timings/logs."""
    data = index.to_dict()
    data['binary'].pop('analyzed_at')
    return {
        'binary': data['binary'],
        **{key: sorted(data[key], key=lambda row: json.dumps(row, sort_keys=True))
           for key in ('functions', 'artifacts', 'function_edges')},
    }


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class BinaryFormatsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baselines = {}

    def index_target(self, name, *, repeat=False):
        path, expected_format, bits = TARGETS[name]
        self.assertTrue(path.is_file(), f'Required real target is missing: {path}')
        before = sha256(path)
        try:
            index = index_binary(path)
        finally:
            after = sha256(path)
            self.assertEqual(before, after, f'Input changed: {path}')

        self.assertIsInstance(index, ProgramIndex)  # Existing binary index model.
        self.assertTrue(index.metadata['analysis_completed'])
        self.assertTrue(index.metadata['input_sha256_unchanged'])
        self.assertTrue(index.metadata['ghidra_version'])
        self.assertEqual(index.binary.sha256, before)
        self.assertIn(expected_format, index.binary.format)
        self.assertTrue(index.binary.architecture)
        self.assertEqual(index.binary.pointer_size * 8, bits)
        self.assertEqual(index.binary.endianness, 'little')
        self.assertGreaterEqual(int(index.binary.image_base, 16), 0)
        self.assertTrue(index.binary.compiler_spec)

        internal = [f for f in index.functions if not f.is_external]
        external = [f for f in index.functions if f.is_external]
        self.assertTrue(internal)
        self.assertTrue(external)
        self.assertTrue(all(f.address and f.signature for f in index.functions))
        self.assertTrue(any(f.decompiled_text for f in internal))
        self.assertTrue(any(f.assembly and f.instruction_count > 0 for f in internal))
        self.assertTrue(any(f.is_thunk for f in internal))
        self.assertTrue(all(f.namespace for f in external))
        counts = Counter(a.type for a in index.artifacts)
        self.assertGreater(counts['STRING'], 0)
        self.assertGreater(counts['IMPORT'], 0)
        # Ghidra external entry points include loader entry symbols as EXPORTs;
        # these are not necessarily dynamic-library export-table entries.
        exports = [a for a in index.artifacts if a.type == 'EXPORT']
        self.assertTrue(exports)
        self.assertTrue(all(a.address for a in exports))
        self.assertTrue({a.address for a in exports} & {f.address for f in internal})

        known = {f.function_id for f in index.functions}
        self.assertEqual(len(known), len(index.functions))
        self.assertTrue(index.function_edges)
        for edge in index.function_edges:
            self.assertIn(edge.caller_function_id, known)
            self.assertIn(edge.callee_function_id, known)
            self.assertTrue(edge.callsite_address)
            self.assertEqual(edge.edge_type, 'CALL')
        self.assertTrue(all(isinstance(warning, str) for warning in index.warnings))
        serialized = json.loads(json.dumps(index.to_dict()))
        self.assertEqual(serialized['binary']['sha256'], before)

        report_dir = os.environ.get('AIRE_FORMAT_REPORT_DIR')
        if report_dir:
            directory = Path(report_dir)
            directory.mkdir(parents=True, exist_ok=True)
            suffix = '_repeat' if repeat else ''
            (directory / f'{name}{suffix}.json').write_text(
                json.dumps(serialized, indent=2) + '\n')
            (directory / f'{name}{suffix}.integrity.json').write_text(json.dumps({
                'path': str(path), 'sha256_before': before, 'sha256_after': after,
                'unchanged': before == after,
            }, indent=2) + '\n')
        return index

    def baseline(self, name):
        if name not in self.baselines:
            self.baselines[name] = self.index_target(name)
        return self.baselines[name]

    def test_01_simple_elf(self):
        self.baseline('simple_elf')

    def test_02_professor_pe(self):
        self.baseline('professor_pe')

    def test_03_professor_elf(self):
        self.baseline('professor_elf')

    def test_04_shared_runtime_format_isolation(self):
        # ELF -> PE -> ELF -> PE, reusing the JVM and disposable projects.
        elf = self.baseline('simple_elf')
        pe = self.baseline('professor_pe')
        for name, baseline in [('simple_elf', elf), ('professor_pe', pe)]:
            with self.subTest(target=name):
                repeated = self.index_target(name, repeat=True)
                self.assertEqual(stable_facts(baseline), stable_facts(repeated))
        for name, (path, _, _) in TARGETS.items():
            if name in self.baselines:
                self.assertEqual(sha256(path), self.baselines[name].binary.sha256)


if __name__ == '__main__':
    unittest.main()
