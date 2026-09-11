"""Pure Python tests: importing the indexer must not import/start PyGhidra."""
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from aire.knowledge.models import BinaryRecord, ProgramIndex
from aire.pyghidra.extractor import (
    AssemblyBuffer, artifact_id, binary_id, decompile_function, function_id, read_fact,
)
from aire.pyghidra.indexer import IndexingError, index_binary
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.graph_builder import build_call_edges


class IndexerTests(unittest.TestCase):
    def record(self):
        return BinaryRecord('id', '/binary', 'abc', None, None, '00100000',
                            datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_import_does_not_load_pyghidra(self):
        subprocess.run([sys.executable, '-c',
                        'import aire.pyghidra.indexer,sys; assert "pyghidra" not in sys.modules; assert "jpype" not in sys.modules'],
                       check=True)

    def test_stable_ids(self):
        digest = hashlib.sha256(b'fixture').hexdigest()
        self.assertEqual(binary_id(digest.upper()), digest)
        self.assertEqual(function_id(digest, 'EXTERNAL:00000001'), f'{digest}:EXTERNAL:00000001')
        self.assertNotEqual(function_id(digest, '00100000'), function_id(digest, '00100001'))

    def test_artifact_ids(self):
        self.assertEqual(artifact_id('b', 'STRING', '01', 'hello'), artifact_id('b', 'STRING', '01', 'hello'))
        identities = {artifact_id('b', kind, address, value) for kind, address, value in
                      [('STRING', '01', 'hello'), ('IMPORT', '01', 'hello'),
                       ('STRING', '02', 'hello'), ('STRING', '01', 'world')]}
        self.assertEqual(len(identities), 4)

    def test_options(self):
        self.assertTrue(IndexOptions().decompile)
        for field in ('max_assembly_instructions', 'max_assembly_characters', 'decompile_timeout_seconds'):
            for value in (0, -1, True, 1.5, '20'):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    IndexOptions(**{field: value})
        with self.assertRaises(ValueError):
            IndexOptions(decompile=1)
        with self.assertRaises(ValueError):
            IndexOptions(decompile_timeout_seconds=2**31)

    def test_construction_and_serialization(self):
        class Kind(Enum):
            STRING = 'STRING'
        index = ProgramIndex(self.record(), metadata={'path': Path('/tmp/x'), 'enum': Kind.STRING})
        value = json.loads(json.dumps(index.to_dict()))
        self.assertEqual(value['binary']['analyzed_at'], '2026-01-01T00:00:00+00:00')
        self.assertEqual(value['metadata'], {'path': '/tmp/x', 'enum': 'STRING'})
        self.assertIsNone(value['binary']['format'])
        other = ProgramIndex(self.record())
        index.warnings.append('warning')
        self.assertEqual(other.warnings, [])
        self.assertEqual(other.functions, [])

    def test_assembly_bounds(self):
        buffer = AssemblyBuffer(2, 7)
        for line in ['abc', 'def', 'g']:
            buffer.append(line)
        self.assertEqual(buffer.text(), 'abc\ndef')
        self.assertTrue(buffer.truncated)
        buffer = AssemblyBuffer(10, 2)
        buffer.append('abc')
        self.assertEqual(buffer.text(), '')
        self.assertTrue(buffer.truncated)
        buffer = AssemblyBuffer(1, 100)
        buffer.append('a')
        self.assertFalse(buffer.truncated)
        buffer.append('b')
        self.assertEqual(buffer.text(), 'a')
        self.assertTrue(buffer.truncated)

    def test_warning_accumulation(self):
        warnings = []
        self.assertIsNone(read_fact(warnings, 'metric at 0010', lambda: 1 / 0))
        self.assertEqual(read_fact(warnings, 'next metric', lambda: 42), 42)
        self.assertEqual(len(warnings), 1)
        self.assertIn('0010', warnings[0])

    def test_decompilation_failure_continues(self):
        decompiler = Mock()
        failed = Mock()
        failed.decompileCompleted.return_value = False
        failed.getErrorMessage.return_value = 'timeout'
        success = Mock()
        success.decompileCompleted.return_value = True
        success.getErrorMessage.return_value = ''
        success.getDecompiledFunction.return_value.getC.return_value = 'void f(void) {}'
        decompiler.decompileFunction.side_effect = [failed, success]
        warnings = []
        options = IndexOptions(decompile_timeout_seconds=7)
        self.assertIsNone(decompile_function(decompiler, 'f', options, 'monitor', warnings, '0010 f'))
        self.assertEqual(decompile_function(decompiler, 'g', options, 'monitor', warnings, '0020 g'), 'void f(void) {}')
        self.assertIn('0010 f decompilation: timeout', warnings[0])
        decompiler.decompileFunction.assert_called_with('g', 7, 'monitor')

    def test_invalid_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IndexingError, 'not a file'):
                index_binary(Path(directory))
            with self.assertRaisesRegex(IndexingError, 'File not found'):
                index_binary(Path(directory) / 'missing')

    def test_setup_error_checks_integrity(self):
        with tempfile.NamedTemporaryFile() as fixture:
            fixture.write(b'not an executable')
            fixture.flush()
            with patch('aire.pyghidra.indexer._start_runtime', side_effect=RuntimeError('setup failed')):
                with self.assertRaisesRegex(IndexingError, 'Ghidra startup.*setup failed'):
                    index_binary(Path(fixture.name))
            self.assertEqual(Path(fixture.name).read_bytes(), b'not an executable')

    def test_direct_call_graph(self):
        caller, callee = Mock(), Mock()
        caller.isExternal.return_value = False
        caller.getEntryPoint.return_value = '0010'
        callee.isExternal.return_value = True
        callee.getEntryPoint.return_value = 'EXTERNAL:0020'
        direct, indirect, unresolved = Mock(), Mock(), Mock()
        for instruction, site, computed in [(direct, '0011', False), (indirect, '0012', True),
                                             (unresolved, '0013', False)]:
            instruction.getAddress.return_value = site
            instruction.getFlowType.return_value.isCall.return_value = True
            instruction.getFlowType.return_value.isComputed.return_value = computed
        reference = Mock()
        reference.getReferenceType.return_value.isCall.return_value = True
        reference.getToAddress.return_value = 'EXTERNAL:0020'
        direct.getReferencesFrom.return_value = [reference, reference]
        unresolved.getReferencesFrom.return_value = []
        program = Mock()
        program.getListing.return_value.getInstructions.return_value = [direct, indirect, unresolved]
        warnings = []
        edges = build_call_edges(program, [caller, callee], 'binary', warnings)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].callee_function_id, 'binary:EXTERNAL:0020')
        self.assertEqual(edges[0].callsite_address, '0011')
        self.assertEqual(len(warnings), 2)
        indirect.getReferencesFrom.assert_not_called()


if __name__ == '__main__':
    unittest.main()
