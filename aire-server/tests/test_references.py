"""Reference facts from an existing Program, plus persisted pure-reader views."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore, TransactionError, UnsupportedSchemaError
from aire.knowledge.models import ReferenceRecord, ThunkRecord
from aire.knowledge.reference_views import (
    string_references, direct_jump_thunks, referenced_bytes_at, referenced_reads,
)
from aire.knowledge.retrieval import ProgramQueryService
from aire.pyghidra.graph_builder import build_call_edges
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import extract_references, REFERENCE_FACTS_VERSION
from aire.security.rule_engine import _ReadOnlyRuleStore
from aire.ai.naming import _ReadOnlyNamingStore
from test_database import sample_index

ROOT = Path(__file__).resolve().parents[2]


class Address(str):
    def add(self, value):
        return Address(f'{int(self, 16) + value:04x}')


def function(address, external=False, thunk=False):
    result = Mock()
    result.getEntryPoint.return_value = Address(address)
    result.isExternal.return_value = external
    result.isThunk.return_value = thunk
    return result


def instruction(address, text, *, call=False, jump=False, computed=False, flows=()):
    result = Mock()
    result.__str__ = Mock(return_value=text)
    result.getAddress.return_value = Address(address)
    result.getMnemonicString.return_value = text.split()[0]
    result.getFlowType.return_value.isCall.return_value = call
    result.getFlowType.return_value.isJump.return_value = jump
    result.getFlowType.return_value.isComputed.return_value = computed
    result.getFlows.return_value = [Address(value) for value in flows]
    return result


def reference(target, kind, *, call=False, read=False, computed=False, operand=0):
    result = Mock()
    result.getToAddress.return_value = Address(target)
    result.getOperandIndex.return_value = operand
    ref_type = result.getReferenceType.return_value
    ref_type.__str__ = Mock(return_value=kind)
    ref_type.isCall.return_value = call
    ref_type.isRead.return_value = read
    ref_type.isComputed.return_value = computed
    return result


def enriched_index(identity='binary'):
    index = sample_index(identity)
    source, target = index.functions[1], index.functions[0]
    index.metadata = {'options': asdict(IndexOptions()), 'reference_facts_version': REFERENCE_FACTS_VERSION}
    index.references = [
        ReferenceRecord(f'{identity}:r:0', identity, '00101003', target.address, 'UNCONDITIONAL_CALL',
                        source.function_id, target.function_id, index.artifacts[1].artifact_id,
                        'CALL puts', 0, True),
        ReferenceRecord(f'{identity}:r:1', identity, '00101008', index.artifacts[0].address, 'DATA',
                        source.function_id, target_artifact_id=index.artifacts[0].artifact_id),
        ReferenceRecord(f'{identity}:r:2', identity, '00101009', '00104000', 'READ',
                        source.function_id, source_instruction='MOV RAX,qword ptr [0x104000]',
                        is_read=True, data_hex='0000000000001e40'),
    ]
    index.thunks = [ThunkRecord(source.function_id, target.function_id, source.address,
                                target.address, 'JMP puts', True)]
    index.program_info = {'Compiler': 'gcc', 'PDB File': "C:\\sample.pdb", 'ELF DF_1_PIE': 'true'}
    return index


class ReferenceExtractionTests(unittest.TestCase):
    def setUp(self):
        self.program = Mock()
        self.program.getDefaultPointerSize.return_value = 4
        self.program.getMemory.return_value.getBlock.return_value = None
        self.program.getOptions.return_value.getOptionNames.return_value = ['PDB File']
        self.program.getOptions.return_value.getValueAsString.return_value = 'sample.pdb'
        self.caller = function('1000')
        self.callee = function('2000')
        self.external = function('3000', external=True)
        self.functions = [self.caller, self.callee, self.external]
        self.instructions = {'1001': instruction('1001', 'CALL 0x2000', call=True),
                             '1002': instruction('1002', 'MOV RAX,qword ptr [0x4000]'),
                             '1003': instruction('1003', 'CALL RAX', call=True, computed=True)}
        self.references = {'1001': [reference('2000', 'UNCONDITIONAL_CALL', call=True)],
                           '1002': [reference('4000', 'READ', read=True)],
                           '1003': [reference('3000', 'COMPUTED_CALL', call=True, computed=True)]}
        self.manager = self.program.getReferenceManager.return_value
        self.manager.getReferenceSourceIterator.return_value = [Address(key) for key in self.references]
        self.manager.getReferencesFrom.side_effect = lambda source: self.references[str(source)]
        self.program.getFunctionManager.return_value.getFunctionContaining.return_value = self.caller
        self.program.getListing.return_value.getInstructionAt.side_effect = lambda source: self.instructions.get(str(source))

    def test_extracts_only_from_supplied_program_without_optional_runtime(self):
        # Block any runtime import; the extractor may only read this Program.
        with patch.dict(sys.modules, {'pyghidra': None, 'jpype': None}):
            warnings = []
            records, thunks, info = extract_references(self.program, self.functions, [], 'b', warnings)
        self.assertEqual(len(records), 3)
        self.program.getReferenceManager.assert_called_once_with()
        self.manager.getReferenceSourceIterator.assert_called_once_with(self.program.getMemory.return_value, True)
        self.assertEqual(records[0].source_function_id, 'b:1000')
        self.assertEqual(records[0].target_function_id, 'b:2000')
        self.assertEqual(records[0].source_instruction, 'CALL 0x2000')
        self.assertEqual(records[0].reference_type, 'UNCONDITIONAL_CALL')
        self.assertEqual(records[2].target_address, '3000')
        self.assertTrue(records[2].is_indirect)
        self.assertIsNone(records[2].target_function_id)
        self.assertEqual(thunks, [])
        self.assertEqual(info, {'PDB File': 'sample.pdb'})
        self.assertEqual(warnings, [])

    def test_computed_jump_preserves_raw_destination_without_resolving_function(self):
        self.instructions['1004'] = instruction('1004', 'JMP RAX', jump=True, computed=True, flows=['2000'])
        self.references['1004'] = [reference('2000', 'COMPUTED_JUMP', computed=True)]
        self.manager.getReferenceSourceIterator.return_value.append(Address('1004'))
        records, _, _ = extract_references(self.program, self.functions, [], 'b', [])
        jump = next(r for r in records if r.source_address == '1004')
        self.assertEqual(jump.target_address, '2000')
        self.assertTrue(jump.is_indirect)
        self.assertIsNone(jump.target_function_id)
        self.assertFalse(jump.is_call)

    def test_string_ownership_read_bytes_and_unknown_data_sources(self):
        artifact = deepcopy(sample_index().artifacts[0])
        artifact.address = '4000'
        memory = self.program.getMemory.return_value
        block = memory.getBlock.return_value = Mock()
        block.isInitialized.return_value = block.contains.return_value = True
        raw = bytes.fromhex('0000000000001e40')
        memory.getByte.side_effect = lambda address: raw[int(address, 16) - 0x4000]
        # A reference from defined data has no function or instruction owner.
        self.references['5000'] = [reference('4000', 'DATA')]
        self.manager.getReferenceSourceIterator.return_value.append(Address('5000'))
        self.program.getFunctionManager.return_value.getFunctionContaining.side_effect = (
            lambda address: None if str(address) == '5000' else self.caller)
        records, _, _ = extract_references(self.program, self.functions, [artifact], 'b', [])
        string_read = next(record for record in records if record.source_address == '1002')
        self.assertEqual(string_read.target_artifact_id, artifact.artifact_id)
        self.assertEqual(string_read.data_hex, raw.hex())
        data_reference = next(record for record in records if record.source_address == '5000')
        self.assertIsNone(data_reference.source_function_id)
        self.assertIsNone(data_reference.source_instruction)
        self.assertEqual(data_reference.target_artifact_id, artifact.artifact_id)

    def test_direct_thunks_and_indirect_external_bindings_remain_distinct(self):
        direct, indirect = function('6000', thunk=True), function('7000', thunk=True)
        direct.getThunkedFunction.return_value = self.callee
        indirect.getThunkedFunction.return_value = self.external
        self.instructions['6000'] = instruction('6000', 'JMP 0x2000', jump=True, flows=['2000'])
        self.instructions['7000'] = instruction('7000', 'JMP [0x3000]', jump=True, computed=True)
        records, thunks, _ = extract_references(
            self.program, self.functions + [direct, indirect], [], 'b', [])
        self.assertEqual([(item.target_function_id, item.is_direct_jump) for item in thunks],
                         [('b:2000', True), ('b:3000', False)])
        self.assertEqual(len(records), 3)
        direct.getThunkedFunction.assert_called_once_with(False)

    def test_existing_direct_call_graph_does_not_resolve_indirect_reference(self):
        direct = self.instructions['1001']
        direct.getReferencesFrom.return_value = self.references['1001']
        computed = self.instructions['1003']
        self.program.getListing.return_value.getInstructions.side_effect = (
            lambda body, forward: [direct, computed] if body is self.caller.getBody.return_value else [])
        warnings = []
        edges = build_call_edges(self.program, self.functions, 'b', warnings)
        self.assertEqual({(edge.caller_function_id, edge.callee_function_id) for edge in edges},
                         {('b:1000', 'b:2000')})
        self.assertTrue(any('Indirect call' in warning for warning in warnings))
        computed.getReferencesFrom.assert_not_called()

    def test_reference_failure_warns_without_losing_other_facts(self):
        self.references['1002'][0].getToAddress.side_effect = RuntimeError('bad reference')
        warnings = []
        records, _, info = extract_references(self.program, self.functions, [], 'b', warnings)
        self.assertEqual(len(records), 2)
        self.assertEqual(info, {'PDB File': 'sample.pdb'})
        self.assertTrue(any('bad reference' in warning for warning in warnings))


class ReferencePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'analysis.sqlite'
        self.store = BinaryKnowledgeStore(self.path)
        self.addCleanup(self.store.close)

    def test_serialization_reopen_queries_and_read_only_access(self):
        original = enriched_index()
        self.assertEqual(json.loads(json.dumps(original.to_dict()))['references'][2]['data_hex'],
                         '0000000000001e40')
        self.store.save_program_index(original)
        self.store.close()
        before = self.path.read_bytes()
        for adapter in (_ReadOnlyRuleStore, _ReadOnlyNamingStore):
            with adapter(self.path) as store:
                loaded = store.load_program_index('binary')
                self.assertEqual(loaded, original)
                query = ProgramQueryService(store)
                source, target = original.functions[1], original.functions[0]
                self.assertEqual(query.get_function_references('binary', source), original.references)
                self.assertEqual(query.get_function_referrers('binary', target), original.references[:1])
                self.assertEqual(query.get_artifact_references('binary', original.artifacts[0].artifact_id),
                                 original.references[1:2])
                self.assertEqual(query.get_thunk_bindings('binary', source), original.thunks)
                self.assertEqual(len(query.get_callees('binary', source)), 2)
                self.assertEqual(len(query.get_callers('binary', target)), 2)
        self.assertEqual(self.path.read_bytes(), before)

    def test_replacement_delete_and_foreign_key_integrity(self):
        original = enriched_index()
        self.store.save_program_index(original)
        self.store.save_program_index(original)
        for field in ('source_function_id', 'target_function_id', 'target_artifact_id'):
            invalid = deepcopy(original)
            setattr(invalid.references[0], field, 'other-binary:missing')
            with self.subTest(field=field), self.assertRaises(TransactionError):
                self.store.save_program_index(invalid)
            self.assertEqual(self.store.load_program_index('binary'), original)
        invalid = deepcopy(original)
        invalid.thunks[0].target_function_id = 'missing'
        with self.assertRaises(TransactionError):
            self.store.save_program_index(invalid)
        replacement = sample_index()
        self.store.save_program_index(replacement)
        self.assertEqual(self.store.load_program_index('binary'), replacement)
        self.store.save_program_index(original)
        self.store.delete_binary('binary')
        for table in ('binary_references', 'thunk_relations', 'program_information'):
            self.assertEqual(self.store._db.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)
        self.assertEqual(self.store._db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_reference_ordinals_and_missing_owners_are_validated_on_load(self):
        self.store.save_program_index(enriched_index())
        self.store._db.execute('UPDATE binary_references SET ordinal=8 WHERE ordinal=2')
        from aire.knowledge.database import PersistedDataError
        with self.assertRaisesRegex(PersistedDataError, 'Non-contiguous'):
            self.store.load_program_index('binary')

    def make_legacy(self):
        original = sample_index()
        self.store.save_program_index(original)
        self.store.close()
        with sqlite3.connect(self.path) as db:
            for table in ('binary_references', 'thunk_relations', 'program_information'):
                db.execute(f'DROP TABLE {table}')
            db.execute('DROP INDEX artifacts_owner_idx')
            db.execute("UPDATE schema_metadata SET value='1' WHERE key='schema_version'")
        return original

    def test_v1_read_only_load_does_not_migrate_and_writable_migration_preserves_snapshot(self):
        original = self.make_legacy()
        before = self.path.read_bytes()
        with _ReadOnlyRuleStore(self.path) as store:
            self.assertEqual(store.load_program_index('binary'), original)
            self.assertEqual(ProgramQueryService(store).get_function_references('binary', original.functions[1]), [])
        self.assertEqual(self.path.read_bytes(), before)
        with BinaryKnowledgeStore(self.path) as store:
            self.assertEqual(store.load_program_index('binary'), original)
            self.assertEqual(store._db.execute('SELECT value FROM schema_metadata').fetchone()[0], '2')
            store.save_program_index(enriched_index())
            self.assertEqual(store.load_program_index('binary'), enriched_index())

    def test_failed_migration_rolls_back_all_schema_changes(self):
        self.make_legacy()
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE binary_references (unexpected TEXT)')
        before = self.path.read_bytes()
        with self.assertRaises(UnsupportedSchemaError):
            BinaryKnowledgeStore(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_cache_hit_preserves_reference_facts_and_legacy_options_miss(self):
        target = Path(self.directory.name) / 'target'
        target.write_bytes(b'controlled target; never execute')
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        original = enriched_index(digest)
        original.binary.sha256 = digest
        original.binary.path = str(target)
        with patch('aire.analysis.cache.index_binary', return_value=original) as indexer:
            first = analyze_binary(target, self.store)
            second = analyze_binary(target, self.store)
            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            self.assertEqual(second.program_index, original)
            indexer.assert_called_once()
            legacy = deepcopy(original)
            legacy.metadata['options'].pop('include_references')
            legacy.references, legacy.thunks, legacy.program_info = [], [], {}
            self.store.save_program_index(legacy)
            self.assertFalse(analyze_binary(target, self.store).cache_hit)
            self.assertEqual(indexer.call_count, 2)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)

    def test_views_and_demo_helpers_need_no_runtime_or_target(self):
        original = enriched_index()
        self.assertEqual(string_references(original, [original.artifacts[0].value])[0]['xrefs'][0]['function'],
                         original.functions[1].address)
        self.assertEqual(len(direct_jump_thunks(original)), 1)
        self.assertEqual(referenced_bytes_at(original, '00104000'), bytes.fromhex('0000000000001e40'))
        self.assertIn('00101009', referenced_reads(original))
        with self.assertRaisesRegex(ValueError, 'Reference facts are absent'):
            string_references(sample_index(), [])
        for name in ('demoL_function_overloading.py', 'demo_function_overloading_WINDOWS_backup.py',
                     'demo_function_overloading.py'):
            spec = importlib.util.spec_from_file_location('reference_demo', ROOT / 'scripts' / name)
            demo = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(demo)
            index = deepcopy(original)
            index.references[2].target_address = '00419b70'
            with patch.dict(sys.modules, {'pyghidra': None, 'jpype': None}):
                strings, thunks, info, raw = demo.collect_xrefs(index)
            self.assertEqual(info, index.program_info)
            self.assertEqual(len(thunks), 1)
            self.assertEqual(raw if name != 'demo_function_overloading.py' else raw['00101009'][0]['raw'],
                             bytes.fromhex('0000000000001e40'))


if __name__ == '__main__':
    unittest.main()
