"""SQLite tests using disposable files, without PyGhidra or a JVM."""
from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from aire.knowledge.database import (
    BinaryKnowledgeStore, BinaryNotFoundError, DatabaseOpenError,
    KnowledgeStoreError, PersistedDataError, TransactionError, UnsupportedSchemaError,
    SCHEMA_VERSION,
)
from aire.knowledge.models import (
    ArtifactRecord, BinaryRecord, FunctionEdge, FunctionRecord, ProgramIndex,
)


def sample_index(identity='binary'):
    binary = BinaryRecord(identity, '/nonexistent/executable', 'ab' * 32,
                          'ELF', 'x86:LE:64:default', '00100000',
                          datetime(2026, 9, 11, 12, 30, tzinfo=timezone.utc),
                          'gcc', 'little', 8, None, 1234, 'sample')
    internal = FunctionRecord(f'{identity}:00101000', identity, '00101000', "f'雪",
                              'void f(void)', 'void f(void) {\n  return;\n}',
                              '00101000: RET', 1, 1, 0, False, False, None,
                              'Global', 'default', True)
    external = FunctionRecord(f'{identity}:EXTERNAL:00000001', identity,
                              'EXTERNAL:00000001', 'puts', None, None, '',
                              0, 0, 0, True, True, False, 'libc', None)
    artifacts = [ArtifactRecord(f'{identity}:a:{i}', identity, kind, address, value)
                 for i, (kind, address, value) in enumerate([
                     ('STRING', '00103000', "hello\n'\x00雪"),
                     ('IMPORT', 'EXTERNAL:00000001', 'puts'), ('EXPORT', None, 'entry')])]
    return ProgramIndex(binary, [external, internal], artifacts,
                        [FunctionEdge(internal.function_id, external.function_id, '00101003', 'CALL'),
                         FunctionEdge(internal.function_id, external.function_id, '00101005', 'CALL')],
                        ['second warning', 'first warning', 'second warning'],
                        {'options': {'decompile': True, 'limit': 200}, 'time': 0.125,
                         'nullable': None, 'items': [1, False, '雪']})


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'nested' / 'analysis.sqlite'
        self.store = BinaryKnowledgeStore(self.path)
        self.addCleanup(self.store.close)

    def counts(self):
        tables = ('binaries', 'functions', 'artifacts', 'function_edges', 'warnings', 'analysis_metadata')
        return {table: self.store._db.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in tables}

    def test_initialize_version_and_indexes(self):
        self.store.initialize()
        self.assertEqual(self.store._db.execute(
            'SELECT value FROM schema_metadata WHERE key = ?', ('schema_version',)).fetchone()[0], str(SCHEMA_VERSION))
        self.assertEqual(self.counts(), dict.fromkeys(self.counts(), 0))
        indexes = {r[0] for r in self.store._db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        self.assertTrue({'functions_address_idx', 'functions_name_idx', 'artifacts_type_idx',
                         'artifacts_value_idx', 'edges_caller_idx', 'edges_callee_idx'} <= indexes)

    def test_foreign_keys_enabled_and_enforced(self):
        self.assertEqual(self.store._db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._db.execute('INSERT INTO warnings(binary_id, ordinal, warning_text) VALUES (?, ?, ?)',
                                   ('missing', 0, 'orphan'))
        self.assertEqual(self.store._db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_minimal_round_trip(self):
        original = ProgramIndex(BinaryRecord('minimal', '/none', 'digest', None, None, 'ram:00', None))
        self.store.save_program_index(original)
        self.assertEqual(self.store.load_program_index('minimal'), original)

    def test_complete_round_trip_after_reopen(self):
        original = sample_index()
        self.store.save_program_index(original)
        self.store.close()
        with BinaryKnowledgeStore(self.path) as reopened:
            loaded = reopened.load_program_index(original.binary.binary_id)
        self.assertEqual(loaded, original)
        self.assertEqual(loaded.to_dict(), original.to_dict())
        self.assertIsInstance(loaded.binary.analyzed_at, datetime)
        self.assertIs(type(loaded.functions[0].is_external), bool)
        self.assertIsNone(loaded.functions[1].is_library)
        self.assertTrue(loaded.functions[1].assembly_truncated)

    def test_duplicate_save(self):
        original = sample_index()
        self.store.save_program_index(original)
        counts = self.counts()
        self.store.save_program_index(original)
        self.assertEqual(self.counts(), counts)
        self.assertEqual(self.store.load_program_index('binary'), original)

    def test_reanalysis_replaces_all_previous_facts(self):
        self.store.save_program_index(sample_index())
        other = sample_index('other')
        self.store.save_program_index(other)
        replacement = sample_index()
        replacement.functions = replacement.functions[1:]
        replacement.functions[0].decompiled_text = 'changed'
        replacement.artifacts = []
        replacement.function_edges = []
        replacement.warnings = ['replacement']
        replacement.metadata = {'replacement': True}
        replacement.binary.program_name = 'reanalyzed'
        self.store.save_program_index(replacement)
        self.assertEqual(self.store.load_program_index('binary'), replacement)
        self.assertEqual(self.store.load_program_index('other'), other)
        self.assertEqual(self.counts()['functions'], 3)

    def test_has_and_missing_load(self):
        self.assertFalse(self.store.has_binary('missing'))
        with self.assertRaises(BinaryNotFoundError):
            self.store.load_program_index('missing')
        self.store.save_program_index(sample_index())
        self.assertTrue(self.store.has_binary('binary'))

    def test_list_is_metadata_only(self):
        self.store.save_program_index(sample_index('z'))
        self.store.save_program_index(sample_index('a'))
        statements = []
        self.store._db.set_trace_callback(statements.append)
        listed = self.store.list_binaries()
        self.store._db.set_trace_callback(None)
        self.assertEqual([b.binary_id for b in listed], ['a', 'z'])
        self.assertEqual(listed[0], sample_index('a').binary)
        self.assertEqual(len(statements), 1)
        self.assertIn('FROM binaries', statements[0])

    def test_delete_cascades_but_does_not_delete_file(self):
        target = Path(self.directory.name) / 'target'
        target.write_bytes(b'fixture bytes')
        original = sample_index()
        original.binary.path = str(target)
        self.store.save_program_index(original)
        self.assertTrue(self.store.delete_binary('binary'))
        self.assertFalse(self.store.delete_binary('binary'))
        self.assertTrue(all(count == 0 for count in self.counts().values()))
        self.assertEqual(target.read_bytes(), b'fixture bytes')

    def test_late_failure_rolls_back_replacement_and_new_binary(self):
        original = sample_index()
        self.store.save_program_index(original)
        before = self.counts()
        self.store._db.execute('''CREATE TRIGGER fail_metadata BEFORE INSERT ON analysis_metadata
                                 BEGIN SELECT RAISE(ABORT, 'injected late failure'); END''')
        for identity in ('binary', 'new'):
            replacement = sample_index(identity)
            replacement.functions[1].current_name = 'replacement'
            with self.assertRaisesRegex(TransactionError, 'injected late failure'):
                self.store.save_program_index(replacement)
            self.assertFalse(self.store._db.in_transaction)
            self.assertEqual(self.counts(), before)
            self.assertEqual(self.store.load_program_index('binary'), original)
            self.assertFalse(self.store.has_binary('new'))
        self.store._db.execute('DROP TRIGGER fail_metadata')
        self.store.save_program_index(sample_index('new'))
        self.assertTrue(self.store.has_binary('new'))

    def test_duplicate_record_id_rolls_back(self):
        original = sample_index()
        self.store.save_program_index(original)
        invalid = deepcopy(original)
        invalid.functions.append(deepcopy(invalid.functions[0]))
        with self.assertRaises(TransactionError):
            self.store.save_program_index(invalid)
        self.assertEqual(self.store.load_program_index('binary'), original)

    def test_invalid_and_cross_binary_edges_roll_back(self):
        self.store.save_program_index(sample_index('other'))
        for target in ('missing', 'other:EXTERNAL:00000001'):
            invalid = sample_index()
            invalid.function_edges[0].callee_function_id = target
            with self.assertRaisesRegex(TransactionError, 'FOREIGN KEY'):
                self.store.save_program_index(invalid)
            self.assertFalse(self.store.has_binary('binary'))
        self.assertEqual(self.store.load_program_index('other'), sample_index('other'))

    def test_mismatched_owner_and_conflicting_id(self):
        other = sample_index('other')
        self.store.save_program_index(other)
        invalid = sample_index()
        invalid.functions[0].binary_id = 'other'
        with self.assertRaisesRegex(TransactionError, 'different binary_id'):
            self.store.save_program_index(invalid)
        invalid = sample_index()
        invalid.functions[0].function_id = other.functions[0].function_id
        with self.assertRaises(TransactionError):
            self.store.save_program_index(invalid)
        self.assertEqual(self.store.load_program_index('other'), other)
        self.assertFalse(self.store.has_binary('binary'))

    def test_metadata_json_normalization(self):
        class Kind(Enum):
            STRING = 'STRING'
        original = sample_index()
        original.binary.path = Path('/sample')
        original.metadata['special'] = {'path': Path('/tmp/雪'), 'when': original.binary.analyzed_at,
                                        'enum': Kind.STRING, 'tuple': (1, None, False)}
        self.store.save_program_index(original)
        loaded = self.store.load_program_index('binary')
        self.assertEqual(loaded.to_dict(), original.to_dict())
        self.assertEqual(loaded.binary.path, '/sample')
        self.assertEqual(loaded.metadata['special']['tuple'], [1, None, False])

    def test_invalid_metadata_does_not_replace(self):
        original = sample_index()
        self.store.save_program_index(original)
        for invalid in (object(), float('nan'), float('inf')):
            modified = deepcopy(original)
            modified.metadata['invalid'] = invalid
            with self.assertRaises(TransactionError):
                self.store.save_program_index(modified)
            self.assertEqual(self.store.load_program_index('binary'), original)

    def test_malformed_persisted_json(self):
        self.store.save_program_index(sample_index())
        for value in ('{broken', 'NaN'):
            self.store._db.execute('UPDATE analysis_metadata SET value = ? WHERE key = ?', (value, 'options'))
            with self.assertRaisesRegex(PersistedDataError, 'Malformed metadata JSON.*options'):
                self.store.load_program_index('binary')
            self.assertFalse(self.store._db.in_transaction)

    def test_malformed_datetime(self):
        self.store.save_program_index(sample_index())
        self.store._db.execute('UPDATE binaries SET analyzed_at = ?', ('bad-date',))
        with self.assertRaises(PersistedDataError):
            self.store.load_program_index('binary')

    def test_unsupported_schema_is_not_modified(self):
        self.store.save_program_index(sample_index())
        self.store._db.execute('UPDATE schema_metadata SET value = ?', ('999',))
        self.store.close()
        before = self.path.read_bytes()
        with self.assertRaisesRegex(UnsupportedSchemaError, '999'):
            BinaryKnowledgeStore(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_version_or_tables_rejected(self):
        self.store._db.execute('DELETE FROM schema_metadata')
        with self.assertRaises(UnsupportedSchemaError):
            self.store.initialize()
        self.store._db.execute('INSERT INTO schema_metadata VALUES (?, ?)', ('schema_version', str(SCHEMA_VERSION)))
        self.store._db.execute('DROP TABLE analysis_metadata')
        with self.assertRaises(UnsupportedSchemaError):
            self.store.initialize()

    def test_unversioned_database_rejected(self):
        for name, statement in [('foreign', 'CREATE TABLE unrelated (value TEXT)'),
                                ('prefix', 'CREATE TABLE sqlitecustom (value TEXT)')]:
            path = Path(self.directory.name) / f'{name}.sqlite'
            with sqlite3.connect(path) as db:
                db.execute(statement)
            with self.assertRaisesRegex(UnsupportedSchemaError, 'no A.I.R.E. schema version'):
                BinaryKnowledgeStore(path)

    def test_open_failure(self):
        with self.assertRaises(DatabaseOpenError):
            BinaryKnowledgeStore(Path(self.directory.name))
        with self.assertRaises(DatabaseOpenError):
            BinaryKnowledgeStore(self.path / 'impossible' / 'child.sqlite')

    def test_close_and_context_manager(self):
        self.store.close()
        self.store.close()
        with self.assertRaisesRegex(KnowledgeStoreError, 'closed'):
            self.store.has_binary('binary')
        with self.assertRaisesRegex(RuntimeError, 'caller failure'):
            with BinaryKnowledgeStore(self.path) as store:
                store.save_program_index(sample_index())
                raise RuntimeError('caller failure')
        with self.assertRaises(KnowledgeStoreError):
            store.list_binaries()
        with BinaryKnowledgeStore(self.path) as reopened:
            self.assertTrue(reopened.has_binary('binary'))

    def test_sql_strings_are_data(self):
        identity = "x'); DROP TABLE binaries; --"
        original = sample_index(identity)
        self.store.save_program_index(original)
        self.assertEqual(self.store.load_program_index(identity), original)
        self.assertTrue(self.store.has_binary(identity))
        self.assertTrue(self.store.delete_binary(identity))
        self.assertEqual(self.store.list_binaries(), [])

    def test_duplicate_edges_preserve_input_order(self):
        original = sample_index()
        original.function_edges.append(deepcopy(original.function_edges[0]))
        self.store.save_program_index(original)
        self.store.save_program_index(original)
        self.assertEqual(self.store.load_program_index('binary'), original)
        self.assertEqual(self.counts()['function_edges'], 3)

    def test_import_does_not_load_ghidra(self):
        subprocess.run([sys.executable, '-c',
                        'import aire.knowledge.database,sys; assert "pyghidra" not in sys.modules; assert "jpype" not in sys.modules'],
                       check=True)


if __name__ == '__main__':
    unittest.main()
