"""Cache orchestration with real SQLite persistence and a mocked static indexer."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import asdict, fields, replace
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore, KnowledgeStoreError, TransactionError
from aire.knowledge.models import BinaryRecord, ProgramIndex
from aire.pyghidra.indexer import IndexingError
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION


class AnalysisCacheTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'target'
        self.path.write_bytes(b'controlled static fixture; never execute')
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.database = Path(directory.name) / 'analysis.sqlite'
        self.store = BinaryKnowledgeStore(self.database)
        self.addCleanup(self.store.close)
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        self.indexer = contexts.enter_context(patch('aire.analysis.cache.index_binary', side_effect=self.index))
        self.runtime = contexts.enter_context(patch('aire.pyghidra.indexer._start_runtime',
                                                    side_effect=AssertionError('Unexpected Ghidra startup')))

    def index(self, path, options):
        return ProgramIndex(
            BinaryRecord(self.digest, str(path), self.digest, None, None, '00100000', None),
            warnings=['original'],
            metadata={'options': asdict(options), 'total_seconds': 12.5,
                      'reference_facts_version': REFERENCE_FACTS_VERSION if options.include_references else None,
                      'input_sha256_unchanged': True})

    def test_old_or_missing_reference_format_is_a_cache_miss(self):
        for version in (None, 1, True, '2', 999):
            with self.subTest(version=version):
                original = self.index(self.path, IndexOptions())
                original.metadata['reference_facts_version'] = version
                self.store.save_program_index(original)
                self.indexer.reset_mock()
                result = analyze_binary(self.path, self.store)
                self.assertFalse(result.cache_hit)
                self.indexer.assert_called_once()
                self.assertEqual(result.program_index.metadata['reference_facts_version'], REFERENCE_FACTS_VERSION)

    def test_first_miss_persists_then_reopened_store_hits(self):
        with patch('aire.analysis.cache.time.perf_counter', side_effect=[10.0, 12.0]):
            fresh = analyze_binary(self.path, self.store)
        self.assertFalse(fresh.cache_hit)
        self.assertEqual(fresh.elapsed_seconds, 2.0)
        self.indexer.assert_called_once_with(self.path.resolve(), IndexOptions())
        self.assertTrue(self.store.has_binary(self.digest))
        self.assertEqual(self.store.load_program_index(self.digest), fresh.program_index)
        self.indexer.reset_mock()
        self.store.close()
        with BinaryKnowledgeStore(self.database) as reopened:
            with patch.object(reopened, 'save_program_index', wraps=reopened.save_program_index) as save:
                with patch('aire.analysis.cache.time.perf_counter', side_effect=[20.0, 20.125]):
                    cached = analyze_binary(self.path, reopened, IndexOptions())
                save.assert_not_called()
        self.assertTrue(cached.cache_hit)
        self.assertEqual(cached.elapsed_seconds, 0.125)
        self.assertEqual(cached.program_index, fresh.program_index)
        self.assertEqual(cached.program_index.metadata['total_seconds'], 12.5)
        self.indexer.assert_not_called()
        self.runtime.assert_not_called()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), self.digest)

    def test_force_reruns_and_replaces_snapshot(self):
        fresh = analyze_binary(self.path, self.store)
        replacement = deepcopy(fresh.program_index)
        replacement.warnings = ['replacement']
        replacement.metadata['total_seconds'] = 42.0
        self.indexer.side_effect = None
        self.indexer.return_value = replacement
        self.indexer.reset_mock()
        with patch.object(self.store, 'has_binary', side_effect=AssertionError('Force looked up cache')):
            forced = analyze_binary(self.path, self.store, force=True)
        self.assertFalse(forced.cache_hit)
        self.indexer.assert_called_once()
        self.assertEqual(self.store.load_program_index(self.digest), replacement)
        self.assertTrue(analyze_binary(self.path, self.store).cache_hit)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), self.digest)

    def test_every_different_option_is_a_miss_and_replaces_options(self):
        default = IndexOptions()
        original = self.index(self.path, default)
        for field in fields(default):
            with self.subTest(option=field.name):
                self.store.save_program_index(original)
                self.indexer.reset_mock()
                value = getattr(default, field.name)
                options = replace(default, **{field.name: not value if type(value) is bool else value + 1})
                result = analyze_binary(self.path, self.store, options)
                self.assertFalse(result.cache_hit)
                self.indexer.assert_called_once_with(self.path.resolve(), options)
                self.assertEqual(self.store.load_program_index(self.digest).metadata['options'], asdict(options))
                self.assertTrue(analyze_binary(self.path, self.store, options).cache_hit)
                self.assertEqual(self.indexer.call_count, 1)

    def test_missing_incomplete_extra_or_malformed_options_are_misses(self):
        defaults = asdict(IndexOptions())
        incomplete = dict(defaults)
        incomplete.pop('include_strings')
        for stored in (None, {}, incomplete, {**defaults, 'unknown': True},
                       {**defaults, 'decompile': 1}, {**defaults, 'max_assembly_instructions': 200.0},
                       'invalid', []):
            with self.subTest(stored=stored):
                original = self.index(self.path, IndexOptions())
                if stored is None:
                    original.metadata.pop('options')
                else:
                    original.metadata['options'] = stored
                self.store.save_program_index(original)
                self.indexer.reset_mock()
                self.assertFalse(analyze_binary(self.path, self.store).cache_hit)
                self.indexer.assert_called_once()

    def test_identical_bytes_at_another_path_hit(self):
        first = analyze_binary(self.path, self.store)
        other = self.path.with_name('copy')
        other.write_bytes(self.path.read_bytes())
        self.indexer.reset_mock()
        second = analyze_binary(str(other), self.store)
        self.assertTrue(second.cache_hit)
        self.assertEqual(first.program_index, second.program_index)
        self.indexer.assert_not_called()

    def test_changed_bytes_at_same_path_miss(self):
        analyze_binary(self.path, self.store)
        self.path.write_bytes(b'different controlled fixture')
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.indexer.reset_mock()
        self.assertFalse(analyze_binary(self.path, self.store).cache_hit)
        self.indexer.assert_called_once()
        self.assertEqual(len(self.store.list_binaries()), 2)

    def test_invalid_files_fail_before_cache_lookup(self):
        analyze_binary(self.path, self.store)
        self.indexer.reset_mock()
        with patch.object(self.store, 'has_binary') as lookup:
            for path, message in ((self.path.parent, 'not a file'),
                                  (self.path.with_name('missing'), 'File not found')):
                with self.subTest(path=path), self.assertRaisesRegex(IndexingError, message):
                    analyze_binary(path, self.store)
            self.path.unlink()
            with self.assertRaisesRegex(IndexingError, 'File not found'):
                analyze_binary(self.path, self.store)
            lookup.assert_not_called()
        self.indexer.assert_not_called()

    def test_invalid_options_fail_before_indexing(self):
        for options in ({}, False, 'invalid'):
            with self.subTest(options=options), self.assertRaises(TypeError):
                analyze_binary(self.path, self.store, options)
        self.indexer.assert_not_called()

    def test_unreadable_file_fails_before_indexing(self):
        with patch('aire.analysis.cache.sha256_file', side_effect=PermissionError('denied')):
            with self.assertRaisesRegex(IndexingError, 'Cannot read.*denied'):
                analyze_binary(self.path, self.store)
        self.indexer.assert_not_called()

    def test_hash_change_during_indexing_rejected_before_save(self):
        def mutate(path, options):
            result = self.index(path, options)
            path.write_bytes(b'simulated external modification')
            return result
        self.indexer.side_effect = mutate
        with self.assertRaisesRegex(IndexingError, 'SHA-256 changed'):
            analyze_binary(self.path, self.store)
        self.assertFalse(self.store.has_binary(self.digest))

    def test_hash_change_during_cache_load_rejected(self):
        original = analyze_binary(self.path, self.store).program_index
        self.indexer.reset_mock()
        def mutate(binary_id):
            self.path.write_bytes(b'simulated external modification')
            return original
        with patch.object(self.store, 'load_program_index', side_effect=mutate):
            with self.assertRaisesRegex(IndexingError, 'SHA-256 changed'):
                analyze_binary(self.path, self.store)
        self.indexer.assert_not_called()
        self.assertEqual(self.store.load_program_index(self.digest), original)

    def test_unverifiable_input_after_load_rejected(self):
        analyze_binary(self.path, self.store)
        with patch('aire.analysis.cache.sha256_file', side_effect=[self.digest, OSError('removed')]):
            with self.assertRaisesRegex(IndexingError, 'Cannot verify input integrity.*removed'):
                analyze_binary(self.path, self.store)

    def test_mismatched_index_identity_rejected_before_save(self):
        for field in ('binary_id', 'sha256'):
            with self.subTest(field=field):
                wrong = self.index(self.path, IndexOptions())
                setattr(wrong.binary, field, '0' * 64)
                self.indexer.side_effect = None
                self.indexer.return_value = wrong
                with self.assertRaisesRegex(IndexingError, 'does not match input'):
                    analyze_binary(self.path, self.store)
                self.assertEqual(self.store.list_binaries(), [])

    def test_mismatched_cached_sha256_is_rejected(self):
        wrong = self.index(self.path, IndexOptions())
        wrong.binary.sha256 = '0' * 64
        self.store.save_program_index(wrong)
        with self.assertRaisesRegex(IndexingError, 'does not match input'):
            analyze_binary(self.path, self.store)
        self.indexer.assert_not_called()

    def test_failed_forced_index_does_not_replace_snapshot(self):
        original = analyze_binary(self.path, self.store).program_index
        self.indexer.side_effect = IndexingError('analysis failed')
        with self.assertRaisesRegex(IndexingError, 'analysis failed'):
            analyze_binary(self.path, self.store, force=True)
        self.assertEqual(self.store.load_program_index(self.digest), original)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), self.digest)

    def test_integrity_checked_even_when_indexing_fails(self):
        def fail(path, options):
            path.write_bytes(b'simulated external modification')
            raise IndexingError('analysis failed')
        self.indexer.side_effect = fail
        with self.assertRaisesRegex(IndexingError, 'SHA-256 changed'):
            analyze_binary(self.path, self.store)
        self.assertFalse(self.store.has_binary(self.digest))

    def test_store_failures_propagate(self):
        with patch.object(self.store, 'save_program_index', side_effect=TransactionError('save failed')):
            with self.assertRaisesRegex(TransactionError, 'save failed'):
                analyze_binary(self.path, self.store)
        self.assertFalse(self.store.has_binary(self.digest))
        self.store.close()
        self.indexer.reset_mock()
        with self.assertRaises(KnowledgeStoreError):
            analyze_binary(self.path, self.store)
        self.indexer.assert_not_called()

    def test_cache_hit_without_pyghidra_installed(self):
        original = analyze_binary(self.path, self.store).program_index
        code = '''
import sys
sys.modules['pyghidra'] = None
sys.modules['jpype'] = None
from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
with BinaryKnowledgeStore(sys.argv[2]) as store:
    result = analyze_binary(sys.argv[1], store)
assert result.cache_hit
assert result.program_index.binary.binary_id == sys.argv[3]
assert sys.modules['pyghidra'] is None
assert sys.modules['jpype'] is None
'''
        subprocess.run([sys.executable, '-c', code, str(self.path), str(self.database),
                        original.binary.binary_id], check=True)


if __name__ == '__main__':
    unittest.main()
