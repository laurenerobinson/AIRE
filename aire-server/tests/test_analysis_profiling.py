"""Deterministic timer accounting and opt-in profiling without a JVM."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, ProgramIndex
from aire.pyghidra.extractor import decompile_function
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION
from aire.profiling import (
    AnalysisProfile, count, profiled, stage, timed_context,
)


class AnalysisProfilingTests(unittest.TestCase):
    def test_nested_stages_are_exclusive_and_sum_to_total(self):
        clock = Mock(perf_counter=Mock(side_effect=[0, 1, 3, 8, 10, 12]))
        with patch('aire.profiling.time', clock):
            with AnalysisProfile() as profile:
                with stage('python_setup'):
                    with stage('decompilation'):
                        pass
        self.assertEqual(profile.seconds['decompilation'], 5)
        self.assertEqual(profile.seconds['python_setup'], 4)
        self.assertEqual(profile.seconds['other'], 3)
        self.assertEqual(sum(profile.seconds.values()), 12)
        self.assertEqual(profile.total_seconds, 12)

    def test_repeated_nested_stage_names_do_not_double_count(self):
        clock = Mock(perf_counter=Mock(side_effect=[0, 1, 2, 4, 8, 10]))
        with patch('aire.profiling.time', clock):
            with AnalysisProfile() as profile:
                with stage('python_setup'):
                    with stage('python_setup'):
                        pass
        self.assertEqual(profile.seconds['python_setup'], 7)
        self.assertEqual(profile.seconds['other'], 3)
        self.assertEqual(sum(profile.seconds.values()), 10)

    def test_inactive_profiling_reads_no_clock_and_preserves_return_value(self):
        @profiled('python_setup', 'index_binary_calls')
        def operation(value):
            with stage('decompilation'):
                count('decompile_attempts')
            return value
        with patch('aire.profiling.time.perf_counter', side_effect=AssertionError('Inactive timer')):
            self.assertEqual(operation(42), 42)
            self.assertIs(timed_context(self, 'python_setup'), self)

    def test_failure_resets_request_context_and_records_stage(self):
        with self.assertRaisesRegex(ValueError, 'failure'):
            with AnalysisProfile() as failed:
                with stage('auto_analysis'):
                    count('analyze_calls')
                    raise ValueError('failure')
        with AnalysisProfile() as following:
            pass
        self.assertEqual(failed.counts['analyze_calls'], 1)
        self.assertEqual(following.counts['analyze_calls'], 0)
        self.assertAlmostEqual(sum(failed.seconds.values()), failed.total_seconds)
        self.assertEqual(failed._stack, [])

    def test_profile_cannot_nest_or_be_reused(self):
        profile = AnalysisProfile()
        with profile:
            with self.assertRaises(RuntimeError):
                with AnalysisProfile():
                    pass
        with self.assertRaises(RuntimeError):
            with profile:
                pass

    def test_timed_resource_preserves_exception_suppression_and_exit_arguments(self):
        resource = Mock()
        resource.__enter__ = Mock(return_value='resource')
        resource.__exit__ = Mock(return_value=True)
        with AnalysisProfile() as profile:
            with timed_context(resource, 'project_creation', counter='projects_created') as value:
                self.assertEqual(value, 'resource')
                raise ValueError('suppressed')
        self.assertIs(resource.__exit__.call_args.args[0], ValueError)
        self.assertEqual(profile.counts['projects_created'], 1)
        self.assertIn('cleanup', profile.seconds)

    def test_timed_resource_cleanup_runs_on_unsuppressed_failure(self):
        closed = []
        @contextmanager
        def resource():
            try:
                yield
            finally:
                closed.append(True)
        with self.assertRaisesRegex(ValueError, 'unsuppressed'):
            with AnalysisProfile() as profile:
                with timed_context(resource(), 'project_creation'):
                    raise ValueError('unsuppressed')
        self.assertEqual(closed, [True])
        self.assertIn('cleanup', profile.seconds)

    def test_failed_resource_entry_is_timed(self):
        resource = Mock()
        resource.__enter__ = Mock(side_effect=RuntimeError('entry failed'))
        resource.__exit__ = Mock()
        with AnalysisProfile() as profile:
            with self.assertRaisesRegex(RuntimeError, 'entry failed'):
                with timed_context(resource, 'project_creation'):
                    pass
        resource.__exit__.assert_not_called()
        self.assertIn('project_creation', profile.seconds)

    def test_decompile_attempts_successes_and_duplicates_are_observable(self):
        decompiler = Mock()
        success = decompiler.decompileFunction.return_value
        success.decompileCompleted.return_value = True
        success.getErrorMessage.return_value = ''
        success.getDecompiledFunction.return_value.getC.return_value = 'void f(void) {}'
        warnings = []
        with AnalysisProfile() as profile:
            first = decompile_function(decompiler, 'function', IndexOptions(), 'monitor', warnings, '0010 f')
            second = decompile_function(decompiler, 'function', IndexOptions(), 'monitor', warnings, '0010 f')
            decompiler.decompileFunction.side_effect = RuntimeError('failure')
            failed = decompile_function(decompiler, 'other', IndexOptions(), 'monitor', warnings, '0020 g')
        self.assertEqual(first, second)
        self.assertIsNone(failed)
        self.assertEqual(profile.counts['decompile_attempts'], 3)
        self.assertEqual(profile.counts['decompile_successes'], 2)
        self.assertEqual(profile.to_dict()['repeated_decompilations'], {'0010 f': 2})
        self.assertEqual(len(warnings), 1)

    def test_profiled_cache_save_and_load_preserve_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'target'
            path.write_bytes(b'fixture; never execute')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original = ProgramIndex(BinaryRecord(digest, str(path), digest, None, None, '0', None),
                                    warnings=['original'], metadata={'options': asdict(IndexOptions()),
                                    'reference_facts_version': REFERENCE_FACTS_VERSION})
            with BinaryKnowledgeStore(Path(directory) / 'analysis.sqlite') as store:
                with patch('aire.analysis.cache.index_binary', return_value=original):
                    with AnalysisProfile() as fresh_profile:
                        fresh = analyze_binary(path, store, force=True)
                with patch('aire.analysis.cache.index_binary', side_effect=AssertionError('Cache indexed')):
                    with AnalysisProfile() as cached_profile:
                        cached = analyze_binary(path, store)
            self.assertFalse(fresh.cache_hit)
            self.assertTrue(cached.cache_hit)
            self.assertEqual(fresh.program_index, original)
            self.assertEqual(cached.program_index, original)
            self.assertNotIn('profile', original.metadata)
            self.assertEqual(fresh_profile.counts['database_saves'], 1)
            self.assertEqual(cached_profile.counts['database_saves'], 0)
            self.assertIn('serialization', fresh_profile.seconds)
            self.assertIn('integrity', fresh_profile.seconds)
            self.assertIn('cache_load', cached_profile.seconds)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            for profile in (fresh_profile, cached_profile):
                self.assertAlmostEqual(sum(profile.seconds.values()), profile.total_seconds)
                self.assertTrue(all(value >= 0 for value in profile.seconds.values()))

    def test_import_starts_no_optional_runtime(self):
        subprocess.run([sys.executable, '-c',
                        'import aire.profiling,sys; '
                        'assert "pyghidra" not in sys.modules; assert "jpype" not in sys.modules'], check=True)


if __name__ == '__main__':
    unittest.main()
