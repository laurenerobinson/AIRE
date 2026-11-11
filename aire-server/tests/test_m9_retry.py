"""M9 hardening: decompilation timeouts are retried once, serially, after the
parallel pass; successful evidence is never overwritten; unrecovered functions
are explicitly marked incomplete. Pure Python with fake Ghidra modules."""
from collections import Counter
from contextlib import ExitStack
import threading
import unittest
from unittest.mock import patch
import sys

from aire.profiling import AnalysisProfile
from aire.pyghidra import extractor
from aire.pyghidra.options import IndexOptions

import test_m9_performance as fakes


class _ScriptedResult(fakes._Result):
    def __init__(self, name, status):
        super().__init__(name)
        self.status = status

    def decompileCompleted(self):
        return self.status == 'ok'

    def getDecompiledFunction(self):
        return fakes._Decompiled(f'void {self.name}(void) {{}}') if self.status == 'ok' else None

    def getErrorMessage(self):
        return {'ok': '', 'timeout': 'Decompiler process timed out', 'error': 'bad instruction'}[self.status]

    def isTimedOut(self):
        return self.status == 'timeout'


class _ScriptedDecompiler(fakes._FakeDecompInterface):
    """Per-function attempt scripts, e.g. {'f3': ['timeout', 'ok']}; default ok."""
    script = {}
    calls = Counter()
    lock = threading.Lock()

    def decompileFunction(self, function, timeout, monitor):
        with _ScriptedDecompiler.lock:
            attempt = _ScriptedDecompiler.calls[function.name]
            _ScriptedDecompiler.calls[function.name] += 1
        plan = _ScriptedDecompiler.script.get(function.name, ['ok'])
        status = plan[min(attempt, len(plan) - 1)]
        return _ScriptedResult(function.name, status)


def _functions(n=40):
    return [fakes._Function(f'{0x2000 + i * 16:08x}', f'f{i}', size=1 + i % 5) for i in range(n)] + \
           [fakes._Function('EXTERNAL:00000001', 'puts', external=True)]


class RetryTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        modules = fakes._fake_ghidra_modules()
        modules['ghidra.app.decompiler'].DecompInterface = _ScriptedDecompiler
        stack.enter_context(patch.dict(sys.modules, modules))
        _ScriptedDecompiler.instances = []
        _ScriptedDecompiler.open_ok = True
        _ScriptedDecompiler.script = {}
        _ScriptedDecompiler.calls = Counter()

    def run_with(self, workers, script=None):
        _ScriptedDecompiler.script = script or {}
        _ScriptedDecompiler.calls = Counter()
        warnings, report = [], {}
        records = extractor.extract_functions(fakes._Program(), _functions(), 'bin', IndexOptions(),
                                              'monitor', warnings, workers=workers, report=report)
        return records, warnings, report

    def test_clean_run_reports_nothing_and_matches_serial(self):
        clean = self.run_with(4)
        self.assertEqual(clean, self.run_with(1))
        records, warnings, report = clean
        self.assertEqual(report['decompile_retry'], {'timed_out': [], 'retried': [], 'recovered': []})
        self.assertEqual(report['decompilation_incomplete'], [])
        self.assertTrue(all(r.decompiled_text for r in records if not r.is_external))

    def test_recovered_timeouts_yield_evidence_identical_to_clean_run(self):
        clean_records, clean_warnings, _ = self.run_with(4)
        script = {'f3': ['timeout', 'ok'], 'f17': ['timeout', 'ok'], 'f30': ['timeout', 'ok']}
        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                records, warnings, report = self.run_with(workers, script)
                self.assertEqual(records, clean_records)
                self.assertEqual(warnings, clean_warnings)
                self.assertEqual(report['decompile_retry']['timed_out'], ['00002030', '00002110', '000021e0'])
                self.assertEqual(report['decompile_retry']['recovered'], ['00002030', '00002110', '000021e0'])
                self.assertEqual(report['decompilation_incomplete'], [])

    def test_successful_functions_are_never_redecompiled(self):
        self.run_with(4, {'f5': ['timeout', 'ok']})
        calls = _ScriptedDecompiler.calls
        self.assertEqual(calls['f5'], 2)
        self.assertTrue(all(count == 1 for name, count in calls.items() if name != 'f5'))
        self.assertNotIn('puts', calls)  # externals are never decompiled

    def test_unrecovered_timeout_is_explicitly_incomplete(self):
        records, warnings, report = self.run_with(4, {'f8': ['timeout', 'timeout']})
        record = next(r for r in records if r.current_name == 'f8')
        self.assertIsNone(record.decompiled_text)
        [entry] = report['decompilation_incomplete']
        self.assertEqual((entry['address'], entry['reason']), ('00002080', 'timeout_after_retry'))
        self.assertEqual(entry['function_id'], 'bin:00002080')
        self.assertIn('INCOMPLETE', entry['message'])
        self.assertTrue(any('f8 decompilation:' in w and 'INCOMPLETE' in w for w in warnings))
        self.assertEqual(report['decompile_retry']['recovered'], [])
        self.assertEqual(_ScriptedDecompiler.calls['f8'], 2)  # exactly one retry

    def test_deterministic_errors_are_not_retried_but_are_listed(self):
        records, warnings, report = self.run_with(4, {'f2': ['error']})
        self.assertEqual(_ScriptedDecompiler.calls['f2'], 1)
        [entry] = report['decompilation_incomplete']
        self.assertEqual((entry['address'], entry['reason']), ('00002020', 'decompiler_error'))
        self.assertIn('Function 00002020 f2 decompilation: bad instruction', warnings)
        self.assertEqual(report['decompile_retry']['retried'], [])

    def test_unavailable_decompiler_is_listed_per_function(self):
        fakes._FakeDecompInterface.open_ok = False  # read by the base fake's openProgram
        self.addCleanup(setattr, fakes._FakeDecompInterface, 'open_ok', True)
        _, _, report = self.run_with(4)
        self.assertEqual(len(report['decompilation_incomplete']), 40)
        self.assertEqual({e['reason'] for e in report['decompilation_incomplete']}, {'decompiler_unavailable'})

    def test_retry_counters(self):
        for workers in (1, 4):
            with self.subTest(workers=workers), AnalysisProfile() as profile:
                self.run_with(workers, {'f1': ['timeout', 'ok'], 'f9': ['timeout', 'timeout']})
            counts = profile.counts
            self.assertEqual(counts['decompile_timeouts'], 2)
            self.assertEqual(counts['decompile_retries'], 2)
            self.assertEqual(counts['decompile_retry_recovered'], 1)
            self.assertEqual(counts['decompile_attempts'], 42)  # 40 + 2 retries
            self.assertEqual(counts['decompile_successes'], 39)

    def test_output_is_deterministic_across_runs_with_timeouts(self):
        script = {'f4': ['timeout', 'ok'], 'f11': ['timeout', 'timeout']}
        first = self.run_with(4, script)
        self.assertEqual(self.run_with(4, script), first)
        self.assertEqual(self.run_with(1, script), first)


if __name__ == '__main__':
    unittest.main()


class IncompleteSurfaceTests(unittest.TestCase):
    """Stored incompleteness is reported by tools, never hidden."""

    def test_tools_report_incomplete_functions(self):
        import tempfile
        from pathlib import Path
        from aire.agent.tools import AgentTools
        from aire.knowledge.database import BinaryKnowledgeStore
        from aire.knowledge.models import BinaryRecord, FunctionRecord, ProgramIndex
        b = 'e' * 64
        functions = [FunctionRecord(f'{b}:1000', b, '1000', 'FUN_1000', None, 'int f(void){}', 'RET', 1, 1, 0),
                     FunctionRecord(f'{b}:2000', b, '2000', 'FUN_2000', None, None, 'RET', 1, 1, 0)]
        metadata = {'decompile_retry': {'timed_out': ['2000'], 'retried': ['2000'], 'recovered': []},
                    'decompilation_incomplete': [{'function_id': f'{b}:2000', 'address': '2000', 'name': 'FUN_2000',
                                                  'reason': 'timeout_after_retry', 'message': 'timed out; INCOMPLETE'}]}
        with tempfile.TemporaryDirectory() as tmp:
            with BinaryKnowledgeStore(Path(tmp) / 'a.sqlite') as store:
                store.save_program_index(ProgramIndex(BinaryRecord(b, '/x', b, 'PE', None, '0', None), functions,
                                                      metadata=metadata))
                tools = AgentTools(store, b)
                missing = tools.registry.run('get_decompiled_text', {'function': '2000'})['data']
                self.assertFalse(missing['available'])
                self.assertEqual(missing['incomplete']['reason'], 'timeout_after_retry')
                present = tools.registry.run('get_decompiled_text', {'function': '1000'})['data']
                self.assertNotIn('incomplete', present)
                summary = tools.registry.run('binary_metadata', {})['data']['decompilation']
                self.assertEqual((summary['incomplete_count'], summary['timeouts_retried'],
                                  summary['timeouts_recovered']), (1, 1, 0))
