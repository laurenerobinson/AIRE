"""M9 performance changes: parallel decompilation equivalence, cache identity,
metadata-first cache lookup and the lightweight GUI-worker cache path.

All tests are pure Python: Ghidra modules are replaced with fakes, so no JVM
starts. The real-binary equivalence check is in test_m9_integration.py.
"""
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import random
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from aire.analysis import versions
from aire.analysis.cache import WARNING_SUMMARY_LIMIT, analyze_binary
from aire.analysis.versions import analyzer_versions
from aire.knowledge.database import BinaryKnowledgeStore, BinaryNotFoundError
from aire.knowledge.models import BinaryRecord, ProgramIndex
from aire.pyghidra import extractor
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION


# ----------------------------------------------------------------- fakes
class _Flow:
    def __init__(self, jump):
        self._jump = jump

    def isJump(self):
        return self._jump


class _Instruction:
    def __init__(self, address, text, jump=False):
        self.address, self.text, self.jump = address, text, jump

    def getFlowType(self):
        return _Flow(self.jump)

    def getAddress(self):
        return self.address

    def __str__(self):
        return self.text


class _Namespace:
    def getName(self, _full):
        return 'Global'


class _Function:
    def __init__(self, address, name, external=False, size=3, fail_signature=False):
        self.address, self.name, self.external = address, name, external
        self.size, self.fail_signature = size, fail_signature

    def getEntryPoint(self):
        return self.address

    def getName(self):
        return self.name

    def getSignature(self):
        if self.fail_signature:
            raise RuntimeError('no signature')
        return f'void {self.name}(void)'

    def getParentNamespace(self):
        return _Namespace()

    def getCallingConventionName(self):
        return '__cdecl'

    def isExternal(self):
        return self.external

    def isThunk(self):
        return False

    def getBody(self):
        return self


class _Listing:
    def getInstructions(self, body, _forward):
        return [_Instruction(f'{body.address}{i}', f'NOP {i}', jump=i % 2 == 0) for i in range(body.size)]


class _Program:
    def getListing(self):
        return _Listing()


class _BasicBlockModel:
    def __init__(self, _program):
        pass

    def getCodeBlocksContaining(self, body, _monitor):
        return range(body.size // 2 + 1)


class _Decompiled:
    def __init__(self, text):
        self._text = text

    def getC(self):
        return self._text


class _Result:
    def __init__(self, name):
        self.name = name

    def decompileCompleted(self):
        return not self.name.startswith('fail')

    def getDecompiledFunction(self):
        return _Decompiled(f'void {self.name}(void) {{}}') if self.decompileCompleted() else None

    def getErrorMessage(self):
        if self.name.startswith('fail'):
            return 'timeout'
        return 'low-confidence' if self.name.startswith('warn') else ''


class _FakeDecompInterface:
    open_ok = True
    instances = []
    lock = threading.Lock()
    concurrent = 0
    peak = 0

    def __init__(self):
        self.disposed = False
        with _FakeDecompInterface.lock:
            _FakeDecompInterface.instances.append(self)

    def openProgram(self, _program):
        return _FakeDecompInterface.open_ok

    def getLastMessage(self):
        return 'decompiler process missing'

    def decompileFunction(self, function, timeout, _monitor):
        assert timeout == 30
        cls = _FakeDecompInterface
        with cls.lock:
            cls.concurrent += 1
            cls.peak = max(cls.peak, cls.concurrent)
        try:
            # Scramble completion order relative to submission order.
            time.sleep(random.random() * 0.004)
            if function.name.startswith('none'):
                return None
            return _Result(function.name)
        finally:
            with cls.lock:
                cls.concurrent -= 1

    def dispose(self):
        self.disposed = True


def _fake_ghidra_modules():
    block = types.ModuleType('ghidra.program.model.block')
    block.BasicBlockModel = _BasicBlockModel
    decompiler = types.ModuleType('ghidra.app.decompiler')
    decompiler.DecompInterface = _FakeDecompInterface
    names = ['ghidra', 'ghidra.program', 'ghidra.program.model', 'ghidra.app']
    modules = {name: types.ModuleType(name) for name in names}
    modules['ghidra.program.model.block'] = block
    modules['ghidra.app.decompiler'] = decompiler
    return modules


def _functions():
    rows = []
    for i in range(60):
        kind = ('fail', 'warn', 'none', 'ok', 'ok')[i % 5]
        rows.append(_Function(f'{0x1000 + i * 16:08x}', f'{kind}_{i}', size=1 + i % 7,
                              fail_signature=i % 11 == 0))
    rows.append(_Function('EXTERNAL:00000001', 'printf', external=True))
    return rows


class ParallelDecompilationTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(sys.modules, _fake_ghidra_modules()))
        _FakeDecompInterface.instances = []
        _FakeDecompInterface.open_ok = True
        _FakeDecompInterface.peak = 0
        random.seed(1234)

    def run_with(self, workers, options=None):
        warnings = ['before']
        records = extractor.extract_functions(_Program(), _functions(), 'bin', options or IndexOptions(),
                                              'monitor', warnings, workers=workers)
        return records, warnings

    def test_parallel_output_is_identical_to_serial(self):
        serial = self.run_with(1)
        for workers in (2, 4, 8):
            with self.subTest(workers=workers):
                self.assertEqual(self.run_with(workers), serial)
        records, warnings = serial
        self.assertEqual(warnings[0], 'before')
        self.assertTrue(any('fail_0' in w and 'decompilation: timeout' in w for w in warnings))
        self.assertTrue(any('warn_1 decompiler: low-confidence' in w for w in warnings))
        self.assertTrue(any('none_2 decompilation: decompiler returned no result' in w for w in warnings))
        self.assertTrue(any('signature: no signature' in w for w in warnings))
        self.assertIsNone(records[-1].decompiled_text)  # external: never decompiled

    def test_parallel_really_runs_concurrently_and_disposes_everything(self):
        self.run_with(4)
        self.assertGreater(_FakeDecompInterface.peak, 1)
        self.assertEqual(len(_FakeDecompInterface.instances), 4)
        self.assertTrue(all(d.disposed for d in _FakeDecompInterface.instances))

    def test_serial_uses_one_instance(self):
        self.run_with(1)
        self.assertEqual(_FakeDecompInterface.peak, 1)
        self.assertEqual(len(_FakeDecompInterface.instances), 1)

    def test_open_failure_matches_serial_warnings(self):
        _FakeDecompInterface.open_ok = False
        serial = self.run_with(1)
        self.assertEqual(self.run_with(4), serial)
        records, warnings = serial
        self.assertEqual(warnings[1], 'Decompiler initialization: decompiler process missing')
        self.assertTrue(all(r.decompiled_text is None for r in records))
        self.assertEqual(sum('decompiler unavailable' in w for w in warnings), 60)
        self.assertTrue(all(d.disposed for d in _FakeDecompInterface.instances))

    def test_decompile_disabled_opens_no_decompiler(self):
        records, _ = self.run_with(4, IndexOptions(decompile=False))
        self.assertEqual(_FakeDecompInterface.instances, [])
        self.assertTrue(all(r.decompiled_text is None for r in records))

    def test_profile_counters_are_recorded_on_the_request_thread(self):
        from aire.profiling import AnalysisProfile
        for workers in (1, 4):
            with self.subTest(workers=workers), AnalysisProfile() as profile:
                self.run_with(workers)
            self.assertEqual(profile.counts['decompile_attempts'], 60)
            self.assertEqual(profile.counts['decompile_successes'], 36)  # warn + ok
            self.assertEqual(profile.counts['decompiler_instances'], workers)
            self.assertEqual(profile.to_dict()['repeated_decompilations'], {})

    def test_worker_count_configuration(self):
        self.assertEqual(extractor.decompile_workers({'AIRE_DECOMPILE_WORKERS': '1'}), 1)
        self.assertEqual(extractor.decompile_workers({'AIRE_DECOMPILE_WORKERS': '3'}), 3)
        self.assertEqual(extractor.decompile_workers({'AIRE_DECOMPILE_WORKERS': '999'}), 32)
        default = max(1, min(4, os.cpu_count() or 1))
        for bad in ('0', '-2', 'many', ''):
            self.assertEqual(extractor.decompile_workers({'AIRE_DECOMPILE_WORKERS': bad}), default)
        self.assertEqual(extractor.decompile_workers({}), default)

    def test_worker_count_is_not_cache_identity(self):
        self.assertNotIn('decompile_workers', asdict(IndexOptions()))


class GhidraVersionResolutionTests(unittest.TestCase):
    """Codex review P2: cache identity must follow the launcher's lastrun fallback."""

    def make_install(self, root, version):
        (root / 'Ghidra').mkdir(parents=True)
        (root / 'Ghidra' / 'application.properties').write_text(
            f'#comment\napplication.version={version}\napplication.revision.ghidra=abc{version}\n')

    def test_env_var_wins_then_lastrun_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            env_install, last_install = tmp / 'env', tmp / 'last'
            self.make_install(env_install, '12.1.3')
            self.make_install(last_install, '11.0')
            (tmp / 'xdg' / 'ghidra').mkdir(parents=True)
            (tmp / 'xdg' / 'ghidra' / 'lastrun').write_text(f'{last_install}\n')
            env = {'XDG_CONFIG_HOME': str(tmp / 'xdg')}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(versions.ghidra_install_dir(), str(last_install))
                self.assertEqual(analyzer_versions()['ghidra'], '11.0')
                self.assertEqual(analyzer_versions()['ghidra_revision'], 'abc11.0')
            with patch.dict(os.environ, {**env, 'GHIDRA_INSTALL_DIR': str(env_install)}, clear=True):
                self.assertEqual(analyzer_versions()['ghidra'], '12.1.3')

    def test_missing_install_and_lastrun_yield_none(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {'XDG_CONFIG_HOME': tmp}, clear=True):
            self.assertIsNone(versions.ghidra_install_dir())
            self.assertIsNone(analyzer_versions()['ghidra'])

    def test_in_place_upgrade_is_noticed(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = Path(tmp) / 'ghidra'
            self.make_install(install, '12.0')
            with patch.dict(os.environ, {'GHIDRA_INSTALL_DIR': str(install)}):
                self.assertEqual(analyzer_versions()['ghidra'], '12.0')
                properties = install / 'Ghidra' / 'application.properties'
                properties.write_text('application.version=12.1\n')
                stamp = properties.stat().st_mtime_ns + 1_000_000
                os.utime(properties, ns=(stamp, stamp))
                self.assertEqual(analyzer_versions()['ghidra'], '12.1')

    def test_import_does_not_load_jpype(self):
        import subprocess
        subprocess.run([sys.executable, '-c',
                        'import aire.analysis.versions as v, sys; v.analyzer_versions(); '
                        'assert "jpype" not in sys.modules and "pyghidra" not in sys.modules'],
                       check=True)


class MetadataFirstCacheTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'target'
        self.path.write_bytes(b'controlled static fixture; never execute')
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'analysis.sqlite')
        self.addCleanup(self.store.close)
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.indexer = stack.enter_context(patch('aire.analysis.cache.index_binary', side_effect=self.index))
        stack.enter_context(patch('aire.pyghidra.indexer._start_runtime',
                                  side_effect=AssertionError('Unexpected Ghidra startup')))

    def index(self, path, options, warnings=3):
        return ProgramIndex(
            BinaryRecord(self.digest, str(path), self.digest, None, None, '00100000', None),
            warnings=[f'warning {i}' for i in range(warnings)],
            metadata={'options': asdict(options), 'total_seconds': 12.5,
                      'analyzer_versions': analyzer_versions(),
                      'ghidra_version': analyzer_versions()['ghidra'],
                      'reference_facts_version': REFERENCE_FACTS_VERSION, 'decompile_workers': 4})

    def test_stale_snapshot_is_not_fully_loaded(self):
        stale = self.index(self.path, IndexOptions())
        stale.metadata['analyzer_versions'] = {'extraction': -1}
        self.store.save_program_index(stale)
        with patch.object(self.store, 'load_program_index',
                          side_effect=AssertionError('stale snapshot loaded')) as loader:
            result = analyze_binary(self.path, self.store)
        loader.assert_not_called()
        self.assertFalse(result.cache_hit)
        self.indexer.assert_called_once()

    def test_compatible_hit_loads_full_snapshot_by_default(self):
        self.store.save_program_index(self.index(self.path, IndexOptions()))
        result = analyze_binary(self.path, self.store)
        self.assertTrue(result.cache_hit)
        self.assertIsNotNone(result.program_index)
        self.assertEqual(result.binary_id, self.digest)
        self.assertEqual(result.warning_count, 3)
        self.indexer.assert_not_called()

    def test_lightweight_hit_skips_snapshot_and_bounds_warnings(self):
        self.store.save_program_index(self.index(self.path, IndexOptions(), warnings=500))
        with patch.object(self.store, 'load_program_index',
                          side_effect=AssertionError('full load on lightweight hit')):
            result = analyze_binary(self.path, self.store, load_snapshot=False)
        self.assertTrue(result.cache_hit)
        self.assertIsNone(result.program_index)
        self.assertEqual(result.binary_id, self.digest)
        self.assertEqual(result.warning_count, 500)
        self.assertEqual(result.warnings, [f'warning {i}' for i in range(WARNING_SUMMARY_LIMIT)])
        self.assertEqual(result.metadata['total_seconds'], 12.5)
        self.indexer.assert_not_called()

    def test_lightweight_miss_still_returns_full_fresh_result(self):
        result = analyze_binary(self.path, self.store, load_snapshot=False)
        self.assertFalse(result.cache_hit)
        self.assertIsNotNone(result.program_index)
        self.assertTrue(self.store.has_binary(self.digest))

    def test_metadata_and_warning_queries(self):
        self.store.save_program_index(self.index(self.path, IndexOptions(), warnings=7))
        self.assertEqual(self.store.load_analysis_metadata(self.digest)['decompile_workers'], 4)
        self.assertEqual(self.store.load_warnings(self.digest, 2), (7, ['warning 0', 'warning 1']))
        self.assertEqual(self.store.load_warnings(self.digest)[1][-1], 'warning 6')
        with self.assertRaises(BinaryNotFoundError):
            self.store.load_analysis_metadata('0' * 64)

    def test_worker_payload_is_bounded(self):
        from aire.api import index_worker
        self.store.save_program_index(self.index(self.path, IndexOptions(), warnings=500))
        self.store.close()
        summary = index_worker.run_analysis(self.path, self.store.path, lambda _phase: None)
        self.assertTrue(summary['cache_hit'])
        self.assertEqual(summary['warning_count'], 500)
        self.assertEqual(len(summary['warnings']), WARNING_SUMMARY_LIMIT)
        self.assertEqual(summary['decompile_workers'], 4)


if __name__ == '__main__':
    unittest.main()
