"""M9 repeatable analysis benchmark: cold fresh, warm fresh, and cached reload.

Run from the repository root with PYTHONPATH=aire-server/src. Each repetition
uses NEW Python/JVM processes, so "cold" includes JVM startup. Targets are only
read (never executed); SHA-256 is verified before and after every request.

    aire-server/.venv/bin/python scripts/benchmark_m9.py BINARY [BINARY ...] \
        --repeat 5 --label after --output docs/m9/benchmarks/after.json

Per repetition:
  1. child A (new process): forced fresh analysis (cold) and, unless --no-warm,
     a second forced fresh analysis in the same JVM (warm), saved to a scratch DB;
  2. child B (new process): normal cached request against that DB, with indexing
     patched to fail so a cache miss cannot be mistaken for a reload.
Facts digests (all stored facts minus timestamps/timing fields) are recorded so
before/after runs can prove identical analysis output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time

TIMING_KEYS = ('analysis_seconds', 'function_extraction_seconds', 'artifact_extraction_seconds',
               'call_graph_seconds', 'reference_extraction_seconds', 'total_seconds',
               'decompile_workers', 'decompile_retry')
VOLATILE_PROGRAM_INFO = ('Analysis Times.Times', 'Date Created')


def facts_digest(index):
    data = index.to_dict()
    data['binary'].pop('analyzed_at')
    data['binary'].pop('path', None)
    for key in TIMING_KEYS:
        data['metadata'].pop(key, None)
    # Ghidra's own wall-clock fields; verified to be the only cold/warm differences.
    # Empty list == the pre-retry snapshots (key absent); a non-empty list is a
    # real evidence difference and stays in the digest.
    if not data['metadata'].get('decompilation_incomplete'):
        data['metadata'].pop('decompilation_incomplete', None)
    for key in VOLATILE_PROGRAM_INFO:
        data.get('program_info', {}).pop(key, None)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def summary(index):
    functions = index.functions
    return {
        'functions': len(functions),
        'internal_functions': sum(not f.is_external for f in functions),
        'decompiled': sum(bool(f.decompiled_text) for f in functions),
        'strings': sum(a.type == 'STRING' for a in index.artifacts),
        'imports': sum(a.type == 'IMPORT' for a in index.artifacts),
        'exports': sum(a.type == 'EXPORT' for a in index.artifacts),
        'call_edges': len(index.function_edges),
        'references': len(index.references),
        'thunks': len(index.thunks),
        'warnings': len(index.warnings),
    }


def parse_task_times(text):
    """Parse Ghidra's 'name   12.345 secs' task-time lines (format is informal)."""
    import re
    times = {}
    for line in text.splitlines():
        match = re.match(r'\s*(.+?)\s+(\d+(?:\.\d+)?)\s*(?:secs?|s)?\s*$', line)
        if match and not match.group(1).lower().startswith('total'):
            times[match.group(1).strip()] = float(match.group(2))
    return times


def _analyzer_capture():
    """Wrap pyghidra.analyze to record Ghidra's own per-analyzer task times."""
    import pyghidra
    captured = []
    original = pyghidra.analyze

    def analyze(program, monitor=None):
        log = original(program, monitor)
        try:
            from ghidra.app.plugin.core.analysis import AutoAnalysisManager
            manager = AutoAnalysisManager.getAnalysisManager(program)
            text = str(manager.getTaskTimesString())
            captured.append({'raw': text, 'parsed_seconds': parse_task_times(text),
                             'total_seconds': int(manager.getTotalTimeInMillis()) / 1000})
        except Exception as exc:  # measurement only
            captured.append({'error': repr(exc)})
        return log
    pyghidra.analyze = analyze
    return captured


class StallDetector:
    """Detect guest-VM freezes (host descheduling): a 0.5 s ticker thread whose
    largest inter-tick gap far exceeds 0.5 s means the whole guest stopped.
    Measurement only; touches no analysis code path."""

    def __init__(self, interval=0.5):
        import threading
        self.interval, self.max_gap, self.stalled = interval, 0.0, 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        last = time.monotonic()
        while not self._stop.wait(self.interval):
            now = time.monotonic()
            gap = now - last - self.interval
            self.max_gap = max(self.max_gap, gap)
            if gap > 2.0:
                self.stalled += gap
            last = now

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(2)

    def to_dict(self):
        return {'max_tick_gap_seconds': self.max_gap, 'stalled_seconds_over_2s': self.stalled}


def child_fresh(path, database, warm, out):
    from contextlib import redirect_stdout
    from aire.analysis.cache import analyze_binary
    from aire.knowledge.database import BinaryKnowledgeStore
    from aire.profiling import AnalysisProfile
    # Import pyghidra lazily only for the wrapper; no JVM starts here.
    captured = _analyzer_capture()
    import aire.pyghidra.indexer as indexer
    import pyghidra
    indexer_pyghidra_analyze = pyghidra.analyze  # noqa: F841 (wrapper installed globally)
    report = {'requests': []}
    with BinaryKnowledgeStore(database) as store, redirect_stdout(sys.stderr):
        for kind in (['cold', 'warm'] if warm else ['cold']):
            started = time.perf_counter()
            epoch = time.time()
            with StallDetector() as stall, AnalysisProfile() as profile:
                result = analyze_binary(path, store, force=True)
            wall = time.perf_counter() - started
            report['requests'].append({
                'kind': kind, 'wall_seconds': wall, 'cache_hit': result.cache_hit,
                'started_epoch': epoch, 'stall': stall.to_dict(),
                'profile': profile.to_dict(), 'summary': summary(result.program_index),
                'facts_sha256': facts_digest(result.program_index),
                'decompile_workers': result.program_index.metadata.get('decompile_workers', 1),
                'analyzers': captured[-1] if captured else None,
                'peak_rss_mib_so_far': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
            })
    Path(out).write_text(json.dumps(report))


def child_cached(path, database, out):
    from unittest.mock import patch
    from aire.analysis.cache import analyze_binary
    from aire.knowledge.database import BinaryKnowledgeStore
    from aire.profiling import AnalysisProfile
    started = time.perf_counter()
    with BinaryKnowledgeStore(database) as store:
        opened = time.perf_counter() - started
        with patch('aire.analysis.cache.index_binary',
                   side_effect=AssertionError('cached request attempted indexing')):
            tick = time.perf_counter()
            with AnalysisProfile() as profile:
                result = analyze_binary(path, store)
            wall = time.perf_counter() - tick
    if not result.cache_hit:
        raise RuntimeError('expected cache hit')
    import sys as _sys
    Path(out).write_text(json.dumps({
        'kind': 'cached', 'wall_seconds': wall, 'open_seconds': opened,
        'profile': profile.to_dict(), 'facts_sha256': facts_digest(result.program_index),
        'jvm_started': 'jpype' in _sys.modules and _sys.modules['jpype'].isJVMStarted(),
        'peak_rss_mib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
    }))


def _run_child(args, env):
    started = time.perf_counter()
    proc = subprocess.run([sys.executable, __file__, *args], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if proc.returncode:
        raise RuntimeError(f'child failed: {proc.stderr[-3000:]}')
    return time.perf_counter() - started


def stats(values):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {'n': len(values), 'mean': statistics.fmean(values), 'median': statistics.median(values),
            'min': min(values), 'max': max(values),
            'stdev': statistics.stdev(values) if len(values) > 1 else 0.0}


def environment():
    def read(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            return None
    from aire.analysis.versions import analyzer_versions
    return {'python': sys.version, 'platform': platform.platform(), 'cpu_count': os.cpu_count(),
            'cpu_model': next((l.split(':', 1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines()
                               if l.startswith('model name')), None),
            'mem_total_kib': next((int(l.split()[1]) for l in Path('/proc/meminfo').read_text().splitlines()
                                   if l.startswith('MemTotal')), None),
            'java': read(['java', '-version']) or read(['bash', '-c', 'java -version 2>&1']),
            'analyzer_versions': analyzer_versions(),
            'loadavg_at_start': os.getloadavg(),
            'decompile_workers_env': os.environ.get('AIRE_DECOMPILE_WORKERS')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binaries', nargs='*', type=Path)
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--label', default='run')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--no-warm', action='append', default=[],
                        help='binary basename for which the warm same-JVM request is skipped')
    parser.add_argument('--child', choices=['fresh', 'cached'])
    parser.add_argument('--database', type=Path)
    parser.add_argument('--child-output', type=Path)
    parser.add_argument('--warm', action='store_true')
    parser.add_argument('--progress', type=Path,
                        help='append one JSON line per finished repetition (crash-resilient)')
    args = parser.parse_args()
    if args.child == 'fresh':
        return child_fresh(args.binaries[0], args.database, args.warm, args.child_output)
    if args.child == 'cached':
        return child_cached(args.binaries[0], args.database, args.child_output)

    env = dict(os.environ)
    report = {'label': args.label, 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
              'environment': environment(), 'repeat': args.repeat, 'binaries': {}}
    for binary in args.binaries:
        binary = binary.resolve()
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        warm = binary.name not in args.no_warm
        rows = []
        for rep in range(args.repeat):
            with tempfile.TemporaryDirectory(prefix='aire-m9-bench-') as tmp:
                db, out_a, out_b = Path(tmp, 'a.sqlite'), Path(tmp, 'a.json'), Path(tmp, 'b.json')
                proc_a = _run_child([str(binary), '--child', 'fresh', '--database', str(db),
                                     '--child-output', str(out_a)] + (['--warm'] if warm else []), env)
                proc_b = _run_child([str(binary), '--child', 'cached', '--database', str(db),
                                     '--child-output', str(out_b)], env)
                fresh, cached = json.loads(out_a.read_text()), json.loads(out_b.read_text())
                row = {'rep': rep, 'fresh_process_seconds': proc_a, 'cached_process_seconds': proc_b,
                       'requests': fresh['requests'], 'cached': cached,
                       'database_bytes': db.stat().st_size}
                rows.append(row)
                if args.progress:
                    args.progress.parent.mkdir(parents=True, exist_ok=True)
                    with args.progress.open('a') as stream:
                        stream.write(json.dumps({'label': args.label, 'binary': binary.name,
                                                 'sha256': before, **row}) + '\n')
                cold = fresh['requests'][0]
                print(f'[{args.label}] {binary.name} rep {rep}: cold {cold["wall_seconds"]:.3f}s'
                      + (f' warm {fresh["requests"][1]["wall_seconds"]:.3f}s' if warm else '')
                      + f' cached {cached["wall_seconds"]:.4f}s facts {cold["facts_sha256"][:12]}',
                      file=sys.stderr, flush=True)
        after = hashlib.sha256(binary.read_bytes()).hexdigest()
        if after != before:
            raise RuntimeError(f'{binary} changed during benchmark')
        def series(kind, getter):
            return [getter(r) for r in rows for q in r['requests'] if q['kind'] == kind for _ in [0]
                    ] if kind != 'cached' else [getter(r) for r in rows]
        stage_names = rows[0]['requests'][0]['profile']['exclusive_seconds'].keys()
        def per_stage(kind):
            out = {}
            for name in stage_names:
                vals = [q['profile']['exclusive_seconds'][name] for r in rows for q in r['requests']
                        if q['kind'] == kind]
                out[name] = statistics.median(vals) if vals else None
            return out
        digests = sorted({q['facts_sha256'] for r in rows for q in r['requests']} |
                         {r['cached']['facts_sha256'] for r in rows})
        report['binaries'][binary.name] = {
            'path': str(binary), 'sha256': before, 'size_bytes': binary.stat().st_size,
            'summary': rows[0]['requests'][0]['summary'],
            'facts_sha256_distinct': digests,
            'cold_seconds': stats([q['wall_seconds'] for r in rows for q in r['requests'] if q['kind'] == 'cold']),
            'warm_seconds': stats([q['wall_seconds'] for r in rows for q in r['requests'] if q['kind'] == 'warm']),
            'cached_seconds': stats([r['cached']['wall_seconds'] for r in rows]),
            'cached_process_seconds': stats([r['cached_process_seconds'] for r in rows]),
            'cold_peak_rss_mib': stats([r['requests'][0]['peak_rss_mib_so_far'] for r in rows]),
            'cached_peak_rss_mib': stats([r['cached']['peak_rss_mib'] for r in rows]),
            'cold_stage_median_seconds': per_stage('cold'),
            'warm_stage_median_seconds': per_stage('warm') if warm else None,
            'database_bytes': rows[0]['database_bytes'],
            'cached_jvm_started': any(r['cached']['jvm_started'] for r in rows),
            'runs': rows,
        }
    report['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    text = json.dumps(report, indent=1)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    for name, b in report['binaries'].items():
        c, w, h = b['cold_seconds'], b['warm_seconds'], b['cached_seconds']
        print(f'{name}: cold median {c["median"]:.3f}s (min {c["min"]:.3f}, max {c["max"]:.3f})'
              + (f'; warm median {w["median"]:.3f}s' if w else '')
              + f'; cached median {h["median"]:.4f}s; facts digests {len(b["facts_sha256_distinct"])}')


if __name__ == '__main__':
    main()
