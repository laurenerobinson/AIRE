"""Measure fresh analysis followed by a cache hit using a disposable database.

Run from the repository root with PYTHONPATH=aire-server/src. Never executes or
modifies the target. The database is reopened before measuring the cache hit.
"""
import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
from aire.pyghidra.indexer import sha256_file
from aire.profiling import AnalysisProfile, COUNTERS, STAGES


def facts_digest(index):
    """Compare all stored facts except the existing timestamp/timing fields."""
    data = index.to_dict()
    data['binary'].pop('analyzed_at')
    for key in ('analysis_seconds', 'function_extraction_seconds',
                'artifact_extraction_seconds', 'call_graph_seconds', 'reference_extraction_seconds', 'total_seconds'):
        data['metadata'].pop(key, None)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def measure(path, store, force):
    with AnalysisProfile() as profile:
        result = analyze_binary(path, store, force=force)
    report = profile.to_dict()
    report.update(cache_hit=result.cache_hit, request_elapsed_seconds=result.elapsed_seconds,
                  indexing_metadata=result.program_index.metadata,
                  reference_count=len(result.program_index.references),
                  thunk_count=len(result.program_index.thunks))
    return result, report


def profile_requests(path, database, xref_script=None):
    # The standalone script starts a new process. Do not initialize/import the
    # optional PyGhidra runtime before measuring the cold request.
    jpype = sys.modules.get('jpype')
    if jpype is not None and jpype.isJVMStarted():
        raise RuntimeError('Cold measurement requires a new Python process/JVM')
    before = sha256_file(path)
    with BinaryKnowledgeStore(database) as store, redirect_stdout(sys.stderr):
        cold, cold_report = measure(path, store, force=True)
        warm, warm_report = measure(path, store, force=True)
    with BinaryKnowledgeStore(database) as store:
        with patch('aire.analysis.cache.index_binary', side_effect=AssertionError(
                'Cached request attempted indexing')):
            cached, cached_report = measure(path, store, force=False)
    if cold.cache_hit or warm.cache_hit or not cached.cache_hit:
        raise RuntimeError('Expected two forced fresh requests followed by one cache hit')
    if warm.program_index != cached.program_index:
        raise RuntimeError('Stored analysis differs from warm analysis')
    cold_digest, warm_digest = facts_digest(cold.program_index), facts_digest(warm.program_index)
    report = {
        'process_id': os.getpid(), 'python_version': sys.version,
        'path': str(path.resolve()), 'cold_fresh': cold_report, 'warm_fresh': warm_report,
        'cached': cached_report, 'cold_warm_facts_equal': cold_digest == warm_digest,
        'cold_facts_sha256': cold_digest, 'warm_facts_sha256': warm_digest,
        'warm_cached_snapshots_equal': True,
        'timing_scope': 'Exclusive request wall time; excludes opening store, report output, '
                        'benchmark comparisons, and process-exit JVM shutdown. Cold means '
                        'new Python/JVM, not cleared OS filesystem caches. Auto-analysis '
                        'includes any analyzer-internal decompilation; decompile counters '
                        'cover A.I.R.E. extraction calls only.',
    }
    if xref_script is not None:
        spec = importlib.util.spec_from_file_location('aire_profile_xref_demo', xref_script)
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        if demo.TARGET.resolve() != path.resolve() or demo.EXPECTED != before:
            raise RuntimeError('Xref demo target/hash differs from the measured binary')
        # The demo consumes the cached index. It must never open Ghidra again.
        with redirect_stdout(sys.stderr), AnalysisProfile() as profile:
            with patch('pyghidra.open_project', side_effect=AssertionError('Demo opened Ghidra')):
                with patch('pyghidra.analyze', side_effect=AssertionError('Demo reran analysis')):
                    demo.collect_xrefs(cached.program_index)
        report['stored_demo_reference_view'] = profile.to_dict()
        report['xref_script'] = str(xref_script)
    after = sha256_file(path)
    if after != before:
        raise RuntimeError('Target SHA-256 changed')
    report.update(sha256_before=before, sha256_after=after, input_sha256_unchanged=True)
    return report


def print_profile(report):
    names = ('cold_fresh', 'warm_fresh', 'cached')
    print(f'{"Stage (seconds, exclusive)":<34} {"Cold Fresh":>12} {"Warm Fresh":>12} {"Cached":>12}')
    print('-' * 73)
    for key, label in STAGES:
        values = [report[name]['exclusive_seconds'][key] for name in names]
        print(f'{label:<34}' + ''.join(f' {value:12.6f}' for value in values))
    print('-' * 73)
    print(f'{"TOTAL":<34}' + ''.join(f' {report[name]["total_seconds"]:12.6f}' for name in names))
    print('\nWork counters (A.I.R.E. calls; excludes Java analyzer internals):')
    for key in COUNTERS:
        print(f'{key:<34}' + ''.join(f' {report[name]["counts"][key]:12d}' for name in names))
    print('\nDetailed report:')
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--profile', action='store_true',
                        help='Measure forced cold and warm fresh analysis, then a cached request')
    parser.add_argument('--output', type=Path, help='Write detailed profiling JSON')
    parser.add_argument('--xref-script', type=Path,
                        help='Verify a matching demo reads cached reference facts without opening Ghidra')
    args = parser.parse_args()
    if (args.output or args.xref_script) and not args.profile:
        parser.error('--output and --xref-script require --profile')
    if args.profile:
        with tempfile.TemporaryDirectory(prefix='aire-analysis-profile-') as directory:
            report = profile_requests(args.path, Path(directory) / 'analysis.sqlite', args.xref_script)
        print_profile(report)
        if args.output:
            args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        return
    before = sha256_file(args.path)
    with tempfile.TemporaryDirectory(prefix='aire-analysis-cache-') as directory:
        database = Path(directory) / 'analysis.sqlite'
        with BinaryKnowledgeStore(database) as store, redirect_stdout(sys.stderr):
            fresh = analyze_binary(args.path, store)
        with BinaryKnowledgeStore(database) as store:
            with patch('aire.analysis.cache.index_binary', side_effect=AssertionError(
                    'Cache hit attempted fresh indexing')):
                cached = analyze_binary(args.path, store)
        if fresh.cache_hit or not cached.cache_hit:
            raise RuntimeError('Expected a cache miss followed by a cache hit')
        if fresh.program_index != cached.program_index:
            raise RuntimeError('Stored analysis differs from fresh analysis')
        after = sha256_file(args.path)
        if after != before:
            raise RuntimeError('Target SHA-256 changed')
        print(f'Fresh analysis: {fresh.elapsed_seconds:.6f} seconds')
        print(f'Loaded cached analysis: {cached.elapsed_seconds:.6f} seconds')
        print(json.dumps({
            'fresh': {'cache_hit': fresh.cache_hit, 'elapsed_seconds': fresh.elapsed_seconds},
            'cached': {'cache_hit': cached.cache_hit, 'elapsed_seconds': cached.elapsed_seconds},
            'indexing_metadata': fresh.program_index.metadata,
            'sha256_before': before, 'sha256_after': after,
            'input_sha256_unchanged': before == after,
        }, indent=2))


if __name__ == '__main__':
    main()
