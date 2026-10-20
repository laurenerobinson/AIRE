"""One forced fresh analysis, persisted demo evidence, and a verified cache hit.

Never executes/modifies the target. Run in a new process for cold-start timing.
"""
import argparse
from contextlib import redirect_stdout
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
from aire.profiling import AnalysisProfile
from aire.pyghidra.indexer import sha256_file


def legacy_facts_digest(index):
    """Compare original facts with the recorded pre-integration profile."""
    data = index.to_dict()
    for key in ('references', 'thunks', 'program_info'):
        data.pop(key)
    data['binary'].pop('analyzed_at')
    for key in ('analysis_seconds', 'function_extraction_seconds', 'artifact_extraction_seconds',
                'call_graph_seconds', 'reference_extraction_seconds', 'reference_facts_version', 'total_seconds'):
        data['metadata'].pop(key, None)
    data['metadata']['options'].pop('include_references')
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--demo-script', type=Path, default=Path('scripts/demoL_function_overloading.py'))
    parser.add_argument('--baseline', type=Path, default=Path('docs/FRESH_ANALYSIS_PROFILE.json'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    before = sha256_file(args.path)
    spec = importlib.util.spec_from_file_location('integrated_reference_demo', args.demo_script)
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    if demo.TARGET.resolve() != args.path.resolve() or demo.EXPECTED != before:
        raise RuntimeError('Demo target/path does not match the benchmark input')
    baseline = json.loads(args.baseline.read_text())
    with tempfile.TemporaryDirectory(prefix='aire-integrated-references-') as directory:
        database = Path(directory) / 'analysis.sqlite'
        with BinaryKnowledgeStore(database) as store, redirect_stdout(sys.stderr):
            with AnalysisProfile() as profile:
                fresh = analyze_binary(args.path, store, force=True)
                # Presentation data is now read from the index, without a JVM operation.
                evidence = demo.collect_xrefs(fresh.program_index)
        with BinaryKnowledgeStore(database) as store:
            with patch('aire.analysis.cache.index_binary', side_effect=AssertionError('Cache indexed')):
                cached = analyze_binary(args.path, store)
        if fresh.cache_hit or not cached.cache_hit or cached.program_index != fresh.program_index:
            raise RuntimeError('Fresh/cache snapshot verification failed')
        if demo.collect_xrefs(cached.program_index) != evidence:
            raise RuntimeError('Persisted demo evidence changed')
    for counter in ('projects_created', 'executable_imports', 'analyze_calls', 'xref_collection_calls'):
        if profile.counts[counter] != 1:
            raise RuntimeError(f'Expected one {counter}, got {profile.counts[counter]}')
    after = sha256_file(args.path)
    if after != before:
        raise RuntimeError('Target SHA-256 changed')
    index = fresh.program_index
    strings = {artifact.artifact_id: artifact for artifact in index.artifacts if artifact.type == 'STRING'}
    example = next(reference for reference in index.references
                   if reference.target_artifact_id in strings
                   and strings[reference.target_artifact_id].value == demo.STRINGS[0])
    report = {
        'before': {
            'normal_analysis_seconds': baseline['cold_fresh']['total_seconds'],
            'duplicate_xref_seconds': baseline['separate_demo_xrefs']['total_seconds'],
            'combined_seconds': baseline['cold_fresh']['total_seconds'] + baseline['separate_demo_xrefs']['total_seconds'],
            'projects_created': 2, 'executable_imports': 2, 'analyze_calls': 2,
        },
        'after': profile.to_dict(),
        'fresh_request_seconds': fresh.elapsed_seconds,
        'cached_request_seconds': cached.elapsed_seconds,
        'cached_snapshot_equal': True, 'cached_demo_evidence_equal': True,
        'legacy_facts_match_baseline': legacy_facts_digest(index) == baseline['cold_facts_sha256'],
        'sha256_before': before, 'sha256_after': after, 'input_sha256_unchanged': True,
        'functions': len(index.functions), 'references': len(index.references), 'thunks': len(index.thunks),
        'example_reference': asdict(example),
        'example_string': strings[example.target_artifact_id].value,
        'indexing_metadata': index.metadata,
        'timing_scope': 'One fresh request including persistence and stored demo view; database opening, '
                        'cache verification, report output, and process-exit JVM shutdown excluded. '
                        'Before timings are historical; run-to-run system load may differ.',
    }
    print(json.dumps(report, indent=2))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
