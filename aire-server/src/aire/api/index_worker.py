"""Persistent static analyzer process. Ghidra and SQLite stay on its main thread.

stdin/stdout carry trusted parent requests and bounded job summaries. Redirect
the native stdout FD before Ghidra starts so analyzer logs cannot corrupt IPC.
No target is ever launched; only this A.I.R.E. Python module is executable.
"""
import json
import os
from pathlib import Path
import sys

from aire.analysis.cache import WARNING_SUMMARY_LIMIT, analyze_binary
from aire.analysis.progress import analysis_progress
from aire.knowledge.database import BinaryKnowledgeStore
from aire.profiling import AnalysisProfile


def run_analysis(path, database, progress):
    with BinaryKnowledgeStore(database) as store:
        with analysis_progress(progress), AnalysisProfile() as profile:
            # The GUI reads facts through its own read-only store; a cache hit
            # needs no full snapshot load here.
            result = analyze_binary(path, store, load_snapshot=False)
    # Bounded IPC/job payload: large binaries can record thousands of warnings
    # (all remain persisted); the GUI displays the count.
    return {'binary_id': result.binary_id,
            'cache_hit': result.cache_hit, 'analysis_seconds': result.elapsed_seconds,
            'profile': profile.to_dict(), 'warning_count': result.warning_count,
            'warnings': result.warnings[:WARNING_SUMMARY_LIMIT],
            'decompile_workers': result.metadata.get('decompile_workers'),
            'decompile_retry': {key: len(value) for key, value in
                                (result.metadata.get('decompile_retry') or {}).items()},
            'decompilation_incomplete_count': len(result.metadata.get('decompilation_incomplete') or []),
            'original_index_seconds': result.metadata.get('total_seconds')}


def prewarm(status_path):
    """Optional pre-warm before serving jobs; never fatal. Status is written
    atomically to status_path for the GUI. No binary is analysed."""
    import time
    started = time.time()
    def write(status, **extra):
        if status_path is None:
            return
        record = {'status': status, 'started_epoch': started, 'pid': os.getpid(), **extra}
        temporary = status_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(record))
        temporary.replace(status_path)
    write('warming')
    tick = time.perf_counter()
    try:
        from aire.pyghidra.indexer import prewarm_runtime
        steps = prewarm_runtime()
    except Exception as exc:  # fallback: first job starts Ghidra lazily
        write('failed', error=str(exc)[:500], seconds=time.perf_counter() - tick)
        return
    write('ready', seconds=time.perf_counter() - tick, steps=steps)


def main():
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), 'w', buffering=1)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    def emit(kind, data):
        protocol.write(json.dumps({'type': kind, 'data': data}, ensure_ascii=True) + '\n')
        protocol.flush()
    flag = next((arg for arg in sys.argv[2:] if arg.startswith('--prewarm=')), None)
    if flag:
        prewarm(Path(flag.split('=', 1)[1]))
    for line in sys.stdin:
        try:
            request = json.loads(line)
            result = run_analysis(Path(request['path']), Path(sys.argv[1]),
                                  lambda phase: emit('progress', phase))
            emit('completed', result)
        except Exception as exc:
            emit('failed', str(exc)[:500])
    protocol.close()


if __name__ == '__main__':
    main()
