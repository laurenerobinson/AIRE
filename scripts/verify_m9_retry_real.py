"""Real-JVM check of decompilation timeout retries (no mocks).

Simulates a host freeze hitting A.I.R.E.'s extraction: once the indexer reports
the extraction phase, every native `decompile` child of this process is
SIGSTOPped for FREEZE seconds (> the per-function timeout), then SIGCONTed.
In-flight decompilations time out; the indexer must retry them once serially
and produce facts identical to a clean run. Targets are only read.

    GHIDRA_INSTALL_DIR=... JAVA_HOME=... PYTHONPATH=aire-server/src \
    aire-server/.venv/bin/python scripts/verify_m9_retry_real.py [binary] [--output report.json]
"""
import argparse
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

from aire.analysis.progress import analysis_progress
from aire.profiling import AnalysisProfile
from aire.pyghidra.indexer import index_binary
from aire.pyghidra.options import IndexOptions

TIMEOUT = 2
FREEZE = 5


def decompiler_children():
    me, pids = os.getpid(), []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / 'stat').read_text()
            comm = stat[stat.index('(') + 1:stat.rindex(')')]
            ppid = int(stat[stat.rindex(')') + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if comm.startswith('decompile') and ppid == me:
            pids.append(int(entry.name))
    return pids


def facts(index):
    data = index.to_dict()
    data['binary'].pop('analyzed_at')
    for key in list(data['metadata']):
        if key.endswith('_seconds') or key in ('decompile_workers', 'decompile_retry'):
            data['metadata'].pop(key)
    for key in ('Analysis Times.Times', 'Date Created'):
        data['program_info'].pop(key, None)
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', nargs='?', default='tests/fixtures/m9/crypto_pe/sha256_hash.exe')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    path = Path(args.binary)
    options = IndexOptions(decompile_timeout_seconds=TIMEOUT)
    with redirect_stdout(sys.stderr):
        clean = index_binary(path, options)
        frozen_pids = []
        lock, armed = threading.Lock(), [False]
        from aire.pyghidra import extractor
        real_attempt = extractor._attempt

        def resume_later():
            time.sleep(FREEZE)
            for pid in frozen_pids:
                try:
                    os.kill(pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass

        def freezing_attempt(*a, **k):
            # Deterministic trigger: the first extraction attempt freezes every
            # native decompiler process (all pool instances are open and idle at
            # this point), then calls the real decompiler. Real timeouts, process
            # restarts and retries follow; nothing else is simulated.
            with lock:
                if armed[0]:
                    armed[0] = False
                    for pid in decompiler_children():
                        try:
                            os.kill(pid, signal.SIGSTOP)
                            frozen_pids.append(pid)
                        except ProcessLookupError:
                            pass
                    threading.Thread(target=resume_later, daemon=True).start()
            return real_attempt(*a, **k)

        def on_progress(message):
            if message.startswith('Extracting functions'):
                armed[0] = True

        extractor._attempt = freezing_attempt
        with analysis_progress(on_progress), AnalysisProfile() as profile:
            frozen = index_binary(path, options)
        extractor._attempt = real_attempt
    retry = frozen.metadata.get('decompile_retry', {'timed_out': [], 'retried': [], 'recovered': []})
    report = {
        'binary': str(path), 'timeout_seconds': TIMEOUT, 'freeze_seconds': FREEZE,
        'frozen_decompiler_processes': len(frozen_pids),
        'decompile_retry': retry,
        'decompilation_incomplete': frozen.metadata.get('decompilation_incomplete'),
        'functions_without_decompiled_text': sum(1 for f in frozen.functions if not f.is_external and f.decompiled_text is None),
        'counts': {k: profile.counts.get(k, 0) for k in ('decompile_attempts', 'decompile_successes',
                                                    'decompile_timeouts', 'decompile_retries',
                                                    'decompile_retry_recovered')},
        'facts_identical_to_clean_run': facts(clean) == facts(frozen),
        'clean_incomplete': clean.metadata.get('decompilation_incomplete'),
    }
    report['passed'] = (bool(retry['timed_out']) and retry['recovered'] == retry['timed_out']
                        and not report['decompilation_incomplete'] and report['facts_identical_to_clean_run'])
    text = json.dumps(report, indent=1)
    if args.output:
        args.output.write_text(text + '\n')
    print(text)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
