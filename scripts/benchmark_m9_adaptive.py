"""Adaptive-decompilation evaluation: serial vs parallel for small binaries.

One warm JVM; each binary is indexed alternately with AIRE_DECOMPILE_WORKERS=1
and =4 (ABAB…, --repeat pairs). Records the A.I.R.E. extraction stages
(decompiler setup + decompilation + assembly + basic blocks), total request
time, peak RSS of native decompiler children, detected freezes, and asserts
identical facts across worker counts. Targets are only read.
"""
import argparse
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import statistics
import sys
import threading
import time
from unittest.mock import patch

from aire.profiling import AnalysisProfile
from aire.pyghidra.indexer import index_binary

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ['tests/fixtures/simple_elf/aire_test_binary',
            'tests/fixtures/m9/corrupt_pe/section_offset_beyond_eof.exe']
STAGES = ('decompiler_setup', 'decompilation', 'assembly', 'basic_blocks')


def children_rss_mib():
    me, total = os.getpid(), 0
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            try:
                stat = (entry / 'stat').read_text()
                if int(stat[stat.rindex(')') + 2:].split()[1]) == me and 'decompile' in stat:
                    for line in (entry / 'status').read_text().splitlines():
                        if line.startswith('VmRSS:'):
                            total += int(line.split()[1])
            except (OSError, ValueError, IndexError):
                pass
    return total / 1024


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
    parser.add_argument('--repeat', type=int, default=10)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    with redirect_stdout(sys.stderr):
        index_binary(ROOT / BINARIES[0])  # JVM/class warm-up, not measured
        for binary in BINARIES:
            reference = None
            for rep in range(args.repeat):
                for workers in ((1, 4) if rep % 2 == 0 else (4, 1)):
                    peak, stop = [0.0], threading.Event()
                    gap = [0.0]
                    def sample():
                        last = time.monotonic()
                        while not stop.wait(0.05):
                            peak[0] = max(peak[0], children_rss_mib())
                            now = time.monotonic()
                            if now - last > 2.0:
                                gap[0] += now - last
                            last = now
                    sampler = threading.Thread(target=sample, daemon=True)
                    sampler.start()
                    with patch.dict(os.environ, {'AIRE_DECOMPILE_WORKERS': str(workers)}):
                        tick = time.perf_counter()
                        with AnalysisProfile() as profile:
                            index = index_binary(ROOT / binary)
                        wall = time.perf_counter() - tick
                    stop.set()
                    sampler.join()
                    current = facts(index)
                    reference = reference or current
                    seconds = profile.to_dict()['exclusive_seconds']
                    rows.append({'binary': Path(binary).name, 'workers': workers, 'rep': rep,
                                 'internal_functions': sum(not f.is_external for f in index.functions),
                                 'extraction_seconds': sum(seconds[s] for s in STAGES),
                                 'stages': {s: seconds[s] for s in STAGES}, 'wall_seconds': wall,
                                 'decompiler_children_peak_rss_mib': peak[0],
                                 'freeze_seconds': gap[0], 'facts_identical': current == reference})
                    print(json.dumps(rows[-1]), file=sys.stderr, flush=True)
    summary = {}
    for binary in {r['binary'] for r in rows}:
        for workers in (1, 4):
            sel = [r for r in rows if r['binary'] == binary and r['workers'] == workers and r['freeze_seconds'] < 1]
            def med(key):
                values = [r[key] for r in sel]
                return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'n': len(values)} if values else None
            summary[f'{binary}:workers={workers}'] = {k: med(k) for k in (
                'extraction_seconds', 'wall_seconds', 'decompiler_children_peak_rss_mib')}
    result = {'rows': rows, 'summary_freeze_free': summary,
              'all_facts_identical': all(r['facts_identical'] for r in rows)}
    args.output.write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'rows'}, indent=1))


if __name__ == '__main__':
    main()
