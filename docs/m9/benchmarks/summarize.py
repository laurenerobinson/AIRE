"""Summarize docs/m9/benchmarks/progress.jsonl into median/range tables.

    python3 docs/m9/benchmarks/summarize.py [--labels i-before,i-after,i-after-w1] > summary.md
Also writes summary.json beside this script. Read-only over recorded data.
"""
import argparse
import json
from pathlib import Path
import statistics as st

HERE = Path(__file__).resolve().parent
STAGES = ('runtime_startup', 'import_open', 'auto_analysis', 'decompiler_setup', 'decompilation',
          'assembly', 'basic_blocks', 'xrefs', 'call_graph', 'database_save', 'cache_load')


def stats(values):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {'n': len(values), 'median': st.median(values), 'min': min(values), 'max': max(values)}


def fmt(s, digits=2):
    if not s:
        return '—'
    return f"{s['median']:.{digits}f} ({s['min']:.{digits}f}–{s['max']:.{digits}f}, n={s['n']})"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--labels', default='i-before,i-after,i-after-w1')
    args = parser.parse_args()
    labels = args.labels.split(',')
    rows = [json.loads(line) for line in (HERE / 'progress.jsonl').read_text().splitlines() if line.strip()]
    binaries = list(dict.fromkeys(r['binary'] for r in rows if r['label'] in labels))
    out = {}
    print('| Binary | Condition | Cold s, median (range, n) | Warm s | Cached s | Cold freeze-free | Warm freeze-free | Facts digests |')
    print('|---|---|---|---|---|---|---|---|')
    for binary in binaries:
        out[binary] = {}
        digests_all = set()
        for label in labels:
            sel = [r for r in rows if r['binary'] == binary and r['label'] == label]
            if not sel:
                continue
            cold = [q for r in sel for q in r['requests'] if q['kind'] == 'cold']
            warm = [q for r in sel for q in r['requests'] if q['kind'] == 'warm']
            digests = {q['facts_sha256'] for r in sel for q in r['requests']} | {r['cached']['facts_sha256'] for r in sel}
            digests_all |= digests
            clean = lambda qs: [q for q in qs if q.get('stall') and q['stall']['stalled_seconds_over_2s'] < 1.0]
            entry = {
                'cold_freeze_free': stats([q['wall_seconds'] for q in clean(cold)]),
                'warm_freeze_free': stats([q['wall_seconds'] for q in clean(warm)]),
                'requests_with_detected_freeze': sum(1 for q in cold + warm if q.get('stall')
                                                     and q['stall']['stalled_seconds_over_2s'] >= 1.0),
                'requests_without_freeze_data': sum(1 for q in cold + warm if not q.get('stall')),
                'cold': stats([q['wall_seconds'] for q in cold]),
                'warm': stats([q['wall_seconds'] for q in warm]),
                'cached': stats([r['cached']['wall_seconds'] for r in sel]),
                'cold_peak_rss_mib': stats([q['peak_rss_mib_so_far'] for q in cold]),
                'cold_stages': {s: stats([q['profile']['exclusive_seconds'][s] for q in cold]) for s in STAGES},
                'warm_stages': {s: stats([q['profile']['exclusive_seconds'][s] for q in warm]) for s in STAGES},
                'ghidra_analyzer_total_cold': stats([(q.get('analyzers') or {}).get('total_seconds') for q in cold]),
                'decompile_workers': sorted({q.get('decompile_workers') for q in cold}),
                'summary': cold[0]['summary'] if cold else None,
                'digests': sorted(digests),
            }
            out[binary][label] = entry
            print(f"| {binary} | {label} | {fmt(entry['cold'])} | {fmt(entry['warm'])} | {fmt(entry['cached'], 4)} | "
                  f"{fmt(entry['cold_freeze_free'])} | {fmt(entry['warm_freeze_free'])} | {len(digests)} |")
        out[binary]['_facts_identical_across_conditions'] = len(digests_all) == 1
    print()
    print('| Binary | Stage (cold median s) | ' + ' | '.join(labels) + ' |')
    print('|---|---|' + '---|' * len(labels))
    for binary in binaries:
        for stage in STAGES:
            cells = []
            for label in labels:
                s = out[binary].get(label, {}).get('cold_stages', {}).get(stage)
                cells.append(f"{s['median']:.2f}" if s else '—')
            if any(c not in ('—', '0.00') for c in cells):
                print(f'| {binary} | {stage} | ' + ' | '.join(cells) + ' |')
    print()
    for binary in binaries:
        print(f"- {binary}: facts identical across {', '.join(l for l in labels if l in out[binary])}: "
              f"**{out[binary]['_facts_identical_across_conditions']}**")
    (HERE / 'summary.json').write_text(json.dumps(out, indent=1) + '\n')


if __name__ == '__main__':
    main()
