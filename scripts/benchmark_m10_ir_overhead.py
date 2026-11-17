"""M10 overhead of structured instruction facts: same warm JVM, alternating
AIRE_INSTRUCTION_IR=1/0 per binary; records total time, extraction stages,
IR size (compressed), freeze time, and that all non-IR facts are identical."""
import argparse, json, os, statistics, sys, threading, time
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from aire.profiling import AnalysisProfile
from aire.pyghidra.indexer import index_binary
from aire.pyghidra.instruction_ir import encode

def freeze_watch(stop, box):
    last = time.monotonic()
    while not stop.wait(0.5):
        now = time.monotonic()
        if now - last - 0.5 > 2: box[0] += now - last - 0.5
        last = now

def facts(index):
    data = index.to_dict(); data['binary'].pop('analyzed_at')
    for k in list(data['metadata']):
        if k.endswith('_seconds') or k in ('decompile_workers', 'decompile_retry', 'instruction_ir'): data['metadata'].pop(k)
    for k in ('Analysis Times.Times', 'Date Created'): data['program_info'].pop(k, None)
    return data

parser = argparse.ArgumentParser(); parser.add_argument('binaries', nargs='+'); parser.add_argument('--pairs', type=int, default=3)
parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
rows = []
with redirect_stdout(sys.stderr):
    index_binary(Path(args.binaries[0]))  # JVM warm-up, not measured
    for binary in args.binaries:
        reference = None
        for pair in range(args.pairs):
            for flag in (('1', '0') if pair % 2 == 0 else ('0', '1')):
                stop, box = threading.Event(), [0.0]
                watcher = threading.Thread(target=freeze_watch, args=(stop, box), daemon=True); watcher.start()
                with patch.dict(os.environ, {'AIRE_INSTRUCTION_IR': flag}):
                    tick = time.perf_counter()
                    with AnalysisProfile() as profile:
                        index = index_binary(Path(binary))
                    wall = time.perf_counter() - tick
                stop.set(); watcher.join()
                current = facts(index); reference = reference or current
                seconds = profile.to_dict()['exclusive_seconds']
                rows.append({'binary': Path(binary).name, 'ir': flag == '1', 'pair': pair, 'wall': wall, 'freeze': box[0],
                             'stages': {k: v for k, v in seconds.items() if v > 0.01},
                             'ir_instructions': sum(len(d['instructions']) for d in index.function_ir.values()),
                             'ir_compressed_bytes': sum(len(encode(d)) for d in index.function_ir.values()),
                             'non_ir_facts_identical': current == reference})
                print(json.dumps({k: (round(v, 2) if isinstance(v, float) else v) for k, v in rows[-1].items() if k != 'stages'}), file=sys.__stderr__, flush=True)
summary = {}
for b in dict.fromkeys(r['binary'] for r in rows):
    for ir in (True, False):
        sel = [r for r in rows if r['binary'] == b and r['ir'] == ir]
        adj = [r['wall'] - r['freeze'] for r in sel]
        summary[f'{b}:ir={ir}'] = {'wall_freeze_adjusted_median': statistics.median(adj), 'raw': [round(r['wall'], 2) for r in sel],
                                   'freeze': [round(r['freeze'], 1) for r in sel],
                                   'instruction_ir_stage_median': statistics.median(r['stages'].get('instruction_ir', 0) for r in sel),
                                   'assembly_stage_median': statistics.median(r['stages'].get('assembly', 0) for r in sel)}
result = {'rows': rows, 'summary': summary, 'all_non_ir_facts_identical': all(r['non_ir_facts_identical'] for r in rows)}
args.output.write_text(json.dumps(result, indent=1) + '\n'); print(json.dumps({k: v for k, v in result.items() if k != 'rows'}, indent=1))
