"""M10 Phase 2 regression: decompiler cross-validation verdicts for every internal function.

Resumable: one result file per binary under docs/m10/crossval_survey/ (written atomically after each
binary); finished binaries are skipped. --merge writes docs/m10/crossval_survey_rerun.json.
Read-only on the store; never executes targets.
Default binaries = the five of the original Phase 2 survey (954 functions); --with-o2 adds the -O2 ELF.
"""
import argparse, collections, json, os, sys, time
from pathlib import Path

from aire.analysis.assembly_intelligence import AssemblyIntelligence
from aire.security.rule_engine import _ReadOnlyRuleStore

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ('aire_test_binary', 'aire_test_binary_stripped', 'aes_gcm.exe', 'sha256_hash.exe', 'ecdsa_sign.exe')


def survey(store, binary):
    ai = AssemblyIntelligence(store, binary.binary_id)
    verdicts, checks, discrepancies = collections.Counter(), collections.Counter(), []
    for fid, name in store._db.execute('SELECT function_id, current_name FROM functions WHERE binary_id=? AND is_external=0',
                                       (binary.binary_id,)).fetchall():
        report = ai.crossvalidate(fid)['crossvalidation']
        verdicts[report['verdict']] += 1
        for finding in report['findings']:
            checks[f"{finding['check']}:{finding['status']}"] += 1
            if finding['status'] == 'POTENTIAL DISCREPANCY':
                discrepancies.append([name, finding['check'], finding['summary'][:200]])
    return {'binary': binary.program_name, 'sha256': binary.sha256, 'functions': sum(verdicts.values()),
            'verdicts': dict(verdicts), 'checks': dict(checks), 'discrepancies': discrepancies}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', default='demo_artifacts/m10/m10.sqlite')
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'docs/m10/crossval_survey')
    parser.add_argument('--with-o2', action='store_true')
    parser.add_argument('--merge', action='store_true')
    args = parser.parse_args()
    names = ORIGINAL + (('aire_test_binary_O2',) if args.with_o2 else ())
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if args.merge:
        parts = {n: json.loads((args.out_dir / f'{n}.json').read_text()) for n in names
                 if (args.out_dir / f'{n}.json').exists()}
        total = collections.Counter()
        for part in parts.values():
            if part['binary'] in ORIGINAL:
                total.update(part['verdicts'])
        out = {'generated': time.strftime('%Y-%m-%dT%H:%M:%S'), 'original_five_verdicts': dict(total),
               'original_five_functions': sum(total.values()), 'binaries': parts,
               'missing': [n for n in names if n not in parts]}
        (args.out_dir.parent / 'crossval_survey_rerun.json').write_text(json.dumps(out, indent=1) + '\n')
        print(json.dumps({k: out[k] for k in ('original_five_verdicts', 'original_five_functions', 'missing')}))
        return
    with _ReadOnlyRuleStore(args.database) as store:
        binaries = {b.program_name: b for b in store.list_binaries()}
        for name in names:
            path = args.out_dir / f'{name}.json'
            if path.exists():
                print(f'{name}: done earlier, skipped', file=sys.stderr)
                continue
            tick = time.perf_counter()
            result = survey(store, binaries[name])
            result['seconds'] = round(time.perf_counter() - tick, 1)
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(result, indent=1) + '\n')
            os.replace(tmp, path)
            print(f"{name}: {result['verdicts']} ({result['seconds']} s)", file=sys.stderr, flush=True)


if __name__ == '__main__':
    main()
