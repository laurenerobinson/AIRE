"""M10 evaluation against independent ground truth (objdump + source-derived facts).

Phase 1 metrics (instruction level), per binary:
  boundaries      every A.I.R.E. instruction address is an objdump instruction start
  mnemonics       normalized mnemonic agreement (condition-code synonyms unified)
  targets         direct branch/call targets agree
  memory          memory-operand base register and displacement agree
  relations       conditional-branch relation (operator, signedness) agrees with a
                  textbook-x86 oracle over objdump's text (nearest cmp/test, no
                  intervening flag writer or control transfer)
Reads the M10 store read-only; never executes targets.
"""
import argparse, collections, json, re, sys
from pathlib import Path
from aire.analysis.assembly_intelligence import AssemblyIntelligence
from aire.evaluation.objdump_truth import branch_oracle, disassemble, memory_operand
from aire.security.rule_engine import _ReadOnlyRuleStore

EQUIVALENT = {('movsd.rep', 'movs'), ('stosd.rep', 'stos'), ('stosq.rep', 'stos'), ('movsq.rep', 'movs'),
              ('movsb.rep', 'movs'), ('stosb.rep', 'stos'), ('cmpsb.repe', 'cmps'), ('scasb.repne', 'scas')}


def relation_of(record):
    relation = (record.get('branch') or {}).get('relation') or {}
    text = relation.get('text')
    if not text:
        return None
    signedness = 'unsigned' if '(unsigned' in text else 'signed' if '(signed' in text else None
    match = re.search(r'\s(==|!=|<=|>=|<|>)\s', text)
    return {'operator': match.group(1) if match else None, 'signedness': signedness, 'setter': relation.get('setter')}


def evaluate_phase1(store, binary, path):
    truth_functions = disassemble(path)
    truth = {i['a']: i for f in truth_functions.values() for i in f['instructions']}
    oracle = {}
    for function in truth_functions.values():
        oracle.update(branch_oracle(function['instructions']))
    ai = AssemblyIntelligence(store, binary.binary_id)
    counts, mismatches = collections.Counter(), collections.Counter()
    examples = collections.defaultdict(list)
    for (fid, external) in store._db.execute('SELECT function_id, is_external FROM functions WHERE binary_id=?',
                                             (binary.binary_id,)).fetchall():
        if external:
            continue
        document = ai.document(ai.resolve(fid))
        for raw, record in zip(document['instructions'], ai.explain(fid, limit=400)['instructions']):
            counts['instructions'] += 1
            expected = truth.get(raw['a'])
            if expected is None:
                mismatches['boundary'] += 1
                examples['boundary'].append(raw['a'])
                continue
            counts['boundary_ok'] += 1
            ours = raw['m'].lower()
            if ours == expected['m'] or (ours, expected['m']) in EQUIVALENT or ours.split('.')[0] == expected['m'] \
                    or (ours == 'nop' and expected['m'] == 'xchg' and expected['ops'] == 'ax,ax'):
                counts['mnemonic_ok'] += 1
            else:
                mismatches[f"mnemonic {ours}~{expected['m']}"] += 1
            if expected['target'] and (raw.get('jump') or raw.get('call')) and not raw.get('computed'):
                counts['targets'] += 1
                if raw['targets'] and raw['targets'][0] == expected['target']:
                    counts['target_ok'] += 1
                else:
                    mismatches['target'] += 1
                    examples['target'].append((raw['a'], raw['targets'], expected['target']))
            ours_mem = next((o['mem'] for o in raw['ops'] if o.get('mem')), None)
            truth_mem = memory_operand(expected['ops'])
            if ours_mem and truth_mem and ours_mem.get('base') not in ('RIP',) and ours_mem.get('absolute') is None:
                counts['memory'] += 1
                if (ours_mem.get('base') or None) == truth_mem['base'] and ours_mem.get('disp', 0) == truth_mem['disp']:
                    counts['memory_ok'] += 1
                else:
                    mismatches['memory'] += 1
                    examples['memory'].append((raw['a'], raw['t'], expected['ops']))
            if raw['a'] in oracle:
                counts['relations'] += 1
                ours_rel = relation_of(record)
                want = oracle[raw['a']]
                if ours_rel is None:
                    mismatches['relation_missing'] += 1
                    examples['relation_missing'].append((raw['a'], raw['t'], (record['notes'] or [''])[0][:80]))
                elif ours_rel['operator'] == want['operator'] and ours_rel['signedness'] == want['signedness'] \
                        and ours_rel['setter'] == want['setter']:
                    counts['relation_ok'] += 1
                else:
                    mismatches['relation_wrong'] += 1
                    examples['relation_wrong'].append((raw['a'], raw['t'], ours_rel, want))
            elif record.get('branch') and record['branch'].get('relation', {}) and record['branch']['relation'].get('text'):
                counts['relations_beyond_oracle'] += 1
    rate = lambda ok, total: round(counts[ok] / counts[total], 4) if counts[total] else None
    return {'binary': binary.program_name, 'sha256': binary.sha256, 'counts': dict(counts),
            'rates': {'boundaries': rate('boundary_ok', 'instructions'), 'mnemonics': rate('mnemonic_ok', 'boundary_ok'),
                      'targets': rate('target_ok', 'targets'), 'memory': rate('memory_ok', 'memory'),
                      'relations': rate('relation_ok', 'relations')},
            'mismatches': dict(mismatches.most_common(20)),
            'examples': {k: v[:8] for k, v in examples.items()}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', default='demo_artifacts/m10/m10.sqlite')
    parser.add_argument('--output', type=Path, default=Path('docs/m10/eval_phase1.json'))
    parser.add_argument('binaries', nargs='+')
    args = parser.parse_args()
    report = []
    with _ReadOnlyRuleStore(args.database) as store:
        by_hash = {b.sha256: b for b in store.list_binaries()}
        import hashlib
        for path in args.binaries:
            digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            report.append(evaluate_phase1(store, by_hash[digest], path))
            print(json.dumps({k: report[-1][k] for k in ('binary', 'rates', 'mismatches')}, indent=None)[:1500])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1) + '\n')


if __name__ == '__main__':
    main()


# ---------------------------------------------------------------- Phase 2
def evaluate_phase2(store, binary, limit_functions=400):
    """Mutation testing of decompiler cross-validation. Ground truth is known by
    construction: positive mutations remove/add observable behaviour and must be
    flagged; benign mutations change only form and must not be flagged."""
    import dataclasses, random
    from aire.analysis.decompiler_crossval import DISCREPANCY, crossvalidate
    rng = random.Random(10)
    ai = AssemblyIntelligence(store, binary.binary_id)
    names = list(ai.function_names().values())
    outcomes = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(list)
    rows = store._db.execute('SELECT function_id FROM functions WHERE binary_id=? AND is_external=0 AND is_thunk=0 '
                             'AND decompiled_text IS NOT NULL ORDER BY address', (binary.binary_id,)).fetchall()
    for (fid,) in rows[:limit_functions]:
        record = ai.resolve(fid)
        document = ai.document(record)
        semantics = ai.semantics(record, document)
        context = ai.context(record, document)
        base = crossvalidate(record, document, semantics, context)
        if base['verdict'] != 'CONSISTENT':
            continue
        text = record.decompiled_text
        lines = text.splitlines()
        brace = next((i for i, l in enumerate(lines) if '{' in l), 0)
        calls = [f for f in base['findings'] if f['check'] == 'call_targets'][0]['evidence']
        strings = [e for f in base['findings'] if f['check'] == 'string_references' for e in f['evidence']]
        branches = [r for r in semantics if r['category'] == 'branch_conditional']
        mutations = {}
        hit = [e for e in calls if e['decompiled_lines']]
        if hit:
            target = hit[0]
            drop = set(target['decompiled_lines'])
            mutations['remove_call'] = '\n'.join(l for n, l in enumerate(lines, 1) if n not in drop or n <= brace + 1)
        literal = next((e for e in strings if e.get('decompiled_line')), None)
        if literal:
            mutations['remove_string'] = '\n'.join(l for n, l in enumerate(lines, 1) if n != literal['decompiled_line'])
        if branches or hit or strings:
            mutations['empty_body'] = '\n'.join(lines[:brace]) + '\n{\n  return;\n}\n'
        uncalled = [n for n in names if n not in text and not n.startswith(('EXTERNAL', '_'))]
        if uncalled and not any(r['category'] == 'call' and r['call'].get('indirect') for r in semantics):
            phantom = rng.choice(uncalled)
            mutations['add_phantom_call'] = text.replace('{', '{\n  ' + phantom + '();', 1)
        locals_ = sorted(set(re.findall(r'\b[a-z]Var\d+\b|\blocal_[0-9a-f]+\b', text)))
        benign = {'rename_locals': text, 'reformat_strip_comments': re.sub(r'/\*.*?\*/', '', text, flags=re.S)
                  .replace('  ', '    '),
                  'constant_base': re.sub(r'\b0x([0-9a-f]+)\b', lambda m: str(int(m.group(1), 16)), text, count=3)}
        for i, name in enumerate(locals_):
            benign['rename_locals'] = re.sub(r'\b' + name + r'\b', f'value_{i}', benign['rename_locals'])
        for kind, mutated in mutations.items():
            result = crossvalidate(dataclasses.replace(record, decompiled_text=mutated), document, semantics, context)
            ok = result['verdict'] == DISCREPANCY
            outcomes['positive:' + kind]['detected' if ok else 'missed'] += 1
            if not ok and len(examples[kind]) < 3:
                examples[kind].append(record.current_name)
        for kind, mutated in benign.items():
            result = crossvalidate(dataclasses.replace(record, decompiled_text=mutated), document, semantics, context)
            ok = result['verdict'] != DISCREPANCY
            outcomes['benign:' + kind]['not_flagged' if ok else 'false_alarm'] += 1
            if not ok and len(examples[kind]) < 3:
                examples[kind].append((record.current_name, [f['summary'][:100] for f in result['findings']
                                                             if f['status'] == DISCREPANCY]))
    return {'binary': binary.program_name, 'outcomes': {k: dict(v) for k, v in outcomes.items()},
            'examples': dict(examples)}


if __name__ == '__main__' and '--phase2' in sys.argv:
    pass
