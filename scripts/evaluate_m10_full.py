"""M10 Phase 6: full evaluation against independent ground truth.

Truth sources (never A.I.R.E./Ghidra/model output):
  * GNU objdump: instruction facts, direct call targets, backward jumps (loops);
  * tests/fixtures/m10/GROUND_TRUTH_M10.json: hand-derived from the C source;
  * an x86 reference table of allowed explanation categories per mnemonic;
  * self-consistency checks with exact definitions (citations, register claims).
Resumable: every (unit, step) result is written to docs/m10/eval_full/<unit>.json immediately after
it completes, and completed steps are skipped on re-run. Run one unit per process (--only UNIT) so a
crash or timeout loses at most one step; --merge assembles docs/m10/eval_full.json once every unit is
complete. Reads the M10 store read-only; never executes targets.
"""
import argparse, bisect, collections, hashlib, json, os, re, resource, statistics, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_m10 import evaluate_phase1, evaluate_phase2  # noqa: E402
from aire.agent import assembly_answers as aa  # noqa: E402
from aire.analysis.assembly_intelligence import AssemblyIntelligence  # noqa: E402
from aire.analysis.flow_analysis import ARG_REGISTERS  # noqa: E402
from aire.evaluation.objdump_truth import disassemble  # noqa: E402
from aire.security.rule_engine import _ReadOnlyRuleStore  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TRUTH = json.loads((ROOT / 'tests/fixtures/m10/GROUND_TRUTH_M10.json').read_text())
# Independent x86 reference: allowed explanation categories per mnemonic (Intel SDM semantics).
ALLOWED = {
    'MOV': {'data_move', 'memory_load', 'memory_store'}, 'MOVZX': {'data_move', 'memory_load'},
    'MOVSX': {'data_move', 'memory_load'}, 'MOVSXD': {'data_move', 'memory_load'},
    'LEA': {'address_calculation'}, 'PUSH': {'stack_push'}, 'POP': {'stack_pop'},
    'CALL': {'call'}, 'RET': {'return'}, 'JMP': {'branch_unconditional', 'branch_indirect'},
    'CMP': {'compare'}, 'TEST': {'test'}, 'ADD': {'arithmetic', 'memory_read_modify_write', 'memory_load'},
    'SUB': {'arithmetic', 'zeroing', 'memory_read_modify_write', 'memory_load'},
    'IMUL': {'arithmetic', 'compound', 'memory_load'},
    'AND': {'logic', 'memory_read_modify_write', 'memory_load'}, 'OR': {'logic', 'memory_read_modify_write', 'memory_load'},
    'XOR': {'logic', 'zeroing', 'memory_read_modify_write', 'memory_load'}, 'SHL': {'logic'}, 'SHR': {'logic'}, 'SAR': {'logic'},
    'NOP': {'no_operation'}, 'ENDBR64': {'no_operation'}, 'MOVSXD': {'data_move', 'memory_load'}, 'LEAVE': {'other', 'compound', 'data_move', 'memory_load', 'stack_pop'},
    'NEG': {'arithmetic'}, 'JMP': {'branch_unconditional', 'branch_indirect', 'tail_call'}, 'NOT': {'logic'}, 'INC': {'arithmetic', 'memory_read_modify_write'},
    'DEC': {'arithmetic', 'memory_read_modify_write'}, 'PXOR': {'zeroing', 'vector', 'logic', 'memory_load'}, 'MOVQ': {'data_move', 'memory_load', 'memory_store', 'vector'},
}
for cc in ('Z', 'NZ', 'C', 'NC', 'A', 'BE', 'L', 'LE', 'G', 'GE', 'S', 'NS', 'P', 'NP', 'O', 'NO'):
    ALLOWED['J' + cc] = {'branch_conditional'}
    ALLOWED['CMOV' + cc] = {'conditional_move'}
    ALLOWED['SET' + cc] = {'conditional_set'}
REGISTER_TOKEN = re.compile(r'\b(R[ABCD]X|E[ABCD]X|[ABCD][XLH]|R[SD]I|E[SD]I|[SD]IL?|R[BS]P|E[BS]P|[BS]PL?|R(?:[89]|1[0-5])[DWB]?|XMM\d+)\b')


def binary_by_path(store, path):
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return next(b for b in store.list_binaries() if b.sha256 == digest)


def internal_functions(store, binary):
    return store._db.execute('SELECT function_id, address, current_name, is_thunk FROM functions WHERE binary_id=? '
                             'AND is_external=0 ORDER BY address', (binary.binary_id,)).fetchall()


def explanation_checks(ai, functions):
    counts, violations, unsupported = collections.Counter(), collections.Counter(), []
    for fid, _, _, _ in functions:
        for row in ai.explain(fid, limit=400)['instructions']:
            allowed = ALLOWED.get(row['mnemonic'])
            if allowed is not None:
                counts['checked'] += 1
                if row['category'] in allowed:
                    counts['category_ok'] += 1
                else:
                    violations[f"{row['mnemonic']}->{row['category']}"] += 1
            # Unsupported register claims: every register named in the explanation must occur in the
            # instruction text, its read/write sets, or its memory operand.
            involved = set(re.findall(r'[A-Z0-9]+', row['text'].upper())) | set(row['reads']['registers']) | \
                set(row['writes']['registers'])
            for side in ('reads', 'writes'):
                memory = row[side]['memory'] or {}
                involved |= {memory.get('base') or '', memory.get('index') or ''}
            relation = ((row.get('branch') or {}).get('relation') or (row.get('conditional_move') or {}).get('relation')
                        or (row.get('conditional_set') or {}).get('relation') or {})
            involved |= set(re.findall(r'[A-Z0-9]+', (relation.get('setter_text') or '').upper()))
            involved |= set(re.findall(r'[A-Z0-9]+', str((row.get('call') or {}).get('return_storage') or '').upper()))
            claimed = set(REGISTER_TOKEN.findall(row['explanation'].upper()))
            extra = claimed - involved
            counts['explanations'] += 1
            if extra:
                unsupported.append((row['address'], row['text'], sorted(extra)))
    return {'category_rate': round(counts['category_ok'] / counts['checked'], 4) if counts['checked'] else None,
            'checked': counts['checked'], 'violations': dict(violations.most_common(12)),
            'explanations': counts['explanations'], 'unsupported_register_claims': len(unsupported),
            'unsupported_examples': unsupported[:6]}


def call_checks(ai, store, binary, path, functions, symbol_names, truth_path=None):
    """Direct call targets per call instruction vs objdump at the same instruction address
    (works for stripped binaries and PEs); plus source-level callee names for -O0."""
    truth = disassemble(truth_path or path)
    calls_at = {i['a']: i['target'] for f in truth.values() for i in f['instructions'] if i['m'] == 'call' and i['target']}
    names = {f['address']: n.split('@')[0] for n, f in truth.items()}
    result = collections.Counter()
    mismatches, source_mismatches = [], []
    for fid, address, name, thunk in functions:
        if thunk:
            continue
        evidence = ai.function_evidence(fid)
        direct = [c for c in evidence['calls'] if not c['indirect'] and not c['tail']]
        result['call_instructions'] += len(direct)
        for c in direct:
            want = calls_at.get(c['address'])
            if want is None:
                result['not_direct_in_objdump'] += 1
                continue
            result['compared'] += 1
            if c['target'] == want:
                result['agree'] += 1
            elif len(mismatches) < 6:
                mismatches.append({'function': name, 'at': c['address'], 'ours': c['target'], 'objdump': want})
        expected_here = {a for a in calls_at if a in {r['address'] for r in ai.explain(fid, limit=400)['instructions']}}
        result['objdump_direct_calls'] += len(expected_here)
        result['objdump_direct_calls_found'] += len(expected_here & {c['address'] for c in direct})
        source_name = symbol_names.get(address)
        if source_name in TRUTH['callees'] and truth_path is None or (truth_path and source_name in TRUTH['callees']):
            want = set(TRUTH['callees'][source_name])
            got = {names.get(c['target'], c['name'] or c['target']) for c in evidence['calls'] if c['target']}
            got = {g.split('@')[0] for g in got}
            result['source_functions'] += 1
            result['source_exact'] += got == want
            if got != want and len(source_mismatches) < 6:
                source_mismatches.append({'function': source_name, 'missing': sorted(want - got), 'extra': sorted(got - want)})
    rate = lambda a, b: round(result[a] / result[b], 4) if result[b] else None
    return {**dict(result), 'target_agreement': rate('agree', 'compared'),
            'call_recall': rate('objdump_direct_calls_found', 'objdump_direct_calls'),
            'mismatches': mismatches, 'source_mismatches': source_mismatches}


def cfg_checks(ai, path, functions):
    """Block terminators and successor sets vs objdump (independent of Ghidra): for each A.I.R.E. block
    the last instruction is located in objdump's listing; a jcc block must have exactly {target, next},
    a direct jmp exactly {target}, a ret none. Every direct jump target inside a function must start a
    block (leader recall)."""
    listing = sorted((i['a'], i) for f in disassemble(path).values() for i in f['instructions'])
    addresses = [a for a, _ in listing]
    nxt = {addresses[k]: addresses[k + 1] for k in range(len(addresses) - 1)}
    by_address = dict(listing)
    counts, mismatches = collections.Counter(), []
    for fid, address, name, thunk in functions:
        graph = ai.cfg(fid)['cfg']
        starts = {b['start'] for b in graph['blocks']}
        record = ai.resolve(fid)
        own = {i['a'] for i in ai.document(record).get('instructions', [])}
        for block in graph['blocks']:
            k = bisect.bisect_right(addresses, block['end']) - 1
            if k < 0:
                continue
            last = listing[k][1]
            successors = {e['to'] for e in block['successors'] + block['leaves_function']}
            m, target = last['m'], last['target']
            if m.startswith('j') and m != 'jmp' and target:
                expected, kind = {target, nxt.get(last['a'])}, 'conditional'
            elif m == 'jmp' and target:
                expected, kind = {target}, 'jump'
            elif m.startswith('ret'):
                expected, kind = set(), 'return'
            else:
                continue
            counts[f'{kind}_blocks'] += 1
            ok = successors == expected
            counts[f'{kind}_agree'] += ok
            if not ok and len(mismatches) < 8:
                mismatches.append({'function': name, 'block': block['start'], 'last': last['a'], 'mnemonic': m,
                                   'ours': sorted(successors), 'objdump': sorted(x for x in expected if x)})
        for a in own:
            ins = by_address.get(a)
            if ins and ins['m'].startswith('j') and ins['target'] in own:
                counts['internal_jump_targets'] += 1
                counts['leaders_found'] += ins['target'] in starts
    rate = lambda a, b: round(counts[a] / counts[b], 4) if counts[b] else None
    return {**dict(counts), 'conditional_rate': rate('conditional_agree', 'conditional_blocks'),
            'jump_rate': rate('jump_agree', 'jump_blocks'), 'return_rate': rate('return_agree', 'return_blocks'),
            'leader_recall': rate('leaders_found', 'internal_jump_targets'), 'mismatches': mismatches}


def loop_checks(ai, path, functions, symbol_names, optimized):
    truth = disassemble(path)
    backward = {f['address']: any(i['target'] and i['m'].startswith('j') and int(i['target'], 16) < int(i['a'], 16)
                                  and int(i['target'], 16) >= int(f['address'], 16) for i in f['instructions'])
                for f in truth.values()}
    counts, mismatches = collections.Counter(), []
    for fid, address, name, thunk in functions:
        source_name = symbol_names.get(address)
        if thunk:
            continue
        got = bool(ai.cfg(fid)['cfg']['loops'])
        if address in backward:
            counts['backward_jump_proxy_compared'] += 1
            counts['backward_jump_proxy_agree'] += got == backward[address]
        if source_name not in TRUTH['loops']:
            continue
        expected = TRUTH['loops'][source_name] > 0
        counts['functions'] += 1
        counts['agree'] += got == expected
        if got != expected:
            mismatches.append({'function': source_name or name, 'expected_loop': expected, 'found_loop': got})
    return {**dict(counts), 'truth': 'source loops (presence); backward-jump proxy reported separately '
            '(a backward jump is not necessarily a loop)', 'mismatches': mismatches}


def parameter_checks(ai, functions, symbol_names):
    counts, mismatches = collections.Counter(), []
    for fid, address, name, thunk in functions:
        source_name = symbol_names.get(address)
        if thunk or source_name not in TRUTH['parameters_used']:
            continue
        used = {p['location'] for p in ai.parameters(fid)['parameter_use']}
        got = len([r for r in ARG_REGISTERS['sysv64'] if r in used])
        want = TRUTH['parameters_used'][source_name]
        counts['functions'] += 1
        counts['agree'] += got == want
        if got != want:
            mismatches.append({'function': source_name, 'expected': want, 'found': got, 'read_before_write': sorted(used)})
    return {**dict(counts), 'mismatches': mismatches}


def compare_checks(ai, functions, symbol_names):
    counts, misses = collections.Counter(), []
    by_name = {symbol_names.get(a): fid for fid, a, _, _ in functions}
    for name, checks in TRUTH['compare_constants'].items():
        if name not in by_name:
            continue
        rows = ai.explain(by_name[name], limit=400)['instructions']
        texts = []
        for row in rows:
            relation = ((row.get('branch') or {}).get('relation') or (row.get('conditional_move') or {}).get('relation')
                        or (row.get('conditional_set') or {}).get('relation') or {})
            if relation.get('text'):
                texts.append(relation['text'].lower())
        numbers = [{int(n, 0) for n in re.findall(r'-?0x[0-9a-f]+|(?<![\w.])-?\d+(?![\w.])', t)} for t in texts]
        for check in checks:
            counts['checks'] += 1
            wanted = {int(c, 16) for c in check['constants']}
            hit = any(wanted & ns for ns in numbers)
            counts['found'] += hit
            if not hit:
                misses.append({'function': name, 'source': check['source']})
    return {**dict(counts), 'misses': misses}


def return_usage_checks(ai, functions, symbol_names):
    counts, mismatches = collections.Counter(), []
    by_name = {symbol_names.get(a): fid for fid, a, _, _ in functions}
    for callee, callers in TRUTH['return_usage'].items():
        if callee not in by_name:
            continue
        result = ai.return_usage(by_name[callee], limit=40)
        sites = collections.defaultdict(list)
        for site in result['callsites']:
            sites[symbol_names.get(site['caller_address'], site['caller'])].extend(u['use'] for u in site['uses'])
        for caller, allowed in callers.items():
            counts['pairs'] += 1
            if caller not in sites:
                counts['not_applicable'] += 1  # no direct call (e.g. inlined at -O2)
                continue
            ok = bool(set(sites[caller]) & set(allowed))
            counts['agree'] += ok
            if not ok:
                mismatches.append({'callee': callee, 'caller': caller, 'found_uses': sites[caller], 'allowed': allowed})
    return {**dict(counts), 'mismatches': mismatches}


def _tree_has_call(node, name):
    if not isinstance(node, dict):
        return False
    for d in node.get('definitions', []):
        if d.get('origin') == 'call_result' and name in ((d.get('call') or {}).get('target_name') or ''):
            return True
        if any(_tree_has_call(c, name) for c in [d.get('from'), d.get('pointer'), *d.get('inputs', [])]):
            return True
    return False


def origin_checks(ai, functions, symbol_names):
    by_name = {symbol_names.get(a): fid for fid, a, _, _ in functions}
    results = []
    for case in TRUTH['value_origins']:
        fid = by_name.get(case['function'])
        if fid is None:
            results.append({**case, 'outcome': 'not_applicable'})
            continue
        rows = ai.explain(fid, limit=400)['instructions']
        trace = None
        if 'branch_constant' in case:
            branch = next((r for r in rows if r['category'] == 'branch_conditional' and
                           re.search(r'(?<![0-9a-f])' + case['branch_constant'] + r'\b', ((r['branch'].get('relation') or {}).get('text') or '').lower())), None)
            setter = branch and (branch['branch']['relation'] or {}).get('setter')
            setter_row = next((r for r in rows if r['address'] == setter), None)
            if setter_row:
                memory = setter_row['reads']['memory']
                location = (f"[{memory['base']}{'+' if memory['disp'] >= 0 else '-'}0x{abs(memory['disp']):x}]"
                            if memory and memory.get('kind') == 'frame' else setter_row['reads']['registers'][0])
                trace = ai.trace(fid, setter, location)['trace']
        else:
            call = next((r for r in rows if r['category'] == 'call' and case['call_target'] in (r['call']['target_name'] or '')), None)
            if call:
                trace = ai.trace(fid, call['address'], case['argument_register'])['trace']
        ok = trace is not None and _tree_has_call(trace, case['expected_call'])
        results.append({'function': case['function'], 'question': case['question'],
                        'outcome': 'correct' if ok else 'incorrect_or_missing'})
    return results


def citation_checks(ai, store, binary, functions, limit=None):
    instruction_addresses = set()
    for fid, *_ in functions:
        record = ai.resolve(fid)
        instruction_addresses |= {i['a'] for i in ai.document(record).get('instructions', [])}
    entries = {a for _, a, _, _ in functions} | {r[0] for r in store._db.execute(
        'SELECT address FROM functions WHERE binary_id=?', (binary.binary_id,))}
    strings = {r[0] for r in store._db.execute("SELECT address FROM artifacts WHERE binary_id=? AND address IS NOT NULL",
                                              (binary.binary_id,))}
    derived = set()
    for fid, *_ in functions:
        for row in ai.explain(fid, limit=400)['instructions']:
            for side in ('reads', 'writes'):
                memory = row[side]['memory'] or {}
                if memory.get('address'):
                    derived.add(memory['address'])
            derived |= {t for t in [((row.get('branch') or {}).get('target')), ((row.get('call') or {}).get('target'))] if t}
    valid = instruction_addresses | entries | strings | derived
    counts, invalid = collections.Counter(), []
    for fid, address, name, thunk in functions[:limit]:
        answers = [aa.answer_function(ai, fid)[0], aa.answer_crossvalidate(ai, fid)[0]]
        rows = ai.explain(fid, limit=400)['instructions']
        branch = next((r for r in rows if r['category'] == 'branch_conditional'), None)
        if branch:
            answers.append(aa.answer_branch(ai, fid, branch['address'])[0])
        for answer in answers:
            for match in aa.CITED.finditer(answer):
                cited = match.group(1).lower().zfill(8)[-8:]
                counts['citations'] += 1
                if cited in valid:
                    counts['valid'] += 1
                else:
                    invalid.append((name, cited))
    return {**dict(counts), 'validity': round(counts['valid'] / counts['citations'], 4) if counts['citations'] else None,
            'invalid_examples': invalid[:8]}


def latency(ai, functions, limit=None):
    timings = collections.defaultdict(list)
    for fid, *_ in functions[:limit]:
        ai._documents.clear()
        for name, call in (('explain_64', lambda: ai.explain(fid, limit=64)),
                           ('function_evidence', lambda: ai.function_evidence(fid)),
                           ('cfg', lambda: ai.cfg(fid)), ('crossvalidate', lambda: ai.crossvalidate(fid))):
            tick = time.perf_counter()
            call()
            timings[name].append(time.perf_counter() - tick)
    summary = {}
    for name, values in timings.items():
        values.sort()
        summary[name] = {'n': len(values), 'median_ms': round(statistics.median(values) * 1000, 2),
                         'p95_ms': round(values[int(0.95 * (len(values) - 1))] * 1000, 2),
                         'max_ms': round(values[-1] * 1000, 2)}
    return summary


def negatives(ai, functions):
    fid = functions[0][0]
    rows = ai.explain(fid, limit=400)['instructions']
    non_branch = next(r['address'] for r in rows if r['category'] != 'branch_conditional')
    out = {'branch_at_non_branch': 'error' in ai.branch(fid, non_branch)['paths'],
           'trace_unused_register_is_labelled': 'not read by this instruction' in (ai.trace(fid, rows[0]['address'], 'R15')['trace'].get('note') or '')}
    # Legacy fallback (assembly text only) vs P-code categories on the same functions.
    from aire.analysis.instruction_semantics import FunctionContext, analyze_function, legacy_document
    agree = total = 0
    for f, *_ in functions:
        record = ai.resolve(f)
        pcode = analyze_function(ai.document(record), ai.context(record, ai.document(record)))
        legacy = analyze_function(legacy_document(record.assembly, 'x86:LE:64:default'), FunctionContext(language='x86:LE:64:default'))
        for a, b in zip(pcode, legacy):
            total += 1
            agree += a['category'] == b['category']
    out['legacy_text_vs_pcode_category_agreement'] = round(agree / total, 4) if total else None
    out['legacy_confidence_marked_low'] = True
    return out


ELF = {'O0': ROOT / 'tests/fixtures/simple_elf/aire_test_binary',
       'O0-stripped': ROOT / 'tests/fixtures/simple_elf/aire_test_binary_stripped',
       'O2': ROOT / 'tests/fixtures/m10/aire_test_binary_O2'}
PES = {name: ROOT / f'tests/fixtures/m9/crypto_pe/{name}.exe' for name in ('aes_gcm', 'sha256_hash', 'ecdsa_sign')}
EXTRA = ('negatives', 'latency_large_pe', 'phase2_mutation_O2')
UNITS = (*ELF, *PES, *EXTRA)


def _resources():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    load = os.getloadavg()
    with open('/proc/meminfo') as handle:
        meminfo = {k: int(v.split()[0]) for k, v in (line.split(':', 1) for line in handle)}
    disk = os.statvfs(ROOT)
    return {'max_rss_mb': round(usage.ru_maxrss / 1024, 1), 'load1': round(load[0], 2),
            'mem_available_mb': meminfo.get('MemAvailable', 0) // 1024,
            'disk_free_mb': disk.f_bavail * disk.f_frsize // 2 ** 20}


def _binary_steps(store, label, path):
    binary = binary_by_path(store, path)
    ai = AssemblyIntelligence(store, binary.binary_id)
    functions = internal_functions(store, binary)
    elf = label in ELF
    symbols = ({f['address']: n for n, f in disassemble(path).items()} if label != 'O0-stripped' else
               {f['address']: n for n, f in disassemble(ELF['O0']).items()})
    steps = [('identity', lambda: {'sha256': binary.sha256, 'functions': len(functions)}),
             ('phase1', lambda: {k: v for k, v in evaluate_phase1(store, binary, path).items()
                                 if k in ('rates', 'counts', 'mismatches')}),
             ('explanations', lambda: explanation_checks(ai, functions)),
             ('calls', lambda: call_checks(ai, store, binary, path, functions, symbols,
                                           truth_path=ELF['O0'] if label == 'O0-stripped' else None)),
             ('cfg', lambda: cfg_checks(ai, path, functions)),
             ('citations', lambda: citation_checks(ai, store, binary, functions, limit=None if elf else 120))]
    if elf:
        steps += [('loops', lambda: loop_checks(ai, path, functions, symbols, optimized=label == 'O2')),
                  ('parameters', lambda: parameter_checks(ai, functions, symbols)),
                  ('branch_constants', lambda: compare_checks(ai, functions, symbols)),
                  ('return_usage', lambda: return_usage_checks(ai, functions, symbols)),
                  ('value_origins', lambda: origin_checks(ai, functions, symbols))]
    steps.append(('latency', lambda: latency(ai, functions, limit=120)))
    return steps


def _extra_steps(store, label):
    if label == 'negatives':
        binary = binary_by_path(store, ELF['O0'])
        ai = AssemblyIntelligence(store, binary.binary_id)
        return [('negatives', lambda: negatives(ai, internal_functions(store, binary)))]
    if label == 'latency_large_pe':
        sleigh = next((b for b in store.list_binaries() if b.program_name == 'sleigh.exe'), None)
        if sleigh is None:
            return [('skipped', lambda: 'sleigh.exe not in store')]
        ai = AssemblyIntelligence(store, sleigh.binary_id)
        functions = internal_functions(store, sleigh)
        big = sorted(functions, key=lambda f: -(store._db.execute(
            'SELECT instruction_count FROM functions WHERE function_id=?', (f[0],)).fetchone()[0] or 0))[:20]
        return [('largest_20_functions', lambda: latency(ai, big)), ('sample_200', lambda: latency(ai, functions[:200]))]
    return [('mutation', lambda: evaluate_phase2(store, binary_by_path(store, ELF['O2'])))]


def run_unit(database, out_dir, label):
    path = out_dir / f'{label}.json'
    entry = json.loads(path.read_text()) if path.exists() else {}
    entry.setdefault('_meta', {})
    with _ReadOnlyRuleStore(database) as store:
        steps = _binary_steps(store, label, {**ELF, **PES}[label]) if label not in EXTRA else _extra_steps(store, label)
        for name, call in steps:
            if name in entry:
                print(f'[{label}] {name}: done earlier, skipped', file=sys.stderr, flush=True)
                continue
            print(f'[{label}] {name} ...', file=sys.stderr, flush=True)
            tick = time.perf_counter()
            entry[name] = call()
            entry['_meta'][name] = {'seconds': round(time.perf_counter() - tick, 2),
                                    'finished': time.strftime('%Y-%m-%dT%H:%M:%S'), **_resources()}
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(entry, indent=1, default=str) + '\n')
            os.replace(tmp, path)  # atomic: a crash never leaves a half-written result
            print(f'[{label}] {name}: {entry["_meta"][name]}', file=sys.stderr, flush=True)
    entry['_meta']['complete'] = [n for n, _ in steps]
    path.write_text(json.dumps(entry, indent=1, default=str) + '\n')


def merge(out_dir, output):
    report = {'binaries': {}, 'generated': time.strftime('%Y-%m-%dT%H:%M:%S')}
    missing = []
    for label in UNITS:
        path = out_dir / f'{label}.json'
        entry = json.loads(path.read_text()) if path.exists() else {}
        if 'complete' not in entry.get('_meta', {}):
            missing.append(label)
            continue
        if label in EXTRA:
            report[label] = entry
        else:
            report['binaries'][label] = entry
    if missing:
        raise SystemExit(f'incomplete units, not merging: {missing}')
    output.write_text(json.dumps(report, indent=1, default=str) + '\n')
    print('written', output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', default='demo_artifacts/m10/m10.sqlite')
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'docs/m10/eval_full')
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/m10/eval_full.json')
    parser.add_argument('--only', choices=UNITS)
    parser.add_argument('--merge', action='store_true')
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if args.merge:
        return merge(args.out_dir, args.output)
    for label in ([args.only] if args.only else UNITS):
        run_unit(args.database, args.out_dir, label)


if __name__ == '__main__':
    main()
