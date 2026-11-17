"""M10 Phase 2: cross-validate Ghidra's decompiled C against assembly/P-code facts.

Each check yields one of
  CONSISTENT            the observable facts agree;
  POTENTIAL DISCREPANCY the assembly contains an observable fact (a call, a
                        string reference, a branch, a returned value) that the
                        decompiled text does not account for, or vice versa,
                        and no recognized decompiler transformation explains it;
  INSUFFICIENT EVIDENCE equivalence cannot be decided from the available facts
                        (e.g. constants folded or rewritten by compiler/decompiler).
Different-but-equivalent forms are never reported as discrepancies. Ghidra's own
decompiler warnings (injection, unreachable-block removal, bad data) downgrade
affected findings to INSUFFICIENT EVIDENCE. No model is involved.
"""
import re

CONSISTENT, DISCREPANCY, INSUFFICIENT = 'CONSISTENT', 'POTENTIAL DISCREPANCY', 'INSUFFICIENT EVIDENCE'
CROSSVAL_VERSION = 'decompiler-crossval-v1'
C_KEYWORDS = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'do', 'else', 'case', 'goto', 'break',
              'continue', 'default'}
CAST_TYPES = re.compile(r'^(?:u?int\d*|u?char|u?short|u?long|longlong|ulonglong|undefined\d*|byte|word|dword|qword|'
                        r'bool|float|double|float10|void|code|size_t|ssize_t)$')
CALL = re.compile(r'(?<![\w.>])([A-Za-z_][\w:]*)\s*\(')
NUMBER = re.compile(r'(?<![\w.])(-?0x[0-9a-fA-F]+|-?\d+)(?:[uUlL]*)(?![\w.])')
STRING_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')
TRIVIAL_CONSTANTS = {0, 1, -1}
CORE_CHECKS = ('call_targets', 'string_references', 'control_flow', 'return_value')
RETURN_REGISTERS = {'RAX', 'EAX', 'AX', 'AL', 'XMM0', 'ST0', 'EDX', 'RDX'}


def _code_lines(text):
    """Decompiled lines with comments removed (line numbers kept, 1-based)."""
    cleaned = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), text or '', flags=re.S)
    return [(number, re.sub(r'//.*$', '', line)) for number, line in enumerate(cleaned.splitlines(), 1)]


def _decompiler_warnings(text):
    return [w.strip() for w in re.findall(r'/\*\s*WARNING:\s*(.*?)\*/', text or '', flags=re.S)]


def _body_lines(lines, name):
    """Skip the signature: everything after the first '{'."""
    for index, (_, line) in enumerate(lines):
        if '{' in line:
            return lines[index:]
    return lines


def _short(name):
    return name.rsplit('::', 1)[-1] if name else name


def _finding(check, status, summary, evidence=None, notes=None):
    return {'check': check, 'status': status, 'summary': summary, 'evidence': evidence or [], 'notes': notes or []}


def crossvalidate(record, document, semantics, context, crosscheck=None):
    """record: FunctionRecord; document: instruction facts; semantics: analyze_function
    output for the whole function; context: FunctionContext; crosscheck: optional
    M9 function_crosscheck report for arithmetic agreement."""
    text = record.decompiled_text
    header = {'function_id': record.function_id, 'name': record.current_name, 'address': record.address,
              'policy': CROSSVAL_VERSION, 'evidence_source': 'ghidra_pcode' if document.get('source') == 'ghidra'
              else 'assembly_text'}
    if not text:
        return {**header, 'verdict': INSUFFICIENT, 'findings': [_finding(
            'decompiled_text', INSUFFICIENT, 'No decompiled text is stored for this function '
            '(decompilation incomplete or disabled); nothing to cross-validate.')], 'decompiler_warnings': []}
    if document.get('truncated'):
        truncated_note = ['Instruction facts are truncated for this very large function; checks cover the stored prefix.']
    else:
        truncated_note = []
    warnings = _decompiler_warnings(text)
    lines = _code_lines(text)
    body = _body_lines(lines, record.current_name)
    body_text = '\n'.join(line for _, line in body)
    if record.is_thunk:
        note = ('Ghidra decompiles a thunk as the body of its target function, so the thunk\'s own jump cannot be '
                'compared with that text; cross-validate the target function instead.')
        return {**header, 'verdict': INSUFFICIENT, 'decompiler_warnings': warnings,
                'findings': [_finding('thunk', INSUFFICIENT, note)],
                'counts': {CONSISTENT: 0, DISCREPANCY: 0, INSUFFICIENT: 1}}
    findings = [
        _calls(record, semantics, context, body, warnings),
        _strings(semantics, body, text),
        _control_flow(document, semantics, body),
        _returns(document, semantics, body),
        _constants(semantics, body_text),
        _globals(semantics, body_text),
    ]
    if crosscheck is not None:
        findings.append(_arithmetic(crosscheck))
    if any(w for w in warnings if re.search(r'unreachable|bad instruction|jumptable|could not recover', w, re.I)):
        for finding in findings:
            if finding['status'] == DISCREPANCY:
                finding['status'] = INSUFFICIENT
                finding['notes'].append('Downgraded: Ghidra reported a decompiler limitation for this function '
                                        '(see decompiler_warnings).')
    for finding in findings:
        finding['notes'].extend(truncated_note)
    statuses = {f['status'] for f in findings}
    core = {f['status'] for f in findings if f['check'] in CORE_CHECKS}
    verdict = DISCREPANCY if DISCREPANCY in statuses else CONSISTENT if core == {CONSISTENT} else INSUFFICIENT
    return {**header, 'verdict': verdict, 'verdict_basis': (
                'Core checks (calls, string references, control flow, return value) decide CONSISTENT; any check can '
                'raise a POTENTIAL DISCREPANCY; constants, global data and arithmetic are supporting evidence.'),
            'findings': findings, 'decompiler_warnings': warnings,
            'counts': {s: sum(f['status'] == s for f in findings) for s in (CONSISTENT, DISCREPANCY, INSUFFICIENT)}}


def _decompiled_calls(body, own_name):
    calls = {}
    for number, line in body:
        for match in CALL.finditer(line):
            name = match.group(1)
            if name in C_KEYWORDS or CAST_TYPES.match(name) or name == own_name:
                continue
            calls.setdefault(name, []).append(number)
    return calls


def _calls(record, semantics, context, body, warnings):
    expected, indirect = {}, set()
    unresolved = []
    for row in semantics:
        if row['category'] in ('call', 'tail_call'):
            call = row['call']
            if call.get('indirect'):
                indirect.add(_short(call.get('target_name')) or (f"FUN_{call['target']}" if call.get('target') else None))
            name = _short(call.get('target_name')) or (f"FUN_{call['target']}" if call.get('target') else None)
            if name:
                expected.setdefault(name, []).append(row['address'])
            else:
                unresolved.append(row['address'])
        elif row['category'] == 'branch_unconditional' and row['branch'] and row['branch']['target'] in context.function_names:
            target = row['branch']['target']
            expected.setdefault(context.function_names[target], []).append(row['address'])  # tail call
    seen = _decompiled_calls(body, record.current_name)
    body_text = '\n'.join(line for _, line in body)
    for name in expected:
        pointer = re.search(r'\bPTR_' + re.escape(_short(name)) + r'_[0-9a-fA-F]+', body_text)
        if pointer and not any(_matches(name, s) for s in seen):
            lines = [n for n, line in body if pointer.group(0) in line]
            seen[pointer.group(0)] = lines  # indirect call through the import/GOT pointer
    injected = {name for w in warnings for name in re.findall(r'Function:\s*([\w:]+)\s+replaced with injection', w)}
    indirect_in_c = re.findall(r'\(\*+\s*\(?\s*code\s*\*+', body_text)
    missing = {n: a for n, a in expected.items() if not any(_matches(n, s) for s in seen) and n not in injected
               and not (n in indirect and indirect_in_c)}
    if any(n in indirect for n in expected) and indirect_in_c:
        notes_indirect = ['Indirect assembly calls (resolved by Ghidra to a target) are matched to indirect call '
                          'expressions in the decompiled text; the exact pointer equivalence is not proven.']
    else:
        notes_indirect = []
    explained = {n: a for n, a in expected.items() if n in injected}
    extra = {s: l for s, l in seen.items() if not any(_matches(n, s) for n in expected) and not s.startswith('(')}
    evidence = [{'name': n, 'instruction_addresses': a,
                 'decompiled_lines': next((seen[s] for s in seen if _matches(n, s)), [])} for n, a in expected.items()]
    notes = list(notes_indirect)
    if explained:
        notes.append('Calls replaced by Ghidra call-fixup injection (not shown as calls): ' + ', '.join(sorted(explained)))
    if unresolved:
        notes.append(f'{len(unresolved)} indirect call(s) without a resolved target: '
                     + ', '.join('0x' + a for a in unresolved[:6]))
    if missing:
        return _finding('call_targets', DISCREPANCY,
                        f"{len(missing)} call target(s) present in the assembly are not called in the decompiled text: "
                        + ', '.join(f"{n} (at {', '.join('0x' + a for a in addrs[:3])})" for n, addrs in missing.items()),
                        evidence, notes)
    known = set(context.function_names.values())
    phantom = {s: l for s, l in extra.items() if s in known and not indirect and not unresolved}
    if phantom:
        return _finding('call_targets', DISCREPANCY,
                        f'The decompiled text calls {len(phantom)} function(s) of this binary that the assembly never '
                        'calls (no indirect calls could account for them): '
                        + ', '.join(f"{n} (line {', '.join(map(str, l[:3]))})" for n, l in phantom.items()),
                        evidence, notes)
    if extra:
        notes.append('Decompiled text calls names not resolved to a direct assembly call target (indirect calls, '
                     'function pointers or macros): ' + ', '.join(sorted(extra)[:8]))
        return _finding('call_targets', INSUFFICIENT if not expected else CONSISTENT,
                        f'All {len(expected)} assembly call target(s) appear in the decompiled text; '
                        f'{len(extra)} decompiled call name(s) have no direct assembly counterpart.', evidence, notes)
    return _finding('call_targets', CONSISTENT, f'All {len(expected)} assembly call target(s) appear in the decompiled text'
                    + (' (no calls in either).' if not expected else '.'), evidence, notes)


def _matches(expected, seen):
    expected, seen = expected.lower(), seen.lower()
    return seen == expected or seen.endswith('_' + expected) or seen.endswith('::' + expected) or \
        seen == 'thunk_' + expected or expected.endswith('::' + seen) or \
        (len(expected) >= 3 and seen.startswith('ptr_' + expected + '_'))


def _strings(semantics, body, full_text):
    strings = {}
    for row in semantics:
        for reference in row['references']:
            if reference['kind'] == 'STRING' and len(reference['value'].strip()) >= 2:
                strings.setdefault((reference['target'], reference['value']), []).append(row['address'])
    if not strings:
        return _finding('string_references', CONSISTENT, 'No string references in this function.')
    literals = [(n, m.group(1)) for n, line in body for m in STRING_LITERAL.finditer(line)]
    missing, evidence = [], []
    for (address, value), sources in strings.items():
        snippet = value[:24].replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') \
            .replace('\t', '\\t').replace('\r', '\\r')
        line = next((n for n, literal in literals if literal.startswith(snippet[:16]) or snippet[:16] in literal), None)
        by_address = address.lstrip('0') and re.search(address.lstrip('0'), full_text, re.I)
        evidence.append({'string': value[:80], 'address': address, 'instruction_addresses': sources,
                         'decompiled_line': line, 'matched_by': 'content' if line else 'address' if by_address else None})
        if line is None and not by_address:
            missing.append((value, sources))
    if missing:
        return _finding('string_references', DISCREPANCY,
                        f'{len(missing)} string(s) referenced by instructions do not appear in the decompiled text: '
                        + '; '.join(f'"{v[:40]}" (at 0x{s[0]})' for v, s in missing[:4]), evidence,
                        ['A string can be absent if the decompiler removed the code that uses it; review the cited '
                         'instructions.'])
    return _finding('string_references', CONSISTENT,
                    f'All {len(strings)} referenced string(s) appear in the decompiled text.', evidence)


def _control_flow(document, semantics, body):
    branches = [r for r in semantics if r['category'] == 'branch_conditional']
    conditional_moves = [r for r in semantics if r['category'] == 'conditional_move']
    text = '\n'.join(line for _, line in body)
    infinite = len(re.findall(r'\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)', text))
    comparisons = len(re.findall(r'(?<![<>=!-])(?:==|!=|<=|>=|<(?![<=])|>(?![>=]))(?![=<>])', text))
    constructs = {k: len(re.findall(p, text)) for k, p in (
        ('if', r'\bif\s*\('), ('while', r'\bwhile\s*\('), ('for', r'\bfor\s*\('), ('do', r'\bdo\s*\{'),
        ('switch', r'\bswitch\s*\('), ('ternary', r'\?[^:;]+:'), ('goto', r'\bgoto\b'),
        ('short_circuit', r'&&|\|\|'))}
    loops_in_c = constructs['while'] + constructs['for'] + constructs['do']
    back_edges = _back_edges(document)
    evidence = {'conditional_branches': [r['address'] for r in branches][:40],
                'conditional_moves': [r['address'] for r in conditional_moves][:20],
                'decompiled_constructs': constructs, 'back_edges': back_edges[:20]}
    constructs['infinite_loops'] = infinite
    constructs['comparisons'] = comparisons
    conditional_c = constructs['if'] + max(0, constructs['while'] + constructs['for'] - infinite) + \
        constructs['switch'] + constructs['ternary'] + constructs['short_circuit'] + comparisons
    notes = ['Branch and construct counts are not expected to be equal (short-circuit conditions, loop '
             'rotation, merged conditions); only presence is compared.']
    if branches and conditional_c == 0 and constructs['goto'] == 0:
        statements = [l for l in text.splitlines() if l.strip() not in ('', '{', '}', 'return;')]
        returned = any(w.startswith(('XMM0', 'RAX', 'EAX')) for r in semantics if r['category'] != 'call'
                       for w in r['writes']['registers'])
        if len(statements) <= 1 and returned:
            notes.append('Likely cause: the decompiled function is empty while the assembly writes a return register '
                         '(RAX/EAX/XMM0); Ghidra probably recovered a void return type and discarded the computation.')
        return _finding('control_flow', DISCREPANCY,
                        f'{len(branches)} conditional branch(es) in the assembly but no conditional construct in the '
                        'decompiled text.', [evidence], notes)
    if not branches and not conditional_moves and (constructs['if'] or max(0, constructs['while'] + constructs['for'] - infinite)):
        return _finding('control_flow', DISCREPANCY,
                        'The decompiled text contains conditional constructs but the assembly has no conditional '
                        'branch or conditional move.', [evidence], notes)
    if back_edges and loops_in_c == 0 and constructs['goto'] == 0:
        return _finding('control_flow', DISCREPANCY,
                        f'{len(back_edges)} loop back-edge(s) in the control-flow graph but no loop construct or goto '
                        'in the decompiled text.', [evidence], notes)
    if document.get('source') != 'ghidra':
        return _finding('control_flow', INSUFFICIENT, 'No basic-block facts (legacy snapshot); presence check only.',
                        [evidence], notes)
    return _finding('control_flow', CONSISTENT,
                    f'{len(branches)} conditional branch(es), {len(back_edges)} back-edge(s); decompiled text has '
                    f"{conditional_c} conditional construct(s) and {loops_in_c} loop(s).", [evidence], notes)


def _back_edges(document):
    """Edges to a block that dominates the source (natural-loop back-edges)."""
    blocks = document.get('blocks') or []
    if not blocks:
        return []
    entry = document.get('function_address') or blocks[0]['start']
    succ = {b['start']: [e['to'] for e in b['succ'] if not e['flow'].endswith('CALL')] for b in blocks}
    nodes = set(succ)
    preds = {n: set() for n in nodes}
    for n, targets in succ.items():
        for t in targets:
            if t in preds:
                preds[t].add(n)
    dom = {n: set(nodes) for n in nodes}
    if entry in dom:
        dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n == entry:
                continue
            ps = [dom[p] for p in preds[n]]
            new = ({n} | set.intersection(*ps)) if ps else {n}
            if new != dom[n]:
                dom[n], changed = new, True
    return [{'from': n, 'to': t} for n, targets in succ.items() for t in targets if t in dom.get(n, ())]


def _returns(document, semantics, body):
    returns = [r for r in semantics if r['category'] == 'return']
    text = '\n'.join(line for _, line in body)
    value_returns = re.findall(r'\breturn\s+[^;]+;', text)
    signature = (document.get('signature') or {}).get('return') or {}
    if not returns:
        return _finding('return_value', INSUFFICIENT, 'No RET instruction in this function (tail call, no-return '
                        'or truncated); return behaviour not compared.')
    writes_before_ret = []
    instructions = document.get('instructions', [])
    index = {ins['a']: i for i, ins in enumerate(instructions)}
    for ret in returns:
        position = index.get(ret['address'])
        found = None
        for prior in reversed(semantics[:position] if position is not None else []):
            if prior['category'] in ('branch_unconditional', 'branch_conditional', 'return'):
                break
            written = {w for w in prior['writes']['registers'] if w in RETURN_REGISTERS or w.startswith('XMM0')}
            if written or prior['category'] == 'call':
                found = prior['address']
                break
        writes_before_ret.append({'ret': ret['address'], 'return_register_written_at': found})
    evidence = [{'ret_instructions': [r['address'] for r in returns], 'value_returns_in_c': len(value_returns),
                 'ghidra_return_storage': signature.get('storage'), 'ghidra_return_type': signature.get('type'),
                 'paths': writes_before_ret}]
    anywhere = [r['address'] for r in semantics if r['category'] == 'call' or
                any(w in RETURN_REGISTERS or w.startswith('XMM0') for w in r['writes']['registers'])]
    if value_returns and not anywhere:
        return _finding('return_value', DISCREPANCY, 'The decompiled text returns a value, but no instruction in the '
                        'function writes a return register and no call could supply one.', evidence)
    if value_returns and not any(p['return_register_written_at'] for p in writes_before_ret):
        return _finding('return_value', INSUFFICIENT, 'The decompiled text returns a value; the return register is '
                        'written elsewhere in the function but not in the straight-line code before RET, so the value '
                        'reaches RET along merged paths (path-level data flow not proven here).', evidence)
    if not value_returns and any(p['return_register_written_at'] for p in writes_before_ret) \
            and signature.get('type') == 'void':
        return _finding('return_value', INSUFFICIENT, 'A return register is written before RET, but the decompiled '
                        'function returns void; the register may be scratch or the return type may be under-recovered.',
                        evidence)
    return _finding('return_value', CONSISTENT, f'{len(value_returns)} value return(s) in the decompiled text; '
                    f'return register written before RET on {sum(bool(p["return_register_written_at"]) for p in writes_before_ret)}'
                    f'/{len(returns)} RET path(s).', evidence)


def _constants(semantics, body_text):
    literals = set()
    for match in NUMBER.finditer(body_text):
        try:
            literals.add(int(match.group(1), 0))
        except ValueError:
            pass
    literals |= {ord(c) for c in re.findall(r"'(.)'", body_text)}
    asm = {}
    for row in semantics:
        if row['category'] in ('stack_push', 'stack_pop', 'call', 'branch_conditional', 'branch_unconditional'):
            continue
        if row['category'] == 'arithmetic' and any(r in ('RSP', 'ESP') for r in row['writes']['registers']):
            continue  # stack-frame allocation
        for value in row['constants']:
            if value in TRIVIAL_CONSTANTS or abs(value) >= 0x400000 or row['references']:
                continue  # trivial values and addresses are not compared here
            asm.setdefault(value, []).append(row['address'])
    def present(value):
        return value in literals or -value in literals or (value & 0xffffffff) in literals \
            or (value & 0xff) in literals and value > 0xff
    matched = {v: a for v, a in asm.items() if present(v)}
    unmatched = {v: a for v, a in asm.items() if not present(v)}
    evidence = [{'matched': {hex(v): a[:3] for v, a in list(matched.items())[:20]},
                 'not_found_in_c': {hex(v): a[:3] for v, a in list(unmatched.items())[:20]}}]
    if not asm:
        return _finding('constants', CONSISTENT, 'No non-trivial immediate constants to compare.', evidence)
    if unmatched:
        return _finding('constants', INSUFFICIENT,
                        f'{len(matched)}/{len(asm)} immediate constant(s) appear literally in the decompiled text; '
                        f'{len(unmatched)} do not (compilers/decompilers fold, rescale or rewrite constants, e.g. '
                        'x*8 as x<<3, structure offsets as field names), so absence is not a discrepancy.', evidence)
    return _finding('constants', CONSISTENT, f'All {len(asm)} immediate constant(s) appear in the decompiled text.',
                    evidence)


def _globals(semantics, body_text):
    addresses = {}
    for row in semantics:
        for side in ('reads', 'writes'):
            memory = row[side]['memory']
            if memory and memory.get('kind') in ('global', 'pc_relative') and not row['references']:
                addresses.setdefault(memory['address'], []).append(row['address'])
    if not addresses:
        return _finding('global_data', CONSISTENT, 'No direct global-data accesses (other than strings).')
    found = {a: s for a, s in addresses.items() if re.search(a.lstrip('0') or '0', body_text, re.I)}
    evidence = [{'global': a, 'instruction_addresses': s[:4], 'address_named_in_c': a in found}
                for a, s in addresses.items()]
    if len(found) == len(addresses):
        return _finding('global_data', CONSISTENT, f'All {len(addresses)} accessed global address(es) appear in the '
                        'decompiled text.', evidence)
    return _finding('global_data', INSUFFICIENT,
                    f'{len(found)}/{len(addresses)} accessed global address(es) appear by address; others may be '
                    'shown under symbol names that are not stored for data, so absence is not a discrepancy.', evidence)


def _arithmetic(report):
    conflicts = report.get('disagreements') or report.get('conflicts') or []
    report = {**report, 'agreements': [a for a in report.get('agreements', []) if a.get('operation') != 'call']}
    if conflicts:
        return _finding('arithmetic', DISCREPANCY, '; '.join(conflicts),
                        [{'agreements': report.get('agreements', [])[:8]}])
    if report.get('agreements'):
        return _finding('arithmetic', CONSISTENT, f"{len(report['agreements'])} local arithmetic operation(s) agree "
                        '(M9 cross-check; local agreement, not whole-function equivalence).',
                        [{'agreements': report['agreements'][:8]}])
    return _finding('arithmetic', INSUFFICIENT, 'No recognized arithmetic operations to compare.',
                    [{'uncertainties': report.get('uncertainties', [])[:4]}])
