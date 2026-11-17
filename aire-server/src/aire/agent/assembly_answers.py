"""M10 Phase 4: evidence-grounded answers to assembly questions.

Routing is deterministic (question patterns + the selected function). Every
answer is assembled from AssemblyIntelligence facts and states: binary
identity, function name/address, instruction addresses with assembly or
P-code evidence, a plain-English explanation, confidence and limitations.
A local model may optionally *narrate* the evidence; its text is accepted only
if every address it cites exists in the evidence and every mnemonic it ties to
an address matches. Otherwise the deterministic answer stands alone.
"""
import re

ADDRESS = re.compile(r'\b(?:0x)?([0-9a-fA-F]{6,16})\b')
# Citations must be 0x-prefixed (bare hex runs are usually hash fragments).
CITED = re.compile(r'\b0x([0-9a-fA-F]{6,16})\b')
LOCATION = re.compile(r'(\[\s*[A-Za-z]{2,3}\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]|\b(?:[RE]?[ABCD]X|[ABCD][LH]|[RE]?(?:SI|DI|BP|SP)|R\d+[DWB]?|XMM\d+)\b)',
                      re.IGNORECASE)
INTENTS = (
    ('crossvalidate', r'decompil\w* (?:code|output|text)?\s*(?:match|support|agree|correct|consistent)|assembly support|'
                      r'support the decompil|cross[- ]?(?:check|validat)'),
    ('branch', r'(?:condition|branch|jump)\b.*\b(?:true|taken|false|evaluat)|what happens when|when .* (?:true|false)'),
    ('trace', r'where does (?:this|the) value|origin|come from|originate|value of'),
    ('return_usage', r'return value.*(?:used|use)|how is .*return'),
    ('callers', r'which functions call|who calls|what calls|callers of'),
    ('validation', r'input validation|where .*validat|validate[sd]? (?:the )?input'),
    # The existing function cards ("Summarize this function", "Explain this assembly") keep the M8 model
    # pipeline; M10 answers its own question forms.
    ('instructions', r'explain (?:these |the |this )?instructions?|what does (?:this|the) instruction'),
    ('function', r'what does (?:this|the) function do|explain (?:this|the) function|what is this function'),
)


def route(question):
    lower = question.lower()
    for intent, pattern in INTENTS:
        if re.search(pattern, lower):
            addresses = [m.group(1).lower().zfill(8)[-8:] for m in ADDRESS.finditer(question)]
            locations = [m.group(1) for m in LOCATION.finditer(question)]
            return {'intent': intent, 'addresses': addresses, 'locations': locations}
    return None


def _cite(address, text=None):
    return f'`0x{address}`' + (f' `{text}`' if text else '')


def _header(result):
    binary, function = result['binary'], result['function']
    source = result['evidence_source']
    lines = [f"**Function:** `{function['name']}` at `0x{function['address']}` — binary `{binary.get('name')}` "
             f"(SHA-256 `{(binary.get('sha256') or '')[:16]}…`, {binary.get('architecture')})",
             f"**Evidence source:** {'Ghidra P-code and instruction facts' if source == 'ghidra_pcode' else 'stored assembly text only (lower confidence; re-analyze for P-code)'}"]
    if result['coverage'].get('truncated'):
        lines.append(f"**Coverage:** instruction facts truncated at {result['coverage']['instructions']} instructions.")
    return lines


def purpose_hints(evidence):
    """Cautious, rule-derived purpose statements, each with supporting addresses."""
    hints = []
    branches = evidence['conditional_branches']
    constant_checks = [b for b in branches if b['condition'] and re.search(r'(?:==|!=|<=|>=|<|>)\s*-?0x[0-9a-f]+', b['condition'])]
    messages = [s for s in evidence['strings']]
    calls = evidence['calls']
    if constant_checks and (messages or len(evidence['returns']) > 1):
        hints.append({'statement': 'Appears to check values against constants and take a separate path when a check '
                                   'fails' + (' (an error-style message is referenced)' if messages else ''),
                      'addresses': [b['address'] for b in constant_checks[:4]] + [s['address'] for s in messages[:2]],
                      'basis': 'compare-with-constant branches plus message references / multiple returns'})
    if evidence['loops']:
        loop = evidence['loops'][0]
        hints.append({'statement': f"Contains {len(evidence['loops'])} loop(s); the first is headed at 0x{loop['header']} "
                                   f"and exits to {', '.join('0x' + e for e in loop['exits'])}",
                      'addresses': [loop['header'], loop['back_edge_from']], 'basis': 'CFG back-edge (dominator analysis)'})
    named = [c for c in calls if c['name']]
    if named:
        hints.append({'statement': 'Calls ' + ', '.join(dict.fromkeys(c['name'] for c in named[:8])),
                      'addresses': [c['address'] for c in named[:8]], 'basis': 'direct/import call targets'})
    if evidence['non_stack_memory_writes']:
        hints.append({'statement': f"Writes to {len(evidence['non_stack_memory_writes'])} non-stack memory location(s) "
                                   '(through pointers or globals), i.e. it has side effects beyond its return value',
                      'addresses': [w['address'] for w in evidence['non_stack_memory_writes'][:4]],
                      'basis': 'memory stores not relative to the stack/frame pointer'})
    used = [p for p in evidence['parameter_use'] if p['recovered_by_ghidra']]
    if used:
        hints.append({'statement': 'Reads ' + ', '.join(f"parameter {p['parameter']['ordinal']} ({p['location']})" for p in used),
                      'addresses': [a for p in used for a in p['first_reads'][:1]], 'basis': 'read-before-write at entry'})
    return hints


def answer_function(ai, selector):
    evidence = ai.function_evidence(selector)
    crossval = ai.crossvalidate(selector)['crossvalidation']
    lines = ['### Function analysis (deterministic evidence)', '', *_header(evidence), '']
    hints = purpose_hints(evidence)
    lines.append('**Purpose (evidence-derived, hedged):** ' + (hints[0]['statement'] + '.' if hints else
                 'No characteristic pattern was recognized; see the evidence below.'))
    lines += ['', '**Evidence:**']
    for hint in hints:
        lines.append(f"- {hint['statement']} — " + ', '.join(_cite(a) for a in hint['addresses'][:6]) + f" ({hint['basis']})")
    for branch in evidence['conditional_branches'][:6]:
        lines.append(f"- {_cite(branch['address'], branch['text'])}: branches to `0x{branch['target']}` when "
                     f"{branch['condition'] or 'its flag condition holds'}")
    for string in evidence['strings'][:4]:
        lines.append(f"- {_cite(string['address'])}: references the string \"{string['value'][:60]}\"")
    lines += ['', f"**Decompiler cross-check:** {crossval['verdict']}"]
    for finding in crossval['findings']:
        if finding['status'] != 'CONSISTENT':
            lines.append(f"- {finding['check']}: {finding['status']} — {finding['summary']}")
    lines += ['', '**Confidence:** high for the listed instruction-level facts (Ghidra P-code); the application-level '
              'purpose is an inference from these patterns and remains unconfirmed.',
              '**Limitations:** static analysis only; intra-procedural data flow; no execution; source-level names '
              'and intent are not recovered.']
    addresses = {evidence['function']['address']} | {a for h in hints for a in h['addresses']} | \
        {b['address'] for b in evidence['conditional_branches']} | {b['target'] for b in evidence['conditional_branches']} | \
        {s['address'] for s in evidence['strings']} | {c['address'] for c in evidence['calls']}
    return '\n'.join(lines), {'tool': 'function_evidence', 'data': evidence}, addresses


def answer_instructions(ai, selector, start=None, limit=24):
    result = ai.explain(selector, start=start, limit=limit)
    lines = ['### Instruction explanations', '', *_header(result), '']
    for row in result['instructions']:
        lines.append(f"- {_cite(row['address'], row['text'])} — {row['explanation']}"
                     + (f" *(confidence {row['confidence']})*" if row['confidence'] != 'high' else ''))
        for note in row['notes'][:1]:
            lines.append(f'  - note: {note}')
    if result['window']['more']:
        lines.append(f"\nShowing {result['window']['returned']} of {result['window']['total']} instructions.")
    lines += ['', '**Basis:** each explanation is derived from Ghidra P-code for that instruction; branch conditions are '
              'reconstructed from the flag predicate and its flag-setting instruction.']
    return '\n'.join(lines), {'tool': 'explain_instructions', 'data': result}, {r['address'] for r in result['instructions']}


def answer_branch(ai, selector, address):
    result = ai.branch(selector, address)
    paths = result['paths']
    if 'error' in paths:
        return paths['error'] + ' Give the address of a conditional jump in this function.', None, set()
    lines = ['### Branch analysis', '', *_header(result), '',
             f"{_cite(paths['branch'], paths['text'])}: {paths['explanation']}", '']
    addresses = {paths['branch']}
    for key in ('when_true', 'when_false'):
        path = paths[key]
        lines.append(f"**{path['label'].capitalize()}** → starts at `0x{path['start']}`; {path['outcome']}.")
        for step in path['steps'][:8]:
            lines.append(f"- {_cite(step['address'], step['text'])} — {step['explanation']}")
            addresses.add(step['address'])
        if path['calls']:
            lines.append('  Calls on this path: ' + ', '.join(f"{c['name'] or c['target']} at `0x{c['address']}`"
                                                              for c in path['calls']))
        lines.append('')
    lines.append('**Confidence:** high for the condition and the straight-line path contents; later merges are not '
                 'followed beyond the next branch.')
    return '\n'.join(lines), {'tool': 'branch_paths', 'data': result}, addresses


def _flatten_trace(node, depth=0, lines=None, addresses=None):
    lines = lines if lines is not None else []
    addresses = addresses if addresses is not None else set()
    pad = '  ' * depth
    if 'definitions' not in node:
        lines.append(f"{pad}- {node['location']} at `0x{node['at']}`: {node.get('note', node.get('origin'))}")
        return lines, addresses
    for d in node['definitions']:
        if 'address' not in d:
            lines.append(f"{pad}- {node['location']} at `0x{node['at']}` comes from function entry: {d['note']}")
            continue
        addresses.add(d['address'])
        detail = {'constant': f"constant {d.get('value')}", 'call_result': f"return value of the call to "
                  f"{(d.get('call') or {}).get('target_name') or (d.get('call') or {}).get('target')}",
                  'stack_slot': 'loaded from a stack slot', 'stored_value': 'stored value',
                  'global_memory': 'loaded from global memory', 'memory': 'loaded through a pointer'}.get(d['origin'], d['origin'])
        lines.append(f"{pad}- {node['location']} at `0x{node['at']}` ← {_cite(d['address'], d['text'])}: {detail}")
        for key in ('from', 'pointer'):
            if d.get(key):
                _flatten_trace(d[key], depth + 1, lines, addresses)
        for child in d.get('inputs', []):
            _flatten_trace(child, depth + 1, lines, addresses)
    return lines, addresses


def answer_trace(ai, selector, address, location):
    result = ai.trace(selector, address, location)
    lines = ['### Value origin', '', *_header(result), '']
    body, addresses = _flatten_trace(result['trace'])
    lines += body[:40] + ['', f"**Limits:** {result['limits']}"]
    return '\n'.join(lines), {'tool': 'trace_value', 'data': result}, addresses | {address}


def answer_return_usage(ai, selector):
    result = ai.return_usage(selector)
    lines = ['### How the return value is used', '', *_header(result), '',
             f"Return storage per Ghidra: {(result['return_storage'] or {}).get('storage')} "
             f"({(result['return_storage'] or {}).get('type')})", '']
    addresses = set()
    for site in result['callsites']:
        addresses.add(site['callsite'])
        uses = '; '.join(f"{u['use']} at `0x{u['address']}`" + (f" → {u['then']}" if u.get('then') else '')
                         for u in site['uses']) or site['note']
        lines.append(f"- In `{site['caller']}` (call at `0x{site['callsite']}`): {uses}")
        addresses.update(u['address'] for u in site['uses'])
    if not result['callsites']:
        lines.append('No stored direct callers (it may be called indirectly or not at all).')
    lines += ['', '**Limits:** straight-line use after each call site, until the register is overwritten or control '
              'leaves the block.']
    return '\n'.join(lines), {'tool': 'return_usage', 'data': result}, addresses


def answer_crossvalidate(ai, selector):
    result = ai.crossvalidate(selector)
    report = result['crossvalidation']
    lines = ['### Does the assembly support the decompiled code?', '', *_header(result), '',
             f"**Verdict:** {report['verdict']}", f"*{report.get('verdict_basis', '')}*", '']
    addresses = set()
    for finding in report['findings']:
        lines.append(f"- **{finding['check']}** — {finding['status']}: {finding['summary']}")
        for note in finding['notes'][:1]:
            lines.append(f'  - {note}')
        for item in finding['evidence'][:3]:
            if isinstance(item, dict):
                for key in ('instruction_addresses',):
                    addresses.update(item.get(key, []))
    if report['decompiler_warnings']:
        lines += ['', 'Ghidra decompiler warnings: ' + '; '.join(report['decompiler_warnings'][:3])]
    lines += ['', 'Different-but-equivalent forms are not reported as discrepancies; POTENTIAL DISCREPANCY means '
              'analyst review is warranted, not that the decompiler is wrong.']
    return '\n'.join(lines), {'tool': 'crossvalidate_function', 'data': result}, addresses


def answer_validation(ai, limit=8):
    """Binary-wide: functions showing an input-validation pattern."""
    rows = ai.store._db.execute('SELECT function_id FROM functions WHERE binary_id=? AND is_external=0 AND is_thunk=0',
                                (ai.binary_id,)).fetchall()
    candidates = []
    for (fid,) in rows:
        evidence = ai.function_evidence(fid)
        hint = next((h for h in purpose_hints(evidence) if h['statement'].startswith('Appears to check values')), None)
        if hint:
            score = len(hint['addresses']) + (2 if evidence['strings'] else 0)
            candidates.append((score, evidence, hint))
    candidates.sort(key=lambda c: (-c[0], c[1]['function']['address']))
    lines = ['### Where input validation appears to be performed', '']
    addresses = set()
    for _, evidence, hint in candidates[:limit]:
        function = evidence['function']
        lines.append(f"- `{function['name']}` at `0x{function['address']}`: {hint['statement']} — "
                     + ', '.join(_cite(a) for a in hint['addresses'][:5]))
        addresses.update(hint['addresses'])
    if not candidates:
        lines.append('No function shows the compare-with-constant + failure-path pattern.')
    lines += ['', '**Basis:** pattern = conditional branches comparing values with constants, plus a referenced '
              'message or multiple return paths. This is a heuristic ranking of candidates, not proof of purpose.']
    return '\n'.join(lines), {'tool': 'validation_candidates', 'data': [c[1]['function'] for c in candidates]}, addresses


def validate_narration(text, allowed_addresses, instructions):
    """Accept model narration only if every cited address/mnemonic is supported."""
    problems = []
    allowed = {a.lower().zfill(8)[-8:] for a in allowed_addresses}
    for match in CITED.finditer(text):
        cited = match.group(1).lower().zfill(8)[-8:]
        if cited not in allowed:
            problems.append(f'cites 0x{cited}, which is not in the retrieved evidence')
    mnemonics = {text_.split()[0].upper() for text_ in instructions.values() if text_}
    for mnemonic, address in re.findall(r'\b([A-Z][A-Z0-9.]{1,11})\b[^.\n]{0,30}?\b(?:at|@)\s*`?(?:0x)?([0-9a-fA-F]{6,16})', text):
        if mnemonic not in mnemonics:
            continue  # only instruction-mnemonic claims are checked
        actual = instructions.get(address.lower().zfill(8)[-8:])
        if actual and actual.split()[0].upper() != mnemonic:
            problems.append(f'calls the instruction at 0x{address} "{mnemonic}" but it is "{actual}"')
    return problems


def render_tool(name, data):
    """Compact, citation-preserving text of an M10 tool result for model prompts."""
    head = f"M10 {name} for {data['function']['name']} at 0x{data['function']['address']} " \
           f"(evidence: {data['evidence_source']}):"
    lines = [head]
    if name == 'explain_instructions':
        lines += [f"- 0x{r['address']} {r['text']}: {r['explanation']}" for r in data['instructions'][:60]]
    elif name == 'function_evidence':
        lines += [f"- calls {c['name'] or c['target']} at 0x{c['address']}" for c in data['calls'][:12]]
        lines += [f"- 0x{b['address']} {b['text']}: to 0x{b['target']} when {b['condition']}" for b in data['conditional_branches'][:12]]
        lines += [f"- 0x{s['address']} string \"{s['value'][:50]}\"" for s in data['strings'][:6]]
        lines += [f"- loop headed at 0x{l['header']}" for l in data['loops'][:4]]
    elif name == 'branch_paths':
        paths = data['paths']
        lines += [paths.get('error') or f"- 0x{paths['branch']}: true -> 0x{paths['when_true']['start']} "
                  f"({paths['when_true']['outcome']}); false -> 0x{paths['when_false']['start']} ({paths['when_false']['outcome']}); "
                  f"condition {paths['condition']}"]
    elif name == 'trace_value':
        lines += _flatten_trace(data['trace'])[0][:30]
    elif name == 'return_usage':
        lines += [f"- {c['caller']} @0x{c['callsite']}: " + ('; '.join(f"{u['use']} at 0x{u['address']}" for u in c['uses'])
                                                          or c['note']) for c in data['callsites']]
    elif name == 'crossvalidate_function':
        report = data['crossvalidation']
        lines += [f"- verdict {report['verdict']}"] + [f"- {f['check']}: {f['status']} - {f['summary']}" for f in report['findings']]
    elif name == 'function_cfg':
        graph = data['cfg']
        lines += [f"- {len(graph['blocks'])} blocks; loops at " + ', '.join('0x' + l['header'] for l in graph['loops'])]
        lines += [f"- block 0x{b['start']}: branch 0x{b['branch']['address']} when {b['branch']['condition']}"
                  for b in graph['blocks'] if b.get('branch')][:16]
    elif name == 'parameter_use':
        lines += [f"- {p['location']} first read at 0x{p['first_reads'][0]}" +
                  (f" (parameter {p['parameter']['ordinal']} {p['parameter']['name']})" if p['parameter'] else '')
                  for p in data['parameter_use']]
    return lines
