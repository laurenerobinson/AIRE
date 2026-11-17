"""M10 Phase 3: bounded, deterministic control-flow and data-flow reasoning.

Inputs are one function's stored facts (blocks, instructions, P-code-derived
semantic records). Everything is intra-procedural except return-value usage,
which inspects stored callers' call sites. Analyses are bounded (depth, block
and instruction limits) and say where they stop; nothing is guessed.

Locations tracked: x86 register families (RAX/EAX/AX/AL -> RAX, XMM lanes ->
XMMn) and frame-pointer-relative stack slots ([RBP+disp] / [EBP+disp]).
Stack-pointer-relative slots are reported but not tracked across pushes/calls.
"""
import re

MAX_TRACE_DEPTH = 6
MAX_PATH_INSTRUCTIONS = 24
ARG_REGISTERS = {'sysv64': ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'], 'win64': ['RCX', 'RDX', 'R8', 'R9']}
_FAMILIES = {}
for stem, names in {'RAX': 'RAX EAX AX AH AL', 'RBX': 'RBX EBX BX BH BL', 'RCX': 'RCX ECX CX CH CL',
                    'RDX': 'RDX EDX DX DH DL', 'RSI': 'RSI ESI SI SIL', 'RDI': 'RDI EDI DI DIL',
                    'RBP': 'RBP EBP BP BPL', 'RSP': 'RSP ESP SP SPL'}.items():
    for name in names.split():
        _FAMILIES[name] = stem


def family(register):
    if register in _FAMILIES:
        return _FAMILIES[register]
    match = re.match(r'^R(\d+)[DWB]?$', register)
    if match:
        return f'R{match.group(1)}'
    match = re.match(r'^([XYZ]MM\d+)', register)
    if match:
        return 'XMM' + re.sub(r'\D', '', match.group(1))
    return register


def canonical_location(text):
    """'eax' -> 'RAX'; '[rbp - 0x10]' / '[RBP+-16]' -> '[RBP-0x10]'."""
    text = text.strip()
    match = re.fullmatch(r'\[\s*([A-Za-z0-9]+)\s*(?:([+-])\s*(-?(?:0x[0-9a-fA-F]+|\d+)))?\s*\]', text)
    if match:
        base, sign, value = match.groups()
        disp = int(value, 0) * (-1 if sign == '-' else 1) if value else 0
        return f"[{base.upper()}{'+' if disp >= 0 else '-'}0x{abs(disp):x}]"
    return family(text.upper())


def _slot(memory):
    if memory and memory.get('kind') == 'frame' and memory.get('index') is None:
        return f"[{memory['base']}{'+' if memory['disp'] >= 0 else '-'}0x{abs(memory['disp']):x}]"
    return None


# ------------------------------------------------------------------ CFG
def control_flow_graph(document):
    blocks = document.get('blocks') or []
    entry = document.get('function_address') or (blocks[0]['start'] if blocks else None)
    starts = {b['start'] for b in blocks}
    succ = {b['start']: [e for e in b['succ'] if not e['flow'].endswith('CALL') and e['to'] in starts] for b in blocks}
    external = {b['start']: [e for e in b['succ'] if not e['flow'].endswith('CALL') and e['to'] not in starts]
                for b in blocks}
    preds = {s: [] for s in starts}
    for source, edges in succ.items():
        for edge in edges:
            preds[edge['to']].append(source)
    dom = _dominators(entry, starts, preds)
    back_edges = [(s, e['to']) for s, edges in succ.items() for e in edges if e['to'] in dom.get(s, ())]
    loops = []
    for tail, head in back_edges:
        # The header is the boundary of the reverse walk. A self-edge has
        # no other loop blocks; walking the header would absorb preheaders.
        body, stack = {head, tail}, [tail] if tail != head else []
        while stack:
            node = stack.pop()
            for p in preds.get(node, []):
                if p not in body:
                    body.add(p)
                    stack.append(p)
        exits = sorted({e['to'] for n in body for e in succ.get(n, []) if e['to'] not in body})
        loops.append({'header': head, 'back_edge_from': tail, 'blocks': sorted(body), 'exits': exits})
    reachable = _reachable(entry, succ)
    return {'entry': entry, 'blocks': [{'start': b['start'], 'end': b['end'],
                                        'successors': [{'to': e['to'], 'kind': _edge_kind(e['flow'])} for e in succ[b['start']]],
                                        'leaves_function': [{'to': e['to'], 'kind': _edge_kind(e['flow'])}
                                                            for e in external[b['start']]],
                                        'predecessors': sorted(preds[b['start']]),
                                        'reachable': b['start'] in reachable} for b in blocks],
            'back_edges': [{'from': s, 'to': t} for s, t in back_edges], 'loops': loops,
            'unreachable_blocks': sorted(starts - reachable)}


def _edge_kind(flow):
    return {'FALL_THROUGH': 'fallthrough', 'CONDITIONAL_JUMP': 'conditional_jump',
            'UNCONDITIONAL_JUMP': 'jump', 'COMPUTED_JUMP': 'computed_jump'}.get(flow, flow.lower())


def _dominators(entry, nodes, preds):
    dom = {n: set(nodes) for n in nodes}
    if entry in dom:
        dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n == entry:
                continue
            ps = [dom[p] for p in preds.get(n, [])]
            new = ({n} | set.intersection(*ps)) if ps else {n}
            if new != dom[n]:
                dom[n], changed = new, True
    return dom


def _reachable(entry, succ):
    seen, stack = set(), [entry] if entry else []
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(e['to'] for e in succ.get(node, []))
    return seen


# ------------------------------------------------------------ branch paths
def branch_paths(document, semantics, address):
    by_address = {r['address']: r for r in semantics}
    order = [r['address'] for r in semantics]
    record = by_address.get(address)
    if record is None or record['category'] != 'branch_conditional':
        return {'error': f'0x{address} is not a conditional branch in this function.'}
    branch = record['branch']
    def walk(start, label):
        steps, calls, outcome = [], [], None
        if start is None or start not in by_address:
            return {'label': label, 'start': start, 'steps': [], 'calls': [],
                    'outcome': 'leaves the stored instructions (target outside this function or not stored)'}
        index = order.index(start)
        for row in semantics[index:index + MAX_PATH_INSTRUCTIONS]:
            steps.append({'address': row['address'], 'text': row['text'], 'explanation': row['explanation']})
            if row['category'] == 'call':
                calls.append({'address': row['address'], 'target': row['call']['target'],
                              'name': row['call']['target_name']})
            if row['category'] == 'return':
                outcome = f"returns at 0x{row['address']}"
                break
            if row['category'] in ('branch_conditional', 'branch_unconditional', 'branch_indirect'):
                outcome = f"reaches another branch at 0x{row['address']} ({row['text']})"
                break
        return {'label': label, 'start': start, 'steps': steps, 'calls': calls,
                'outcome': outcome or f'continues beyond {MAX_PATH_INSTRUCTIONS} instructions (bounded)'}
    relation = branch.get('relation') or {}
    condition = relation.get('text') or (f"flag condition {branch['predicate']}" if branch.get('predicate') else 'unknown')
    return {'branch': address, 'text': record['text'], 'condition': condition,
            'flag_setter': relation.get('setter'), 'explanation': record['explanation'],
            'when_true': walk(branch['target'], 'condition true (branch taken)'),
            'when_false': walk(branch['fallthrough'], 'condition false (falls through)')}


# --------------------------------------------------------- data flow
def _defs_uses(row):
    defs = {family(r) for r in row['writes']['registers'] if family(r) not in ('RIP',)}
    uses = {family(r) for r in row['reads']['registers'] if family(r) not in ('RIP',)}
    if row['category'] == 'zeroing':
        uses = set()  # XOR/SUB reg,reg does not depend on the register's prior value
    slot_write = _slot(row['writes']['memory'])
    slot_read = _slot(row['reads']['memory'])
    if slot_write:
        defs.add(slot_write)
    if slot_read:
        uses.add(slot_read)
    if row['category'] == 'call':  # caller-saved registers are clobbered by a call
        defs |= {'RAX', 'RCX', 'RDX', 'R8', 'R9', 'R10', 'R11', 'XMM0'}
    return defs, uses


def reaching_definitions(document, semantics):
    """Block-level iterative reaching definitions; returns per-instruction
    {address: {location: [defining addresses]}} for locations used there."""
    blocks = document.get('blocks') or []
    by_block, block_of = {}, {}
    for row in semantics:
        value = int(row['address'], 16)
        block = next((b['start'] for b in blocks if int(b['start'], 16) <= value <= int(b['end'], 16)), None)
        by_block.setdefault(block, []).append(row)
        block_of[row['address']] = block
    succ = {b['start']: [e['to'] for e in b['succ'] if not e['flow'].endswith('CALL')] for b in blocks}
    gen, kill_locations = {}, {}
    for block, rows in by_block.items():
        last = {}
        for row in rows:
            defs, _ = _defs_uses(row)
            for location in defs:
                last[location] = row['address']
        gen[block] = last
        kill_locations[block] = set(last)
    entry = document.get('function_address')
    reach_in = {b: {} for b in by_block}
    changed, rounds = True, 0
    while changed and rounds < 64:
        changed, rounds = False, rounds + 1
        for block in by_block:
            incoming = {}
            for pred in (p for p, targets in succ.items() if block in targets):
                out = dict(reach_in.get(pred, {}))
                out = {loc: addrs for loc, addrs in out.items() if loc not in kill_locations.get(pred, ())}
                for loc, addr in gen.get(pred, {}).items():
                    out[loc] = {addr}
                for loc, addrs in out.items():
                    incoming.setdefault(loc, set()).update(addrs)
            if incoming != reach_in[block]:
                reach_in[block], changed = incoming, True
    result = {}
    available = {}
    for block, rows in by_block.items():
        current = {loc: set(addrs) for loc, addrs in reach_in.get(block, {}).items()}
        for row in rows:
            defs, uses = _defs_uses(row)
            result[row['address']] = {loc: sorted(current.get(loc, set())) or ['ENTRY'] for loc in uses}
            available[row['address']] = {loc: sorted(addrs) for loc, addrs in current.items()}
            for location in defs:
                current[location] = {row['address']}
    result['__available__'] = available  # definitions reaching each instruction (used or not)
    return result, rounds


def parameter_registers(document):
    signature = document.get('signature') or {}
    mapping = {}
    for parameter in signature.get('parameters', []):
        storage = parameter.get('storage', '')
        register = storage.split(':')[0]
        if re.fullmatch(r'[A-Z0-9]+', register):
            mapping[family(register)] = parameter
        elif storage.startswith('Stack'):
            mapping[storage] = parameter
    return mapping


def _value_registers(row):
    """Registers read as data (excludes registers used only to form an address)."""
    address = set()
    for side in ('reads', 'writes'):
        memory = row[side]['memory'] or {}
        for key in ('base', 'index'):
            if memory.get(key):
                address.add(family(memory[key]))
    return [r for r in dict.fromkeys(family(x) for x in row['reads']['registers'])
            if r not in address and r not in ('RSP', 'RIP')]


MAX_TRACE_NODES = 160


def trace_value(document, semantics, address, location, depth=0, reaching=None, seen=frozenset(), budget=None):
    """Where does `location` (register or frame slot) used at `address` come from?
    `seen` holds only the current path's ancestors (loop detection); `budget`
    bounds the total number of nodes in the trace tree."""
    reaching = reaching if reaching is not None else reaching_definitions(document, semantics)[0]
    budget = budget if budget is not None else [MAX_TRACE_NODES]
    location = canonical_location(location)
    key = (address, location)
    if key in seen:
        return {'location': location, 'at': address, 'origin': 'loop', 'note': 'value flows around a loop'}
    if budget[0] <= 0:
        return {'location': location, 'at': address, 'origin': 'budget',
                'note': f'Trace size limit ({MAX_TRACE_NODES} nodes) reached.'}
    budget[0] -= 1
    seen = seen | {key}
    by_address = {r['address']: r for r in semantics}
    sources = reaching.get(address, {}).get(location)
    note = None
    if sources is None and depth == 0 and address in reaching.get('__available__', {}):
        # Not read here: report the value the location holds when this instruction executes.
        sources = reaching['__available__'][address].get(location) or ['ENTRY']
        note = f'{location} is not read by this instruction; showing the value it holds when 0x{address} executes.'
    if sources is None:
        return {'location': location, 'at': address, 'origin': 'not_used_here',
                'note': f'{location} is not read by the instruction at 0x{address}.'}
    node = {'location': location, 'at': address, 'definitions': [], **({'note': note} if note else {})}
    params = parameter_registers(document)
    for source in sources:
        if source == 'ENTRY':
            parameter = params.get(location)
            node['definitions'].append({'origin': 'parameter' if parameter else 'function_entry',
                                        'parameter': parameter,
                                        'note': (f"parameter {parameter['ordinal']} ({parameter['name']}, {parameter['storage']}) "
                                                 'per Ghidra signature' if parameter else
                                                 f'{location} holds its value from function entry (caller-provided or '
                                                 'callee-saved state; not a recovered parameter)')})
            continue
        row = by_address[source]
        entry = {'address': source, 'text': row['text'], 'category': row['category'], 'explanation': row['explanation']}
        if depth >= MAX_TRACE_DEPTH:
            entry['origin'] = 'depth_limit'
            entry['note'] = f'Trace stopped at depth {MAX_TRACE_DEPTH}.'
        elif row['category'] == 'call':
            entry['origin'] = 'call_result' if location in ('RAX', 'XMM0') else 'clobbered_by_call'
            entry['call'] = row['call']
        elif row['category'] == 'zeroing':
            entry['origin'], entry['value'] = 'constant', 0
        elif row['category'] in ('data_move', 'memory_store') and row['constants'] and not _value_registers(row) \
                and not row['reads']['memory']:
            entry['origin'], entry['value'] = 'constant', row['constants'][0]
            if row['references']:
                entry['reference'] = row['references'][0]
        elif row['category'] == 'memory_load' and _slot(row['reads']['memory']):
            entry['origin'] = 'stack_slot'
            entry['from'] = trace_value(document, semantics, source, _slot(row['reads']['memory']), depth + 1,
                                        reaching, seen, budget)
        elif row['category'] == 'memory_load':
            memory = row['reads']['memory'] or {}
            entry['origin'] = 'global_memory' if memory.get('kind') in ('global', 'pc_relative') else 'memory'
            entry['memory'] = memory
            base = memory.get('base')
            if base and memory.get('kind') not in ('global', 'pc_relative'):
                entry['pointer'] = trace_value(document, semantics, source, base, depth + 1, reaching, seen, budget)
        else:
            entry['origin'] = 'stored_value' if row['category'] == 'memory_store' else \
                'copied' if row['category'] == 'data_move' else 'computed'
            slot = _slot(row['reads']['memory'])
            entry['inputs'] = [trace_value(document, semantics, source, r, depth + 1, reaching, seen, budget)
                               for r in _value_registers(row)][:4]
            if slot:
                entry['inputs'].append(trace_value(document, semantics, source, slot, depth + 1, reaching, seen, budget))
        node['definitions'].append(entry)
    return node


def parameter_use(document, semantics):
    """Which argument registers / recovered parameters are read before written."""
    reaching, _ = reaching_definitions(document, semantics)
    params = parameter_registers(document)
    used = {}
    for row in semantics:
        for location, sources in reaching.get(row['address'], {}).items():
            if 'ENTRY' in sources and (location in params or location in sum(ARG_REGISTERS.values(), [])):
                used.setdefault(location, []).append(row['address'])
    return [{'location': loc, 'parameter': params.get(loc), 'first_reads': addrs[:5],
             'recovered_by_ghidra': loc in params} for loc, addrs in used.items()]


def return_usage_at_callsite(document, semantics, callsite):
    """How the caller uses RAX/EAX/XMM0 after the call at `callsite` (bounded,
    straight-line until redefinition, branch or return)."""
    order = [r['address'] for r in semantics]
    if callsite not in order:
        return {'callsite': callsite, 'uses': [], 'note': 'call site not in stored instructions'}
    uses, live = [], {'RAX', 'XMM0'}
    for row in semantics[order.index(callsite) + 1:order.index(callsite) + 1 + MAX_PATH_INSTRUCTIONS]:
        defs, read = _defs_uses(row)
        hit = {family(r) for r in row['reads']['registers']} & live
        if hit:
            kind = {'compare': 'compared', 'test': 'tested', 'memory_store': 'stored to memory',
                    'call': 'passed to another call', 'return': 'returned', 'data_move': 'copied',
                    'arithmetic': 'used in arithmetic', 'logic': 'used in a logical operation',
                    'memory_load': 'used as a pointer (dereferenced)'}.get(row['category'], row['category'])
            uses.append({'address': row['address'], 'text': row['text'], 'use': kind, 'explanation': row['explanation']})
        if row['category'] == 'call':
            live -= {'RAX', 'XMM0'}  # the call's own result replaces them
        else:
            live -= defs
        if row['category'] in ('branch_conditional', 'branch_unconditional', 'return') or not live:
            if row['category'] == 'branch_conditional' and uses:
                uses[-1]['then'] = row['explanation']
            break
    return {'callsite': callsite, 'uses': uses,
            'note': None if uses else 'No use of the return register before it is overwritten or control leaves '
                                      'the straight-line code (the result may be ignored or used on a later path).'}
