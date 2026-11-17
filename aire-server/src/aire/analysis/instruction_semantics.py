"""M10 Phase 1: deterministic instruction semantics from Ghidra facts.

Input: one function's stored structured facts (aire.pyghidra.instruction_ir).
Output: per-instruction semantic records and plain-English explanations that
state only what the instruction does at machine level. Classification is
derived from Ghidra P-code (LOAD/STORE/CBRANCH/CALL/RETURN, flag outputs);
the mnemonic is used only to name x86 condition relations, and that use is
recorded in the evidence. Source-level meanings (variable names/types) are
never asserted.

Supported: x86 and x86-64 (full, incl. condition relations); other Ghidra
languages get generic P-code explanations (reads/writes, loads/stores, branch
predicates over flags) marked as such. Legacy snapshots without facts can be
parsed from stored assembly text at lower confidence (no P-code).
"""
import re

FLAG_NAMES = ('CF', 'PF', 'AF', 'ZF', 'SF', 'OF', 'DF', 'TF', 'IF')
FRAME_POINTERS = {'RBP', 'EBP', 'BP'}
STACK_POINTERS = {'RSP', 'ESP', 'SP'}
PC_REGISTERS = {'RIP', 'EIP', 'IP'}
ARITHMETIC = {'INT_ADD': 'adds', 'INT_SUB': 'subtracts', 'INT_MULT': 'multiplies', 'INT_DIV': 'divides (unsigned)',
              'INT_SDIV': 'divides (signed)', 'INT_REM': 'takes the unsigned remainder',
              'INT_SREM': 'takes the signed remainder', 'INT_2COMP': 'negates', 'FLOAT_ADD': 'adds (floating point)',
              'FLOAT_SUB': 'subtracts (floating point)', 'FLOAT_MULT': 'multiplies (floating point)',
              'FLOAT_DIV': 'divides (floating point)', 'FLOAT_SQRT': 'takes the square root (floating point)'}
LOGIC = {'INT_AND': 'bitwise-ANDs', 'INT_OR': 'bitwise-ORs', 'INT_XOR': 'bitwise-XORs', 'INT_NEGATE': 'bitwise-inverts',
         'INT_LEFT': 'shifts left', 'INT_RIGHT': 'shifts right (logical)', 'INT_SRIGHT': 'shifts right (arithmetic)'}
SIZE_WORDS = {1: 'byte', 2: 'word (2 bytes)', 4: 'dword (4 bytes)', 8: 'qword (8 bytes)', 10: '10-byte',
              16: '16-byte'}
SIZE_BYTES = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8, 'tword': 10, 'xmmword': 16, 'ymmword': 32}
# Normalized CBRANCH flag predicates after CMP/SUB a, b (Intel semantics).
CMP_RELATIONS = {
    'ZF': ('==', None), '!ZF': ('!=', None),
    'CF': ('<', 'unsigned'), '!CF': ('>=', 'unsigned'), 'CF|ZF': ('<=', 'unsigned'), '!CF&!ZF': ('>', 'unsigned'),
    'OF!=SF': ('<', 'signed'), 'OF==SF': ('>=', 'signed'), '(OF!=SF)|ZF': ('<=', 'signed'),
    '!ZF&(OF==SF)': ('>', 'signed'),
}
# After TEST/AND/OR/XOR (CF and OF are cleared), flags describe the result.
TEST_RELATIONS = {'ZF': '{} == 0', '!ZF': '{} != 0', 'SF': '{} < 0 (signed)', '!SF': '{} >= 0 (signed)',
                  'OF!=SF': '{} < 0 (signed; OF is cleared)', 'OF==SF': '{} >= 0 (signed; OF is cleared)',
                  '(OF!=SF)|ZF': '{} <= 0 (signed; OF is cleared)', '!ZF&(OF==SF)': '{} > 0 (signed; OF is cleared)',
                  'CF|ZF': '{} == 0 (CF is cleared)', '!CF&!ZF': '{} != 0 (CF is cleared)'}
# UCOMIS*/COMIS*/FUCOMI*: ZF,PF,CF = 1,1,1 when unordered (a NaN operand).
FLOAT_COMPARES = {'UCOMISS', 'UCOMISD', 'COMISS', 'COMISD', 'FUCOMI', 'FUCOMIP', 'FCOMI', 'FCOMIP',
                  'VUCOMISS', 'VUCOMISD', 'VCOMISS', 'VCOMISD'}
FLOAT_RELATIONS = {'ZF': '{} == {} or unordered (floating point)', '!ZF': '{} != {} and ordered (floating point)',
                   'CF': '{} < {} or unordered (floating point)', '!CF': '{} >= {} and ordered (floating point)',
                   'CF|ZF': '{} <= {} or unordered (floating point)', '!CF&!ZF': '{} > {} and ordered (floating point)',
                   'PF': '{} and {} are unordered (a NaN operand)', '!PF': '{} and {} are ordered (no NaN operand)'}
# Instructions whose ZF describes the value they write (so 'result == 0' is accurate).
RESULT_FLAG_MNEMONICS = {'ADD', 'SUB', 'ADC', 'SBB', 'INC', 'DEC', 'NEG', 'AND', 'OR', 'XOR', 'SHL', 'SAL', 'SHR',
                         'SAR', 'ANDN', 'BLSR', 'BLSI', 'POPCNT', 'LZCNT', 'TZCNT'}
ABI_RETURN = {'x86:LE:64': 'RAX', 'x86:LE:32': 'EAX'}


def _vn(v):
    if v is None:
        return None
    if v['k'] == 'reg':
        return v['n']
    if v['k'] == 'const':
        return _hex(v.get('sv', v['v']))
    if v['k'] == 'tmp':
        return v['n']
    return f"{v.get('sp', 'mem')}:0x{v['a']}"


def _hex(value):
    return f'-0x{-value:x}' if value < 0 else f'0x{value:x}'


def _predicate_tree(ops, varnode, before=None, depth=0):
    """Boolean expression over flags from P-code defs preceding the use:
    ('flag', F) | ('not', x) | ('and', [..]) | ('or', [..]) | ('eq', a, b) |
    ('ne', a, b) | ('const', 0/1). None if not a pure flag expression."""
    if varnode is None or depth > 16:
        return None
    before = len(ops) if before is None else before
    if varnode['k'] == 'reg':
        return ('flag', varnode['n'])
    if varnode['k'] == 'const':
        return ('const', varnode['v'] & 1)
    if varnode['k'] != 'tmp':
        return None
    position = next((i for i in range(before - 1, -1, -1)
                     if ops[i]['out'] and ops[i]['out'].get('n') == varnode['n']), None)
    if position is None:
        return None
    definition = ops[position]
    args = [_predicate_tree(ops, i, position, depth + 1) for i in definition['in']]
    if any(a is None for a in args):
        return None
    op = definition['op']
    if op == 'BOOL_NEGATE':
        return ('not', args[0])
    if op in ('BOOL_AND', 'BOOL_OR'):
        return ('and' if op == 'BOOL_AND' else 'or', args)
    if op in ('INT_EQUAL', 'INT_NOTEQUAL'):
        return ('eq' if op == 'INT_EQUAL' else 'ne', args[0], args[1])
    if op == 'COPY':
        return args[0]
    return None


def _normalize(node, negate=False):
    kind = node[0]
    if kind == 'not':
        return _normalize(node[1], not negate)
    if kind == 'const':
        return ('const', node[1] ^ int(negate))
    if kind == 'flag':
        return ('not', node) if negate else node
    if kind in ('and', 'or'):
        flipped = {'and': 'or', 'or': 'and'}[kind] if negate else kind
        children = []
        for child in node[1]:
            normalized = _normalize(child, negate)
            children.extend(normalized[1] if normalized[0] == flipped else [normalized])
        return (flipped, children)
    if kind in ('eq', 'ne'):
        left, right = node[1], node[2]
        effective = kind if not negate else ('ne' if kind == 'eq' else 'eq')
        consts = [n for n in (left, right) if n[0] == 'const']
        others = [n for n in (left, right) if n[0] != 'const']
        if len(consts) == 1 and len(others) == 1:  # FLAG == 1 / FLAG == 0
            truth = consts[0][1] if effective == 'eq' else 1 - consts[0][1]
            return _normalize(others[0], negate=not truth)
        return (effective, _normalize(left), _normalize(right))
    return node


def _render(node):
    kind = node[0]
    if kind == 'flag':
        return node[1]
    if kind == 'const':
        return str(node[1])
    if kind == 'not':
        inner = _render(node[1])
        return '!' + inner if node[1][0] == 'flag' else f'!({inner})'
    if kind in ('eq', 'ne'):
        return ('==' if kind == 'eq' else '!=').join(sorted([_render(node[1]), _render(node[2])]))
    joiner = '&' if kind == 'and' else '|'
    parts = []
    for child in node[1]:
        text = _render(child)
        atomic = child[0] == 'flag' or (child[0] == 'not' and child[1][0] == 'flag')
        parts.append(text if atomic else f'({text})')
    return joiner.join(sorted(parts))


def _predicate(ops, varnode, before=None):
    tree = _predicate_tree(ops, varnode, before)
    return _render(_normalize(tree)) if tree is not None else None


def _flag_reads(ops):
    return sorted({i['n'] for op in ops for i in op['in'] if i['k'] == 'reg' and i['n'] in FLAG_NAMES})


def _region(mem, instruction):
    """Classify an operand's addressing without asserting source meaning."""
    if mem is None:
        return None
    base, index = mem.get('base'), mem.get('index')
    disp = mem.get('disp') or 0
    if mem.get('absolute') is not None and base is None and index is None:
        return {'kind': 'global', 'address': f"{mem['absolute']:08x}", 'text': f"absolute address 0x{mem['absolute']:x}"}
    if base in PC_REGISTERS and index is None:
        target = int(instruction['a'], 16) + instruction['len'] + disp
        return {'kind': 'pc_relative', 'address': f'{target:08x}',
                'text': f'PC-relative address 0x{target:x} (next instruction + {_hex(disp)})'}
    expression = base or ''
    if index:
        expression += (' + ' if expression else '') + index + (f"*{mem['scale']}" if mem.get('scale', 1) != 1 else '')
    if disp:
        expression += f' {"-" if disp < 0 else "+"} 0x{abs(disp):x}' if expression else _hex(disp)
    if base in FRAME_POINTERS and index is None:
        kind, note = 'frame', 'frame-pointer-relative stack slot'
    elif base in STACK_POINTERS and index is None:
        kind, note = 'stack', 'stack-pointer-relative stack slot'
    elif index is not None:
        kind, note = 'indexed', f'indexed memory (base {base or "none"}, index {index})'
    else:
        kind, note = 'indirect', f'memory addressed through {base}'
    return {'kind': kind, 'expression': expression, 'text': f'{expression} ({note})',
            'base': base, 'index': index, 'disp': disp}


def _memory_operand(instruction):
    for position, operand in enumerate(instruction['ops']):
        if operand.get('mem'):
            return position, operand
    return None, None


def _registers(ops, side):
    """Registers written, or read before being written within this instruction
    (an input that the instruction itself produced earlier is not an input)."""
    names, written = [], set()
    for op in ops:
        if side == 'read':
            for v in op['in']:
                if v and v['k'] == 'reg' and v['n'] not in names and v['n'] not in written:
                    names.append(v['n'])
        if op['out'] and op['out']['k'] == 'reg':
            if side == 'write' and op['out']['n'] not in names:
                names.append(op['out']['n'])
            written.add(op['out']['n'])
    return names


class FunctionContext:
    """Lookups an explanation may cite: names by address, references by
    instruction address, callee return storage. All from stored facts."""

    def __init__(self, function_names=None, references=None, callee_return=None, language=''):
        self.function_names = function_names or {}
        self.references = references or {}
        self.callee_return = callee_return or (lambda address: None)
        self.language = language

    @property
    def x86(self):
        return self.language.startswith('x86')

    def abi_return(self):
        for prefix, register in ABI_RETURN.items():
            if self.language.startswith(prefix):
                return register
        return None


def analyze_instruction(instruction, context, previous=()):
    """Semantic record for one instruction. previous = earlier instructions in
    the same basic block (nearest last), used only to find the flag setter."""
    ops = instruction.get('pcode') or []
    opcodes = [op['op'] for op in ops]
    mnemonic = instruction['m'].upper()
    # Direct memory (absolute/PC-relative operands) appears as RAM varnodes, not LOAD/STORE.
    data_ops = [op for op in ops if op['op'] not in ('BRANCH', 'CBRANCH', 'BRANCHIND', 'CALL', 'CALLIND', 'RETURN')]
    direct_read = any(v['k'] == 'mem' for op in data_ops for v in op['in'])
    direct_write = any(op['out'] and op['out']['k'] == 'mem' for op in data_ops)
    loads, stores = 'LOAD' in opcodes or direct_read, 'STORE' in opcodes or direct_write
    position, mem_operand = _memory_operand(instruction)
    region = _region(mem_operand['mem'], instruction) if mem_operand else None
    reg_reads = [r for r in _registers(ops, 'read') if r not in FLAG_NAMES]
    reg_writes = [r for r in _registers(ops, 'write') if r not in FLAG_NAMES]
    flags_written = [r for r in _registers(ops, 'write') if r in FLAG_NAMES]
    flags_read = _flag_reads(ops)
    constants = []
    for operand in instruction['ops']:
        if operand['kinds'] == ['SCAL'] or 'SCAL' in operand['kinds'] and 'mem' not in operand:
            try:
                constants.append(int(operand['text'], 0))
            except ValueError:
                pass
    record = {
        'address': instruction['a'], 'text': instruction['t'], 'mnemonic': mnemonic,
        'reads': {'registers': reg_reads, 'flags': flags_read, 'memory': region if loads else None},
        'writes': {'registers': reg_writes, 'flags': flags_written, 'memory': region if stores else None},
        'constants': constants, 'references': context.references.get(instruction['a'], []),
        'branch': None, 'call': None, 'category': 'other', 'pcode_ops': opcodes,
        'evidence_source': 'ghidra_pcode' if ops else 'assembly_text', 'confidence': 'high' if ops else 'low',
        'notes': [],
    }
    size_word = None
    if mem_operand:
        size_word = mem_operand['mem'].get('size')
    data_width = SIZE_WORDS.get(SIZE_BYTES.get(size_word or '', 0), size_word or 'value')

    branch_op = next((op for op in ops if op['op'] in ('CBRANCH', 'BRANCH', 'BRANCHIND')), None)
    # Ghidra's flow type is authoritative: a CBRANCH inside an instruction that
    # Ghidra does not treat as a jump only skips part of that instruction.
    internal_skip = branch_op is not None and branch_op['op'] == 'CBRANCH' and not instruction.get('jump') \
        and 'pcode' in instruction and instruction.get('flow') is not None
    if internal_skip:
        branch_op = None  # P-code-internal skip (CMOVcc, BSR, REP...), not control flow
    call_op = next((op for op in ops if op['op'] in ('CALL', 'CALLIND')), None)
    return_op = next((op for op in ops if op['op'] == 'RETURN'), None)
    if not ops and instruction.get('source') != 'legacy':
        record['notes'].append('No P-code stored for this instruction; mnemonic-only interpretation.')
    if mnemonic.startswith('NOP') or mnemonic in ('ENDBR64', 'ENDBR32', 'PAUSE'):
        record['category'] = 'no_operation'
        record['explanation'] = 'Performs no data operation (padding, alignment or control-flow-enforcement marker).'
        return record

    if (call_op or instruction.get('call')) and mnemonic.startswith('JMP'):
        target = instruction['targets'][0] if instruction.get('targets') else None
        name = context.function_names.get(target) if target else None
        imports = [r['value'] for r in record['references'] if r.get('kind') == 'IMPORT']
        record['category'] = 'tail_call'
        record['call'] = {'target': target, 'target_name': name or (imports[0] if imports else None),
                          'indirect': bool(instruction.get('computed')), 'return_storage': None, 'return_address': None}
        via = f"through {instruction['ops'][0]['text']}" if instruction.get('computed') and instruction['ops'] else ''
        who = record['call']['target_name'] or (f'0x{target}' if target else 'a computed target')
        record['explanation'] = (f'Jumps {via + " " if via else ""}to {who} without pushing a return address (tail jump): '
                                 "the target returns directly to this function's caller.")
        return record
    if call_op or instruction.get('call'):
        target = instruction['targets'][0] if instruction.get('targets') else None
        name = context.function_names.get(target) if target else None
        imports = [r['value'] for r in record['references'] if r.get('kind') == 'IMPORT']
        returned = context.callee_return(target) if target else None
        abi = context.abi_return()
        record['category'] = 'call'
        record['call'] = {'target': target, 'target_name': name or (imports[0] if imports else None),
                          'indirect': bool(instruction.get('computed')) or (call_op and call_op['op'] == 'CALLIND'),
                          'return_storage': returned or (f'{abi} (ABI convention, not callee-specific)' if abi else None),
                          'return_address': instruction.get('ft')}
        how = 'indirectly through ' + (instruction['ops'][0]['text'] if instruction['ops'] else 'a computed address') \
            if record['call']['indirect'] else f"0x{target}" if target else 'an unresolved target'
        who = f" ({record['call']['target_name']})" if record['call']['target_name'] else ''
        record['explanation'] = (f"Calls {how}{who}; execution resumes at 0x{instruction['ft']} after it returns"
                                 if instruction.get('ft') else f"Calls {how}{who}") + \
            (f"; a return value, if any, is in {record['call']['return_storage']}." if record['call']['return_storage'] else '.')
        return record

    if return_op or (instruction.get('term') and mnemonic.startswith('RET')):
        record['category'] = 'return'
        record['explanation'] = 'Returns to the caller (pops the return address from the stack).'
        return record

    if internal_skip and mnemonic.startswith('CMOV'):
        skip = next(op for op in ops if op['op'] == 'CBRANCH')
        tree = _predicate_tree(ops, skip['in'][1], ops.index(skip)) if len(skip['in']) > 1 else None
        move_when = _render(_normalize(tree, negate=True)) if tree is not None else None
        relation = condition_relation(move_when, previous, context) if move_when else None
        destination = instruction['ops'][0]['text'] if instruction['ops'] else '?'
        source = instruction['ops'][1]['text'] if len(instruction['ops']) > 1 else '?'
        record['category'] = 'conditional_move'
        record['conditional_move'] = {'predicate': move_when, 'relation': relation}
        when = f'the flag condition {move_when} holds' if move_when else 'its flag condition holds'
        if relation and relation.get('text'):
            when += f", i.e. when {relation['text']} (flags set by {relation['setter_text']} at 0x{relation['setter']})"
        record['explanation'] = f'Copies {source} into {destination} only when {when}; otherwise {destination} is unchanged.'
        return record
    if mnemonic.startswith('SET') and instruction['ops'] and not loads:
        destination = instruction['ops'][0]['text']
        definition = next((i for i in range(len(ops) - 1, -1, -1) if ops[i]['out'] and ops[i]['out']['k'] == 'reg'
                           and ops[i]['out']['n'] not in FLAG_NAMES), None)
        tree = _predicate_tree(ops, ops[definition]['in'][0], definition) if definition is not None and ops[definition]['in'] else None
        predicate = _render(_normalize(tree)) if tree is not None else None
        relation = condition_relation(predicate, previous, context) if predicate else None
        record['category'] = 'conditional_set'
        record['conditional_set'] = {'predicate': predicate, 'relation': relation}
        when = f'the flag condition {predicate} holds' if predicate else 'its flag condition holds'
        if relation and relation.get('text'):
            when += f", i.e. when {relation['text']} (flags set by {relation['setter_text']} at 0x{relation['setter']})"
        record['explanation'] = f'Sets {destination} to 1 when {when}, otherwise to 0.'
        return record
    if branch_op or instruction.get('jump'):
        target = instruction['targets'][0] if instruction.get('targets') else None
        conditional = bool(instruction.get('cond')) or (branch_op and branch_op['op'] == 'CBRANCH')
        record['category'] = 'branch_conditional' if conditional else ('branch_indirect' if instruction.get('computed')
                                                                         else 'branch_unconditional')
        branch = {'target': target, 'fallthrough': instruction.get('ft') if conditional else None,
                  'conditional': conditional, 'predicate': None, 'relation': None}
        if conditional and branch_op:
            branch['predicate'] = _predicate(ops, branch_op['in'][1], ops.index(branch_op)) if len(branch_op['in']) > 1 else None
            branch['relation'] = condition_relation(branch['predicate'], previous, context)
        record['branch'] = branch
        if not conditional:
            record['explanation'] = (f'Jumps unconditionally to 0x{target}.' if target else
                                     f"Jumps indirectly to an address computed from {instruction['ops'][0]['text'] if instruction['ops'] else 'a register'}.")
        else:
            condition = f"the flag condition {branch['predicate']} holds" if branch['predicate'] else 'its flag condition holds'
            relation = branch['relation']
            if relation and relation.get('text'):
                condition += f", i.e. when {relation['text']} (flags set by {relation['setter_text']} at 0x{relation['setter']})"
            elif relation:
                record['notes'].append(relation.get('note', 'Flag setter not found in this basic block.'))
            record['explanation'] = (f'Jumps to 0x{target} when {condition}; otherwise continues at '
                                     f"0x{branch['fallthrough']}.")
        return record

    if mnemonic == 'PUSH' and stores and 'RSP' in reg_writes + reg_reads or mnemonic == 'PUSH' and stores:
        record['category'] = 'stack_push'
        source = instruction['ops'][0]['text'] if instruction['ops'] else 'a value'
        record['explanation'] = f'Pushes {source} onto the stack (decrements the stack pointer, then stores it).'
        return record
    if mnemonic == 'POP' and loads:
        record['category'] = 'stack_pop'
        target = instruction['ops'][0]['text'] if instruction['ops'] else 'a register'
        record['explanation'] = f'Pops the top of the stack into {target} (loads it, then increments the stack pointer).'
        return record

    flag_only = flags_written and not reg_writes and not stores
    if flag_only and any(op['op'] in ('INT_SUB', 'INT_AND', 'FLOAT_LESS', 'FLOAT_EQUAL') for op in ops):
        is_test = any(op['op'] == 'INT_AND' for op in ops) and not any(op['op'] == 'INT_SUB' for op in ops)
        left = instruction['ops'][0]['text'] if instruction['ops'] else '?'
        right = instruction['ops'][1]['text'] if len(instruction['ops']) > 1 else '?'
        record['category'] = 'test' if is_test else 'compare'
        record['compare'] = {'left': left, 'right': right, 'kind': 'and' if is_test else 'subtract'}
        if is_test:
            what = f'tests {left} against itself' if left == right else f'bitwise-ANDs {left} with {right}'
            record['explanation'] = (f"{_upper_first(what)} without storing the result, setting flags "
                                     f"({', '.join(flags_written)}).")
        elif mnemonic in FLOAT_COMPARES:
            record['compare']['kind'] = 'floating_point'
            record['explanation'] = (f'Compares {left} with {right} as floating-point values (no result stored), '
                                     f"setting flags ({', '.join(flags_written)}); ZF, PF and CF are all set if either "
                                     'operand is NaN (unordered).')
        else:
            record['explanation'] = (f'Compares {left} with {right} by subtraction without storing the result, '
                                     f"setting flags ({', '.join(flags_written)}).")
        return record

    destination = instruction['ops'][0]['text'] if instruction['ops'] else None
    source = instruction['ops'][1]['text'] if len(instruction['ops']) > 1 else None
    if mem_operand and not loads and not stores and region:
        record['category'] = 'address_calculation'
        record['explanation'] = (f"Computes the address {region['text']} and writes it to {destination}; "
                                 'no memory is read.')
        _cite_references(record)
        return record
    if loads and stores:
        record['category'] = 'memory_read_modify_write'
        record['explanation'] = f"Reads a {data_width} at {region['text'] if region else 'memory'}, updates it, and writes it back."
        _append_operation(record, ops, source)
        return record
    if loads:
        record['category'] = 'memory_load'
        computing = [op for op in _relevant_ops(ops) if op['op'] in ARITHMETIC or op['op'] in LOGIC]
        if computing and not mnemonic.startswith('MOV') and destination and position != 0:
            phrase = _two_operand_phrase(computing[0]['op'], destination,
                                         f"the {data_width} at {region['text'] if region else 'memory'}")
            if phrase:
                record['category'] = 'memory_load'
                record['explanation'] = (f'{phrase} (memory operand read); the result is written to {destination}'
                                         + (f"; sets flags ({', '.join(flags_written)})." if flags_written else '.'))
                return record
        extra = _operation_phrase(ops)
        if extra and not extra.startswith(('zero-extends', 'sign-extends')) and mnemonic.startswith('MOV'):
            extra = None  # a MOV load performs no arithmetic on the value
        record['explanation'] = (f"Reads a {data_width} value from memory at {region['text'] if region else 'an address'}"
                                 + (f', {extra},' if extra else '') + f" and writes it to {destination}.")
        return record
    if stores:
        record['category'] = 'memory_store'
        what = source if source else 'a value'
        record['explanation'] = f"Writes {what} as a {data_width} to memory at {region['text'] if region else 'an address'}."
        return record
    relevant = _relevant_ops(ops)
    computing = [op for op in relevant if op['op'] in ARITHMETIC or op['op'] in LOGIC]
    kinds = list(dict.fromkeys(op['op'] for op in computing))
    lane_write = any(re.match(r'^(?:[XYZ]MM\d+_|MM\d)', r) for r in reg_writes)
    if mnemonic in ('XOR', 'SUB', 'PXOR', 'XORPS', 'XORPD', 'VPXOR', 'VXORPS', 'VXORPD') and destination \
            and destination == source and reg_writes:
        record['category'] = 'zeroing'
        record['explanation'] = (f'Sets {destination} to zero ({mnemonic} of a register with itself)'
                                 + (' and sets flags.' if flags_written else '.'))
        return record
    if lane_write or (len(kinds) > 1):
        record['category'] = 'vector' if lane_write else 'compound'
        operands = ', '.join(o['text'] for o in instruction['ops'])
        sequence = ' → '.join(kinds) if kinds else ', '.join(dict.fromkeys(op['op'] for op in relevant)) or 'none'
        record['explanation'] = ((f'Performs the vector (SIMD) operation {mnemonic} {operands}; ' if lane_write else
                                  f'Performs the compound operation {mnemonic} {operands}; ')
                                 + f'P-code steps: {sequence}; writes {", ".join(reg_writes) or "no registers"}'
                                 + (f"; sets flags ({', '.join(flags_written)})." if flags_written else '.'))
        record['confidence'] = 'medium'
        record['notes'].append('Multi-step or lane-wise semantics are listed as P-code steps, not paraphrased.')
        return record
    arithmetic = next((op for op in computing if op['op'] in ARITHMETIC), None)
    logic = next((op for op in computing if op['op'] in LOGIC), None)
    if arithmetic or logic:
        op = arithmetic or logic
        verb = (ARITHMETIC.get(op['op']) or LOGIC.get(op['op']))
        record['category'] = 'arithmetic' if arithmetic else 'logic'
        operands = ', '.join(o['text'] for o in instruction['ops'])
        phrase = _two_operand_phrase(op['op'], destination, source) if len(instruction['ops']) == 2 else None
        record['explanation'] = ((f"{phrase}; the result is written to {op['out']['n']}" if phrase else
                                  f"{_upper_first(verb)} ({instruction['m']} {operands}) and writes the result to {op['out']['n']}")
                                 + (f"; sets flags ({', '.join(flags_written)})." if flags_written else '.'))
        return record
    if relevant and all(op['op'] in ('COPY', 'INT_ZEXT', 'INT_SEXT', 'SUBPIECE', 'PIECE') for op in relevant) and reg_writes:
        record['category'] = 'data_move'
        extension = ' with zero extension' if 'INT_ZEXT' in opcodes and mnemonic.startswith('MOVZX') else \
            ' with sign extension' if 'INT_SEXT' in opcodes else ''
        record['explanation'] = f'Copies {source or "a value"} into {destination}{extension}.'
        _cite_references(record)
        return record
    if not ops and mnemonic in ('NOP', 'ENDBR64', 'ENDBR32') or opcodes == []:
        record['category'] = 'no_operation' if mnemonic in ('NOP', 'ENDBR64', 'ENDBR32') else 'other'
        record['explanation'] = ('Performs no data operation (padding or control-flow-enforcement marker).'
                                 if record['category'] == 'no_operation' else
                                 f"{instruction['t']}: no P-code semantics available.")
        return record
    record['explanation'] = (f"{instruction['t']}: P-code {', '.join(dict.fromkeys(opcodes))}; reads "
                             f"{', '.join(reg_reads) or 'no registers'}, writes {', '.join(reg_writes) or 'no registers'}.")
    record['confidence'] = 'medium'
    record['notes'].append('Generic P-code description; no specific template for this instruction.')
    return record


def _cite_references(record):
    for reference in record['references']:
        if reference['kind'] == 'STRING':
            value = reference['value'] if len(reference['value']) <= 60 else reference['value'][:57] + '...'
            record['explanation'] = record['explanation'][:-1] + \
                f' — 0x{reference["target"]} is the address of the string "{value}".'
            return
        if reference['kind'] == 'IMPORT':
            record['explanation'] = record['explanation'][:-1] + f' — references import {reference["value"]}.'
            return


def _relevant_ops(ops):
    """P-code ops contributing to non-flag register results or memory stores
    (backward slice inside the instruction); flag bookkeeping and address
    arithmetic are excluded."""
    skip = _address_temporaries(ops)
    live, relevant = set(), []
    for op in reversed(ops):
        out = op['out']
        contributes = op['op'] == 'STORE' or (out is not None and (
            (out['k'] == 'reg' and out['n'] not in FLAG_NAMES) or (out['k'] == 'tmp' and out['n'] in live)))
        if out is not None and out['k'] == 'tmp' and out['n'] in skip:
            contributes = False
        if not contributes:
            continue
        relevant.append(op)
        inputs = op['in'][2:] if op['op'] == 'STORE' else op['in'][1:] if op['op'] == 'LOAD' else op['in']
        live.update(i['n'] for i in inputs if i['k'] == 'tmp')
    relevant = list(reversed(relevant))
    # x86 shift/rotate count masking (count & 0x1f / 0x3f) is not a data operation.
    counts = {op['in'][1]['n'] for op in relevant if op['op'] in ('INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT')
              and len(op['in']) > 1 and op['in'][1]['k'] == 'tmp'}
    return [op for op in relevant if not (op['op'] == 'INT_AND' and op['out'] and op['out']['k'] == 'tmp'
                                          and op['out']['n'] in counts)]


def _address_temporaries(ops):
    """P-code temporaries used only as LOAD/STORE addresses (address arithmetic)."""
    return {op['in'][1]['n'] for op in ops if op['op'] in ('LOAD', 'STORE') and len(op['in']) > 1
            and op['in'][1]['k'] == 'tmp'}


def _data_ops(ops):
    skip = _address_temporaries(ops)
    return [op for op in ops if not (op['out'] and op['out']['k'] == 'tmp' and op['out']['n'] in skip)]


def _operation_phrase(ops, operand=None):
    for op in _data_ops(ops):
        if op['op'] in ARITHMETIC or op['op'] in LOGIC:
            verb = ARITHMETIC.get(op['op']) or LOGIC.get(op['op'])
            return f'{verb} {operand} {"to" if op["op"] == "INT_ADD" else "with" if op["op"] in LOGIC else "from" if op["op"] == "INT_SUB" else "by"} it' \
                if operand else f'{verb} it'
        if op['op'] == 'INT_ZEXT':
            return 'zero-extends it'
        if op['op'] == 'INT_SEXT':
            return 'sign-extends it'
    return None


def _append_operation(record, ops, operand=None):
    phrase = _operation_phrase(ops, operand)
    if phrase:
        record['explanation'] = record['explanation'].replace(', updates it,', f', {phrase},')


def _upper_first(text):
    return text[:1].upper() + text[1:]


def _two_operand_phrase(op_name, destination, source):
    templates = {'INT_ADD': 'Adds {s} to {d}', 'INT_SUB': 'Subtracts {s} from {d}', 'INT_MULT': 'Multiplies {d} by {s}',
                 'INT_AND': 'Bitwise-ANDs {d} with {s}', 'INT_OR': 'Bitwise-ORs {d} with {s}',
                 'INT_XOR': 'Bitwise-XORs {d} with {s}', 'INT_LEFT': 'Shifts {d} left by {s}',
                 'INT_RIGHT': 'Shifts {d} right (logical) by {s}', 'INT_SRIGHT': 'Shifts {d} right (arithmetic) by {s}'}
    template = templates.get(op_name)
    return template.format(d=destination, s=source) if template and destination and source else None


def condition_relation(predicate, previous, context):
    """Relate a flag predicate to the nearest preceding flag setter in the block."""
    if predicate is None:
        return {'note': 'Branch condition could not be reconstructed from P-code.'}
    needed = set(re.findall(r'[A-Z]F', predicate))
    for prior in reversed(previous):
        written = {v['n'] for op in prior.get('pcode', []) for v in [op['out']] if v and v['k'] == 'reg'}
        if not needed & written:
            continue
        if not needed <= written:
            return {'note': f"Flags {', '.join(sorted(needed))} were last set by different instructions; relation not derived.",
                    'setter': prior['a'], 'setter_text': prior['t']}
        mnemonic = prior['m'].upper()
        left = prior['ops'][0]['text'] if prior['ops'] else '?'
        right = prior['ops'][1]['text'] if len(prior['ops']) > 1 else None
        result = {'setter': prior['a'], 'setter_text': prior['t'], 'predicate': predicate, 'text': None,
                  'across_blocks': bool(prior.get('_from_predecessor')),
                  'basis': 'P-code flag predicate; x86 relation table' if context.x86 else 'P-code flag predicate'}
        if not context.x86:
            result['text'] = f'{predicate} (flags from {prior["t"]})'
            return result
        if mnemonic in ('CMP', 'SUB') and right is not None and predicate in CMP_RELATIONS:
            operator, signedness = CMP_RELATIONS[predicate]
            result['text'] = f"{left} {operator} {right}" + (f' ({signedness})' if signedness else '')
        elif mnemonic in FLOAT_COMPARES and right is not None and predicate in FLOAT_RELATIONS:
            result['text'] = FLOAT_RELATIONS[predicate].format(left, right)
        elif mnemonic in ('TEST', 'AND', 'OR', 'XOR') and right is not None and predicate in TEST_RELATIONS:
            subject = left if left == right else f'({left} {"&" if mnemonic in ("TEST", "AND") else "|" if mnemonic == "OR" else "^"} {right})'
            result['text'] = TEST_RELATIONS[predicate].format(subject)
        elif predicate in ('ZF', '!ZF') and mnemonic in RESULT_FLAG_MNEMONICS:
            result['text'] = f"the result of {prior['t']} {'==' if predicate == 'ZF' else '!='} 0"
        else:
            result['note'] = f'Flag predicate {predicate} after {mnemonic} has no relation template; flags reported only.'
        return result
    return {'note': f"No instruction earlier in this basic block sets {', '.join(sorted(needed))}; "
                    'the flags come from a predecessor block.'}


def block_of(blocks, address):
    value = int(address, 16)
    for block in blocks:
        if int(block['start'], 16) <= value <= int(block['end'], 16):
            return block
    return None


def analyze_function(document, context, start=None, limit=None):
    """Semantic records for a function (optionally a window). Preceding
    instructions of the same basic block are supplied for flag linking."""
    instructions = document.get('instructions', [])
    blocks = document.get('blocks', [])
    records, block_start, history = [], None, []
    # Flags may come from a block's unique predecessor (flags survive branches).
    by_block, predecessors = {}, {}
    for instruction in instructions:
        block = block_of(blocks, instruction['a']) if blocks else None
        if block:
            by_block.setdefault(block['start'], []).append(instruction)
    for block in blocks:
        for edge in block['succ']:
            if not edge['flow'].endswith('CALL'):
                predecessors.setdefault(edge['to'], set()).add(block['start'])
    begin = 0
    if start is not None:
        begin = next((i for i, ins in enumerate(instructions) if ins['a'] == start), 0)
    for index, instruction in enumerate(instructions):
        block = block_of(blocks, instruction['a']) if blocks else None
        if block is None or block['start'] != block_start:
            block_start = block['start'] if block else None
            preds = predecessors.get(block_start, set())
            # Shallow copies: never mutate the cached function facts.
            history = [dict(prior, _from_predecessor=True) for prior in by_block.get(next(iter(preds)), [])] \
                if len(preds) == 1 else []
        if index >= begin and (limit is None or len(records) < limit):
            record = analyze_instruction(instruction, context, history)
            record['block'] = block['start'] if block else None
            records.append(record)
        history.append(instruction)
        if limit is not None and len(records) >= limit:
            break
    return records


_ASM_LINE = re.compile(r'^([0-9a-fA-F:]+):\s+(\S+)\s*(.*)$')


def legacy_document(assembly_text, language=''):
    """Low-confidence pseudo-facts parsed from stored assembly text (snapshots
    indexed before M10). No P-code, no blocks; explanations say so."""
    from aire.pyghidra.instruction_ir import memory_operand
    instructions = []
    for line in (assembly_text or '').splitlines():
        match = _ASM_LINE.match(line.strip())
        if not match:
            continue
        address, mnemonic, rest = match.groups()
        operands = [o.strip() for o in rest.split(',')] if rest else []
        upper = mnemonic.upper()
        jump = upper.startswith('J')
        target = re.match(r'0x([0-9a-fA-F]+)$', operands[0]) if operands else None
        instructions.append({'a': address, 'm': upper, 't': f'{mnemonic} {rest}'.strip(), 'len': 0,
                             'ops': [{'text': o, 'kinds': ['SCAL'] if re.fullmatch(r'-?0x[0-9a-fA-F]+|\d+', o) else [],
                                      **({'mem': memory_operand(o)} if '[' in o else {})} for o in operands],
                             'call': upper == 'CALL', 'jump': jump, 'cond': jump and upper != 'JMP',
                             'term': upper.startswith('RET'), 'computed': bool(operands) and not target and (jump or upper == 'CALL'),
                             'targets': [target.group(1).lower().zfill(8)] if target else [], 'ft': None, 'pcode': []})
    return {'version': 0, 'source': 'assembly_text', 'language': language, 'instructions': instructions,
            'blocks': [], 'signature': {}, 'truncated': None}
