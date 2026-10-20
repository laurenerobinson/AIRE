"""Conservative Intel-syntax x86 observations, not execution or a CPU model.

Value identities survive only a short straight-line window. Calls, branches,
unknown instructions, register aliases and memory writes invalidate tracking.
An identity establishes repeated local bits, never source authorship or input.
"""
import re

MAX_CHARS = 32000
MAX_INSTRUCTIONS = 512
MAX_OBSERVATIONS = 64
WINDOW = 16

FAMILIES = {
    **dict.fromkeys(('ADD', 'INC'), 'integer_addition'),
    **dict.fromkeys(('SUB', 'DEC'), 'integer_subtraction'),
    **dict.fromkeys(('MUL', 'IMUL'), 'integer_multiplication'),
    **dict.fromkeys(('DIV', 'IDIV'), 'integer_division'),
    'NEG': 'integer_negation', 'CMP': 'integer_comparison', 'TEST': 'bit_test',
    **{m: 'bitwise_' + n for m, n in [('AND', 'and'), ('OR', 'or'), ('XOR', 'xor'),
        ('NOT', 'not'), ('SHL', 'shift_left'), ('SAL', 'shift_left'),
        ('SHR', 'shift_right'), ('SAR', 'arithmetic_shift_right'),
        ('ROL', 'rotate_left'), ('ROR', 'rotate_right')]},
    **{op + suffix: 'scalar_' + precision + '_' + meaning
       for op, meaning in [('ADD', 'addition'), ('SUB', 'subtraction'),
           ('MUL', 'multiplication'), ('DIV', 'division'), ('SQRT', 'square_root'),
           ('COMI', 'comparison'), ('UCOMI', 'comparison')]
       for suffix, precision in [('SS', 'float'), ('SD', 'double')]},
}
MOVES = {'MOV', 'MOVZX', 'MOVSX', 'MOVSXD', 'MOVSS', 'MOVSD'}
KNOWN = MOVES | {'LEA', 'PUSH', 'POP', 'NOP', 'ENDBR64', 'ENDBR32', 'LEAVE',
                 'FLD', 'FSTP', 'CDQ', 'CQO', 'CLD'}
REGISTER = re.compile(r'^(?:[RE]?(?:AX|BX|CX|DX|SI|DI|BP|SP)|[ABCD][HL]|[SD]IL|[BS]PL|R\d+(?:D|W|B)?|XMM\d+)$')


def register_family(reg):
    for stem, aliases in {'A': ('RAX', 'EAX', 'AX', 'AH', 'AL'),
            'B': ('RBX', 'EBX', 'BX', 'BH', 'BL'), 'C': ('RCX', 'ECX', 'CX', 'CH', 'CL'),
            'D': ('RDX', 'EDX', 'DX', 'DH', 'DL'), 'SI': ('RSI', 'ESI', 'SI', 'SIL'),
            'DI': ('RDI', 'EDI', 'DI', 'DIL'), 'BP': ('RBP', 'EBP', 'BP', 'BPL'),
            'SP': ('RSP', 'ESP', 'SP', 'SPL')}.items():
        if reg in aliases:
            return stem
    return re.sub(r'([R][0-9]+)[DWB]$', r'\1', reg)


def parse_instructions(text):
    result, malformed = [], 0
    bounded = (text or '')[:MAX_CHARS]
    for number, line in enumerate(bounded.splitlines()[:MAX_INSTRUCTIONS * 2]):
        line = line.split(';', 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'(?:(?P<address>(?:\w+:)?[0-9a-fA-F]+):\s*)?(?P<mnemonic>[A-Za-z][A-Za-z0-9_.]*)\s*(?P<operands>[^\n]*)', line)
        if not match or len(line) > 1024:
            malformed += 1
            result.append({'address': None, 'line': number + 1, 'mnemonic': 'UNPARSED', 'operands': []})
            continue
        result.append({'address': match['address'], 'line': number + 1,
                       'mnemonic': match['mnemonic'].upper(),
                       'operands': [re.sub(r'\s+', '', p.upper()) for p in match['operands'].split(',') if p.strip()]})
        if len(result) >= MAX_INSTRUCTIONS:
            break
    return result, malformed, len(text or '') > MAX_CHARS or len(result) >= MAX_INSTRUCTIONS or len(bounded.splitlines()) > MAX_INSTRUCTIONS * 2


def extract_assembly(text, *, truncated=False, architecture='x86', resolved_calls=()):
    instructions, malformed, bounded = parse_instructions(text)
    supported_arch = bool(re.search(r'(?:x86|amd64|i[3-6]86)', architecture or '', re.I))
    observations, annotations, unknown = [], [], set()
    registers, versions = {}, {}
    counts = dict(conditional_branch_count=0, unconditional_branch_count=0, call_count=0,
                  return_count=0, backward_branch_count=0)
    calls = {}
    for row in resolved_calls:
        calls.setdefault(row['callsite_address'], []).append(row)
    targets = {i['operands'][0].removeprefix('0X').lower().lstrip('0')
               for i in instructions if i['mnemonic'].startswith('J') and i['operands']}
    return_values = []

    def clear():
        registers.clear()
        versions.clear()

    def read(operand, n, width='integer'):
        if REGISTER.fullmatch(operand):
            value = registers.get(operand)
            if value and n - value[1] <= WINDOW and value[2] == width:
                return value[0]
            return ('register', width, operand, versions.get(register_family(operand), 0))
        if '[' in operand:
            # Register versions prevent equality after a base/index changes.
            refs = re.findall(r'\b(?:R\d+[DWB]?|[RE](?:AX|BX|CX|DX|SI|DI|BP|SP))\b', operand)
            return ('memory', width, operand, tuple((r, versions.get(register_family(r), 0)) for r in refs))
        return ('literal', operand)

    def write(operand, value, n, width='integer'):
        if not REGISTER.fullmatch(operand):
            clear()  # Stores may alias any previously loaded memory.
            return
        family = register_family(operand)
        for reg in list(registers):
            if register_family(reg) == family:
                del registers[reg]
        versions[family] = versions.get(family, 0) + 1
        registers[operand] = (value, n, width)

    for n, ins in enumerate(instructions if supported_arch else []):
        mnemonic, operands = ins['mnemonic'], ins['operands']
        address = (ins['address'] or '').split(':')[-1].lower().lstrip('0')
        if address and address in targets:
            clear()  # No assumptions across a possible control-flow join.
        site = {'address': ins['address'], 'line': ins['line'], 'mnemonic': mnemonic}
        explanation = None
        family = FAMILIES.get(mnemonic)
        if family:
            width = 'double' if mnemonic.endswith('SD') else 'float' if mnemonic.endswith('SS') else 'integer'
            args = operands[-2:] if mnemonic == 'IMUL' and len(operands) == 3 else operands[:2]
            if len(args) == 1 and mnemonic in ('MUL', 'IMUL', 'DIV', 'IDIV'):
                args = ['RAX' if args[0].startswith('R') or 'QWORD' in args[0] else 'EAX', args[0]]
            same = (len(args) == 2 and read(args[0], n, width) == read(args[1], n, width))
            # Literal equality is not an input identity; immediates are still useful constants.
            same = same and not all(re.fullmatch(r'(?:0X[0-9A-F]+|\d+)', a) for a in args)
            row = {**site, 'operation_family': family, 'same_operand': bool(same)}
            if family.endswith('multiplication') and same:
                row['likely_pattern'] = 'value_squared'
            if len(args) == 2 and re.fullmatch(r'(?:0X[0-9A-F]+|\d+)', args[1]):
                row['constant_operand'] = args[1]
            if operands and operands[0] in ('ESP', 'RSP') and mnemonic in ('ADD', 'SUB'):
                row['context'] = 'stack_adjustment'
            if len(observations) < MAX_OBSERVATIONS:
                observations.append(row)
            explanation = family.replace('_', ' ')
            if mnemonic == 'IMUL':
                explanation = 'performs signed integer multiplication'
            elif mnemonic == 'MUL':
                explanation = 'performs unsigned integer multiplication'
            elif family.startswith('scalar_'):
                explanation = family.replace('scalar_double_', 'scalar double-precision floating-point ').replace(
                    'scalar_float_', 'scalar single-precision floating-point ').replace('_', ' ')
            if row.get('likely_pattern'):
                explanation += ' using the same locally tracked value twice (likely value squared)'
            if operands and mnemonic not in ('CMP', 'TEST', 'COMISS', 'COMISD', 'UCOMISS', 'UCOMISD'):
                write(operands[0], ('computed', n, family, row.get('likely_pattern')), n, width)
                if len(operands) == 1 and mnemonic in ('MUL', 'IMUL', 'DIV', 'IDIV'):
                    clear()  # Implicit wide accumulator/high-half effects are not modeled.
        elif mnemonic in MOVES and len(operands) == 2:
            # MOVSD without XMM operands can be a string copy, not scalar SSE.
            if mnemonic == 'MOVSD' and not any('XMM' in p for p in operands):
                clear()
            else:
                width = 'double' if mnemonic == 'MOVSD' else 'float' if mnemonic == 'MOVSS' else 'integer'
                value = read(operands[1], n, width)
                if mnemonic in ('MOVZX', 'MOVSX', 'MOVSXD'):
                    value = ('extended', mnemonic, value)
                write(operands[0], value, n, width)
            explanation = 'copies a value' if mnemonic in ('MOV', 'MOVSS', 'MOVSD') else 'extends a value to a wider register'
        elif mnemonic.startswith('CALL'):
            counts['call_count'] += 1
            operand = operands[0] if operands else ''
            indirect = '[' in operand or bool(REGISTER.fullmatch(operand))
            targets_at_site = calls.get(ins['address'], ()) if not indirect else ()
            resolved = targets_at_site[0] if len(targets_at_site) == 1 else None
            row = {**site, 'operation_family': 'call', 'resolution':
                   'resolved_stored_call' if resolved else 'indirect_call_unresolved' if indirect else
                   'ambiguous_stored_call' if len(targets_at_site) > 1 else 'direct_call_unresolved'}
            if resolved:
                row['resolved_edge'] = resolved
            if len(observations) < MAX_OBSERVATIONS:
                observations.append(row)
            clear()  # Includes memory: callees may modify any tracked source.
            explanation = 'transfers control to a callee; ' + row['resolution']
        elif mnemonic in ('RET', 'RETN', 'RETF'):
            counts['return_count'] += 1
            for reg in ('EAX', 'RAX', 'XMM0'):
                value = registers.get(reg)
                if value and n - value[1] <= WINDOW and value[0][0] == 'computed':
                    return_values.append({**site, 'register': reg, 'operation_family': value[0][2],
                                          'likely_pattern': value[0][3]})
            clear()
            explanation = 'returns to the caller; return-register candidates require ABI interpretation'
        elif mnemonic.startswith('J') or mnemonic.startswith('LOOP'):
            key = 'unconditional_branch_count' if mnemonic in ('JMP', 'JMPQ') else 'conditional_branch_count'
            counts[key] += 1
            try:
                counts['backward_branch_count'] += int(operands[0].removeprefix('0X'), 16) < int(ins['address'], 16)
            except (ValueError, TypeError, IndexError):
                pass
            clear()
            explanation = 'branches to another instruction; condition semantics are not reconstructed'
        elif mnemonic in KNOWN:
            if mnemonic == 'PUSH':
                # A stack write can alias a stack-relative source.
                clear()
            elif mnemonic == 'POP' and operands:
                write(operands[0], ('unknown_pop', n), n)
                versions['SP'] = versions.get('SP', 0) + 1
            elif mnemonic not in ('NOP', 'ENDBR64', 'ENDBR32', 'CLD'):
                clear()
            explanation = {'LEA': 'computes an address', 'FLD': 'loads a floating-point value onto the x87 stack',
                           'PUSH': 'pushes a value onto the stack', 'POP': 'restores a value from the stack'}.get(mnemonic)
        else:
            unknown.add(mnemonic)
            clear()
        # Movement is context; reserve annotation slots for behavior.
        if explanation and mnemonic not in MOVES and mnemonic not in ('PUSH', 'POP') and len(annotations) < MAX_OBSERVATIONS:
            annotations.append({**site, 'explanation': explanation})
    coverage = {'parsed_instructions': len(instructions), 'malformed_lines': malformed,
                'bounded': bounded, 'upstream_truncated': bool(truncated),
                'unsupported_architecture': not supported_arch,
                'unsupported_mnemonics': sorted(unknown)[:16],
                'observations_bounded': len(observations) == MAX_OBSERVATIONS}
    return {'observations': observations, 'important_instructions': annotations,
            'operation_families': sorted({r['operation_family'] for r in observations}),
            'sqrt_instruction_present': any(i['mnemonic'] in ('SQRTSS', 'SQRTSD') for i in instructions) if supported_arch else None,
            'control_flow': counts, 'return_register_candidates': return_values[:16], 'coverage': coverage}
