"""Independent ground truth from GNU objdump (binutils), never from Ghidra or a model.

Parses `objdump -d -M intel --no-show-raw-insn` for x86/x86-64 ELF and PE files
(static disassembly only; the target is never executed) and provides:
* per-function instruction lists (address, mnemonic, operands);
* branch/call targets;
* a textbook-x86 oracle for conditional-branch relations: nearest preceding
  flag-setting cmp/test in linear order within the function, with no
  intervening flag writer or control transfer.
"""
import re
import subprocess

_FUNCTION = re.compile(r'^([0-9a-f]+) <([^>]+)>:$')
_LINE = re.compile(r'^\s*([0-9a-f]+):\s+(.*)$')
_TARGET = re.compile(r'^(?:0x)?([0-9a-f]+)(?:\s+<[^>]*>)?$')
PREFIXES = ('rex', 'rex.w', 'rex.W', 'rex.b', 'rex.r', 'rex.x', 'bnd', 'notrack', 'lock', 'rep', 'repz', 'repnz', 'repe', 'repne', 'data16', 'cs', 'ds', 'es', 'ss', 'addr32')

# objdump spelling -> Ghidra spelling (condition-code synonyms).
ALIASES = {
    'je': 'jz', 'jne': 'jnz', 'jb': 'jc', 'jnae': 'jc', 'jae': 'jnc', 'jnb': 'jnc', 'jnbe': 'ja', 'jna': 'jbe',
    'jnge': 'jl', 'jnl': 'jge', 'jng': 'jle', 'jnle': 'jg', 'jpe': 'jp', 'jpo': 'jnp',
    'cmove': 'cmovz', 'cmovne': 'cmovnz', 'cmovb': 'cmovc', 'cmovae': 'cmovnc', 'cmovnb': 'cmovnc',
    'sete': 'setz', 'setne': 'setnz', 'setb': 'setc', 'setae': 'setnc', 'movabs': 'mov',
    'xchg ax,ax': 'nop', 'retq': 'ret', 'callq': 'call', 'jmpq': 'jmp', 'leaveq': 'leave', 'pushq': 'push', 'popq': 'pop',
}
# Textbook relation for jcc after `cmp a, b` (Intel operand order).
CMP_JCC = {'jz': ('==', None), 'jnz': ('!=', None), 'jc': ('<', 'unsigned'), 'jnc': ('>=', 'unsigned'),
           'jbe': ('<=', 'unsigned'), 'ja': ('>', 'unsigned'), 'jl': ('<', 'signed'), 'jge': ('>=', 'signed'),
           'jle': ('<=', 'signed'), 'jg': ('>', 'signed')}
# After test, the signed-condition jumps compare the AND result with 0 (signed).
TEST_JCC = {'jz': ('==', None), 'jnz': ('!=', None), 'js': ('<', 'signed'), 'jns': ('>=', 'signed'),
            'jle': ('<=', 'signed'), 'jg': ('>', 'signed'), 'jl': ('<', 'signed'), 'jge': ('>=', 'signed')}
FLAG_WRITERS = {'add', 'sub', 'adc', 'sbb', 'and', 'or', 'xor', 'cmp', 'test', 'inc', 'dec', 'neg', 'shl', 'shr',
                'sar', 'sal', 'rol', 'ror', 'imul', 'mul', 'bsr', 'bsf', 'bt', 'ucomiss', 'ucomisd', 'comiss',
                'comisd', 'fucomi', 'fucomip', 'fcomi', 'fcomip', 'popcnt', 'lzcnt', 'tzcnt', 'bts', 'btr', 'btc', 'cmpxchg', 'xadd', 'shld', 'shrd', 'sahf'}


def normalize_mnemonic(mnemonic):
    mnemonic = mnemonic.lower()
    return ALIASES.get(mnemonic, mnemonic)


def disassemble(path, objdump='objdump'):
    """{function_name: {'address': hex8, 'instructions': [{'a','m','ops','target'}]}}"""
    output = subprocess.run([objdump, '-d', '-M', 'intel', '--no-show-raw-insn', str(path)],
                            capture_output=True, text=True, check=True).stdout
    functions, current = {}, None
    for line in output.splitlines():
        header = _FUNCTION.match(line)
        if header:
            current = {'address': header.group(1)[-8:].rjust(8, '0'), 'instructions': []}
            functions[header.group(2)] = current
            continue
        match = _LINE.match(line)
        if not match or current is None:
            continue
        address, body = match.groups()
        body = body.split('#')[0].strip()
        if not body or body.startswith('(bad)'):
            continue
        parts = body.split()
        while parts and parts[0] in PREFIXES and len(parts) > 1:
            parts = parts[1:]
        mnemonic = normalize_mnemonic(parts[0])
        operands = ' '.join(parts[1:])
        target = None
        if mnemonic.startswith(('j', 'call', 'loop')):
            found = _TARGET.match(operands)
            if found:
                target = found.group(1)[-8:].rjust(8, '0')
        current['instructions'].append({'a': address.rjust(8, '0')[-8:], 'm': mnemonic, 'ops': operands, 'target': target})
    return functions


def memory_operand(operands):
    """Base register and displacement of objdump's Intel memory operand."""
    match = re.search(r'\[([^\]]+)\]', operands)
    if not match:
        return None
    inner = match.group(1).replace(' ', '')
    if ':' in inner:
        inner = inner.split(':', 1)[1]
    # Base = a register term not scaled by '*'; scaled terms are the index.
    terms = re.findall(r'(?<![0-9a-z])[a-z][a-z0-9]*(?:\*\d+)?', inner)
    base = next((t for t in terms if '*' not in t), None)
    disp = re.search(r'([+-])0x([0-9a-f]+)$', inner)
    return {'base': base.upper() if base else None,
            'disp': (int(disp.group(2), 16) * (-1 if disp.group(1) == '-' else 1)) if disp else 0}


def branch_oracle(instructions):
    """{branch address: expected relation} using textbook x86 semantics."""
    expected = {}
    for index, instruction in enumerate(instructions):
        mnemonic = instruction['m']
        if not mnemonic.startswith('j') or mnemonic == 'jmp':
            continue
        for prior in reversed(instructions[:index]):
            if prior['m'].startswith(('j', 'call', 'ret')):
                break  # control transfer in between: linear search stops (conservative)
            if prior['m'] in FLAG_WRITERS:
                operands = [o.strip() for o in re.split(r',(?![^\[]*\])', prior['ops'])]
                if prior['m'] == 'cmp' and mnemonic in CMP_JCC and len(operands) == 2:
                    operator, signedness = CMP_JCC[mnemonic]
                    expected[instruction['a']] = {'setter': prior['a'], 'kind': 'cmp', 'operator': operator,
                                                  'signedness': signedness}
                elif prior['m'] == 'test' and mnemonic in TEST_JCC and len(operands) == 2:
                    operator, signedness = TEST_JCC[mnemonic]
                    expected[instruction['a']] = {'setter': prior['a'], 'kind': 'test',
                                                  'operator': operator, 'signedness': signedness}
                break
    return expected
