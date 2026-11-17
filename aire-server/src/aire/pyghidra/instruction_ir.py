"""M10 structured instruction facts (IR) read from Ghidra's analyzed Program.

Per function this records, without interpretation:
* every instruction (bounded): address, mnemonic, text, length, typed operands
  with Ghidra's operand objects (registers, scalars, addresses), flow type,
  flow targets, fall-through, and Ghidra raw P-code (normalized text);
* basic blocks (BasicBlockModel) with successor addresses and flow types;
* Ghidra-recovered calling convention, parameter/return storage and the
  signature source (IMPORTED / ANALYSIS / DEFAULT / USER_DEFINED).

Interpretation lives in aire.analysis.instruction_semantics; this module only
reads facts. No program state is modified. JPype calls are kept minimal: P-code
is parsed from PcodeOp.toString() and register varnodes are resolved through a
per-program (offset, size) cache.
"""
import json
import re
import zlib

from aire.pyghidra.extractor import read_fact
from aire.profiling import count

from aire.analysis.versions import INSTRUCTION_IR_VERSION as IR_VERSION
MAX_IR_INSTRUCTIONS = 4096
_VARNODE = re.compile(r'\((\w+), (0x[0-9a-f]+), (\d+)\)')


class _Context:
    """Per-program caches (register names by register-space offset/size)."""

    def __init__(self, program):
        self.program = program
        self.language = program.getLanguage()
        self.register_space = program.getAddressFactory().getRegisterSpace()
        self.registers = {}

    def register(self, offset, size):
        key = (offset, size)
        if key not in self.registers:
            register = None
            try:
                register = self.language.getRegister(self.register_space.getAddress(offset), size)
            except Exception:
                register = None
            self.registers[key] = str(register.getName()) if register is not None else f'reg{offset:x}:{size}'
        return self.registers[key]

    def varnode(self, space, offset, size):
        value, size = int(offset, 16), int(size)
        if space == 'register':
            return {'k': 'reg', 'n': self.register(value, size), 's': size}
        if space == 'const':
            bits = 8 * size
            signed = value - (1 << bits) if bits and value >= 1 << (bits - 1) else value
            return {'k': 'const', 'v': value, 'sv': signed, 's': size}
        if space == 'unique':
            return {'k': 'tmp', 'n': f'u{value:x}', 's': size}
        return {'k': 'mem', 'sp': space, 'a': f'{value:x}', 's': size}


_OP_SPLIT = re.compile(r'(?<=\S), (?=\(\w+, 0x|\s*---)')
_MEMORY = re.compile(r'\[([^\]]*)\]')
_TERM = re.compile(r'^\s*(-)?\s*(0x[0-9a-fA-F]+|\d+|[A-Za-z_][A-Za-z0-9_]*)(?:\*(0x[0-9a-fA-F]+|\d+))?\s*$')


def _pcode(context, op_text):
    """'(register, 0x0, 8) INT_ADD (register, 0x0, 8) , (const, 0x1, 8)' ->
    {'op': 'INT_ADD', 'out': varnode|None, 'in': [varnodes]}."""
    text = op_text.strip()
    if text.startswith('---'):
        output, rest = None, text[3:].strip()
    else:
        match = _VARNODE.match(text)
        output = context.varnode(*match.groups()) if match else None
        rest = text[match.end():].strip() if match else text
    opcode, _, operands = rest.partition(' ')
    inputs = [context.varnode(*m.groups()) for m in _VARNODE.finditer(operands)]
    return {'op': opcode, 'out': output, 'in': inputs}


def parse_pcode_list(context, text):
    """Parse java.util.Arrays.asList(PcodeOp[]).toString(): '[op, op, ...]'.
    Elements are separated by ', ' directly after a non-space; varnode inputs
    within an op are separated by ' , ' (space before the comma)."""
    body = text.strip()
    if body.startswith('[') and body.endswith(']'):
        body = body[1:-1]
    if not body.strip():
        return []
    return [_pcode(context, part) for part in _OP_SPLIT.split(body)]


def memory_operand(text):
    """Structure of an Intel-syntax memory operand from Ghidra's text, e.g.
    'dword ptr [RBP + -0x4]' -> {'base': 'RBP', 'index': None, 'scale': 1,
    'disp': -4, 'size': 'dword', 'absolute': None}. None if not memory."""
    match = _MEMORY.search(text)
    if not match:
        return None
    prefix = text[:match.start()].replace(' ptr', '').strip()
    segment = None
    if prefix.endswith(':'):
        prefix, _, segment = prefix[:-1].rpartition(' ')
    result = {'base': None, 'index': None, 'scale': 1, 'disp': 0, 'absolute': None,
              'size': prefix.strip() or None, 'segment': segment or None}
    inner = match.group(1)
    if ':' in inner:
        result['segment'], inner = inner.split(':', 1)
    for raw in re.findall(r'[+-]?[^+-]+', inner.replace(' ', '').replace('+-', '-')):
        term = _TERM.match(raw.lstrip('+'))
        if not term:
            return dict(result, unparsed=inner)
        negative, value, scale = term.group(1), term.group(2), term.group(3)
        if value[0].isdigit():
            number = int(value, 0) * (-1 if negative else 1)
            if result['base'] is None and result['index'] is None and number >= 0x1000 and not result['disp']:
                result['absolute'] = number
            else:
                result['disp'] += number
        elif scale is not None:
            result['index'], result['scale'] = value, int(scale, 0)
        elif result['base'] is None:
            result['base'] = value
        else:
            result['index'] = value
    return result


class _FlowCache:
    """Flow-type booleans computed once per distinct FlowType (few exist)."""

    def __init__(self):
        self.cache = {}

    def get(self, flow):
        name = str(flow)
        if name not in self.cache:
            self.cache[name] = {'jump': bool(flow.isJump()), 'call': bool(flow.isCall()),
                                'cond': bool(flow.isConditional()), 'term': bool(flow.isTerminal()),
                                'computed': bool(flow.isComputed()), 'fallthrough': bool(flow.hasFallthrough())}
        return name, self.cache[name]


def _storage(variable):
    return {'storage': str(variable.getVariableStorage()), 'type': str(variable.getDataType())}


def _hex_add(address, length):
    """Same-width hex address + length for flat spaces ('0040116d' + 1)."""
    if not re.fullmatch(r'[0-9a-f]+', address):
        return None
    return format(int(address, 16) + length, f'0{len(address)}x')


class FunctionCollector:
    """Builds one function's IR from the extractor's single instruction pass."""

    def __init__(self, context, flows, operand_types, arrays):
        self.context, self.flows, self.operand_types, self.arrays = context, flows, operand_types, arrays
        self.instructions, self.truncated = [], False

    def add(self, instruction, address, text):
        """Returns the flow booleans (also used for the extractor's metrics)."""
        name, flags = self.flows.get(instruction.getFlowType())
        if len(self.instructions) >= MAX_IR_INSTRUCTIONS:
            self.truncated = True
            return flags
        length = int(instruction.getLength())
        operands = []
        for index in range(instruction.getNumOperands()):
            operand_text = str(instruction.getDefaultOperandRepresentation(index))
            kinds = [k.strip() for k in str(self.operand_types.toString(instruction.getOperandType(index))).split('|')
                     if k.strip()]
            entry = {'text': operand_text, 'kinds': kinds}
            if 'DYN' in kinds or '[' in operand_text:
                entry['mem'] = memory_operand(operand_text)
            operands.append(entry)
        targets = [str(t) for t in instruction.getFlows()] if (flags['jump'] or flags['call']) else []
        self.instructions.append({
            'a': address, 'm': str(instruction.getMnemonicString()), 't': text, 'len': length,
            'ops': operands, 'flow': name, **{k: flags[k] for k in ('call', 'jump', 'cond', 'term', 'computed')},
            'targets': targets,
            'ft': _hex_add(address, length) if flags['fallthrough'] else None,
            'pcode': parse_pcode_list(self.context, str(self.arrays.asList(instruction.getPcode()))),
        })
        return flags

    def document(self, program, function, blocks, warnings, label):
        signature = {}
        def collect_signature():
            signature.update({
                'calling_convention': str(function.getCallingConventionName()),
                'signature_source': str(function.getSignatureSource()),
                'parameters': [{'ordinal': int(p.getOrdinal()), 'name': str(p.getName()), **_storage(p)}
                               for p in function.getParameters()],
                'return': _storage(function.getReturn()),
                'varargs': bool(function.hasVarArgs()),
                'stack_frame_size': int(function.getStackFrame().getFrameSize()),
            })
        read_fact(warnings, f'{label}: signature storage', collect_signature)
        count('ir_instructions', len(self.instructions))
        return {'version': IR_VERSION, 'source': 'ghidra', 'language': self.context.language_id,
                'function_address': str(function.getEntryPoint()), 'instructions': self.instructions,
                'truncated': self.truncated, 'max_instructions': MAX_IR_INSTRUCTIONS,
                'blocks': sorted(blocks, key=lambda b: b['start']), 'signature': signature}


def new_collector_factory(program):
    """Per-program factory; Java classes are imported once."""
    from ghidra.program.model.lang import OperandType
    from java.util import Arrays
    context, flows = _Context(program), _FlowCache()
    context.language_id = str(program.getLanguageID())
    return lambda: FunctionCollector(context, flows, OperandType, Arrays)


def collect_blocks(block_iterator, monitor):
    blocks = []
    for block in block_iterator:
        successors = []
        destinations = block.getDestinations(monitor)
        while destinations.hasNext():
            reference = destinations.next()
            successors.append({'to': str(reference.getDestinationAddress()), 'flow': str(reference.getFlowType())})
        blocks.append({'start': str(block.getMinAddress()), 'end': str(block.getMaxAddress()), 'succ': successors})
    return blocks


def encode(document):
    return zlib.compress(json.dumps(document, separators=(',', ':'), ensure_ascii=True).encode(), 6)


def decode(blob):
    return json.loads(zlib.decompress(blob))
