"""Read reference evidence from the caller's already analyzed Program.

No runtime/project/import/analysis/decompilation lifecycle belongs here. Direct
CALL edges retain graph_builder's stricter policy; raw references and Ghidra
thunk bindings never synthesize extra call edges or resolve computed flows.
"""
import hashlib
import json
import struct

from aire.knowledge.models import ReferenceRecord, ThunkRecord
from aire.pyghidra.extractor import function_id, read_fact
from aire.profiling import count, profiled

REFERENCE_FACTS_VERSION = 2


def _bytes(memory, address, size):
    block = memory.getBlock(address)
    if block is None or not block.isInitialized() or not block.contains(address.add(size - 1)):
        return None
    return bytes(int(memory.getByte(address.add(i))) & 255 for i in range(size))


@profiled('xrefs', 'xref_collection_calls')
def extract_references(program, functions, artifacts, binary, warnings):
    """Return deterministic references, immediate thunk bindings, and loader info.

    Visit every reference source in Program memory (including data sources),
    retaining source/destination/type/operand and exact known ownership. Attach
    STRING/IMPORT artifacts only at their recorded destination address. Missing
    optional facts become warnings. No decompiler is opened or called.
    """
    listing = program.getListing()
    manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()
    memory = program.getMemory()
    known = {str(function.getEntryPoint()): function for function in functions}
    by_address = {}
    # Prefer a string/import association over an export at the same address.
    for artifact in sorted(artifacts, key=lambda a: (a.type not in ('STRING', 'IMPORT'), a.artifact_id)):
        if artifact.address is not None:
            by_address.setdefault(artifact.address, artifact.artifact_id)
    records = {}
    read_cache = {}

    def collect(source):
        owner = manager.getFunctionContaining(source)
        owner_address = str(owner.getEntryPoint()) if owner is not None else None
        source_id = function_id(binary, owner_address) if owner_address in known else None
        instruction = listing.getInstructionAt(source)
        instruction_text = str(instruction) if instruction is not None else None
        for reference in reference_manager.getReferencesFrom(source):
            def extract():
                destination = reference.getToAddress()
                target = str(destination)
                kind = reference.getReferenceType()
                is_call, is_read = bool(kind.isCall()), bool(kind.isRead())
                is_indirect = bool(kind.isComputed() or
                    (instruction is not None and instruction.getFlowType().isComputed()))
                target_id = function_id(binary, target) if target in known and not is_indirect else None
                operand = int(reference.getOperandIndex())
                payload = json.dumps([str(source), target, str(kind), operand], separators=(',', ':'))
                identity = f'{binary}:reference:{hashlib.sha256(payload.encode()).hexdigest()}'
                data_hex = None
                if is_read:
                    if target not in read_cache:
                        raw = read_fact(warnings, f'Referenced bytes at {target}',
                                        lambda: _bytes(memory, destination, 8))
                        read_cache[target] = raw.hex() if raw is not None else None
                    data_hex = read_cache[target]
                records[identity] = ReferenceRecord(
                    identity, binary, str(source), target, str(kind), source_id, target_id,
                    by_address.get(target), instruction_text, operand, is_call, is_indirect,
                    is_read, data_hex)
            read_fact(warnings, f'Reference from {source}', extract)

    for source in reference_manager.getReferenceSourceIterator(memory, True):
        read_fact(warnings, f'References at {source}', lambda: collect(source))

    thunks = []
    for function in functions:
        if function.isExternal() or not function.isThunk():
            continue
        def thunk():
            target = function.getThunkedFunction(False)
            if target is None or str(target.getEntryPoint()) not in known:
                return
            source = function.getEntryPoint()
            instruction = listing.getInstructionAt(source)
            direct = bool(instruction is not None and instruction.getFlowType().isJump()
                          and not instruction.getFlowType().isComputed()
                          and target.getEntryPoint() in list(instruction.getFlows()))
            thunks.append(ThunkRecord(
                function_id(binary, str(source)), function_id(binary, str(target.getEntryPoint())),
                str(source), str(target.getEntryPoint()),
                str(instruction) if instruction is not None else None, direct))
        read_fact(warnings, f'Thunk at {function.getEntryPoint()}', thunk)

    info = {}
    def program_info():
        options = program.getOptions('Program Information')
        for name in options.getOptionNames():
            info[str(name)] = str(options.getValueAsString(name))
    read_fact(warnings, 'Program information', program_info)

    def elf_info():
        # Preserve the ELF demo's actual loaded-memory DF_1_PIE and interpreter
        # evidence. Decode only the supported ELF64 little-endian layout.
        if int(program.getDefaultPointerSize()) != 8 or program.getLanguage().isBigEndian():
            return
        dynamic = memory.getBlock('.dynamic')
        if dynamic is not None:
            for offset in range(0, int(dynamic.getSize()) - 15, 16):
                raw = _bytes(memory, dynamic.getStart().add(offset), 16)
                if raw is None:
                    break
                tag, value = struct.unpack('<QQ', raw)
                if tag == 0:
                    break
                if tag == 0x6ffffffb:
                    info['ELF DF_1_PIE'] = str(bool(value & 0x08000000)).lower()
        interpreter = memory.getBlock('.interp')
        if interpreter is not None:
            raw = _bytes(memory, interpreter.getStart(), int(interpreter.getSize()))
            if raw is not None:
                info['ELF interpreter'] = raw.split(b'\0', 1)[0].decode('ascii')
    read_fact(warnings, 'ELF program information', elf_info)
    result = sorted(records.values(), key=lambda r: (
        r.source_address, r.target_address, r.reference_type, r.operand_index))
    thunks.sort(key=lambda r: (r.source_address, r.target_address))
    count('xrefs_collected', len(result))
    count('thunks_collected', len(thunks))
    return result, thunks, info
