"""Read Ghidra facts. Java imports are delayed until extraction is requested."""
import hashlib
import json
from datetime import datetime, timezone

from aire.knowledge.models import ArtifactRecord, BinaryRecord, FunctionRecord
from aire.profiling import count, decompile_attempt, profiled, stage


def binary_id(sha256: str) -> str:
    return sha256.lower()


def function_id(binary: str, address: str) -> str:
    return f'{binary}:{address}'


def artifact_id(binary: str, kind: str, address: str | None, value: str) -> str:
    payload = json.dumps([kind, address, value], ensure_ascii=True, separators=(',', ':'))
    return f'{binary}:artifact:{hashlib.sha256(payload.encode()).hexdigest()}'


def read_fact(warnings, context, getter, default=None):
    try:
        return getter()
    except Exception as exc:
        warnings.append(f'{context}: {exc}')
        return default


class AssemblyBuffer:
    """Keep only complete lines within both caps (including newline characters)."""
    def __init__(self, max_instructions, max_characters):
        self.max_instructions = max_instructions
        self.max_characters = max_characters
        self.lines = []
        self.characters = 0
        self.truncated = False

    def append(self, line):
        if self.truncated:
            return
        size = len(line) + bool(self.lines)
        if len(self.lines) >= self.max_instructions or self.characters + size > self.max_characters:
            self.truncated = True
            return
        self.lines.append(line)
        self.characters += size

    def text(self):
        return '\n'.join(self.lines)


def extract_binary(program, path, digest, warnings):
    def fact(label, getter):
        return read_fact(warnings, f'Binary {label}', getter)
    return BinaryRecord(
        binary_id=binary_id(digest), path=str(path), sha256=digest,
        format=fact('format', lambda: str(program.getExecutableFormat())),
        architecture=fact('language', lambda: str(program.getLanguageID())),
        image_base=str(program.getImageBase()), analyzed_at=datetime.now(timezone.utc),
        compiler_spec=fact('compiler', lambda: str(program.getCompilerSpec().getCompilerSpecID())),
        endianness=fact('endianness', lambda: 'big' if program.getLanguage().isBigEndian() else 'little'),
        pointer_size=fact('pointer size', lambda: int(program.getDefaultPointerSize())),
        executable_size=path.stat().st_size, program_name=str(program.getName()),
    )


@profiled('decompilation')
def decompile_function(decompiler, function, options, monitor, warnings, context):
    def attempt():
        decompile_attempt(context)
        result = decompiler.decompileFunction(function, options.decompile_timeout_seconds, monitor)
        if result is None:
            raise RuntimeError('decompiler returned no result')
        if not result.decompileCompleted() or result.getDecompiledFunction() is None:
            raise RuntimeError(str(result.getErrorMessage()) or 'decompilation did not complete')
        message = str(result.getErrorMessage() or '')
        if message:
            warnings.append(f'{context} decompiler: {message}')
        text = str(result.getDecompiledFunction().getC())
        count('decompile_successes')
        return text
    return read_fact(warnings, f'{context} decompilation', attempt)


@profiled('function_metadata')
def extract_functions(program, functions, binary, options, monitor, warnings):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.app.decompiler import DecompInterface

    records = []
    blocks = BasicBlockModel(program)
    decompiler = None
    try:
        if options.decompile:
            with stage('decompiler_setup'):
                count('decompiler_instances')
                decompiler = DecompInterface()
                try:
                    if not decompiler.openProgram(program):
                        raise RuntimeError(str(decompiler.getLastMessage()))
                except Exception as exc:
                    warnings.append(f'Decompiler initialization: {exc}')
                    decompiler.dispose()
                    decompiler = None
        for function in functions:
            address = str(function.getEntryPoint())
            name = str(function.getName())
            context = f'Function {address} {name}'
            def fact(label, getter):
                return read_fact(warnings, f'{context} {label}', getter)
            external = bool(function.isExternal())
            record = FunctionRecord(
                function_id(binary, address), binary, address, name,
                fact('signature', lambda: str(function.getSignature())), None,
                '' if options.include_assembly else None, None, None, None,
                is_external=external, is_thunk=bool(function.isThunk()),
                namespace=fact('namespace', lambda: str(function.getParentNamespace().getName(True))),
                calling_convention=fact('calling convention', lambda: str(function.getCallingConventionName())),
            )
            if external:
                record.instruction_count = record.basic_block_count = record.branch_count = 0
            else:
                with stage('assembly'):
                    buffer = AssemblyBuffer(options.max_assembly_instructions, options.max_assembly_characters)
                def instructions():
                    count = branches = 0
                    for instruction in program.getListing().getInstructions(function.getBody(), True):
                        count += 1
                        branches += bool(instruction.getFlowType().isJump())
                        if options.include_assembly and not buffer.truncated:
                            buffer.append(f'{instruction.getAddress()}: {instruction}')
                    return count, branches
                with stage('assembly'):
                    metrics = fact('instructions/branches', instructions)
                    if metrics is not None:
                        record.instruction_count, record.branch_count = metrics
                    if options.include_assembly:
                        record.assembly = buffer.text()
                        record.assembly_truncated = buffer.truncated
                with stage('basic_blocks'):
                    record.basic_block_count = fact('basic blocks', lambda: sum(
                        1 for _ in blocks.getCodeBlocksContaining(function.getBody(), monitor)))
                if options.decompile:
                    if decompiler is None:
                        warnings.append(f'{context} decompilation: decompiler unavailable')
                    else:
                        record.decompiled_text = decompile_function(
                            decompiler, function, options, monitor, warnings, context)
            records.append(record)
    finally:
        if decompiler is not None:
            with stage('cleanup'):
                decompiler.dispose()
    return records


@profiled('artifact_setup')
def extract_artifacts(program, binary, options, warnings):
    from ghidra.program.model.data import StringDataInstance
    from ghidra.program.model.symbol import SymbolType
    artifacts = {}
    def add(kind, address, value):
        if value is None:
            raise ValueError('Ghidra returned no value')
        address = str(address) if address is not None else None
        value = str(value)
        identity = artifact_id(binary, kind, address, value)
        artifacts[identity] = ArtifactRecord(identity, binary, kind, address, value)

    if options.include_strings:
        with stage('strings'):
            for data in program.getListing().getDefinedData(True):
                def string():
                    if StringDataInstance.isString(data):
                        add('STRING', data.getAddress(),
                            StringDataInstance.getStringDataInstance(data).getStringValue())
                read_fact(warnings, f'String at {data.getAddress()}', string)
    symbols = program.getSymbolTable()
    if options.include_imports:
        with stage('imports'):
            for symbol in symbols.getExternalSymbols():
                def imported():
                    if symbol.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL):
                        add('IMPORT', symbol.getAddress(), symbol.getName(True))
                read_fact(warnings, f'Import symbol {symbol.getID()}', imported)
    if options.include_exports:
        with stage('exports'):
            for address in symbols.getExternalEntryPointIterator():
                def exported():
                    for symbol in symbols.getSymbols(address):
                        add('EXPORT', address, symbol.getName(True))
                read_fact(warnings, f'Export at {address}', exported)
    return list(artifacts.values())
