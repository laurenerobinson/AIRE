"""Read Ghidra facts. Java imports are delayed until extraction is requested."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import queue
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
    """Single attempt (public helper, original contract): text or None with the
    failure recorded in warnings."""
    decompile_attempt(context)
    outcome = _attempt(decompiler, function, options, monitor, context)
    _apply_warnings(outcome, warnings, context)
    if outcome.text is not None:
        count('decompile_successes')
    return outcome.text


DEFAULT_MAX_DECOMPILE_WORKERS = 4


def decompile_workers(environ=None):
    """Parallel decompiler instances. Not part of IndexOptions/cache identity:
    output is verified identical for any worker count (see docs/M9_PERFORMANCE.md).
    AIRE_DECOMPILE_WORKERS overrides; 1 restores the original serial path."""
    environ = os.environ if environ is None else environ
    value = environ.get('AIRE_DECOMPILE_WORKERS')
    if value is not None:
        try:
            parsed = int(value)
        except ValueError:
            parsed = 0
        if parsed >= 1:
            return min(parsed, 32)
    return max(1, min(DEFAULT_MAX_DECOMPILE_WORKERS, os.cpu_count() or 1))


def _open_decompiler(program):
    from ghidra.app.decompiler import DecompInterface
    decompiler = DecompInterface()
    try:
        if not decompiler.openProgram(program):
            raise RuntimeError(str(decompiler.getLastMessage()))
    except Exception:
        decompiler.dispose()
        raise
    return decompiler


def _attach_daemon():
    # Worker threads must never keep the JVM alive at process exit.
    try:
        import jpype
        if jpype.isJVMStarted():
            jpype.java.lang.Thread.attachAsDaemon()
    except Exception:
        pass


class _DecompilerPool:
    """N independent DecompInterface instances (each its own native process)
    shared through a queue. Results are keyed by function so callers merge them
    in the original deterministic order."""

    def __init__(self, program, workers, warnings):
        self.decompilers = []
        self.available = queue.Queue()
        self.executor = None
        with stage('decompiler_setup'):
            count('decompiler_instances', workers)
            errors = []
            if workers == 1:
                opened = [self._try_open(program)]
            else:
                self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='aire-decompile',
                                                   initializer=_attach_daemon)
                opened = list(self.executor.map(lambda _: self._try_open(program), range(workers)))
            for decompiler, error in opened:
                if decompiler is not None:
                    self.decompilers.append(decompiler)
                    self.available.put(decompiler)
                else:
                    errors.append(error)
            if not self.decompilers:
                # Same warning text as the original single-instance path.
                warnings.append(f'Decompiler initialization: {errors[0]}')

    @staticmethod
    def _try_open(program):
        try:
            return _open_decompiler(program), None
        except Exception as exc:
            return None, exc

    @property
    def usable(self):
        return bool(self.decompilers)

    def submit(self, function, options, monitor, context):
        def run():
            decompiler = self.available.get()
            try:
                return _attempt(decompiler, function, options, monitor, context)
            finally:
                self.available.put(decompiler)
        return self.executor.submit(run)

    def attempt_serial(self, function, options, monitor, context):
        """Retry on the caller's thread with one pooled instance (all parallel
        work has finished, so every instance is idle)."""
        decompiler = self.available.get()
        try:
            return _attempt(decompiler, function, options, monitor, context)
        finally:
            self.available.put(decompiler)

    def close(self):
        with stage('cleanup'):
            if self.executor is not None:
                self.executor.shutdown(wait=True)
            for decompiler in self.decompilers:
                decompiler.dispose()


class Outcome:
    """Result of one decompile attempt. status: ok | timeout | failed."""
    __slots__ = ('text', 'status', 'message', 'notes')

    def __init__(self, text, status, message='', notes=()):
        self.text, self.status, self.message, self.notes = text, status, message, tuple(notes)


def _timed_out(result):
    try:
        return bool(result.isTimedOut())
    except Exception:
        return False


def _attempt(decompiler, function, options, monitor, context):
    """One decompile attempt. Thread-safe: touches no shared or profiling state."""
    try:
        result = decompiler.decompileFunction(function, options.decompile_timeout_seconds, monitor)
        if result is None:
            return Outcome(None, 'failed', 'decompiler returned no result')
        if not result.decompileCompleted() or result.getDecompiledFunction() is None:
            message = str(result.getErrorMessage() or '') or 'decompilation did not complete'
            return Outcome(None, 'timeout' if _timed_out(result) else 'failed', message)
        message = str(result.getErrorMessage() or '')
        notes = [f'{context} decompiler: {message}'] if message else []
        return Outcome(str(result.getDecompiledFunction().getC()), 'ok', notes=notes)
    except Exception as exc:
        return Outcome(None, 'failed', str(exc))


def _apply_warnings(outcome, warnings, context):
    # Identical text to the original read_fact-based messages.
    if outcome.text is None:
        warnings.append(f'{context} decompilation: {outcome.message}')
    warnings.extend(outcome.notes)


@profiled('function_metadata')
def extract_functions(program, functions, binary, options, monitor, warnings, workers=None, report=None, ir=None):
    """Extract function facts. report (dict, optional) receives decompilation
    reliability facts: 'decompile_retry' (timed_out/retried/recovered address
    lists) and 'decompilation_incomplete' (functions left without decompiled
    text, each with reason and message). Timed-out functions are retried once,
    serially, after the main pass; successful results are never re-decompiled.
    ir (dict, optional) receives M10 structured instruction facts per function_id,
    collected in the same single instruction pass that produces assembly text and
    metrics (identical strings/counts), while decompilation runs in parallel."""
    from ghidra.program.model.block import BasicBlockModel

    records = []
    blocks = BasicBlockModel(program)
    pool = None
    pending = []  # (record, pre-decompile warnings, future/_Done or None, context, function)
    timed_out, retried, recovered, incomplete = [], [], [], []
    ir_factory = None
    if ir is not None:
        from aire.pyghidra.instruction_ir import collect_blocks, new_collector_factory
        ir_factory = new_collector_factory(program)
    else:
        collect_blocks = None
    workers = decompile_workers() if workers is None else workers
    try:
        if options.decompile:
            pool = _DecompilerPool(program, workers, warnings)
        for function in functions:
            address = str(function.getEntryPoint())
            name = str(function.getName())
            context = f'Function {address} {name}'
            local = []
            def fact(label, getter):
                return read_fact(local, f'{context} {label}', getter)
            external = bool(function.isExternal())
            record = FunctionRecord(
                function_id(binary, address), binary, address, name,
                fact('signature', lambda: str(function.getSignature())), None,
                '' if options.include_assembly else None, None, None, None,
                is_external=external, is_thunk=bool(function.isThunk()),
                namespace=fact('namespace', lambda: str(function.getParentNamespace().getName(True))),
                calling_convention=fact('calling convention', lambda: str(function.getCallingConventionName())),
            )
            future = None
            if external:
                record.instruction_count = record.basic_block_count = record.branch_count = 0
            else:
                # Submit first so native decompilation overlaps the Python
                # assembly/basic-block work below.
                if options.decompile and pool.usable and pool.executor is not None:
                    future = pool.submit(function, options, monitor, context)
                with stage('assembly'):
                    buffer = AssemblyBuffer(options.max_assembly_instructions, options.max_assembly_characters)
                collector = ir_factory() if ir_factory is not None else None
                def instructions():
                    count = branches = 0
                    for instruction in program.getListing().getInstructions(function.getBody(), True):
                        count += 1
                        if collector is not None:
                            address, text = str(instruction.getAddress()), str(instruction)
                            with stage('instruction_ir'):
                                flags = collector.add(instruction, address, text)
                            branches += flags['jump']
                            if options.include_assembly and not buffer.truncated:
                                buffer.append(f'{address}: {text}')
                            continue
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
                    if collector is None:
                        record.basic_block_count = fact('basic blocks', lambda: sum(
                            1 for _ in blocks.getCodeBlocksContaining(function.getBody(), monitor)))
                    else:
                        block_rows = fact('basic blocks', lambda: collect_blocks(
                            blocks.getCodeBlocksContaining(function.getBody(), monitor), monitor))
                        record.basic_block_count = len(block_rows) if block_rows is not None else None
                if collector is not None:
                    with stage('instruction_ir'):
                        ir[record.function_id] = collector.document(
                            program, function, block_rows or [], local, f'{context} instruction facts')
                if options.decompile and future is None:
                    if not pool.usable:
                        local.append(f'{context} decompilation: decompiler unavailable')
                        incomplete.append(_incomplete(record, 'decompiler_unavailable', 'decompiler unavailable'))
                    else:  # serial path: original single-instance behavior
                        with stage('decompilation'):
                            decompile_attempt(context)
                            future = _Done(_attempt(pool.decompilers[0], function, options, monitor, context))
            records.append(record)
            pending.append((record, local, future, context, function))
        # Collect outcomes in the original function order (completion order is
        # irrelevant), then retry timeouts once, serially, before any warning is
        # emitted. A recovered function yields exactly the warnings of a clean
        # run; the retry itself is recorded in report['decompile_retry'].
        outcomes = {}
        with stage('decompilation'):
            for index, (record, local, future, context, function) in enumerate(pending):
                if future is None:
                    continue
                if not isinstance(future, _Done):
                    decompile_attempt(context)
                outcome = future.result()
                if outcome.status == 'timeout':
                    count('decompile_timeouts')
                    timed_out.append(record.address)
                outcomes[index] = outcome
            for index, outcome in list(outcomes.items()):
                if outcome.status != 'timeout':
                    continue
                record, local, future, context, function = pending[index]
                count('decompile_retries')
                retried.append(record.address)
                decompile_attempt(context)
                retry = pool.attempt_serial(function, options, monitor, context)
                if retry.text is not None:
                    count('decompile_retry_recovered')
                    recovered.append(record.address)
                    outcomes[index] = retry
                else:
                    outcomes[index] = Outcome(None, 'timeout_after_retry',
                                              f'{outcome.message}; serial retry: {retry.message}; '
                                              'decompilation INCOMPLETE')
        for index, (record, local, future, context, function) in enumerate(pending):
            outcome = outcomes.get(index)
            if outcome is not None:
                record.decompiled_text = outcome.text
                _apply_warnings(outcome, local, context)
                if outcome.text is not None:
                    count('decompile_successes')
                else:
                    reason = outcome.status if outcome.status == 'timeout_after_retry' else 'decompiler_error'
                    incomplete.append(_incomplete(record, reason, outcome.message))
            warnings.extend(local)
    finally:
        if pool is not None:
            pool.close()
    if report is not None:
        report['decompile_retry'] = {'timed_out': timed_out, 'retried': retried, 'recovered': recovered}
        report['decompilation_incomplete'] = sorted(incomplete, key=lambda row: row['address'])
    return records


class _Done:
    """Serial-path outcome wrapped like a completed future."""

    def __init__(self, outcome):
        self._outcome = outcome

    def result(self):
        return self._outcome


def _incomplete(record, reason, message):
    return {'function_id': record.function_id, 'address': record.address, 'name': record.current_name,
            'reason': reason, 'message': message}


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
