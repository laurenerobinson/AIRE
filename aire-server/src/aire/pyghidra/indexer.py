"""Read-only whole-binary indexing. No JVM starts on module import.

Analysis changes only an unsaved disposable Ghidra program. The process-wide JVM
is reused across index calls and shut down at process exit, never per function.
Index calls are serialized because Ghidra initialization is process-global.
"""
import argparse
import atexit
from contextlib import redirect_stdout
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time

from aire.knowledge.models import ProgramIndex
from aire.pyghidra.extractor import decompile_workers, extract_artifacts, extract_binary, extract_functions
from aire.pyghidra.graph_builder import build_call_edges
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION, extract_references
from aire.pyghidra.instruction_ir import IR_VERSION
from aire.profiling import count, profiled, stage as profile_stage, timed_context
from aire.analysis.progress import report_progress
from aire.analysis.versions import analyzer_versions

_LOCK = threading.Lock()
_RUNTIME = None


class IndexingError(RuntimeError):
    """Fatal input, startup, import, analysis, or integrity failure."""


def sha256_file(path: Path) -> str:
    count('sha256_reads')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


@profiled('runtime_startup', 'runtime_checks')
def _start_runtime():
    global _RUNTIME
    import jpype
    import pyghidra
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    if pyghidra.started():
        return
    if jpype.isJVMStarted():
        raise RuntimeError('A JVM is running without initialized PyGhidra; use a fresh process')
    runtime = tempfile.TemporaryDirectory(prefix='aire_ghidra_runtime_')
    try:
        launcher = HeadlessPyGhidraLauncher()
        launcher.vm_args.append('-Djava.awt.headless=true')
        java_home = os.environ.get('JAVA_HOME_OVERRIDE') or os.environ.get('JAVA_HOME')
        if java_home:
            launcher.java_home = Path(java_home)
        for key, directory in [('application.settingsdir', 'settings'),
                               ('application.cachedir', 'cache'),
                               ('application.tempdir', 'temp')]:
            launcher.vm_args.append(f'-D{key}={runtime.name}/{directory}')
        count('launcher_start_calls')
        launcher.start()
    except BaseException:
        if jpype.isJVMStarted():
            jpype.shutdownJVM()
        runtime.cleanup()
        raise
    _RUNTIME = runtime
    def close_runtime():
        try:
            if jpype.isJVMStarted():
                jpype.shutdownJVM()
        finally:
            runtime.cleanup()
    atexit.register(close_runtime)


def prewarm_runtime():
    """Start the JVM/PyGhidra and load the classes a first analysis needs,
    without importing or analysing any binary. Moves (does not remove) the
    one-time startup cost off the first user request. Returns step timings.
    Raises on failure; callers must treat that as "not warmed" and continue."""
    steps = {}
    with _LOCK:
        tick = time.perf_counter()
        _start_runtime()
        steps['runtime_start'] = time.perf_counter() - tick
        tick = time.perf_counter()
        import pyghidra
        from ghidra.app.util.importer import MessageLog  # noqa: F401
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: F401
        from ghidra.app.decompiler import DecompInterface  # noqa: F401
        from ghidra.program.model.block import BasicBlockModel  # noqa: F401
        from ghidra.program.model.data import StringDataInstance  # noqa: F401
        from ghidra.framework import Application
        steps['class_loading'] = time.perf_counter() - tick
        tick = time.perf_counter()
        # An empty disposable project exercises project/framework initialization.
        with tempfile.TemporaryDirectory(prefix='aire_prewarm_') as directory:
            with pyghidra.open_project(directory, 'prewarm', create=True):
                pyghidra.program_loader()  # loader builder initialization only; nothing is loaded
        steps['project_framework'] = time.perf_counter() - tick
        steps['ghidra_version'] = str(Application.getApplicationVersion())
    return steps


@profiled('python_setup', 'index_binary_calls')
def index_binary(path: Path, options: IndexOptions | None = None) -> ProgramIndex:
    """Import/analyze once, extract facts, dispose without saving, verify input hash.

    Raises IndexingError on fatal failures. Optional fact failures are warnings.
    No target code executes; Ghidra's static analyzer/decompiler are the only engines.
    """
    options = options if options is not None else IndexOptions()
    if not isinstance(options, IndexOptions):
        raise TypeError('options must be IndexOptions or None')
    with profile_stage('hashing'):
        path = Path(path).expanduser().resolve()
        if not path.exists():
            raise IndexingError(f'File not found: {path}')
        if not path.is_file():
            raise IndexingError(f'Path is not a file: {path}')
        try:
            before = sha256_file(path)
        except OSError as exc:
            raise IndexingError(f'Cannot read {path}: {exc}') from exc
    started = time.perf_counter()
    stage = 'Ghidra startup'
    try:
        with _LOCK:
            report_progress('Starting or reusing PyGhidra/JVM')
            _start_runtime()
            import pyghidra
            from java.lang import Object
            from ghidra.app.util.importer import MessageLog
            from ghidra.framework import Application
            with timed_context(tempfile.TemporaryDirectory(prefix='aire_index_'), 'python_setup') as directory:
                stage = 'temporary project creation'
                with profile_stage('project_creation'):
                    project_context = pyghidra.open_project(directory, 'index', create=True)
                with timed_context(project_context,
                                   'project_creation', counter='projects_created') as project:
                    stage = 'binary import'
                    report_progress('Importing binary into disposable Ghidra project')
                    import_log = MessageLog()
                    with profile_stage('import_open'):
                        count('executable_imports')
                        loaded_context = pyghidra.program_loader().project(project).source(str(path)).log(import_log).load()
                    with timed_context(loaded_context, 'import_open') as loaded:
                        with profile_stage('import_open'):
                            consumer = Object()
                            program = loaded.getPrimaryDomainObject(consumer)
                        try:
                            warnings = []
                            if str(import_log):
                                warnings.append(f'Import: {import_log}')
                            stage = 'analysis initialization/completion'
                            report_progress('Running Ghidra static auto-analysis')
                            tick = time.perf_counter()
                            with profile_stage('auto_analysis'):
                                count('analyze_calls')
                                analysis_log = pyghidra.analyze(program)
                            analysis_seconds = time.perf_counter() - tick
                            if analysis_log:
                                warnings.append(f'Analysis: {analysis_log}')
                            monitor = pyghidra.task_monitor()
                            stage = 'fact extraction'
                            report_progress('Extracting functions, decompilation and assembly')
                            binary = extract_binary(program, path, before, warnings)
                            with profile_stage('function_discovery'):
                                manager = program.getFunctionManager()
                                functions = list(manager.getFunctions(True)) + list(manager.getExternalFunctions())
                                functions.sort(key=lambda f: (bool(f.isExternal()), str(f.getEntryPoint())))
                                count('functions_discovered', len(functions))
                            tick = time.perf_counter()
                            workers = decompile_workers() if options.decompile else 0
                            reliability = {}
                            # AIRE_INSTRUCTION_IR=0 disables M10 facts (benchmark A/B only);
                            # such snapshots are not cache-compatible and refresh later.
                            collect_ir = os.environ.get('AIRE_INSTRUCTION_IR', '1') != '0'
                            function_ir = {} if collect_ir else None
                            records = extract_functions(program, functions, binary.binary_id, options, monitor,
                                                        warnings, workers=workers or 1, report=reliability,
                                                        ir=function_ir)
                            function_ir = function_ir or {}
                            function_seconds = time.perf_counter() - tick
                            tick = time.perf_counter()
                            report_progress('Extracting strings, imports and exports')
                            artifacts = extract_artifacts(program, binary.binary_id, options, warnings)
                            artifact_seconds = time.perf_counter() - tick
                            tick = time.perf_counter()
                            report_progress('Extracting call relationships, references and thunks')
                            edges = build_call_edges(program, functions, binary.binary_id, warnings) if options.include_call_edges else []
                            graph_seconds = time.perf_counter() - tick
                            tick = time.perf_counter()
                            references, thunks, program_info = extract_references(
                                program, functions, artifacts, binary.binary_id, warnings
                            ) if options.include_references else ([], [], {})
                            reference_seconds = time.perf_counter() - tick
                            result = ProgramIndex(binary, records, artifacts, edges, warnings, {
                                'schema_version': 1,
                                'ghidra_version': str(Application.getApplicationVersion()),
                                'analyzer_versions': analyzer_versions(),
                                'analysis_completed': True,
                                'ghidra_function_count': int(manager.getFunctionCount()),
                                'options': asdict(options),
                                'branch_count_definition': 'Instructions with FlowType.isJump(); excludes calls and returns',
                                'basic_block_count_definition': 'BasicBlockModel blocks intersecting the function body',
                                'entry_point_note': 'None: no generic single loader entry point exposed; external entry points are EXPORT artifacts',
                                'analysis_seconds': analysis_seconds,
                                'function_extraction_seconds': function_seconds,
                                'artifact_extraction_seconds': artifact_seconds,
                                'call_graph_seconds': graph_seconds,
                                'reference_extraction_seconds': reference_seconds,
                                # Execution detail only; not cache identity (output is identical).
                                'decompile_workers': workers,
                                # Timed-out functions are retried once; any function still
                                # lacking decompiled text is listed explicitly (fact).
                                'decompile_retry': reliability.get('decompile_retry',
                                                                   {'timed_out': [], 'retried': [], 'recovered': []}),
                                'decompilation_incomplete': reliability.get('decompilation_incomplete', []),
                                'reference_facts_version': REFERENCE_FACTS_VERSION if options.include_references else None,
                                'instruction_ir': {
                                    'version': IR_VERSION if collect_ir else None, 'functions': len(function_ir),
                                    'instructions': sum(len(d['instructions']) for d in function_ir.values()),
                                    'truncated_functions': sorted(d['function_address'] for d in function_ir.values()
                                                                  if d['truncated']),
                                },
                            }, references, thunks, program_info, function_ir)
                        finally:
                            with profile_stage('cleanup'):
                                program.release(consumer)
    except Exception as exc:
        raise IndexingError(f'{stage} failed for {path}: {exc}') from exc
    finally:
        with profile_stage('integrity'):
            try:
                after = sha256_file(path)
            except OSError as exc:
                raise IndexingError(f'Cannot verify input integrity for {path}: {exc}') from exc
            if after != before:
                raise IndexingError(f'Input SHA-256 changed during indexing: {path}')
    result.metadata['input_sha256_unchanged'] = True
    result.metadata['total_seconds'] = time.perf_counter() - started
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only PyGhidra whole-binary indexer')
    parser.add_argument('path', type=Path)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--no-decompile', action='store_true')
    parser.add_argument('--no-assembly', action='store_true')
    parser.add_argument('--max-assembly-instructions', type=int, default=200)
    args = parser.parse_args(argv)
    try:
        options = IndexOptions(decompile=not args.no_decompile, include_assembly=not args.no_assembly,
                               max_assembly_instructions=args.max_assembly_instructions)
        with redirect_stdout(sys.stderr):
            result = index_binary(args.path, options)
        if args.json:
            print(json.dumps(result.to_dict(), ensure_ascii=True))
        else:
            binary = result.binary
            rows = [('Program', binary.program_name), ('SHA-256', binary.sha256),
                    ('Format', binary.format), ('Architecture', binary.architecture),
                    ('Compiler spec', binary.compiler_spec), ('Image base', binary.image_base),
                    ('Functions', len(result.functions)),
                    ('Decompiled', sum(bool(f.decompiled_text) for f in result.functions))]
            rows.extend((label, sum(a.type == kind for a in result.artifacts))
                        for label, kind in [('Strings', 'STRING'), ('Imports', 'IMPORT'), ('Exports', 'EXPORT')])
            rows.extend([('Call edges', len(result.function_edges)), ('Warnings', len(result.warnings)),
                         ('Indexing seconds', f'{result.metadata["total_seconds"]:.3f}')])
            for label, value in rows:
                print(f'{label}: {value}')
            for warning in result.warnings:
                print(f'Warning: {warning}', file=sys.stderr)
        return 0
    except (IndexingError, ValueError) as exc:
        print(f'Indexing error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
