"""Runtime-independent, opt-in exclusive wall timers; no logging or stored facts.

Only an explicit AnalysisProfile context activates measurement. Nested stage
time is subtracted from its parent, so all stages sum to the request wall time.
Java analyzer-internal work remains inside the auto-analysis stage.
"""
from collections import Counter, defaultdict
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from functools import wraps
import time

_ACTIVE = ContextVar('aire_analysis_profile', default=None)

STAGES = (
    ('hashing', 'Hashing / validation'),
    ('python_setup', 'Python setup / metadata'),
    ('runtime_startup', 'PyGhidra/JVM startup'),
    ('project_creation', 'Project creation'),
    ('import_open', 'Binary import/open'),
    ('auto_analysis', 'Ghidra auto-analysis'),
    ('function_discovery', 'Function discovery'),
    ('decompiler_setup', 'Decompiler setup'),
    ('decompilation', 'Decompilation'),
    ('assembly', 'Assembly / instruction metrics'),
    ('basic_blocks', 'Basic-block metrics'),
    ('function_metadata', 'Function metadata'),
    ('artifact_setup', 'Artifact setup'),
    ('strings', 'Strings'),
    ('imports', 'Imports / external symbols'),
    ('exports', 'Exports'),
    ('call_graph', 'Call graph'),
    ('xrefs', 'Xref collection'),
    ('serialization', 'Serialization'),
    ('database_save', 'Database save'),
    ('cache_load', 'Cache lookup / load'),
    ('integrity', 'Integrity verification'),
    ('cleanup', 'Program/project cleanup'),
    ('other', 'Other / profiling overhead'),
)
COUNTERS = (
    'index_binary_calls', 'runtime_checks', 'pyghidra_start_calls',
    'launcher_start_calls', 'projects_created', 'executable_imports',
    'analyze_calls', 'functions_discovered', 'decompiler_instances',
    'decompile_attempts', 'decompile_successes', 'xref_collection_calls',
    'database_saves', 'sha256_reads',
    'xrefs_collected', 'thunks_collected',
)


class AnalysisProfile:
    """One synchronous request on its current context/thread; never persisted."""

    def __init__(self):
        self.seconds = defaultdict(float)
        self.counts = Counter()
        self.decompiled_functions = Counter()
        self.total_seconds = 0.0
        self._stack = []
        self._used = False

    def __enter__(self):
        if self._used or _ACTIVE.get() is not None:
            raise RuntimeError('Use one new AnalysisProfile per request; nesting is unsupported')
        self._used = True
        self._token = _ACTIVE.set(self)
        self._root = self.stage('other')
        self._root.__enter__()
        return self

    def __exit__(self, *exc):
        try:
            return self._root.__exit__(*exc)
        finally:
            _ACTIVE.reset(self._token)

    @contextmanager
    def stage(self, name):
        frame = [time.perf_counter(), 0.0]
        self._stack.append(frame)
        try:
            yield
        finally:
            elapsed = time.perf_counter() - frame[0]
            self._stack.pop()
            self.seconds[name] += elapsed - frame[1]
            if self._stack:
                self._stack[-1][1] += elapsed
            else:
                self.total_seconds = elapsed

    def to_dict(self):
        return {
            'exclusive_seconds': {key: self.seconds[key] for key, _ in STAGES},
            'total_seconds': self.total_seconds,
            'accounted_seconds': sum(self.seconds.values()),
            'counts': {key: self.counts[key] for key in COUNTERS},
            'decompile_calls_by_function': dict(self.decompiled_functions),
            'repeated_decompilations': {key: count for key, count in self.decompiled_functions.items()
                                        if count > 1},
        }


def stage(name):
    profile = _ACTIVE.get()
    return profile.stage(name) if profile is not None else nullcontext()


def count(name, amount=1):
    profile = _ACTIVE.get()
    if profile is not None:
        profile.counts[name] += amount


def decompile_attempt(identity):
    profile = _ACTIVE.get()
    if profile is not None:
        profile.counts['decompile_attempts'] += 1
        profile.decompiled_functions[identity] += 1


def profiled(name, counter=None):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if _ACTIVE.get() is None:
                return function(*args, **kwargs)
            if counter:
                count(counter)
            with stage(name):
                return function(*args, **kwargs)
        return wrapped
    return decorate


class _TimedContext:
    def __init__(self, context, enter, exit, counter):
        self.context, self.enter, self.exit, self.counter = context, enter, exit, counter

    def __enter__(self):
        with stage(self.enter):
            if self.counter:
                count(self.counter)
            return self.context.__enter__()

    def __exit__(self, *exc):
        with stage(self.exit):
            return self.context.__exit__(*exc)


def timed_context(context, enter, exit='cleanup', counter=None):
    """Measure resource entry/exit while preserving exception suppression."""
    return _TimedContext(context, enter, exit, counter) if _ACTIVE.get() is not None else context
