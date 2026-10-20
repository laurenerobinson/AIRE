"""SHA-256 and option-aware orchestration of persisted static analysis.

Importing this module starts no JVM. The caller owns the store and uses it on
its creating thread, following BinaryKnowledgeStore's single-writer contract.
"""
from dataclasses import asdict, dataclass
from pathlib import Path
import time

from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import ProgramIndex
from aire.pyghidra.indexer import IndexingError, index_binary, sha256_file
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION
from aire.profiling import profiled, stage


@dataclass(frozen=True)
class AnalysisResult:
    """Per-request timing, including hashing, cache lookup, and any indexing/save.

    Timing is separate from ProgramIndex.metadata, which retains the original
    indexing timings on cache hits. elapsed_seconds excludes opening the store.
    """

    program_index: ProgramIndex
    cache_hit: bool
    elapsed_seconds: float


def _compatible_options(stored: object, requested: IndexOptions) -> bool:
    expected = asdict(requested)
    # Require complete, exact metadata. In particular, JSON 1 is not bool True.
    return (isinstance(stored, dict) and stored.keys() == expected.keys()
            and all(type(stored[key]) is type(value) and stored[key] == value
                    for key, value in expected.items()))


@profiled('python_setup')
def analyze_binary(
    path: Path | str,
    store: BinaryKnowledgeStore,
    options: IndexOptions | None = None,
    force: bool = False,
) -> AnalysisResult:
    """Return a compatible snapshot or index and atomically replace its facts.

    Missing, incomplete, or different option metadata causes fresh indexing.
    Requested reference facts also require the current extraction-format version.
    force=True bypasses cache lookup. Cache hits never start/import into Ghidra.
    The target is only read; SHA-256 is checked before and after lookup/indexing,
    even on failure, and against the returned binary identity before saving.
    IndexingError reports input/integrity failures; store errors propagate.
    """
    started = time.perf_counter()
    options = options if options is not None else IndexOptions()
    if not isinstance(options, IndexOptions):
        raise TypeError('options must be IndexOptions or None')
    with stage('hashing'):
        path = Path(path).expanduser().resolve()
        if not path.exists():
            raise IndexingError(f'File not found: {path}')
        if not path.is_file():
            raise IndexingError(f'Path is not a file: {path}')
        try:
            before = sha256_file(path)
        except OSError as exc:
            raise IndexingError(f'Cannot read {path}: {exc}') from exc

    cache_hit = False
    try:
        with stage('cache_load'):
            if not force and store.has_binary(before):
                result = store.load_program_index(before)
                cache_hit = _compatible_options(result.metadata.get('options'), options)
                if options.include_references:
                    version = result.metadata.get('reference_facts_version')
                    cache_hit = cache_hit and type(version) is int and version == REFERENCE_FACTS_VERSION
        if not cache_hit:
            result = index_binary(path, options)
        if result.binary.binary_id != before or result.binary.sha256 != before:
            raise IndexingError(f'Analysis SHA-256 does not match input: {path}')
    finally:
        with stage('integrity'):
            try:
                after = sha256_file(path)
            except OSError as exc:
                raise IndexingError(f'Cannot verify input integrity for {path}: {exc}') from exc
            if after != before:
                raise IndexingError(f'Input SHA-256 changed during analysis request: {path}')

    if not cache_hit:
        store.save_program_index(result)
    return AnalysisResult(result, cache_hit, time.perf_counter() - started)
