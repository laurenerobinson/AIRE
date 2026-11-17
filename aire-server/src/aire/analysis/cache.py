"""SHA-256 and option-aware orchestration of persisted static analysis.

Importing this module starts no JVM. The caller owns the store and uses it on
its creating thread, following BinaryKnowledgeStore's single-writer contract.
"""
from dataclasses import asdict, dataclass, field
from pathlib import Path
import time

from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import ProgramIndex
from aire.pyghidra.indexer import IndexingError, index_binary, sha256_file
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION
from aire.analysis.versions import INSTRUCTION_IR_VERSION as IR_VERSION
from aire.profiling import profiled, stage
from aire.analysis.versions import analyzer_versions
from aire.analysis.progress import report_progress


WARNING_SUMMARY_LIMIT = 50


@dataclass(frozen=True)
class AnalysisResult:
    """Per-request timing, including hashing, cache lookup, and any indexing/save.

    Timing is separate from ProgramIndex.metadata, which retains the original
    indexing timings on cache hits. elapsed_seconds excludes opening the store.
    """

    program_index: ProgramIndex | None
    cache_hit: bool
    elapsed_seconds: float
    # Always populated. With load_snapshot=False a cache hit leaves
    # program_index None and these come from cheap metadata-only queries.
    binary_id: str | None = None
    metadata: dict = field(default_factory=dict)
    warning_count: int = 0
    warnings: list = field(default_factory=list)

    def __post_init__(self):
        if self.program_index is not None:
            index = self.program_index
            object.__setattr__(self, 'binary_id', index.binary.binary_id)
            object.__setattr__(self, 'metadata', index.metadata)
            object.__setattr__(self, 'warning_count', len(index.warnings))
            object.__setattr__(self, 'warnings', index.warnings)


def _compatible_options(stored: object, requested: IndexOptions) -> bool:
    expected = asdict(requested)
    # Require complete, exact metadata. In particular, JSON 1 is not bool True.
    return (isinstance(stored, dict) and stored.keys() == expected.keys()
            and all(type(stored[key]) is type(value) and stored[key] == value
                    for key, value in expected.items()))


def compatible_metadata(metadata, options=None):
    options = options or IndexOptions()
    versions = analyzer_versions()
    return (metadata.get('analyzer_versions') == versions
            and metadata.get('ghidra_version') == versions['ghidra']
            and _compatible_options(metadata.get('options'), options)
            # M10: snapshots must carry structured instruction facts.
            and isinstance(metadata.get('instruction_ir'), dict)
            and metadata['instruction_ir'].get('version') == IR_VERSION
            and (not options.include_references or
                 (type(metadata.get('reference_facts_version')) is int and
                  metadata['reference_facts_version'] == REFERENCE_FACTS_VERSION)))


@profiled('python_setup')
def analyze_binary(
    path: Path | str,
    store: BinaryKnowledgeStore,
    options: IndexOptions | None = None,
    force: bool = False,
    load_snapshot: bool = True,
) -> AnalysisResult:
    """Return a compatible snapshot or index and atomically replace its facts.

    Missing, incomplete, or different option metadata causes fresh indexing.
    Requested reference facts also require the current extraction-format version.
    force=True bypasses cache lookup. Cache hits never start/import into Ghidra.
    The target is only read; SHA-256 is checked before and after lookup/indexing,
    even on failure, and against the returned binary identity before saving.
    IndexingError reports input/integrity failures; store errors propagate.

    Compatibility is decided from analysis_metadata alone, so a stale snapshot is
    never fully loaded just to be discarded. load_snapshot=False (GUI worker)
    skips the full snapshot load on a cache hit and returns only identity,
    metadata and a bounded warning summary; fresh results are unchanged.
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
        report_progress('Checking SHA-256 and persisted analysis compatibility')
        result = stored_metadata = None
        with stage('cache_load'):
            if not force and store.has_binary(before):
                stored_metadata = store.load_analysis_metadata(before)
                cache_hit = compatible_metadata(stored_metadata, options)
                if cache_hit and load_snapshot:
                    result = store.load_program_index(before)
                    # Defensive: the snapshot's own metadata must agree.
                    cache_hit = compatible_metadata(result.metadata, options)
        if not cache_hit:
            result = index_binary(path, options)
        if result is not None and (result.binary.binary_id != before or result.binary.sha256 != before):
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
        report_progress('Saving analysis to SQLite')
        store.save_program_index(result)
    report_progress('Reused persisted analysis' if cache_hit else 'Static analysis completed')
    if result is None:
        with stage('cache_load'):
            total, first = store.load_warnings(before, WARNING_SUMMARY_LIMIT)
        return AnalysisResult(None, True, time.perf_counter() - started, binary_id=before,
                              metadata=stored_metadata, warning_count=total, warnings=first)
    return AnalysisResult(result, cache_hit, time.perf_counter() - started)
