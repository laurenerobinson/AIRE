"""M4 request/result records and deterministic, character-budgeted rendering."""
from dataclasses import asdict, dataclass, field
import json

from aire.knowledge.models import ArtifactRecord, BinaryRecord, FunctionEdge, FunctionRecord, _json_safe


@dataclass(frozen=True)
class EvidenceRequest:
    binary_id: str
    target: str | FunctionRecord | None = None
    target_by: str = 'auto'
    include_function: bool = True
    include_decompiled_text: bool = True
    include_assembly: bool = True
    include_strings: bool = True
    include_imports: bool = True
    include_exports: bool = False
    include_callers: bool = True
    include_callees: bool = True
    include_warnings: bool = True
    traversal_direction: str | None = None
    max_depth: int = 1
    max_functions: int = 20
    max_artifacts: int = 50
    max_edges: int = 100
    max_decompiled_chars_per_function: int = 12000
    max_assembly_chars_per_function: int = 8000
    max_total_chars: int = 60000
    max_warnings: int = 3
    max_warning_chars: int = 2000

    def __post_init__(self):
        if not isinstance(self.binary_id, str) or not self.binary_id:
            raise ValueError('binary_id must be a nonempty string')
        if self.target is not None and not isinstance(self.target, (str, FunctionRecord)):
            raise ValueError('target must be a string, FunctionRecord, or None')
        if self.target == '':
            raise ValueError('target must not be empty')
        if self.target_by not in ('auto', 'id', 'address', 'name'):
            raise ValueError('target_by must be auto, id, address, or name')
        if self.traversal_direction not in (None, 'forward', 'reverse', 'both'):
            raise ValueError('traversal_direction must be None, forward, reverse, or both')
        for name in self.__dataclass_fields__:
            if name.startswith('include_') and type(getattr(self, name)) is not bool:
                raise ValueError(f'{name} must be bool')
        caps = {'max_depth': 64, 'max_functions': 1000, 'max_artifacts': 5000,
                'max_edges': 10000, 'max_decompiled_chars_per_function': 1000000,
                'max_assembly_chars_per_function': 1000000, 'max_total_chars': 2000000,
                'max_warnings': 100, 'max_warning_chars': 100000}
        for name, cap in caps.items():
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= cap:
                raise ValueError(f'{name} must be an integer from 0 to {cap}')

    def summary(self):
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        if isinstance(self.target, FunctionRecord):
            result['target'] = self.target.function_id
        return result


@dataclass(frozen=True)
class Provenance:
    source_table: str
    source_id: str
    binary_id: str
    address: str | None
    reason: str
    related_function_ids: tuple[str, ...] = ()
    depth: int | None = None


@dataclass(frozen=True)
class Truncation:
    category: str
    reason: str
    limit: int | None
    observed_count_or_size: int | None
    retained_count_or_size: int
    source_id: str | None = None


@dataclass
class FunctionEvidence:
    function: FunctionRecord
    inclusion_reason: str
    depth: int
    provenance: Provenance


@dataclass(frozen=True)
class FunctionReference:
    function_id: str
    address: str
    current_name: str


@dataclass
class EdgeEvidence:
    edge: FunctionEdge
    caller: FunctionReference
    callee: FunctionReference
    inclusion_reason: str
    depth: int
    provenance: Provenance


@dataclass
class ArtifactEvidence:
    artifact: ArtifactRecord
    inclusion_reason: str
    scope: str
    provenance: Provenance


@dataclass
class WarningEvidence:
    text: str
    ordinal: int
    provenance: Provenance


@dataclass
class EvidenceBundle:
    binary: BinaryRecord
    request_summary: dict
    functions: list[FunctionEvidence] = field(default_factory=list)
    artifacts: list[ArtifactEvidence] = field(default_factory=list)
    edges: list[EdgeEvidence] = field(default_factory=list)
    warnings: list[WarningEvidence] = field(default_factory=list)
    truncations: list[Truncation] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    _rendered_text: str = field(default='', repr=False)

    def render_text(self) -> str:
        """Return the immutable text snapshot finalized by ContextBuilder.build()."""
        return self._rendered_text

    def to_dict(self, *, include_timings=True):
        result = asdict(self)
        result['rendered_text'] = result.pop('_rendered_text')
        if not include_timings:
            result['metadata'].pop('timings', None)
        return _json_safe(result)


def _json(value):
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(',', ':'))


class _Writer:
    """Append complete labeled blocks, or bounded JSON-quoted text prefixes.

    A reserved notice reports truncation when space permits. No final string
    slicing is used; JSON escaping, labels, separators and the notice all count.
    """
    def __init__(self, bundle):
        self.bundle = bundle
        self.limit = bundle.request_summary['max_total_chars']
        notice = '\nTRUNCATIONS\nSee structured truncations for categories, sources and original/retained sizes.\n'
        self.notice = notice if len(notice) <= self.limit else '[truncated]' if self.limit >= 11 else ''
        self.notice_budget = min(512, max(len(self.notice), self.limit // 20)) if self.notice else 0
        self.remaining = self.limit - self.notice_budget
        self.parts = []
        self.observed = 0
        self.omitted = False

    def block(self, label, value):
        text = label + '\n' + _json(value) + '\n'
        self.observed += len(text)
        if len(text) > self.remaining:
            self.omitted = True
            self.bundle.truncations.append(Truncation(
                'render_block', f'{label} block omitted; preserved in structured bundle',
                self.limit, len(text), 0))
            return False
        self.parts.append(text)
        self.remaining -= len(text)
        return True

    def text(self, label, value, category, source_id, *, enabled=True):
        if value is None:
            return None
        full_size = len(label) + len(_json(value)) + 2
        self.observed += full_size
        length = len(value)
        if not enabled or len(label) + 4 > self.remaining:
            retained = 0
            emitted = False
        else:
            low, high = 0, length
            while low < high:
                middle = (low + high + 1) // 2
                if len(label) + len(_json(value[:middle])) + 2 <= self.remaining:
                    low = middle
                else:
                    high = middle - 1
            retained = low
            text = label + '\n' + _json(value[:retained]) + '\n'
            self.parts.append(text)
            self.remaining -= len(text)
            emitted = True
        if retained < length or not emitted:
            self.omitted = True
            self.bundle.truncations.append(Truncation(
                category, 'max_total_chars; text prefix retained only if its identifying block fits',
                self.limit, length, retained, source_id))
        return value[:retained]

    def finish(self):
        if self.notice.startswith('\nTRUNCATIONS'):
            footer = '\nTRUNCATIONS\n'
            tail = 'Details and source IDs remain in structured truncations.\n'
            categories = {}
            for item in self.bundle.truncations:
                categories.setdefault(item.category, []).append(item)
            for category, items in categories.items():
                item = items[0]
                if category in ('functions', 'edges', 'artifacts', 'warnings'):
                    line = f'{category}: {item.observed_count_or_size} observed -> {item.retained_count_or_size} retained\n'
                else:
                    line = f'{category}: {len(items)} truncation/omission record(s)\n'
                if len(footer) + len(line) + len(tail) <= self.notice_budget:
                    footer += line
            if self.omitted:
                line = f'total_chars: content omitted to fit {self.limit}\n'
                if len(footer) + len(line) + len(tail) <= self.notice_budget:
                    footer += line
            self.notice = footer + tail
        if self.omitted:
            retained = sum(map(len, self.parts)) + len(self.notice)
            self.bundle.truncations.append(Truncation(
                'total_chars', 'rendered blocks/text omitted; structured identities remain available',
                self.limit, self.observed + len(self.notice), retained))
        if self.bundle.truncations:
            self.parts.append(self.notice)
        return ''.join(self.parts)


def render_bundle(bundle: EvidenceBundle) -> str:
    """Finalize text and reduce selected text fields to exactly what can be shown.

    Complete structured metadata/IDs are retained even if their rendered block
    cannot fit. Optional text/value fields are bounded; timings are never rendered.
    """
    writer = _Writer(bundle)
    writer.block('BINARY', asdict(bundle.binary))
    writer.block('REQUEST', bundle.request_summary)

    def function(item):
        record = item.function
        details = asdict(record)
        details.pop('decompiled_text')
        details.pop('assembly')
        label = {'target function': 'TARGET FUNCTION', 'direct caller of target': 'CALLERS',
                 'direct callee of target': 'CALLEES'}.get(item.inclusion_reason, 'RELATED FUNCTIONS')
        shown = writer.block(label, {'function': details, 'reason': item.inclusion_reason, 'depth': item.depth})
        record.decompiled_text = writer.text('DECOMPILED_TEXT (stored data)', record.decompiled_text,
                                             'decompiled_text', record.function_id, enabled=shown)
        record.assembly = writer.text('ASSEMBLY (stored data)', record.assembly,
                                     'assembly', record.function_id, enabled=shown)

    for item in bundle.functions:
        if item.inclusion_reason == 'target function':
            function(item)
    for item in bundle.edges:
        if item.depth == 1:
            writer.block('CALL EDGE', {'edge': asdict(item.edge), 'caller': asdict(item.caller),
                                      'callee': asdict(item.callee), 'reason': item.inclusion_reason, 'depth': item.depth})
    for item in bundle.functions:
        if item.inclusion_reason != 'target function':
            function(item)
    for item in bundle.edges:
        if item.depth > 1:
            writer.block('CALL EDGE', {'edge': asdict(item.edge), 'reason': item.inclusion_reason, 'depth': item.depth})
    for item in bundle.artifacts:
        details = asdict(item.artifact)
        details.pop('value')
        shown = writer.block('ARTIFACTS', {'artifact': details, 'reason': item.inclusion_reason, 'scope': item.scope})
        item.artifact.value = writer.text('VALUE (stored data)', item.artifact.value, 'artifact_value',
                                          item.artifact.artifact_id, enabled=shown)
    for item in bundle.warnings:
        shown = writer.block('WARNINGS', {'ordinal': item.ordinal, 'reason': item.provenance.reason})
        item.text = writer.text('WARNING (stored data)', item.text, 'warning_text',
                                item.provenance.source_id, enabled=shown)
    writer.block('OMITTED WARNINGS', {'count': bundle.metadata.get('omitted_warning_count', 0),
                                    'reason': 'no persisted function association or request limit'})
    bundle._rendered_text = writer.finish()
    bundle.metadata['rendered_chars'] = len(bundle._rendered_text)
    return bundle._rendered_text
