"""M6 transient analyst review data. No persistence or application actions."""
from dataclasses import asdict, dataclass, field
from aire.knowledge.models import _json_safe

CONFIDENCE = ('low', 'medium', 'high')


@dataclass(frozen=True)
class NamingOptions:
    max_candidates: int = 20
    max_suggestions_per_function: int = 3
    min_confidence: str | None = None
    include_decompiled_text: bool = True
    include_assembly: bool = True
    max_depth: int = 1
    max_context_chars: int = 5000
    skip_external: bool = True
    skip_thunks: bool = True
    skip_meaningful_names: bool = True
    skip_library: bool = True

    def __post_init__(self):
        for name, low, high in (('max_candidates', 1, 100),
                               ('max_suggestions_per_function', 1, 5),
                               ('max_depth', 0, 2), ('max_context_chars', 2000, 12000)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{name} must be an integer from {low} to {high}')
        for name in self.__dataclass_fields__:
            if name.startswith(('include_', 'skip_')) and type(getattr(self, name)) is not bool:
                raise ValueError(f'{name} must be bool')
        if self.min_confidence is not None and self.min_confidence not in CONFIDENCE:
            raise ValueError('min_confidence must be None, low, medium, or high')


@dataclass(frozen=True)
class NameSuggestion:
    suggested_name: str
    confidence: str
    rationale: str
    evidence_ids: tuple[str, ...]


@dataclass
class NamingResult:
    binary_id: str
    function_id: str
    current_name: str
    function_address: str
    suggestions: list[NameSuggestion] = field(default_factory=list)
    evidence_summary: dict = field(default_factory=dict)
    context_truncated: bool = False
    model: str | None = None
    timing: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    citations: dict = field(default_factory=dict)
    context_truncations: list = field(default_factory=list)
    sizes: dict = field(default_factory=dict)
    attempts: int = 0
    status: str = 'ok'
    error: dict | None = None

    def to_dict(self):
        return _json_safe(asdict(self))
