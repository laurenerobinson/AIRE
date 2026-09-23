"""M5 transient requests/results. Model output is never persisted as program facts."""
from dataclasses import asdict, dataclass
from aire.knowledge.evidence import EvidenceRequest, EvidenceBundle, Truncation
from aire.knowledge.models import _json_safe


class ChatError(RuntimeError):
    def __init__(self, message, *, code='chat_error', raw_responses=()):
        super().__init__(message)
        self.code = code
        self.raw_responses = tuple(raw_responses)

    def to_dict(self):
        return {'error': self.code, 'message': str(self)}


@dataclass(frozen=True)
class ChatRequest:
    binary_id: str
    question: str
    target: str | None = None
    target_by: str = 'auto'
    max_depth: int = 1
    max_functions: int = 8
    max_artifacts: int = 12
    max_edges: int = 20
    max_total_context_chars: int = 24000
    include_decompiled_text: bool = True
    include_assembly: bool = True

    def __post_init__(self):
        if not isinstance(self.question, str) or not self.question.strip() or len(self.question) > 2000:
            raise ValueError('question must contain 1–2000 characters')
        if self.target is not None and (not isinstance(self.target, str) or not 0 < len(self.target) <= 500):
            raise ValueError('target must contain 1–500 characters')
        for name, low, high in [('max_depth', 0, 4), ('max_functions', 1, 32),
                                ('max_artifacts', 0, 100), ('max_edges', 0, 100),
                                ('max_total_context_chars', 1000, 60000)]:
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{name} must be an integer from {low} to {high}')
        self.evidence_request()

    def evidence_request(self):
        return EvidenceRequest(self.binary_id, self.target, target_by=self.target_by,
            max_depth=self.max_depth, traversal_direction='forward' if self.max_depth > 1 else None,
            max_functions=self.max_functions, max_artifacts=self.max_artifacts, max_edges=self.max_edges,
            max_total_chars=self.max_total_context_chars, max_decompiled_chars_per_function=4000,
            max_assembly_chars_per_function=2000, include_exports=True,
            include_decompiled_text=self.include_decompiled_text, include_assembly=self.include_assembly)


@dataclass(frozen=True)
class Claim:
    claim: str
    evidence_ids: tuple[str, ...]
    confidence: str | None = None


@dataclass
class ChatResponse:
    question: str
    binary_id: str
    target: str | None
    summary: Claim
    facts: list[Claim]
    interpretations: list[Claim]
    uncertainties: list[str]
    citations: dict
    context_truncations: list[Truncation]
    model: str
    timing: dict
    sizes: dict
    evidence_bundle: EvidenceBundle
    attempts: int
    raw_response: str | None = None
    selection_policy: str = ''

    @property
    def context_truncated(self):
        return bool(self.context_truncations)

    def to_dict(self):
        data = asdict(self)
        data['evidence_bundle'] = self.evidence_bundle.to_dict()
        data['context_truncated'] = self.context_truncated
        return _json_safe(data)
