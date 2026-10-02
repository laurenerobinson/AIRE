"""M7 transient deterministic evidence and review states; no exploit probability."""
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json
from aire.knowledge.models import _json_safe


class EvaluationState(str, Enum):
    NOT_APPLICABLE = 'NOT_APPLICABLE'
    INSUFFICIENT_EVIDENCE = 'INSUFFICIENT_EVIDENCE'
    SIGNAL = 'SIGNAL'
    CANDIDATE = 'CANDIDATE'


class EvidenceStrength(str, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'


class EvidenceType(str, Enum):
    FUNCTION = 'FUNCTION'
    IMPORT = 'IMPORT'
    CALL_EDGE = 'CALL_EDGE'
    ANALYSIS_METADATA = 'ANALYSIS_METADATA'


def stable_id(prefix, *parts):
    encoded = json.dumps(parts, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    return prefix + ':' + hashlib.sha256(encoded.encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class SecurityEvidence:
    evidence_id: str
    binary_id: str
    type: EvidenceType
    description: str
    source: str
    source_id: str
    function_id: str | None = None
    address: str | None = None
    callsite: str | None = None
    artifact_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.type, EvidenceType):
            raise ValueError('Evidence type must be EvidenceType')
        expected = stable_id('EVIDENCE', self.binary_id, self.type.value, self.source, self.source_id)
        if self.evidence_id != expected:
            raise ValueError('Evidence ID does not match its source identity')

    def to_dict(self):
        return _json_safe(asdict(self))


@dataclass
class SecurityFinding:
    finding_id: str
    binary_id: str
    rule_id: str
    rule_version: str
    cwe_id: str
    title: str
    status: EvaluationState
    evidence_strength: EvidenceStrength
    primary_function_id: str
    primary_address: str
    message: str
    discriminator: str
    supporting_evidence: list[SecurityEvidence] = field(default_factory=list)
    contradicting_evidence: list[SecurityEvidence] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    # Transient results have no wall-clock creation event by default. Time is
    # intentionally excluded from identities and deterministic comparisons.
    created_at: datetime | None = None

    def __post_init__(self):
        if not isinstance(self.status, EvaluationState) or self.status not in (EvaluationState.SIGNAL, EvaluationState.CANDIDATE):
            raise ValueError('Findings must be SIGNAL or CANDIDATE, never confirmed')
        if not isinstance(self.evidence_strength, EvidenceStrength):
            raise ValueError('evidence_strength must be LOW/MEDIUM/HIGH, not a probability')
        if self.finding_id != stable_id('FINDING', self.binary_id, self.rule_id, self.rule_version,
                                       self.primary_function_id, self.primary_address, self.discriminator):
            raise ValueError('Finding ID does not match its deterministic identity')

    def to_dict(self):
        return _json_safe(asdict(self))


@dataclass(frozen=True)
class RuleEvaluation:
    binary_id: str
    rule_id: str
    rule_version: str
    status: EvaluationState
    message: str
    findings: tuple[SecurityFinding, ...] = ()
    supporting_evidence: tuple[SecurityEvidence, ...] = ()
    contradicting_evidence: tuple[SecurityEvidence, ...] = ()
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.status, EvaluationState):
            raise ValueError('Invalid rule evaluation state')
        if self.status in (EvaluationState.NOT_APPLICABLE, EvaluationState.INSUFFICIENT_EVIDENCE) and self.findings:
            raise ValueError('No findings allowed for absent or insufficient prerequisites')
        if self.status in (EvaluationState.SIGNAL, EvaluationState.CANDIDATE) and not self.findings:
            raise ValueError('SIGNAL/CANDIDATE evaluation requires findings')

    def to_dict(self):
        return _json_safe(asdict(self))


@dataclass(frozen=True)
class RuleFailure:
    rule_id: str
    rule_version: str
    error_type: str
    message: str


@dataclass
class SecurityScanResult:
    binary_id: str
    evaluations: list[RuleEvaluation]
    findings: list[SecurityFinding]
    errors: list[RuleFailure]
    rule_counts: dict
    timing: dict
    warnings: list[str]

    def to_dict(self, *, include_timings=True):
        data = asdict(self)
        if not include_timings:
            data.pop('timing')
        return _json_safe(data)
