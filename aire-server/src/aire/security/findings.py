"""Finding representation only; no vulnerability detection is implemented."""
from dataclasses import dataclass, field


@dataclass
class SecurityFinding:
    finding_id: str
    rule_id: str
    cwe_candidate: str | None
    address: str
    status: str
    confidence: float
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
