"""Stateless rule contract and explicit in-process registration; no discovery."""
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
import re
from aire.security.facts import RuleFacts
from aire.security.findings import RuleEvaluation


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    version: str
    title: str
    description: str
    cwe_id: str
    cwe_title: str
    required_facts: tuple[str, ...]
    tags: tuple[str, ...] = ()
    severity_hint: str | None = None

    def __post_init__(self):
        for name, pattern in [('rule_id', r'[A-Z][A-Z0-9-]{2,100}'),
                              ('version', r'[0-9]+\.[0-9]+\.[0-9]+'), ('cwe_id', r'CWE-[0-9]+')]:
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise ValueError(f'Invalid {name}')
        for name in ('title', 'description', 'cwe_title'):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f'{name} must be nonempty text')
        for name in ('required_facts', 'tags'):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(not isinstance(v, str) or not v for v in values):
                raise ValueError(f'{name} must be a tuple of nonempty strings')

    def to_dict(self):
        return asdict(self)


class SecurityRule(ABC):
    metadata: RuleMetadata

    @abstractmethod
    def evaluate(self, facts: RuleFacts) -> RuleEvaluation:
        """Consume an immutable fact snapshot and return explicit applicability/results."""


class RuleRegistry:
    def __init__(self):
        self._rules = {}

    def register(self, rule: SecurityRule):
        if not isinstance(rule, SecurityRule) or not isinstance(rule.metadata, RuleMetadata):
            raise TypeError('Expected SecurityRule with RuleMetadata')
        identity = rule.metadata.rule_id
        if identity in self._rules:
            raise ValueError(f'Duplicate rule ID: {identity}; only one active version per ID')
        self._rules[identity] = rule

    def select(self, rule_ids=None):
        if rule_ids is None:
            ids = list(self._rules)
        else:
            if not isinstance(rule_ids, (list, tuple)) or any(not isinstance(i, str) for i in rule_ids):
                raise ValueError('rule_ids must be a list/tuple of exact rule IDs')
            ids = list(rule_ids)
            if len(ids) != len(set(ids)):
                raise ValueError('Duplicate selected rule IDs')
            unknown = set(ids) - self._rules.keys()
            if unknown:
                raise ValueError('Unknown rule IDs: ' + ', '.join(sorted(unknown)))
        return tuple(self._rules[i] for i in sorted(ids))

    def list_rules(self):
        return tuple(rule.metadata for rule in self.select())
