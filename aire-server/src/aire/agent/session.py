"""Mutable conversation state lives outside the immutable binary fact store."""
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path


@dataclass
class AgentSession:
    binary_id: str
    current_function_id: str | None = None
    history: list[dict] = field(default_factory=list)
    evidence_references: list[dict] = field(default_factory=list)
    recent_results: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.binary_id, str) or not self.binary_id:
            raise ValueError('Session requires a binary identity')
        if self.current_function_id is not None and not isinstance(self.current_function_id, str):
            raise ValueError('Invalid current function')
        if not all(isinstance(v, list) for v in (self.history, self.evidence_references, self.recent_results)):
            raise ValueError('Invalid session collections')
        self._bound()

    def require_binary(self, binary_id):
        if binary_id != self.binary_id:
            raise ValueError('Session belongs to a different binary')

    def resolve_selector(self, selector):
        if isinstance(selector, str) and selector.lower().strip() in (
                'it', 'this', 'this function', 'that function', 'current', 'current function'):
            if self.current_function_id is None:
                raise ValueError('No function selected for this follow-up')
            return self.current_function_id
        return selector

    def _bound(self):
        self.history = [{'role': v['role'], 'text': v['text'][:2000]} for v in self.history[-8:]
                        if isinstance(v, dict) and v.get('role') in ('user', 'assistant') and isinstance(v.get('text'), str)]
        self.evidence_references = [v for v in self.evidence_references[-64:]
            if isinstance(v, dict) and v.get('binary_id') == self.binary_id]
        self.recent_results = [v for v in self.recent_results[-4:] if isinstance(v, dict)]
        # Retain compact identifiers/metrics only, not arbitrary prior tool bodies.
        self.recent_results = [{'tool': v.get('tool'), 'ok': bool(v.get('ok'))} for v in self.recent_results]

    def remember(self, question, answer, references=(), results=()):
        self.history.extend([{'role': 'user', 'text': question}, {'role': 'assistant', 'text': answer}])
        self.evidence_references.extend(references)
        self.recent_results.extend(results)
        self._bound()

    def to_dict(self):
        self._bound()
        return asdict(self)

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.tmp')
        temporary.write_text(json.dumps(self.to_dict(), ensure_ascii=True), encoding='utf-8')
        temporary.replace(path)

    @classmethod
    def load(cls, path, binary_id):
        path = Path(path)
        if path.stat().st_size > 100000:
            raise ValueError('Session file exceeds size limit')
        session = cls(**json.loads(path.read_text(encoding='utf-8')))
        session.require_binary(binary_id)
        return session
