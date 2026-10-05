"""Public operational activity only. Never attach model responses or reasoning."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json

EVENT_TYPES = frozenset(('agent_started', 'request_received', 'tool_started', 'tool_completed',
    'evidence_found', 'function_selected', 'progress', 'warning', 'answer_started',
    'answer_completed', 'error', 'agent_finished'))


@dataclass(frozen=True)
class AgentEvent:
    event_type: str
    timestamp: str
    message: str
    tool_name: str | None = None
    function_id: str | None = None
    function_name: str | None = None
    function_address: str | None = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.event_type not in EVENT_TYPES:
            raise ValueError('Unknown activity event')
        datetime.fromisoformat(self.timestamp)
        if not isinstance(self.message, str) or not 0 < len(self.message) <= 500:
            raise ValueError('Event message must contain 1–500 characters')
        # Metadata has a narrow operational vocabulary; arbitrary model text is forbidden.
        allowed = {'iteration', 'tool_calls', 'ok', 'code', 'count', 'status', 'truncated'}
        if set(self.metadata) - allowed:
            raise ValueError('Unsupported activity metadata')
        json.dumps(asdict(self), allow_nan=False)

    def to_dict(self):
        return asdict(self)


class EventStream:
    def __init__(self, callback=None, clock=None):
        self.callback = callback
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self.events = []

    def emit(self, event_type, message, *, tool_name=None, function=None, metadata=None):
        event = AgentEvent(event_type, self.clock(), message, tool_name,
            function.get('function_id') if function else None,
            function.get('current_name') if function else None,
            function.get('address') if function else None, metadata or {})
        self.events.append(event)
        if self.callback:
            self.callback(event)
        return event
