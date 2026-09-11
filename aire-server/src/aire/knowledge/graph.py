"""Transient query results, separate from persisted ProgramIndex facts."""
from dataclasses import dataclass

from aire.knowledge.models import FunctionRecord


@dataclass(frozen=True)
class CallRelationship:
    caller: FunctionRecord
    callee: FunctionRecord
    callsite_address: str
    edge_type: str


@dataclass(frozen=True)
class TraversalNode:
    function: FunctionRecord
    depth: int
    predecessor: str
    edge: CallRelationship

    @property
    def callsite_address(self) -> str:
        return self.edge.callsite_address


@dataclass(frozen=True)
class CallPath:
    functions: list[FunctionRecord]
    edges: list[CallRelationship]

    @property
    def hop_count(self) -> int:
        return len(self.edges)


@dataclass(frozen=True)
class FunctionRelationshipSummary:
    function: FunctionRecord
    unique_callers: int
    incoming_callsites: int
    unique_callees: int
    outgoing_callsites: int

    @property
    def is_external(self) -> bool:
        return self.function.is_external

    @property
    def is_thunk(self) -> bool:
        return self.function.is_thunk

    @property
    def is_leaf(self) -> bool:
        """Leaf in the stored resolved CALL graph only."""
        return self.unique_callees == 0

    @property
    def is_root(self) -> bool:
        """Root in the stored resolved CALL graph only."""
        return self.unique_callers == 0
