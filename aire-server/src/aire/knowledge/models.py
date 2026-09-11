"""Pure in-memory records; addresses retain Ghidra address-space notation."""
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


@dataclass
class BinaryRecord:
    binary_id: str
    path: str
    sha256: str
    format: str | None
    architecture: str | None
    image_base: str
    analyzed_at: datetime | None
    compiler_spec: str | None = None
    endianness: str | None = None
    pointer_size: int | None = None
    entry_point: str | None = None
    executable_size: int | None = None
    program_name: str | None = None


@dataclass
class FunctionRecord:
    function_id: str
    binary_id: str
    address: str
    current_name: str
    signature: str | None
    decompiled_text: str | None
    assembly: str | None
    instruction_count: int | None
    basic_block_count: int | None
    branch_count: int | None
    is_external: bool = False
    is_thunk: bool = False
    is_library: bool | None = None
    namespace: str | None = None
    calling_convention: str | None = None
    assembly_truncated: bool = False


@dataclass
class ArtifactRecord:
    artifact_id: str
    binary_id: str
    type: str
    address: str | None
    value: str


@dataclass
class FunctionEdge:
    caller_function_id: str
    callee_function_id: str
    callsite_address: str
    edge_type: str


@dataclass
class ProgramIndex:
    binary: BinaryRecord
    functions: list[FunctionRecord] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    function_edges: list[FunctionEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return _json_safe(asdict(self))


def _json_safe(value):
    if isinstance(value, Enum):
        return _json_safe(value.value)
    if isinstance(value, (Path, datetime)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f'Not JSON serializable: {type(value).__name__}')


@dataclass
class BehaviorTag:
    function_id: str
    tag: str
    evidence: list[str] = field(default_factory=list)
