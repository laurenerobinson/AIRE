# A.I.R.E. Python backend

M1 implements a read-only, in-memory whole-binary indexer. Importing the package
starts no services or JVM. M2 adds SQLite persistence and reload of ProgramIndex.
M3 adds deterministic relationship queries and bounded call-graph traversal.
M4 constructs bounded, provenance-rich evidence bundles without AI reasoning.
M5 adds local Ollama chat with deterministic fact selection, cited interpretation,
strict JSON validation and a CLI. M5 is committed; targeted local inference passed.
M6 adds bounded advisory naming suggestions with strict evidence/name validation.
M7 adds two deterministic, evidence-backed CWE signals without LLM dependencies.
M8 adds a bounded read-only agent, public operational activity and follow-up sessions.
The optional local GUI/API uses the same agent and read-only tools.
Semantic retrieval remains unimplemented. The Java v1 plugin is unchanged.

## Conversational agent (M8)

```bash
aire-server/.venv/bin/pip install --no-deps -e aire-server
export AIRE_OLLAMA_HOST=http://127.0.0.1:11434
export AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b
export AIRE_OLLAMA_NUM_CTX=4096
aire-server/.venv/bin/aire chat aire_test_binary --database analysis.sqlite \
  --session /tmp/aire-session.json
```

The existing database must contain the binary's persisted analysis. File arguments
are matched by SHA-256; stored IDs and unique names also work. Activity prints as
tools execute. Session state is separate from stored facts. Standard-library module
fallback: `python -m aire.agent.cli chat <binary> --database analysis.sqlite`.
See [M8 architecture, tools, controls and validation](../docs/M8_AGENT.md).

## Local GUI workspace

```bash
aire-server/.venv/bin/aire gui tests/fixtures/simple_elf/aire_test_binary \
  --database analysis.sqlite
```

The selected binary must already be indexed in the database. The GUI defaults to
`http://127.0.0.1:8765/`; use `--no-browser` to skip automatic browser launch.
Conversation state lives separately under `~/.aire/gui-sessions/`.
See [GUI workspace](../docs/GUI.md) for preparation, tools, and limits.

Validated environment: Python 3.11, PyGhidra 3.1.0, Ghidra 12.1.3, JDK 21.
PyGhidra is an optional `indexing` dependency; pure record/unit-test imports do
not need it. Use the existing configured venv; no installation is needed here.

From the repository root:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/binaries/aire_test_stripped
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/binaries/aire_test_stripped --json > /tmp/aire-index.json
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_indexer_integration.py -v
```

```python
from pathlib import Path
from aire.pyghidra.indexer import IndexOptions, index_binary

index = index_binary(Path("tests/binaries/aire_test_stripped"), IndexOptions())
json_safe = index.to_dict()
```

CLI switches: `--json`, `--no-decompile`, `--no-assembly`,
`--max-assembly-instructions N`. JSON output includes all extracted text; the
normal summary does not. Diagnostics go to stderr. Options also control strings,
imports, exports, call edges, assembly character limits, and decompiler timeout
in seconds. Limits must be positive integers.

Each call imports once into a temporary project, runs static analysis, extracts
facts and closes the unsaved program/project. No rename/comment/signature/type/
byte edits, project saves, target execution, or model calls are performed.
Analysis itself creates Ghidra's temporary analysis facts. The source file's
SHA-256 is checked before and after, including on failures.

A process-wide headless JVM is reused; index calls are serialized. An owned JVM
and its temporary settings/cache are cleaned up at process exit. An already
initialized PyGhidra JVM belongs to its caller. Do not shut down and restart
JPype within one process. Force-killing a process can leave temporary state.

See [architecture](../docs/ARCHITECTURE.md) for fact definitions and limitations.

## Persist and reload an index (M2)

```python
from pathlib import Path
from aire.pyghidra.indexer import index_binary
from aire.knowledge.database import BinaryKnowledgeStore

index = index_binary(Path("sample"))
with BinaryKnowledgeStore(Path("analysis.sqlite")) as store:
    store.save_program_index(index)
    loaded = store.load_program_index(index.binary.binary_id)
    assert loaded == index
```

The store initializes schema v1 automatically and supports explicit `initialize`,
`has_binary`, `list_binaries` (binary metadata only), `delete_binary` (bool), and
`close`. Missing loads raise BinaryNotFoundError. Each save atomically replaces
all facts for that binary; foreign keys enforce ownership and cascade database
row deletion. Executable files are never opened or deleted by the store.
All M1 fields and list ordering survive; metadata uses JSON-safe normalization.
Use one instance on its creating thread in a single-writer workflow. Context
exit closes; each successful save/delete is already committed. No migrations,
semantic retrieval or AI calls are included in M2; M3 queries are separate.

Use temporary database paths during development; `*.db`, `*.sqlite`, `*.sqlite3`
are ignored and must not be committed. No extra package is required for SQLite.
Run all static integration tests and all unit tests with:

```bash
AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

See [development](../docs/DEVELOPMENT.md) for reopen/load and reporting examples.

## Query persisted relationships (M3)

Use the binary_id returned by indexing/saving. This example uses exact addresses
from the controlled fixture because names such as socket have multiple matches.
No Ghidra or target file is needed to query an existing database.

```python
from pathlib import Path
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.retrieval import ProgramQueryService

with BinaryKnowledgeStore(Path("analysis.sqlite")) as store:
    query = ProgramQueryService(store)
    # binary_id = index.binary.binary_id from the saved analysis
    matches = query.find_functions(binary_id, "socket", by="name")
    socket = query.resolve_function(binary_id, "00101060", by="address")
    callers = query.get_callers(binary_id, socket)
    callees = query.get_callees(binary_id, "00101efe")
    sites = query.get_callsites(binary_id, "00101efe", socket)
    reachable = query.get_reachable(binary_id, "00101efe", max_depth=3)
    reverse = query.get_reverse_reachable(binary_id, socket, max_depth=3)
    path = query.find_call_path(binary_id, "00101efe", socket, max_depth=3)
    summary = query.get_summary(binary_id, socket)
    top = query.rank_functions(binary_id, metric="unique_callers", limit=10)
```

Relationship results contain caller/callee FunctionRecords, callsite_address,
and edge_type. Traversal results contain function, depth, predecessor ID and
edge; reverse edges retain the original CALL direction. A path has ordered
functions/edges and hop_count. Exact duplicate edges are coalesced, while distinct
callsites remain separate. No external/thunk identity is collapsed.

Depth defaults to 3 and accepts integers 0–64; the start is excluded from walks,
and cycles never repeat nodes. Source=target returns a zero-hop path. A missing
path returns None only for the supplied bound. Rankings support unique_callers,
unique_callees, incoming_callsites and outgoing_callsites; ties use numeric hex
addresses within each address space, then IDs. Callsite counts are distinct
stored addresses. These rankings describe connectivity, not absolute importance.

Unknown binaries raise BinaryNotFoundError; unknown functions raise
FunctionNotFoundError; ambiguous names/selector collisions raise
AmbiguousFunctionError with `.matches`; foreign function IDs/records raise
BinaryMismatchError. Explicit find_functions returns all exact matches or [].
Selectors also accept function IDs or FunctionRecords. Use explicit `by` on
resolution to distinguish names from addresses/IDs. Addresses match exact text.
Invalid depth/metric/limit raises ValueError. Keep the store open on its owning
thread. No query loads an entire ProgramIndex, writes facts, or infers targets
from unresolved-call warnings.

Pure query tests and the opt-in integration/performance report:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_retrieval.py -v
AIRE_RUN_GHIDRA_TESTS=1 AIRE_QUERY_REPORT=/tmp/aire-m3-report.json PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_retrieval_integration.py -v
```

Semantic search, CWE analysis, taint/data-flow analysis and dynamic validation
are not implemented. M4 context selection and M5 local chat are described below.

## Select bounded evidence (M4)

```python
from pathlib import Path
from aire.ai.context_builder import ContextBuilder, EvidenceRequest
from aire.knowledge.database import BinaryKnowledgeStore

with BinaryKnowledgeStore(Path("analysis.sqlite")) as store:
    builder = ContextBuilder(store)
    # binary_id is the ID of the analysis previously saved with M2.
    request = EvidenceRequest(
        binary_id=binary_id,
        target="00101efe",
        max_depth=2,
        traversal_direction="forward",
        max_functions=12,
    )
    bundle = builder.build(request)
    print(bundle.render_text())
    json_safe = bundle.to_dict()
```

Targets use M3 exact resolution; duplicate names remain errors. Set target_by to
id/address/name when needed, or supply a FunctionRecord. target=None selects a
binary-level overview without choosing functions. Direct callers/callees default
on; deeper traversal requires forward/reverse/both explicitly (default None).
include_function controls inclusion of the target's full record.

Defaults: 20 functions, 50 artifacts, 100 edges, 12,000 decompiled and 8,000
assembly characters per function, and 60,000 rendered characters overall.
Strings/imports default on, exports off; at most 3 global warnings of 2,000
characters each are selected. Options also disable function/text/graph/artifact/
warning sections. All limits support zero and reject negative, non-integer or
excessive values; see ARCHITECTURE.md for finite ceilings.

Bundles expose functions/artifacts/edges/warnings with inclusion reasons and
source provenance, structured truncations, request summary, and timings. Exact
target evidence takes priority, then direct edges/callers/callees, shallow graph
context, address-associated imports and remaining binary-level artifacts. No
string is attributed to a function without a persisted xref (none exist yet).
Only imports at a selected external function's exact address get that association.
Global Import:/Analysis: diagnostics are bounded; unassociated warnings are counted
as omitted, not guessed to belong to functions.

The renderer quotes stored text as data, counts labels/escaping/newlines, and
retains text prefixes incrementally. It never blindly cuts the final string.
Truncations include original/retained sizes and omitted blocks; small budgets keep
structured identities even if those blocks cannot be rendered. Up to 512
characters are reserved for a notice; extremely small budgets may leave the
notice in structured form only. max_total_chars bounds rendered text, not all
JSON metadata/IDs. render_text() returns a finalized snapshot; timings are not
rendered. Compare to_dict(include_timings=False) across repeated builds.

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_context_builder.py -v
AIRE_RUN_GHIDRA_TESTS=1 AIRE_CONTEXT_REPORT=/tmp/aire-m4-report.json AIRE_CONTEXT_EXAMPLE=/tmp/aire-m4-context.txt PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_context_builder_integration.py -v
```

M4 itself performs no model calls. M5 consumes its evidence through the API below.

## Grounded local chat (M5)

```python
from aire.ai.chat import AireChatService, ChatRequest, render_response
from aire.ai.ollama_client import OllamaClient
from aire.knowledge.database import BinaryKnowledgeStore

client = OllamaClient()  # default loopback host; set AIRE_OLLAMA_MODEL explicitly
# client.list_models() discovers already installed names, without pulling models.
with BinaryKnowledgeStore("analysis.sqlite") as store:
    response = AireChatService(store, client).ask(
        binary_id=binary_id, question="What does this function appear to do?",
        target="process_input")
    print(render_response(response))
```

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.chat \
  analysis.sqlite '<binary_id>' 'What does process_input interact with?' \
  --target process_input --model your-installed-model
```

Omit `--target` for a bounded root/connectivity overview. No semantic relevance is
guessed from question prose. `ChatRequest` exposes depth/function/artifact/edge/
character limits and assembly/decompilation flags. `ChatResponse` includes cited
summary, deterministic stored facts, separate interpretations/confidence,
uncertainties, evidence bundle/provenance, truncations, model, timing and sizes.

Default endpoint: http://127.0.0.1:11434. Set AIRE_OLLAMA_HOST/AIRE_OLLAMA_MODEL or
explicit constructor/CLI values. There is no default model, automatic pull or
service startup. Non-loopback hosts require `allow_remote_host=True` or
`--allow-remote-host`; proxies and redirects are disabled. No internet is needed
for local inference. Raw responses are debug-only. Model prose cannot invoke
tools or write facts. Invalid citations/structures permit one format retry.

Primary fixture: tests/fixtures/simple_elf/aire_test_binary; use its stripped
partner for address-based validation. See [M5 specification](../docs/M5_CHAT.md)
for all public fields, prompt-injection defenses, exact policies and limitations.
Not implemented: semantic/vector retrieval, vulnerability confirmation,
CVE matching, dynamic validation, exploit generation, or autonomous actions.


## Advisory function naming (M6)

```python
from aire.ai.naming import NamingService, NamingOptions, render_naming_result

service = NamingService(store, chat_service)  # existing AireChatService, same store
candidates = service.find_naming_candidates(binary_id, NamingOptions(max_candidates=5))
result = service.suggest_names(binary_id, "004012f8")
print(render_naming_result(result))
# Explicit serial inference only when requested:
results = service.suggest_for_binary(binary_id, NamingOptions(max_candidates=2))
```

Current names remain stored facts; suggested names are transient interpretations.
No rename, comments, schema migration, execution or Ghidra write-back exists.
Candidate discovery is deterministic and makes no model calls. Per-function
prompts are bounded; whole-binary batching is serial and capped. The CLI opens
an existing database read-only and provides no apply/rename/write flags:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.naming \
  analysis.sqlite '<binary_id>' --candidates --limit 5
AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b AIRE_OLLAMA_NUM_CTX=4096 \
 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.naming \
  analysis.sqlite '<stripped_binary_id>' --function 004012f8 --no-assembly
```

See [M6 contracts, testing and stripped evaluation](../docs/M6_NAMING.md).
The unstripped partner supplies evaluation truth only; its meaningful names are
not included in the stripped naming prompt. M7 runs separately over stored facts.


## Deterministic security rules (M7)

```python
from aire.security.rule_engine import RuleEngine, render_scan

result = RuleEngine(store).scan_binary(binary_id)
print(render_scan(result))
json_safe = result.to_dict()
# Exact optional selection; unknown or duplicate IDs are errors.
selected = RuleEngine(store).scan_binary(binary_id, ["AIRE-CWE-120-UNBOUNDED-COPY"])
```

`RuleRegistry.register(SecurityRule)` rejects duplicate IDs, retains versioned
metadata and lists/executes rules in sorted rule-ID order. Rules consume immutable
`RuleFacts` snapshots, return `RuleEvaluation`, and never receive a model or store
write handle. `SecurityScanResult` contains evaluations, transient findings,
explicit per-rule errors, counts, warnings and per-rule/total timings.

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.security.rule_engine \
  analysis.sqlite '<binary_id>' --json
```

The CLI opens an existing database read-only; optional `--rule ID` is repeatable.
`--list-rules` lists metadata (with the same positional arguments). There are no
fix/patch/execute flags. Both initial rules emit SIGNAL at most: `strcpy` maps to
CWE-120 and `gets` to CWE-242. A direct external CALL uses MEDIUM evidence strength;
a call to an exactly matching import-named thunk uses LOW and discloses that its
external binding is not persisted. Missing corroboration remains insufficient.
No schema migration, finding persistence, target execution or Ghidra edits occur.
See [M7 contracts and validation](../docs/M7_SECURITY_RULES.md).
