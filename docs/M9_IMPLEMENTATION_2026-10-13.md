# M9 foundation implementation — October 13, 2026

## Audit and scope

The complete research document was read before changes. It exists at
[`../AIRE_competitive_research_and_implementation_plan_2026-10-13.md`](../AIRE_competitive_research_and_implementation_plan_2026-10-13.md),
not at the requested `docs/` path. Its source snapshot predates this working tree.
The repository already had substantial uncommitted changes, including:

- Integrated same-Program reference extraction, deterministic reference IDs,
  immediate thunk bindings, schema v2, transactional v1 migration, ownership
  foreign keys, read-only v1/v2 readers and hash/option-aware analysis caching.
- Application relevance ranking, a bounded Intel-syntax x86 assembly/decompiler
  crosschecker, and a local browser workspace with cached agent tools.
- Fourteen registered agent tools. Documentation still described twelve or thirteen,
  and M4/M5 still treated all strings as binary-level facts.

Those implementations were retained and extended. No rewrite, new dependency,
competitor code, new test binary, target execution, original-binary modification,
automatic rename, Java extension change, commit or push was performed.
Tests used Python 3.12.3 and the existing Ghidra 12.1.3 PUBLIC installation/JDK 21.

## Phase 0

The baseline was already green in this environment: 416 tests, 394 passed,
22 opt-in integrations skipped. The mapped-IPv6 issue was nevertheless still
version-dependent in source. Ollama now explicitly excludes IPv4-mapped IPv6
addresses from its default loopback allowlist. Ordinary `127.0.0.1`, `localhost`
(normalized to IPv4) and `::1` remain supported. The existing explicit
`allow_remote_host=True` escape hatch is preserved. A regression test forces
Python to classify mapped IPv6 as loopback and verifies the same rejection policy.

Phase 0 validation: 417 tests, 395 passed, 22 skipped. No existing test failures
required unrelated repairs. Existing M1–M8 unit tests remained operational.

## Phase 1: implemented behavior

### Exact reference retrieval and provenance

`aire.knowledge.investigation.InvestigationService` adds bounded read-only views:

```python
service.references(binary_id, function, direction='outgoing', limit=20, offset=0)
service.references(binary_id, function, strings_only=True, limit=20, offset=0)
service.thunk_chain(binary_id, function, max_depth=8)
service.classification(binary_id, function)
```

References retain source instruction address, destination address, operand index,
reference type, function/artifact IDs, source instruction, raw-byte evidence where
available, and `binary_references` provenance. Incoming lookup means an exact
function-entry reference, not every reference to its body. String retrieval joins
an actual stored artifact link and excludes call/computed-flow records. Unknown
owners remain unknown. Binary-global strings never become local merely because
their text appears in pseudo-C.

Pages accept 1–100 items and offsets up to 1,000,000. Results disclose observed
count, omitted count, offset, remaining pages and reference coverage. The agent
retains at most 512 characters per string value and 200 per source instruction,
with explicit truncation information. Full stored values are unchanged. The
registry's existing 100 KB serialization ceiling still applies; large pages may
require a smaller limit. SQL counts/joins still scale with matching stored facts.

### CALL, JMP and thunk distinctions

`getThunkedFunction(False)` bindings remain separate from `function_edges`.
The chain view follows at most sixteen hops, labels independently verified direct
JMPs separately from Ghidra-only bindings, and reports terminal function, unresolved
thunk, cycle, depth limit, ambiguous binding, or legacy coverage. It never picks
an arbitrary target from multiple bindings. Thunk provenance uses a deterministic
canonical composite identity from the stored source/target IDs and addresses.

Computed JMPs now follow the same unresolved-target policy as computed CALLs:
raw destinations are retained, but no resolved function association is asserted.
Reference extraction format is now **2**, while the SQLite schema remains **2**.
Cache requests with references require a matching integer extraction-format version;
older/missing versions trigger a fresh static analysis when `analyze_binary()` is
explicitly requested. This can make the first request after upgrade slower.
Reference-disabled requests keep their existing option-based cache behavior.

Existing databases remain readable without reindexing. Read-only investigation,
M4, and reference query views conservatively normalize old `COMPUTED_*` records
and clear resolved function targets; persisted historical rows and complete
`load_program_index()` snapshots are not rewritten. Demo readers accept both
reference formats 1 and 2. New saves retain the existing atomic replacement and
transactional v1-to-v2 migration contracts. No new migration was needed.

Direct CALL queries, paths, callers and callees preserve their original semantics.
Neither a thunk binding nor a jump creates a direct call to the implementation.
General interprocedural reachability through arbitrary jumps is not implemented.
Direct-JMP verification of a thunk currently examines its entry instruction;
multi-instruction forwarding can remain a Ghidra binding without jump verification.

### Agent and evidence integration

Four new tools bring the catalog to eighteen:

| Tool | Facts available |
| --- | --- |
| `get_xrefs` | Paged incoming/outgoing typed references and exact source addresses |
| `get_function_strings` | Exact local string references, values and dual reference/artifact provenance |
| `get_thunk_target` | Bounded separate thunk chain and explicit resolution status |
| `classify_function` | Derived classification, stored library flag, loader entry/export and import sources |

These work in the existing CLI and GUI registry. Exact selected-function string,
xref and thunk-target questions bypass model planning and synthesis, retain public
tool events, and render stored facts with IDs. Ambiguous explicit symbols are not
silently treated as a previous selection by this new routing. General natural
language routing remains bounded and incomplete; unknown requests use the existing
agent framework.

Examples against an already indexed professor sample:

```bash
aire-server/.venv/bin/aire chat FunctionOverloading.exe --database analysis.sqlite \
  --question 'Show local strings for 00412620'
aire-server/.venv/bin/aire chat FunctionOverloading.exe --database analysis.sqlite \
  --question 'Show xrefs for 00412790'
aire-server/.venv/bin/aire chat FunctionOverloading.exe --database analysis.sqlite \
  --question 'Resolve thunk target 00411028'
```

M4 evidence adds independently capped reference and thunk lists in the same SQLite
read snapshot. Defaults: 32 references and 16 thunk bindings; each can be disabled
or set to zero. Selection caps, text truncation, legacy coverage and omitted render
blocks are disclosed. True referenced strings precede unrelated artifacts. Only
strings with retained supporting references receive `function-reference` scope;
other strings retain `binary` scope. M5 admits separate `XREF`/`THUNK` citation
blocks and deterministic fact statements; model prose remains advisory. Existing
code-grounding guards are preserved. A valid citation still does not prove that a
model interpretation follows from its source.

CLI/GUI agent transport starts with smaller caps of eight references and four
bindings. If the full structured payload would exceed the existing 100 KB ceiling,
a shared helper rebuilds from SQLite with progressively smaller new relationship
sections. It preserves complete records and existing code/edge caps; standard
truncation records disclose observed/retained counts and the request summary shows
the final caps. It starts no JVM or model and writes no rows. The GUI retains its
existing separate audit/model budgets and omission of duplicate rendered text.
Oversized pre-existing fields can still produce an explicit `result_limit` after
the new relationship sections reach zero. This is not a general token estimator.

### Classification and ranking

Relevance policy v2 adds conservative `STANDARD_LIBRARY` identification for
recognized `std::` names/namespaces and `__cxa_`, `__gxx_`, `_Unwind_` symbols.
Custom C++ names and generic internals remain eligible. External and thunk flags
take precedence. Library/runtime candidates are demoted, not removed; exact graph
and reference tools retain their relationships. Ranking continues to expose scores,
reasons and bounded paths, without claiming risk or ML confidence.

Persisted thunk bindings now precede the older single-instruction x86 literal-JMP
fallback in ranking. Paths distinguish verified JMPs from Ghidra-only bindings.
Ambiguous persisted bindings are not replaced by an assembly guess. GUI cache keys
already include the relevance policy version, so the policy change invalidates
older cached rankings/answers.

`classify_function` additionally reports stored entry-point/export and import
association with source provenance. An external entry/export is not proof of
`main`, initialization order, or execution. Classification is derived from stored
flags/symbols and is not persisted as observed authorship. `is_library` remains
nullable and is disclosed rather than treated as a reliable Ghidra classification.
Unknown CRT symbols, stripped library code, complete initialization roots and
source authorship remain uncertain.

## Validation

Final default-suite command:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python \
  -m unittest discover -s aire-server/tests -v
```

Final static integration command:

```bash
AIRE_RUN_GHIDRA_TESTS=1 GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra \
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
PYTHONPATH=aire-server/src:aire-server/tests aire-server/.venv/bin/python \
  -m unittest test_investigation_integration test_references_integration \
  test_database_integration test_analysis_cache_integration -v
```

Focused command during development:

```bash
PYTHONPATH=aire-server/src:aire-server/tests aire-server/.venv/bin/python \
  -m unittest test_investigation test_references test_context_builder \
  test_agent_tools test_application_relevance -v
```

| Run | Actual result |
| --- | --- |
| Baseline | 416 run; 394 passed, 22 skipped; 7.976 s |
| Phase 0 | 417 run; 395 passed, 22 skipped; 8.494 s |
| Focused Phase 1, before final computed-flow controls | 82 passed; 1.637 s |
| Final default suite | 441 run; 418 passed, 23 skipped; 10.723 s |
| Static integration group | 4 passed; 47.913 s |
| Final expanded PE/ELF CLI/GUI transport regression | 1 passed; 50.911 s |
| `git diff --check` | Passed |

Default skips are opt-in integrations, including the new small-ELF integration.
The static run deliberately enables four integration methods. Its reference
method checks both existing professor PE/ELF samples; its new investigation method
checks both existing small debug/stripped ELF fixtures. Other integration methods
cover actual database round trips and cache reopening. All projects/databases are
disposable. No target is executed, rebuilt, downloaded or modified.

After adding the real-payload regression, `test_references_integration` was rerun
with the same static environment above and that single module as the unittest
argument. It additionally verifies three PE targets and overview evidence through
the ordinary registry, then PE target/overview evidence through cached GUI tools.
Both samples' existing single-import, cache and integrity checks still pass.

Exact PE controls include:

- `00412653 -> 00419b38` owned by `00412620`;
- `004126fc -> 00419b50` owned by `004126c0`;
- `00412857 -> 00419b68` owned by `00412790`;
- CALLs `004127ba -> 00411028` and `00412802 -> 004110cd`, followed
  by separately verified thunk JMPs to `00412620` and `004126c0`;
- absence of fabricated direct CALLs from the common caller to either body.

Regression coverage includes exact operands and ownership, paged omission counts,
cross-binary rejection, unknown functions, unresolved computed CALL/JMP targets,
legacy computed-JMP normalization without writes, depth/cycle/ambiguity stops,
deterministic save/reload order, local/global string scope, zero/tiny budgets,
citations, read-only v1 compatibility, entry/import provenance, conservative C++
classification, no-model exact routing, and insufficient tool budgets. Existing
migration rollback and ownership tests remain in the passing suite.

Intermediate failures were resolved: three old tool-count assertions needed the
expanded catalog count; a demo reader's old format-v1-only guard rejected format
v2 in a unit run and static integrations. Its compatibility guard now explicitly
accepts formats 1 and 2, with regression coverage. Final results supersede those
development failures. An additional real-PE test exposed an oversized agent payload;
the shared CLI/GUI relationship transport bounds address that regression, with
real target/overview checks and a unit control for oversized reference identities.
No live Ollama quality/performance benchmark or Java build
was run in this increment; static tests do not establish model explanation accuracy.

## Files in this increment

Created:

- `aire-server/src/aire/knowledge/investigation.py`
- `aire-server/tests/test_investigation.py`
- `aire-server/tests/test_investigation_integration.py`
- `docs/M9_IMPLEMENTATION_2026-10-13.md`

Modified, including files already dirty/untracked before this session:

- `aire-server/src/aire/agent/tools.py`, `runner.py`
- `aire-server/src/aire/ai/ollama_client.py`, `context_builder.py`,
  `evidence_selector.py`, `prompt_builder.py`
- `aire-server/src/aire/analysis/cache.py`
- `aire-server/src/aire/api/workspace.py`
- `aire-server/src/aire/knowledge/evidence.py`, `models.py`, `retrieval.py`,
  `application_relevance.py`, `reference_views.py`
- `aire-server/src/aire/pyghidra/references.py`
- `aire-server/tests/test_ollama_client.py`, `test_agent_tools.py`,
  `test_agent_runner.py`, `test_function_crosscheck.py`, `test_references.py`,
  `test_references_integration.py`, `test_analysis_cache.py`,
  `test_analysis_profiling.py`
- `README.md`, `aire-server/README.md`, `docs/CURRENT_STATE.md`,
  `docs/ARCHITECTURE.md`, `docs/M8_AGENT.md`, `docs/APPLICATION_RELEVANCE.md`,
  `docs/REFERENCE_FACTS.md`

The full Git diff includes earlier user work; it must not be attributed entirely
to this increment. No existing analyzed database was migrated or replaced by these
tests. All changes remain uncommitted.

## Phase checklist and next session

- [x] **Phase 0:** audit, green baseline, explicit mapped-IPv6 policy, regression
  validation, environment compatibility and static module smoke checks.
- [x] **Phase 1 foundation:** reuse/validate persistent exact references and safe
  migration; explicit thunk/jump handling; CALL separation; deterministic IDs and
  provenance; conservative classification; read-only queries/tools and cited evidence.
- [ ] **Phase 2:** existing bounded x86 English annotations and local assembly/C
  comparisons remain operational. No new P-code extraction, stored basic-block
  membership, architecture adapters or def-use slice is implemented here. These
  require a bounded same-Program/on-demand lifecycle, a supported opcode contract,
  persistence/version design and live Ghidra regression controls. Agreement from
  Ghidra-derived P-code must never be presented as independent proof of pseudo-C.
- [ ] **Phase 3:** exact reference routing and conservative library ranking improved
  as part of making Phase 1 usable. General intent planning, token budgets, curated
  tool discovery, string-usage search, configurable ranking contributions and
  semantic entailment controls remain incomplete. Existing framework is preserved.
- [ ] **Phase 4:** no consolidated investigation-report/export or Java panel change.
  Existing CLI/GUI can show individual tools and evidence, but this is not yet the
  complete function investigation report requested in the roadmap.

Next-session priorities:

1. Complete Phase 2 with bounded selected-function raw P-code and CFG facts on
   the existing small fixtures; disclose unsupported operations, joins and coverage.
2. Add address-linked English explanations and comparisons combining assembly,
   P-code and pseudo-C with supported/uncertain/mismatch categories. Preserve the
   existing crosscheck public status contract unless an explicit version is added.
3. Expand deterministic preflight to callers/callees, call paths and security
   intents; add approximate token accounting and smaller planning tool catalogs.
4. Build one read-only function report with purpose interpretations, exact data
   references, direct CALLs, separate thunk paths, instruction observations, security
   signals, source IDs and explicit omissions. Reuse CLI/export and current UI.
5. Improve initialization-root and unknown-library evidence, then benchmark model
   claim correctness and context cost. Add no binaries during this work; test-library
   expansion remains a separate user-authorized session.
