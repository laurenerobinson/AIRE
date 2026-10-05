# Current state

M8 implements the initial A.I.R.E. conversational agent: twelve validated
read-only tools, immediate activity callbacks, a bounded model action loop,
binary-scoped persistent follow-up sessions and `aire chat <binary>`. Existing
M1–M7 modules remain the sources of facts and grounded synthesis. The default
regression suite passes; live small-model success is qualified by per-question
results in [M8 validation and limitations](M8_AGENT.md).

M0 restores the archived Java v1 implementation and establishes a Python package
layout. M1 now implements a read-only whole-binary PyGhidra indexer, validated
against the controlled stripped fixture. M2 now persists and reloads complete
ProgramIndex snapshots in SQLite. M3 adds deterministic persisted relationship
queries and bounded graph traversal. M4 now constructs deterministic bounded
evidence bundles without an LLM. M5 implements local grounded chat; both targeted
live pipelines passed with explicit low-memory context allocation. Binary-summary
validation remains pending. M6 adds advisory, bounded function naming with
deterministic candidate discovery. M7 adds deterministic CWE rule evaluation
and transient evidence-backed security signals without an LLM. The v1 description below remains based on
source inspection, not a new live Ghidra/Ollama session.

## Local GUI workspace (Oct. 2026)

The optional `aire gui` workspace adds binary-scoped chat, recent conversations,
public agent activity, stored binary metadata, and a collapsible Analysis Tools
panel over the existing M8 agent. It uses standard-library HTTP, reads analysis
facts through the existing read-only store, and saves GUI sessions separately.
See [GUI.md](GUI.md).

## Working v1 behavior

`AirePlugin` registers the extension, a Tools → A.I.R.E → Hello action, and the
`AireSuggestionsProvider` dockable Swing panel. Refresh enumerates up to 250
functions in the current program. Suggest extracts evidence for the selected
function in a Ghidra task, queries Ollama, and renders candidate cards with
reasons/evidence. Selecting a candidate and pressing Apply (or Enter) sets a
USER_DEFINED function name inside a Ghidra transaction; failures roll back.
There is no automatic or program-wide rename pass.

`ContextExtractor` collects name, entry point, prototype, decompiler C (12,000
characters plus truncation marker), up to 40 assembly instructions, instruction,
branch, return, basic-block and backward-jump loop-hint counts, branch ratio,
up to 24 strings, 25 named callees, 3 callers, and 20 referenced symbols/import
categories. It inspects references, defined data, operand scalars, and symbols.
Generic callee names are excluded. Keyword heuristics flag memory copies,
string comparisons, allocation, file/network I/O and crypto; extra categories
include parsing, formatting, synchronization and coordination.

`SymbolContext`, `NameSuggestion`, and `SuggestionStatus` carry results.
`SuggestionProvider` defines the backend contract. `SuggestionRow` and
`SuggestionsTableModel` hold UI state; `AirePluginPackage` supplies registration.
All 11 canonical Java files were preserved byte-for-byte.

## Ollama

`OllamaSuggestionProvider` uses Java HttpClient and bundled Gson 2.10.1 to POST
non-streaming JSON to `/api/generate`. Defaults: `http://localhost:11434` and
`gemma3:4b`. JVM properties `aire.ollama.url` / `aire.ollama.model` override
`AIRE_OLLAMA_URL` / `AIRE_OLLAMA_MODEL`, which override defaults. Endpoint
configuration is unrestricted in v1: local-only use requires a local endpoint.
No cloud integration has been added.

The prompt retains the first two-thirds and last third of a 3,200-character
budget for decompiled text. Assembly (320-character budget) is a fallback when
C is absent, not simultaneous prompt evidence. Lists are capped at 8 items.
Some extracted metrics/flags are used in scoring or alignment checks rather
than directly printed in the prompt.

Responses use `CANDIDATE: name | CONFIDENCE: score | REASON: text` lines.
Model confidence is multiplied by heuristic evidence weights (callees 1.25,
strings 1.20, callers 1.10, multiple blocks 1.05; generic current names 0.90,
short decompile 0.75). The multiplier is clamped to [0.5, 1.5], final score to
[0, 1]. Candidates below 0.55 are dropped; domain misalignment applies a further
0.85 penalty. Name validation, generic-name rejection, edit-distance/root
filtering and diversity filtering leave at most 3 candidates.

No accepted candidates triggers one retry, including when parsing succeeded
but filtering removed every candidate. INSUFFICIENT_EVIDENCE returns an empty
result without retry. Repeated invalid output yields an explanatory empty
result; network, missing-model and timeout failures reach UI error states.
Connection timeout is 3 seconds, request timeout 240 seconds. Logs include
model output and context summaries, which may contain analyzed information.

## Corpus and limitations

Six C sources, eight x86-64 ELF binaries, two historical maps and the original
demo survive. See [test inventory](../tests/README.md). The RAPTOR historical
map is stale; a separate symbol-derived map matches the preserved binary.
No Java/Python automated tests were found in the archive; C assets are manual
analysis fixtures, not evidence that naming accuracy targets were achieved.

The v1 UI evidence is bounded and heuristic, not a whole-program index. Import categories
are not a complete import table; loop hints are not formal loop analysis.
The constant `MAX_DECOMPILE_MS = 3000` is passed directly to Ghidra's
`decompileFunction` timeout argument; verify the API's units before relying on
it as a 3-second limit. Cancellation is swallowed by several extraction helpers,
so partial evidence may survive. Program switching during UI tasks needs live
regression testing. Confidence is not a calibrated probability. Historical demo
claims of guaranteed naming, accuracy or speedup are not verified benchmarks.
Skeleton language definitions (disabled in skel.ldefs) and help remain template
assets. Plugin metadata still describes an MVP; neither implies a full indexer.

## Implemented M1

The Python API `aire.pyghidra.indexer.index_binary` returns a serializable
ProgramIndex containing binary metadata, every discovered internal/external
function, decompilation, bounded assembly, structural metrics, defined strings,
imports, exports, direct call edges, warnings, and timing metadata. It uses
PyGhidra 3.1.0 / Ghidra 12.1.3 / JDK 21 / Python 3.11. No target execution,
explicit Ghidra program edits, project saves, or original binary writes occur.

Real integration passed against `tests/binaries/aire_test_stripped`: ELF,
`x86:LE:64:default`, gcc, base `00100000`, 106 functions (81 non-external
functions decompiled), 132 strings, 25 imports, 8 exports, 134 direct call edges.
The final validated full index took 20.268 seconds, including JVM initialization
(the initial integration run took 29.974 seconds).
There were 26 warning entries: one import log (runtime-copy relocation for stderr,
missing external libraries/symbol resolution) and 25 omitted indirect callsites.
Warnings preserve loader diagnostics; they are not security findings.

SHA-256 remained
`157c7089f3d612607cb64ca960d060788c4c317a7d6ba0f6a12a9b5d998c46de`.
The integration checks all 12 map entry addresses with PIE load bias and stable
function/artifact IDs across two calls in one JVM. The second call disables
assembly/decompilation. The M1 acceptance suite passed all 14 tests (13 pure-Python and one integration test).
Pure-Python tests cover records, IDs, options, bounds,
serialization, warning/failure recovery, and JVM-free imports. See the
[backend README](../aire-server/README.md) for commands.

## Implemented M2

`aire.knowledge.database.BinaryKnowledgeStore` provides initialize, save/load,
has/list/delete, close, and context-manager operations. Initialization is automatic;
explicit initialize is idempotent. Schema **version 1** uses standard-library
sqlite3 and seven tables for binary metadata, functions, artifacts, direct edges,
warnings, analysis metadata, and schema version. Foreign keys are enabled;
complete replacements are atomic, and deletes cascade only through database rows.
Missing analyses raise BinaryNotFoundError. Invalid persisted JSON raises
PersistedDataError. No M1 extraction or Java plugin code changed for M2.

The real round trip indexes aire_test_stripped, saves to a temporary database,
closes, reopens, and compares the entire ProgramIndex and JSON-safe data.
Original and reloaded counts matched exactly: 106 functions, 81 decompiled bodies,
132 strings, 25 imports, 8 exports, 134 direct CALL edges, and 26 ordered warnings.
Full text, metrics, IDs, nullable fields, booleans, timestamps, and metadata matched.
Save took **0.534512 seconds**, load **0.001609 seconds**, excluding Ghidra and
schema initialization. The closed database occupied **425,984 bytes (416 KiB)**.
These are one development run, not production benchmarks. Input SHA-256 before
and after was `157c7089f3d612607cb64ca960d060788c4c317a7d6ba0f6a12a9b5d998c46de`.

At M2 acceptance, **40 tests passed**: 25 new database unit tests, 13 existing unit tests, and
both real M1/M2 integrations. A forced failure at the final metadata insertion
proved rollback preserves the previous analysis and leaves no partial new one.
Duplicate/replacement saves, same-binary edge constraints, cascade deletion,
unsupported schemas, malformed JSON, SQL parameterization, and clean close were
also tested. Syntax compilation and git diff --check passed. No SQLite databases
were staged; tests use temporary directories. No target execution occurred.

M2 limitations: latest snapshot per binary only, schema v1 without migrations,
single-thread-owned connections intended for a single writer, no cross-binary
edges, no semantic retrieval, and no arbitrary Python object restoration from
metadata. Graph queries are now implemented separately in M3. SQLite retains freed pages until separately compacted;
M2 does not run VACUUM automatically. See DEVELOPMENT.md for API examples.

## Implemented M3

ProgramQueryService provides exact function resolution, callers, callees,
connecting callsites, bounded forward/reverse BFS, shortest bounded call paths,
relationship summaries and four connectivity rankings. Query results preserve
stored function facts and exact callsite provenance. Ambiguous names, unknown
identifiers, invalid depth, and cross-binary selectors produce explicit errors.
Queries read SQLite snapshots without loading ProgramIndex or changing rows.
M1 extraction and M2 persistence/schema remain unchanged.

The real integration indexes the fixture, saves and reopens a temporary database,
then verifies queries against persisted edges, repeated determinism, and unchanged
binary SHA-256. At M3 acceptance, the suite passed **69 tests**: 66 pure-Python tests (28 new M3
query tests) and the real M1, M2 and M3 integrations. Existing M1/M2 counts remain
106 functions, 81 decompiled bodies, 132 strings, 25 imports, 8 exports, 134 CALL
edges and 26 warnings.

Observed example: FUN_00101efe (`00101efe`) calls the socket thunk (`00101060`)
at `00101f39`. That caller has 14 outgoing relationships and reaches 10 other
functions within depth 3. Reverse depth 3 from the socket thunk finds 2 nodes.
Socket and write each have 1 stored caller callsite at their primary thunks;
memset (`00101090`) has 10 callsites from 4 distinct callers. Each name also
matches another thunk and an EXTERNAL entry with no stored direct callers;
name-only resolution is deliberately ambiguous.

Highest unique caller count: FUN_00101269 has 14 callers / 48 incoming callsites,
followed by FUN_0010129a with 7 / 9. These are connectivity facts, not security
or behavioral interpretations.

Mean query times over 20 warm repetitions, excluding indexing/persistence:
callers **0.078 ms**, callees **0.162 ms**, depth-3 traversal **0.706 ms**, and
top-five unique-caller ranking **0.688 ms**. These are development observations,
not production benchmarks. Target SHA-256 before/after remains
`157c7089f3d612607cb64ca960d060788c4c317a7d6ba0f6a12a9b5d998c46de`.

M3 limits: stored resolved CALL graph only, no inferred indirect/thunk links,
no cross-binary graph, one shortest-route predecessor per node, depth 0–64
(default 3), and no separate node/time budget or pagination. Exact addresses
are preserved; numeric parsing affects sorting only. API use and error semantics
are documented in the backend README and ARCHITECTURE.md.

## Implemented M4

ContextBuilder builds structured EvidenceBundle snapshots from validated
EvidenceRequest values, using M3 exact resolution and graph selection inside a
single SQLite read transaction. Bundles include binary metadata, selected function
facts/text, exact edge endpoints/callsites, explicitly scoped artifacts, bounded
global diagnostics, provenance and truncations. Text is bounded incrementally,
including formatting/escaping overhead, rather than cutting a final huge string.
Repeated builds produce identical text and JSON-safe content excluding timings.
No M1–M3 source/schema or chat.py changes were needed.

The real test indexes and persists aire_test_stripped, builds contexts for
`00101efe`, `00101060`, `00101090`, and `00101269`, verifies stored text prefixes
and callsites, and checks small-budget truncation. The example target
FUN_00101efe includes 12 functions, 16 edges, 8 binary-level artifacts, and one
global warning; 25 unassociated warnings are omitted. It preserves the socket
thunk call at `00101f39` → `00101060`. Artifact and warning omissions are explicit.
The example renders to **37,624 characters** under its 60,000-character budget;
a constrained example retains **1,970 characters** under a 2,000-character budget.
Warm means over 10 builds: target-only **0.831 ms**, direct neighbors **3.485 ms**,
depth-3 context **5.200 ms**. The first reported example took 9.660 ms in total,
including 0.210 ms target resolution, 2.070 ms graph selection, 2.995 ms artifact
selection and 3.979 ms rendering. These are development observations, excluding
Ghidra indexing and persistence, not production benchmarks.

The suite passes 99 tests: 95 pure-Python tests (29 new M4 tests) and real M1,
M2, M3, M4 integrations. Tests cover exact/ambiguous/unknown resolution, forward
and reverse context, cycles/deduplication, priorities, count and text bounds,
Unicode and embedded NULs, zero budgets, artifact scope, warning filtering,
JSON serialization, deterministic rendering and zero database-row writes.
The target SHA-256 before/after is
`157c7089f3d612607cb64ca960d060788c4c317a7d6ba0f6a12a9b5d998c46de`.

M4 limits: no function-string xrefs, no warning-function association, no semantic
relevance, no token estimator, and no separate candidate-scan/time budget.
The rendered-character limit does not bound all structured identity/metadata
fields; omitted render blocks are recorded while those fields remain usable.
Global artifacts are not claimed to be used by selected functions. The renderer
is a finalized snapshot; re-build to change it.

Git baseline note for this implementation: M3 was present but still uncommitted
on top of aire-m2 at task start. Its source/test files were preserved; a pre-M4
archive was saved under /tmp. Neither milestone was automatically committed.

## Implemented M5; targeted live validation passed

M5 adds a standard-library Ollama client, transient ChatRequest/ChatResponse,
AireChatService, deterministic prompt/citation catalog, strict response parser,
bounded overview selector and development CLI. Explicit targets consume M4
unchanged; no target selects roots/connectivity evidence with no semantic search.
The model selects deterministic fact IDs; its summary and interpretation remain
advisory prose. Existing citation IDs are validated, malformed responses retry
once, and context omissions are disclosed independently of model output.

The endpoint defaults to 127.0.0.1:11434 and requires an explicit model. Remote
hosts require opt-in; proxies and redirects are disabled. The minimal M5 change
adds `AIRE_OLLAMA_NUM_CTX`: positive integer only, explicit constructor argument
first, environment second, compatible default 32768. Invalid values fail clearly.
Context allocation controls KV-cache memory independently of evidence characters.

Local `qwen2.5-coder:1.5b` passed both targeted live pipelines at **4096** context
with 6000/5000-character evidence caps. Ollama allocated 112 MiB KV rather than
896 MiB at the previously failing 32768 setting. Both accepted responses cited
actual evidence, selected only deterministic facts and kept interpretation
separate. Exact process_input / FUN_004012f8 calls to entries 004011bc and
00401269 at callsites 00401316 and 00401334 match GROUND_TRUTH.md. Truncation was
disclosed and both fixture hashes remained unchanged. No target was executed,
no Ghidra program was modified, and no remote evidence transport occurred.

An earlier stripped response had valid citations but an incorrect interpretation;
it was not counted as a grounded success. The accepted smaller request retained
target decompilation and both edges and explicitly omitted assembly. Citation
existence is not semantic entailment. Binary-summary requests timed out and
remain unvalidated; the 32768 default is not claimed to work on this VM.

Seven new configuration tests bring the pure suite to 149 passes, with eight
opt-in integration skips. Final full regression: 157 run, 155 passed, two live
timeout errors, zero skips. All pure and static integrations passed. Standalone
targeted success does not establish a clean full live regression; overall live
validation remains pending. Results and resource-isolation details are recorded
in [the validation report](M5_VALIDATION.md). No packages/models,
swap settings or service configuration were changed. See [M5 contracts](M5_CHAT.md)
for configuration and response guarantees.

Git baseline: M4 was committed at 0c36ffb (tag aire-m4), with a clean working tree
before M5. No history was rewritten and M5 was not committed automatically.
M1–M4 source/schema, Java plugin and binary fixtures are unchanged.

## Implemented M6 advisory naming

M5 is committed at `7aa5e22` / `aire-m5`. M6 adds `NamingService`, validated
`NamingOptions`, transient `NameSuggestion`/`NamingResult`, strict naming JSON,
a deterministic renderer and read-only development CLI. Generic-name discovery
uses metadata and graph counts without a model. Meaningful names, external/import,
thunk and known-runtime/library functions are skipped by default. Overrides are
explicit. Batch inference is bounded and serial; completed results survive errors.

Suggestions must cite admitted target evidence and pass snake_case, address,
generic-name and confidence validation. They remain interpretations; stored
current names are unchanged. M6 has no write-back, application, persistence,
Ghidra mutation, target execution or security scanning path. M1–M5 source is unchanged.

Static evaluation maps stripped `FUN_004012f8` by address to unstripped
`process_input`; meaningful target/callee names are checked absent from model
prompts. The fake-provider result `validate_then_transform` is a close descriptive
test example, not evidence of real model accuracy. See [M6 naming](M6_NAMING.md)
for exact validation totals, hashes and limitations. The optional local 1.5B
naming request completed both calls but failed strict validation: address-bearing
names and invented citation IDs were rejected. No live naming suggestion was
accepted. This output-quality limitation does not replace the passing static
naming contracts or weaken M5 validation. Final pure suite: 182 passed, eleven
integration skips. Final full static suite: 190 passed, three live skips, zero
failures/errors. Both M6 success and rejection paths preserve analysis unchanged.
The separate live naming test reports one validation error, not a pass or skip.

## Implemented M7 deterministic security rules

M6 is committed at `ed8881e` / `aire-m6`. M7 adds immutable stored-fact snapshots,
versioned stateless rule contracts, a deterministic registry/engine, typed
provenance evidence, stable finding IDs, transient scan results and a read-only
CLI. No model or Ghidra runtime is needed to scan an existing knowledge store.
M1–M6 implementation and schema v1 are unchanged; the original unused finding
scaffold and its container-isolation test now use the M7 typed representation.

Initial rules are `AIRE-CWE-120-UNBOUNDED-COPY` (strcpy only) and
`AIRE-CWE-242-DANGEROUS-API` (gets only), both version 1.0.0. Their maximum state
is SIGNAL; CANDIDATE is a reserved contract state and CONFIRMED does not exist.
Missing coverage or unresolved API context remains INSUFFICIENT_EVIDENCE. Exact
API imports and resolved callsites are required; import-named thunk association
is LOW strength with an explicit missing-binding limitation. No inferred edge,
argument/size proof, taint flow or exploitability claim is added.

Three newly compiled, never-executed controls passed real indexing → persistence
→ rule scans. strcpy and gets each produce one SIGNAL; the bounded memcpy
control produces none. All 39 new pure M7 tests pass. Full pure suite: 221 passed,
14 integration/live skips. Full static M1–M7 regression: 232 passed, three live
Ollama skips, zero failures/errors. Syntax compilation and diff whitespace checks
pass. Total security scans measured 0.628–3.906 ms in the recorded run, excluding
indexing/persistence. Both simple-ELF and all new control hashes are unchanged.

Evidence forgery/cross-binary rejection, failure isolation, deterministic repeat
results, blocked model/Ghidra imports, zero row writes, unchanged database bytes
and unchanged ProgramIndex are tested. No persistence/schema migration, target
execution, Ghidra edits or binary writes occur during scanning. See
[M7 contracts, exact hashes/IDs and measurements](M7_SECURITY_RULES.md).

## Not implemented

Semantic/vector retrieval, embeddings, vulnerability confirmation, CVE matching, taint analysis, dynamic validation, exploit generation,
autonomous actions, and automatic renaming/comments/signatures remain
unimplemented. The GUI/API exposes existing read-only functionality on loopback;
browser indexing and interactive node-graph visualization remain unimplemented.
Richer deterministic security checks and source/sink/context
facts remain future work after the M8 read-only agent. The Java v1 plugin remains unchanged.
