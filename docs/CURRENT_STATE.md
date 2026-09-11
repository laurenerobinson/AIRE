# Current state

M0 restores the archived Java v1 implementation and establishes a Python package
layout. M1 now implements a read-only whole-binary PyGhidra indexer, validated
against the controlled stripped fixture. M2 now persists and reloads complete
ProgramIndex snapshots in SQLite. The v1 description below remains based
on source inspection, not a new live Ghidra/Ollama session.

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

All **40 tests passed**: 25 new database unit tests, 13 existing unit tests, and
both real M1/M2 integrations. A forced failure at the final metadata insertion
proved rollback preserves the previous analysis and leaves no partial new one.
Duplicate/replacement saves, same-binary edge constraints, cascade deletion,
unsupported schemas, malformed JSON, SQL parameterization, and clean close were
also tested. Syntax compilation and git diff --check passed. No SQLite databases
were staged; tests use temporary directories. No target execution occurred.

M2 limitations: latest snapshot per binary only, schema v1 without migrations,
single-thread-owned connections intended for a single writer, no cross-binary
edges, no semantic retrieval or graph-query API, and no arbitrary Python object
restoration from metadata. SQLite retains freed pages until separately compacted;
M2 does not run VACUUM automatically. See DEVELOPMENT.md for API examples.

## Not implemented

Broader program relationships and graph queries, semantic retrieval, whole-binary
chat, program-level renaming, CWE rules, CVE matching, vulnerability checks,
evidence calibration, dynamic validation, exploitation, API service, benchmark
harness, and reporting pipeline remain unimplemented. The Java v1 plugin remains
unchanged. M3 will focus on persisted program relationships and graph queries;
it has not started.
