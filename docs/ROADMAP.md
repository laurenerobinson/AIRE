# Roadmap

Current scope (2026-11-17): M1–M10 static functionality is implemented, including
the browser GUI/API and assembly intelligence. Completion of implementation
does not imply completed evaluation. [M10 Phase 6](M10_CHECKPOINT.md) remains
incomplete; Windows deployment verification and defense rehearsal are pending.
See [architecture](ARCHITECTURE.md) and [defense evidence](MS_DEFENSE_M10.md).

**2026-11-19 audit status.** Both test suites pass on the current tree (see
[TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md)). Feature
status is traced to source and tests in
[FEATURE_TRACEABILITY.md](FEATURE_TRACEABILITY.md). Open defects and risks are
in [BUG_AND_RISK_REGISTER.md](BUG_AND_RISK_REGISTER.md). M11 and M12 remain
planned.

M0 is established. M1 is complete with a passing real controlled-binary
integration test. M2 is complete with a passing real SQLite round trip.
M3 is complete with passing deterministic query tests and real persisted-graph
integration. M4 is complete with passing evidence-bundle integration.
M5 implementation and targeted low-memory live validation are complete;
binary-summary and a clean full live regression remain pending after
runtime/resource timeouts.
M6 advisory function naming is implemented and committed (`ed8881e`, `aire-m6`).
M7 deterministic security rules and the M8 read-only conversational agent are
implemented. M9 subsequently added richer references, format-aware analysis,
crypto evidence and recovery/performance work; M10 adds assembly intelligence.

| Milestone | Scope |
| --- | --- |
| M0 | Repository cleanup and architecture |
| M1 (complete) | Read-only PyGhidra whole-binary indexer, including resolved direct CALL facts |
| M2 (complete) | SQLite knowledge store with atomic ProgramIndex save/reload |
| M3 (complete) | Deterministic relationship queries and bounded graph traversal |
| M4 (complete) | Deterministic, bounded evidence/context selection |
| M5 (targeted live validation passed) | Local evidence-grounded chat, strict citations and separate interpretation |
| M6 (implemented) | Analyst-controlled whole-binary naming suggestions; no automatic renaming |
| M7 (implemented) | Versioned deterministic CWE rule framework; two API signals |
| M8 (implemented) | Read-only tools, visible activity, bounded agent, sessions and CLI |
| M9 (implemented) | Reference/thunk provenance, format-aware ELF/PE intake, crypto evidence, caching/parallel decompilation/recovery |
| M10 (implemented; evaluation incomplete) | Instruction IR, semantics, CFG/loops, bounded data flow, decompiler cross-validation, agent/GUI integration |
| M11 | Benchmark/evaluation |
| M12 | Reporting/final integration |

## M1 acceptance

Real integration passed against aire_test_stripped using PyGhidra 3.1.0 and
Ghidra 12.1.3: 106 functions, 81 decompiled bodies, bounded assembly, strings,
imports, exports, 134 direct CALL edges, explicit warnings, and unchanged input
SHA-256. Unit tests run without a JVM. Temporary programs are never saved;
resources close and repeat calls preserve fact IDs. See CURRENT_STATE.md for
counts and known limitations. No target execution or analyst-program edits occur.

## M2 acceptance

A real M1 ProgramIndex was saved, the store closed/reopened, and every field was
compared after loading. Exact current-run counts, decompiled text, assembly,
metrics, artifacts, edges, ordered warnings and metadata survived. Schema v1,
foreign keys, duplicate saves, complete reanalysis replacement, cascade deletion,
rollback on late failure, and explicit error handling have passing unit tests.
Both Ghidra integration tests pass; input SHA-256 remains unchanged. Databases
are temporary/ignored. M2 does not change M1 or implement semantic retrieval.

## M3 acceptance

Callers/callees and connecting callsites preserve exact edge provenance. Forward
and reverse BFS are bounded, cycle-safe and deterministic; shortest path search
reports absence only within its depth bound. Exact function resolution handles
ambiguity and cross-binary IDs explicitly. Summaries and four connectivity
rankings use stored CALL facts without behavioral interpretation.

The 69-test suite passed, including all M1/M2 tests, 28 new pure query tests, and
real M3 integration against persisted aire_test_stripped. Queries returned only
stored edges, repeat results matched, and input SHA-256 stayed unchanged. No
schema migration, AI, target execution, or Ghidra modification was introduced.

## M4 acceptance

EvidenceRequest validates finite limits; EvidenceBundle preserves source identity,
selection reasons, graph depth/callsites, global-artifact scope, warning omission
counts and explicit truncations. Its renderer accounts incrementally for text,
labels/escaping and a truncation notice, including tiny/zero budgets. Exact target
resolution and graph selection reuse M3 without schema changes or model calls.

The real controlled-fixture integration verifies repeated deterministic output,
stored text prefixes and callsite provenance, count/text limits, and unchanged
input SHA-256. All 99 tests pass, including 29 new pure M4 tests and all four
real integrations. No AI reasoning or target execution was introduced.

## M5 implementation

Local-only-default Ollama adapter, explicit model configuration, bounded target/
binary-level evidence, deterministic prompts, injection-aware data boundaries,
validated citations, reconstructed facts, separate model interpretation, one
format retry, timing/size metrics and a development CLI are implemented.
See [M5 contracts](M5_CHAT.md). Explicit `AIRE_OLLAMA_NUM_CTX` now configures
positive integer context allocation, preserving default 32768. Both targeted
simple-ELF pipelines passed with local `qwen2.5-coder:1.5b`, context **4096** and
6000/5000-character evidence caps. Allocation shrank the KV cache to 112 MiB;
reducing evidence alone had not fixed the prior 32768 OOM failures. Citations,
separate deterministic facts, truncation and unchanged hashes were verified.
Binary-summary validation remains pending after timeouts. An earlier stripped
interpretation was wrong despite valid citations; grounded success is limited
to the accepted requests, not general reasoning accuracy. The unchanged 32768
default is not validated on this VM. Final regression ran 157 tests: 155 passed,
two live timeout errors, zero skips. Overall M5 live validation remains pending;
see [the validation report](M5_VALIDATION.md).

## M6 acceptance

Deterministic high-connectivity generic-name candidates feed separate bounded
M4/M5 evidence requests. Strict naming JSON, safe snake_case, generic-name filters,
confidence and real citation checks produce transient analyst review results.
Exact duplicates retain the highest confidence. Completed batch results survive
errors; provider failure stops further calls. Current names are never updated.
Static stripped-fixture evaluation uses the unstripped address map without leaking
meaningful names into prompts. The optional 1.5B live naming request completed
but its invalid names/citations were rejected; no live suggestion was accepted.
All 190 enabled pure/static tests pass; three live cases skip in that run.
See [M6 validation and limits](M6_NAMING.md).

## M7 acceptance

Versioned stateless rule contracts, sorted explicit registration, immutable
single-binary fact snapshots, provenance-validated evidence and stable findings
operate without Ollama/Ghidra at scan time. Both initial API rules emit SIGNAL
only: strcpy/CWE-120 and gets/CWE-242. Missing coverage or API corroboration is
INSUFFICIENT_EVIDENCE. A bounded memcpy control emits neither signal. Signals do
not establish overflow, input control or exploitability. No persistence/schema
change or write-back is added. See [M7 validation](M7_SECURITY_RULES.md).

## M8 acceptance

The initial twelve validated read-only tools delegated to M2–M7 functionality;
subsequent M9/M10 tools extend the registry with evidence and assembly queries.
Serializable activity exposes execution, retrieval, selected functions and
grounded results without private chain-of-thought. Iteration, tool-call, context,
deadline and cancellation controls bound orchestration. Session state is separate
from immutable facts. `aire chat <binary>` opens an existing database read-only.
Deterministic tests mock the model; debug/stripped integrations and opt-in local
inference record limitations. See [M8 implementation and validation](M8_AGENT.md).

## Next work — finish evaluation and verify the split-host demonstration

Complete the missing Phase 6 units and merged report, then assess broader model
quality separately from citation validity. Rehearse Windows Chrome token login,
verify Windows ports 8770/11434, NAT Host IP, external-device rejection and
Adapter 2. Retain the small pre-indexed deterministic fallback. Dynamic
validation was a historical M10 proposal; it is not the implemented M10 scope
and remains future work. No target execution or automatic write-back is implemented.


Expand the small deterministic security checks and begin richer source/sink/
context analysis with explicit provenance and positive/negative controls.
Thunk bindings are already persisted (`thunk_relations`, schema v2). The M7
rules do not yet consume them, so ELF PLT signals stay LOW strength
([BR-12](BUG_AND_RISK_REGISTER.md)).
First use those bindings and add bounded argument/source/destination facts,
then design rules that can use those facts without guessing missing flows.
Preserve SIGNAL/CANDIDATE versus confirmed-vulnerability distinctions. Do not
introduce model-created findings, target execution or automatic changes as part
of static rule work. Evaluate agent tool selection and grounded answers across
more binaries and models before expanding autonomous analysis scope.
