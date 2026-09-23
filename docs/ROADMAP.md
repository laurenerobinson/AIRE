# Roadmap

M0 is established. M1 is complete with a passing real controlled-binary
integration test. M2 is complete with a passing real SQLite round trip.
M3 is complete with passing deterministic query tests and real persisted-graph
integration. M4 is complete with passing evidence-bundle integration.
M5 implementation and targeted low-memory live validation are complete;
binary-summary and a clean full live regression remain pending after
runtime/resource timeouts.
M6 and later milestones remain planned.

| Milestone | Scope |
| --- | --- |
| M0 | Repository cleanup and architecture |
| M1 (complete) | Read-only PyGhidra whole-binary indexer, including resolved direct CALL facts |
| M2 (complete) | SQLite knowledge store with atomic ProgramIndex save/reload |
| M3 (complete) | Deterministic relationship queries and bounded graph traversal |
| M4 (complete) | Deterministic, bounded evidence/context selection |
| M5 (targeted live validation passed) | Local evidence-grounded chat, strict citations and separate interpretation |
| M6 | Analyst-controlled whole-binary naming suggestions; no automatic renaming |
| M7 | CWE rule framework |
| M8 | Initial vulnerability checks |
| M9 | Evidence/confidence model |
| M10 | Dynamic validation prototype |
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

## Next milestone

The remaining M5 summary validation is documented separately. Future **M6 should focus
on analyst-controlled naming suggestions across the whole binary using the M5
evidence/chat pipeline**. Preserve exact function IDs, citations, uncertainty
and analyst review. **M6 must not automatically rename functions.**
M6 has not started. No execution, vulnerability confirmation, semantic/vector
retrieval, CWE/CVE engine, exploit generation or autonomous actions are added.
