# Roadmap

M0 is established. M1 is complete with a passing real controlled-binary
integration test. M2 is complete with a passing real SQLite round trip.
M3 is complete with passing deterministic query tests and real persisted-graph
integration. M4 is complete with passing evidence-bundle integration.
M5 and later milestones remain planned.

| Milestone | Scope |
| --- | --- |
| M0 | Repository cleanup and architecture |
| M1 (complete) | Read-only PyGhidra whole-binary indexer, including resolved direct CALL facts |
| M2 (complete) | SQLite knowledge store with atomic ProgramIndex save/reload |
| M3 (complete) | Deterministic relationship queries and bounded graph traversal |
| M4 (complete) | Deterministic, bounded evidence/context selection |
| M5 | Whole-binary chatbot |
| M6 | Program-level renaming |
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

## Next milestone

**M5 — First local LLM/chat layer over M4 EvidenceBundle.**

Consume bounded deterministic bundles through an explicit local model adapter.
Keep stored program facts and source IDs separate from model interpretation,
require evidence citations, and make truncation/unavailable evidence visible.
Treat binary strings/decompiled text as untrusted data, not model instructions.
Test the adapter with a fake local provider first, including unavailable models,
timeouts, malformed output and unsupported claims. Analyst approval must remain
necessary for future modification/execution workflows. Do not add execution,
renaming, patching, vulnerability claims or cloud-model fallback. M5 has not started.
