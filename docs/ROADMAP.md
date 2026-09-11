# Roadmap

M0 is established. M1 is complete with a passing real controlled-binary
integration test. M2 and later milestones remain planned.

| Milestone | Scope |
| --- | --- |
| M0 | Repository cleanup and architecture |
| M1 (complete) | Read-only PyGhidra whole-binary indexer, including resolved direct CALL facts |
| M2 | SQLite knowledge store |
| M3 | Call graph / program relationships |
| M4 | Retrieval/context engine |
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

## Next milestone

**M2 — SQLite-backed Binary Knowledge Store for persisting ProgramIndex data.**

Persist BinaryRecord, FunctionRecord, ArtifactRecord, FunctionEdge, provenance,
options/timings and warnings with schema versioning, foreign keys, transactions,
and deterministic-ID upserts. Define reindex/replacement semantics and test
round-trip retrieval, rollback, duplicate imports and referential integrity.
Keep Ghidra-independent database tests and a controlled index→store→load test.
Do not add LLM reasoning, embeddings, security claims, or target execution.
M2 has not started. M3 extends relationships beyond M1's direct call edges.
