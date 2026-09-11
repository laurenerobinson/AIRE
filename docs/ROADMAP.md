# Roadmap

M0 is established. M1 is complete with a passing real controlled-binary
integration test. M2 is complete with a passing real SQLite round trip.
M3 and later milestones remain planned.

| Milestone | Scope |
| --- | --- |
| M0 | Repository cleanup and architecture |
| M1 (complete) | Read-only PyGhidra whole-binary indexer, including resolved direct CALL facts |
| M2 (complete) | SQLite knowledge store with atomic ProgramIndex save/reload |
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

## M2 acceptance

A real M1 ProgramIndex was saved, the store closed/reopened, and every field was
compared after loading. Exact current-run counts, decompiled text, assembly,
metrics, artifacts, edges, ordered warnings and metadata survived. Schema v1,
foreign keys, duplicate saves, complete reanalysis replacement, cascade deletion,
rollback on late failure, and explicit error handling have passing unit tests.
Both Ghidra integration tests pass; input SHA-256 remains unchanged. Databases
are temporary/ignored. M2 does not change M1 or implement semantic retrieval.

## Next milestone

**M3 — Richer program relationships and graph queries over the persisted store.**

Add deterministic caller/callee queries and bounded graph traversals with cycle
handling, callsite provenance, and clear unresolved/thunk/external semantics.
Define and test any new relationship types and schema changes explicitly;
preserve stable IDs, atomic storage, and read-only extraction. Test exact graph
queries on small fixtures and the controlled persisted index. Defer AI/chat,
embeddings, semantic retrieval, security claims, and target execution. M3 has
not started.
