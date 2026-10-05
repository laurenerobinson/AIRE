# A.I.R.E. — AI-Assisted Reverse Engineering

A.I.R.E. helps analysts understand binary programs using Ghidra evidence and
local language models. This repository restores the working Java v1 extension
and implements **A.I.R.E. 2.0 M1–M8: read-only whole-binary indexing, SQLite
persistence, relationship queries, bounded evidence, local grounded chat and
advisory function naming, deterministic security rules and a bounded conversational agent**.
M5 is committed/tagged; targeted local inference passed. M6 adds bounded naming
suggestions for analyst review, with no automatic rename or write-back.

## Current capabilities

The Python backend statically analyzes a binary into ProgramIndex: binary metadata,
functions, decompilation, bounded assembly, strings/imports/exports, and direct
call edges. M2 saves and reloads complete ProgramIndex snapshots in SQLite.
M3 queries callers/callees, callsites, bounded reachability/paths, and connectivity
rankings over persisted facts without an LLM. M4 selects, bounds, orders and
labels evidence with provenance and explicit truncations. M5 sends bounded evidence
to configured local Ollama, validates citations, and separates stored facts from
model interpretation. M6 discovers high-connectivity generic-name candidates and
returns validated, cited naming interpretations separately from current names.
M7 evaluates versioned, deterministic CWE rules over stored facts, without a model.
Its `strcpy` and `gets` signals preserve callsite/import provenance and require
analyst review; they do not establish a vulnerability.
See [M7 security rules](docs/M7_SECURITY_RULES.md), [M6 naming](docs/M6_NAMING.md) and [M5 chat](docs/M5_CHAT.md).
M8 adds 12 read-only tools, immediate operational activity, bounded model actions,
binary-scoped follow-up sessions and `aire chat <binary>` over an existing database.
See [agent architecture, CLI and validation](docs/M8_AGENT.md).
It does not execute or modify the target. See the
[backend README](aire-server/README.md) for API, CLI, and test commands.

The Ghidra extension extracts per-function decompiled code, assembly, callers,
named callees, strings, import-related evidence, structural metrics and behavior
flags. It asks local Ollama for naming candidates, filters confidence and near
duplicates, and presents evidence in a dockable panel. The analyst selects and
applies each rename. The UI currently lists up to 250 functions; confidence is
heuristic, not a measured probability of correctness.

The original Java implementation, six C fixtures, eight intentional test binaries,
ground-truth maps and demo are preserved. See [current state](docs/CURRENT_STATE.md)
for exact behavior and limitations, and [audit](docs/AUDIT.md) for provenance.

## Implemented and planned 2.0 architecture

Implemented: Binary → PyGhidra → ProgramIndex → SQLite Knowledge Store →
Relationship Queries → Evidence Context Builder → Local Grounded Model →
Naming Suggestion Service (M6) → Analyst Review. **No write-back.**

A separate M7 branch runs Relationship Queries → Deterministic CWE Rule Engine
→ Evidence-backed security signals → Analyst Review. It needs no Ollama.

Not implemented: semantic/vector retrieval, vulnerability confirmation,
CVE matching, dynamic validation, exploit generation, and autonomous actions.

Ghidra supplies facts, rules identify deterministic findings where possible,
and local models explain evidence. Analysts approve changes and execution.
See [architecture](docs/ARCHITECTURE.md) for the trust boundaries.

## Repository layout

```text
AIRE/
├── ghidra-plugin/   Canonical v1 Ghidra extension and bundled Gson
├── aire-server/     Read-only indexer, SQLite store, deterministic graph queries
├── tests/           Sources, preserved binaries, ground truth, integration instructions
├── docs/            Current state, architecture, roadmap, setup, demo and recovery archive
├── scripts/         Repository-relative fixture rebuild scripts
├── .gitignore
├── README.md
└── LICENSE-TODO.md
```

## Setup overview

The archived build target is Ghidra 12.0.1 PUBLIC and JDK 21. Select the Gradle
version required by that Ghidra installation, set GHIDRA_INSTALL_DIR and JAVA_HOME,
and run `./ghidra-plugin/scripts/build_extension.sh`. Install the generated
extension zip in Ghidra and enable AIRE. Configure a local Ollama service and model
(default `gemma3:4b` at `http://localhost:11434`), then Refresh → select function →
Suggest → select candidate → Apply. Keep endpoint overrides local.

M1 is validated with Python 3.11, PyGhidra 3.1.0, Ghidra 12.1.3 and JDK 21.
Use the existing aire-server/.venv; pure Python checks need no Ghidra runtime.
There is no running Python API server.
See [development](docs/DEVELOPMENT.md) and [test corpus](tests/README.md) for commands.
No packages or models are installed automatically.

## Roadmap

M0 cleanup and architecture → M1 read-only indexing → M2 SQLite → M3 relationships
→ M4 retrieval → M5 chat → M6 analyst-controlled naming suggestions → M7 CWE framework →
M8 read-only agent → M9 evidence/confidence and richer stored provenance → M10 optional dynamic validation →
M11 evaluation → M12 reporting/integration. See [roadmap](docs/ROADMAP.md).

**Next: M8 — expand deterministic checks and source/sink/context facts while
preserving incomplete-evidence states. M8 has not started. No automatic renaming.**

## Safety and licensing

This project is intended only for authorized reverse engineering, vulnerability research, education, and defensive security testing. Dynamic execution must only be performed against binaries the analyst is authorized to test and in an isolated environment.

No exploitation or dynamic execution functionality is implemented in the 2.0
scaffold. The project-wide license remains undecided; see [LICENSE-TODO.md](LICENSE-TODO.md).
Original author metadata credits Laurene Robinson.
