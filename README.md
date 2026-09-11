# A.I.R.E. — AI-Assisted Reverse Engineering

A.I.R.E. helps analysts understand binary programs using Ghidra evidence and
local language models. This repository restores the working Java v1 extension
and implements **A.I.R.E. 2.0 M1–M4: read-only whole-binary indexing, SQLite
persistence, relationship queries, and deterministic bounded evidence bundles**.
Local LLM/chat and later analysis services remain planned.

## Current capabilities

The Python backend statically analyzes a binary into ProgramIndex: binary metadata,
functions, decompilation, bounded assembly, strings/imports/exports, and direct
call edges. M2 saves and reloads complete ProgramIndex snapshots in SQLite.
M3 queries callers/callees, callsites, bounded reachability/paths, and connectivity
rankings over persisted facts without an LLM. M4 selects, bounds, orders and
labels evidence with provenance and explicit truncations for future model input.
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

## Planned 2.0 architecture

Binary → PyGhidra Whole-Binary Indexer → Binary Knowledge Store →
Call/Relationship Graph → Retrieval Engine → Chat / LLM or CWE Rule Engine →
Findings / Evidence → Optional Dynamic Validation → Analyst.

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
→ M4 retrieval → M5 chat → M6 program-level renaming → M7 CWE framework →
M8 initial checks → M9 evidence/confidence → M10 optional dynamic validation →
M11 evaluation → M12 reporting/integration. See [roadmap](docs/ROADMAP.md).

**Next: M5 — First local LLM/chat layer over M4 EvidenceBundle, keeping facts separate from interpretation.**

## Safety and licensing

This project is intended only for authorized reverse engineering, vulnerability research, education, and defensive security testing. Dynamic execution must only be performed against binaries the analyst is authorized to test and in an isolated environment.

No exploitation or dynamic execution functionality is implemented in the 2.0
scaffold. The project-wide license remains undecided; see [LICENSE-TODO.md](LICENSE-TODO.md).
Original author metadata credits Laurene Robinson.
