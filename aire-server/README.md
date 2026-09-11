# A.I.R.E. Python backend

M1 implements a read-only, in-memory whole-binary indexer. Importing the package
starts no services or JVM. M2 adds SQLite persistence and reload of ProgramIndex.
Semantic retrieval, Python chatbot, security rules, and an API service remain
unimplemented. The Java v1 plugin is unchanged.

Validated environment: Python 3.11, PyGhidra 3.1.0, Ghidra 12.1.3, JDK 21.
PyGhidra is an optional `indexing` dependency; pure record/unit-test imports do
not need it. Use the existing configured venv; no installation is needed here.

From the repository root:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/binaries/aire_test_stripped
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/binaries/aire_test_stripped --json > /tmp/aire-index.json
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_indexer_integration.py -v
```

```python
from pathlib import Path
from aire.pyghidra.indexer import IndexOptions, index_binary

index = index_binary(Path("tests/binaries/aire_test_stripped"), IndexOptions())
json_safe = index.to_dict()
```

CLI switches: `--json`, `--no-decompile`, `--no-assembly`,
`--max-assembly-instructions N`. JSON output includes all extracted text; the
normal summary does not. Diagnostics go to stderr. Options also control strings,
imports, exports, call edges, assembly character limits, and decompiler timeout
in seconds. Limits must be positive integers.

Each call imports once into a temporary project, runs static analysis, extracts
facts and closes the unsaved program/project. No rename/comment/signature/type/
byte edits, project saves, target execution, or model calls are performed.
Analysis itself creates Ghidra's temporary analysis facts. The source file's
SHA-256 is checked before and after, including on failures.

A process-wide headless JVM is reused; index calls are serialized. An owned JVM
and its temporary settings/cache are cleaned up at process exit. An already
initialized PyGhidra JVM belongs to its caller. Do not shut down and restart
JPype within one process. Force-killing a process can leave temporary state.

See [architecture](../docs/ARCHITECTURE.md) for fact definitions and limitations.

## Persist and reload an index (M2)

```python
from pathlib import Path
from aire.pyghidra.indexer import index_binary
from aire.knowledge.database import BinaryKnowledgeStore

index = index_binary(Path("sample"))
with BinaryKnowledgeStore(Path("analysis.sqlite")) as store:
    store.save_program_index(index)
    loaded = store.load_program_index(index.binary.binary_id)
    assert loaded == index
```

The store initializes schema v1 automatically and supports explicit `initialize`,
`has_binary`, `list_binaries` (binary metadata only), `delete_binary` (bool), and
`close`. Missing loads raise BinaryNotFoundError. Each save atomically replaces
all facts for that binary; foreign keys enforce ownership and cascade database
row deletion. Executable files are never opened or deleted by the store.
All M1 fields and list ordering survive; metadata uses JSON-safe normalization.
Use one instance on its creating thread in a single-writer workflow. Context
exit closes; each successful save/delete is already committed. No migrations,
semantic retrieval, AI calls, or graph-query layer are included.

Use temporary database paths during development; `*.db`, `*.sqlite`, `*.sqlite3`
are ignored and must not be committed. No extra package is required for SQLite.
Run both integration tests with:

```bash
AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

See [development](../docs/DEVELOPMENT.md) for reopen/load and reporting examples.
