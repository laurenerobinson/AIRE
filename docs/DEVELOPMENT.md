# Development

No packages were installed during reconstruction. Commands below are manual
setup/build instructions, not actions already performed. Run from repository
root unless stated otherwise.

## Ghidra

The original README and packaged filenames identify Ghidra 12.0.1 PUBLIC as
the historical target. Obtain that release through the official Ghidra project
and consult its bundled installation documentation. Set `GHIDRA_INSTALL_DIR`
to the unpacked installation. The directory must contain
`support/buildExtension.gradle` and `Ghidra/application.properties`.

## Java / JDK

The archived README specifies JDK 21. Confirm the requirements in the chosen
Ghidra release's documentation, set JAVA_HOME, and put its bin directory on PATH.
Check both `java -version` and `javac -version`. M1/M2 static integration uses
the configured JDK 21; this does not claim a new Java plugin build validation.

## Gradle

Read `application.gradle.version` in the selected Ghidra installation's
`Ghidra/application.properties`; use that version and its required JDK.
No Gradle wrapper is supplied. The canonical build uses Ghidra's extension
build script and the existing `lib/gson-2.10.1.jar`, without Maven resolution.

```bash
./ghidra-plugin/scripts/build_extension.sh
# Equivalent:
gradle --offline -p ghidra-plugin buildExtension
```

The helper requires GHIDRA_INSTALL_DIR and forwards extra Gradle arguments.
It replaces the old manual javac/zip script, which depended on deleted build/help
output and shared fixed /tmp directories. Ghidra now generates help and packages
from source. It no longer accepts the old positional date-stamp argument.
`buildTemplate.gradle` is retained as an unmodified reference, not the active build.
Output belongs in `ghidra-plugin/dist/`. Offline build may still require locally
available Ghidra build dependencies; no successful build is claimed here.
Install the resulting zip through Ghidra's File → Install Extensions, restart,
and enable AIRE in the tool's plugin configuration. Use Refresh, select a row,
Suggest, select a candidate, then Apply.

## Python venv and PyGhidra

M1 is validated with the existing `aire-server/.venv` (Python 3.11), PyGhidra
3.1.0, Ghidra 12.1.3 and JDK 21. `GHIDRA_INSTALL_DIR` and `JAVA_HOME` must point
to the configured installations. Do not replace them to run these checks.
PyGhidra is declared as the optional `indexing` dependency; unit tests need only
Python's standard library. No editable install is required with PYTHONPATH.

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/binaries/aire_test_stripped
AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_indexer_integration.py -v
```

See the [backend README](../aire-server/README.md) for JSON output, options and
JVM ownership. Ghidra static analysis modifies an unsaved temporary program,
never the original binary or an existing project. No target code is executed.

## SQLite Binary Knowledge Store (M2)

Use the existing venv and standard-library sqlite3; no ORM or extra installation
is required. Run Python with `PYTHONPATH=aire-server/src` from the root. Store
construction creates missing parent directories and initializes schema v1.

```python
from pathlib import Path
from aire.pyghidra.indexer import index_binary
from aire.knowledge.database import BinaryKnowledgeStore

index = index_binary(Path("tests/binaries/aire_test_stripped"))
with BinaryKnowledgeStore(Path("/tmp/aire-analysis.sqlite")) as store:
    store.save_program_index(index)
    print(index.binary.binary_id)

# Loading does not require Ghidra, a JVM, or the executable file.
with BinaryKnowledgeStore(Path("/tmp/aire-analysis.sqlite")) as store:
    loaded = store.load_program_index(index.binary.binary_id)
    assert loaded == index
    print(store.list_binaries())  # BinaryRecord metadata only
    assert store.has_binary(index.binary.binary_id)
    # store.delete_binary(index.binary.binary_id) deletes DB rows, not the binary.
```

`load_program_index` raises BinaryNotFoundError for a missing ID; unsupported
schemas raise UnsupportedSchemaError, malformed stored data PersistedDataError,
failed writes TransactionError, and file-opening failures DatabaseOpenError.
All inherit KnowledgeStoreError. `close()` is idempotent; context exit closes.
Each save/delete commits atomically and is independent of the outer Python
context. Treat instances as single-thread-owned, single-process/single-writer.
Metadata round trips as JSON-safe data; binary timestamps restore as datetime.

Run database tests alone or the complete suite (including both real integrations):

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_database.py -v
AIRE_RUN_GHIDRA_TESTS=1 AIRE_DATABASE_REPORT=/tmp/aire-m2-report.json PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

The M2 integration measures save/load separately from Ghidra and initialization,
reports exact round-trip counts and DB size, and deletes its temporary database.
The optional report is JSON, not a persisted runtime database. `.gitignore`
includes `*.db`, `*.sqlite`, and `*.sqlite3`; do not stage generated databases.
M2 adds no CLI switches or web service; the Python persistence API is the entry
point. Semantic retrieval in retrieval.py remains unimplemented.

## Ollama

The Java extension uses a separately managed local Ollama service. Install it
manually if needed, provision the chosen model locally, and start `ollama serve`
if the service is not already running. Model provisioning is separate from AIRE;
no model download was performed during cleanup.

```bash
export AIRE_OLLAMA_URL=http://localhost:11434
export AIRE_OLLAMA_MODEL=gemma3:4b
```

Launch Ghidra with those environment variables. JVM properties
`aire.ollama.url` and `aire.ollama.model` take precedence. Keep the endpoint local.
The Python Ollama client is not implemented.

## Controlled fixtures

See [tests](../tests/README.md). Rebuild helpers use repository-relative sources
and write to ignored `build/test-corpus/`, or AIRE_TEST_OUTPUT_DIR if set.
They compile and strip only; they never launch the target. OpenSSL development
headers/libraries enable the crypto paths. Without them, the scripts compile
fallback variants; these are not equivalent to the historical crypto corpus.
