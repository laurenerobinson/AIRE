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

Run database tests alone or the complete suite (including static integrations):

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_database.py -v
AIRE_RUN_GHIDRA_TESTS=1 AIRE_DATABASE_REPORT=/tmp/aire-m2-report.json PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

The M2 integration measures save/load separately from Ghidra and initialization,
reports exact round-trip counts and DB size, and deletes its temporary database.
The optional report is JSON, not a persisted runtime database. `.gitignore`
includes `*.db`, `*.sqlite`, and `*.sqlite3`; do not stage generated databases.
M2 adds no CLI switches or web service; the Python persistence API is the entry
point. M3 deterministic relationship queries are now implemented in retrieval.py;
semantic retrieval remains unimplemented.

## Deterministic graph queries (M3)

ProgramQueryService reads stored CALL edges without a JVM or target access.
See the [backend examples](../aire-server/README.md#query-persisted-relationships-m3)
for exact resolution, callers/callees, bounded walks, paths, summaries and rankings.
Use exact addresses or IDs when import/thunk names are ambiguous. Keep the store
open and use it only from its owning thread.

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_retrieval.py -v
AIRE_RUN_GHIDRA_TESTS=1 AIRE_QUERY_REPORT=/tmp/aire-m3-report.json PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

The query report records observed thunk/external matches, edge provenance and
mean timings over 20 repeated queries, excluding indexing and persistence.
Integration databases are temporary and removed. No query CLI or HTTP service
was added in M3. M4 evidence selection and M5 local chat are now implemented.

## Bounded evidence context (M4)

Use ContextBuilder over an existing open store. From the root with
PYTHONPATH=aire-server/src and the configured venv:

```python
from pathlib import Path
from aire.knowledge.database import BinaryKnowledgeStore
from aire.ai.context_builder import ContextBuilder, EvidenceRequest

with BinaryKnowledgeStore(Path("/tmp/aire-analysis.sqlite")) as store:
    # Use the binary_id printed when the analysis was persisted.
    request = EvidenceRequest(binary_id=binary_id, target="00101efe",
                              max_depth=2, traversal_direction="forward",
                              max_functions=12, max_artifacts=8)
    bundle = ContextBuilder(store).build(request)
    print(bundle.render_text())
    assert len(bundle.render_text()) <= request.max_total_chars
```

No JVM or target-file access is needed for context selection alone. Exact names
can be ambiguous; use addresses/IDs or explicit target_by. Strings are global
artifacts, not claimed function references. Text and count omissions have
structured truncations; keep those available to future consumers. ContextBuilder
uses one read snapshot on the store's owning thread and leaves stored facts intact.

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_context_builder.py -v
AIRE_RUN_GHIDRA_TESTS=1 AIRE_CONTEXT_REPORT=/tmp/aire-m4-report.json AIRE_CONTEXT_EXAMPLE=/tmp/aire-m4-context.txt PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

The report includes selected counts, rendered sizes, truncation categories,
per-stage timings and warm means for target-only/direct/depth-3 bundles. The
example file contains deterministic rendered evidence. SQLite files are temporary
and removed by integration tests. No tools/models are installed or called.

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
Python M5 uses AIRE_OLLAMA_HOST (not the Java URL variable), with no assumed model.
See the M5 development workflow below.

## Controlled fixtures

See [tests](../tests/README.md). Rebuild helpers use repository-relative sources
and write to ignored `build/test-corpus/`, or AIRE_TEST_OUTPUT_DIR if set.
They compile and strip only; they never launch the target. OpenSSL development
headers/libraries enable the crypto paths. Without them, the scripts compile
fallback variants; these are not equivalent to the historical crypto corpus.

## M5 development workflow

Use the small unstripped fixture as primary; its GROUND_TRUTH.md is authoritative.
Do not execute or rebuild it during chat validation. Persist an M1 index into
an ignored SQLite file, then ask questions without accessing the target again:

```bash
export AIRE_OLLAMA_HOST=http://127.0.0.1:11434
export AIRE_OLLAMA_MODEL=your-installed-model
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.chat \
  analysis.sqlite '<binary_id>' 'What does process_input interact with?' --target process_input
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=1 \
  AIRE_CHAT_REPORT=/tmp/aire-m5-report.json PYTHONPATH=aire-server/src \
  aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

Without either integration flag, pure tests require no Ghidra or Ollama. The real
M5 tests statically index both simple fixtures, check exact graph ground truth,
build/parse chat responses with a fake provider, and separately try live local
Ollama if enabled. Missing services/models skip only live tests with a reason.
Never install/start/pull automatically. The report distinguishes fake-model
pipeline results from live inference and includes citations, timing, sizes and
before/after hashes. See [M5 contracts](M5_CHAT.md) for configuration and limits.

M6 has not started. Its next scope is analyst-controlled whole-binary naming
suggestions using M5 evidence, with explicit review and no automatic renaming.
