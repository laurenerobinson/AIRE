# Integration checks

M1 provides the opt-in PyGhidra integration test below. The archived demo in
docs/AIRE_DEMO_SCRIPT.md remains a manual v1 scenario, not an automated test.

## M1 whole-binary indexer

The executable integration test is
`aire-server/tests/test_indexer_integration.py`. From the project root:

```bash
AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_indexer_integration.py -v
```

It is skipped unless explicitly enabled. Once enabled, missing Ghidra/PyGhidra
or a setup error fails the test rather than silently skipping validation.
Optional `AIRE_INDEX_REPORT=/tmp/aire-index.json` saves JSON test output.

The controlled fixture is statically analyzed twice in one JVM (the second pass
disables decompilation/assembly). Checks cover metadata, all discovered functions
including externals, known import names, defined strings, exports, direct call
edges, assembly bounds, stable IDs, and unchanged input hashes. FUNCTION_MAP.txt
is used only for entry addresses with the 0x100000 PIE load bias; stripped local
names are not compared with debug names. No fixture or map is modified/executed.

## M2 SQLite round trip

`aire-server/tests/test_database_integration.py` indexes the same controlled
fixture, saves to a temporary SQLite file, closes/reopens the store and compares
all ProgramIndex fields. It verifies approximate discovery coverage plus exact
current-run equality, ordered warnings/metadata, foreign-key integrity, and an
unchanged target hash. The database is removed after the test. No fixture is run.

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_DATABASE_REPORT=/tmp/aire-m2-report.json PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_database_integration.py -v
```

The optional JSON report contains counts, save/load seconds (excluding indexing
and schema initialization), closed database size, and before/after hashes.
With no filename pattern, discovery runs M1, M2, M3 and M4 integration tests plus
all pure-Python tests. Integration tests remain opt-in.

## M3 persisted relationship queries

`aire-server/tests/test_retrieval_integration.py` indexes the controlled fixture,
saves/reopens a temporary database, resolves socket/write/memset candidates, and
checks callers, callees, bounded forward/reverse walks, a shortest path, and
ranking. Every returned relationship must match an M1 edge that was persisted;
repeated results must be equal, query row writes must be zero, and target hashes
must remain identical. No indirect or thunk-to-external link is inferred.

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_QUERY_REPORT=/tmp/aire-m3-report.json PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_retrieval_integration.py -v
```

The optional JSON report includes actual candidates, callsite examples, top
connectivity counts and mean milliseconds over 20 repeated queries. Known names
can match multiple thunks and EXTERNAL functions; only some have stored callers.
Assertions use those observed edges without requiring each external entry to
have a caller. Temporary databases are removed after the test.

## M4 evidence/context bundles

`aire-server/tests/test_context_builder_integration.py` indexes and persists the
controlled fixture, then builds bundles using exact addresses 00101efe, 00101060,
00101090 and 00101269. It checks stored text prefixes, callsite/source provenance,
explicit global artifact scope, warning filtering, count/text limits, deterministic
repeat output and unchanged target SHA-256. No model or target execution occurs.

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_CONTEXT_REPORT=/tmp/aire-m4-report.json AIRE_CONTEXT_EXAMPLE=/tmp/aire-m4-context.txt PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_context_builder_integration.py -v
```

The optional report includes example counts, truncation categories, rendered
character size, per-stage timings and warm means over 10 builds for target-only,
direct-neighbor and depth-3 requests. The optional example contains rendered text;
it is not a model response. Temporary database files are removed after the test.

## M5 simple-ELF chat

`aire-server/tests/test_chat_integration.py` uses the small unstripped fixture
`tests/fixtures/simple_elf/aire_test_binary` as primary and its stripped partner
for address-based comparison. It statically indexes both, persists/reopens SQLite,
queries M3, builds M4 evidence, and checks the M5 pipeline with a fake model.
Two separate live tests use local Ollama only with AIRE_RUN_OLLAMA_TESTS=1.

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=1 \
  AIRE_CHAT_REPORT=/tmp/aire-m5-report.json PYTHONPATH=aire-server/src \
  aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_chat_integration.py -v
```

The model comes from AIRE_OLLAMA_MODEL or the first sorted installed name for
these opt-in integration tests only. Missing Ollama or models cause explicit
live-test skips; nothing is pulled/installed/started. The production service
requires explicit model configuration. An available model returning invalid
structures, nonexistent citations, or missing requested direct-callee facts
fails integration, rather than being labeled unavailable.

The test verifies exact targets, citations/provenance, confidence, truncations,
zero query writes, unchanged SHA-256 and the two process_input direct callees
from GROUND_TRUTH.md. Stripped targets are resolved using the debug partner's
address; no names are transferred into the model evidence. The JSON report
separates fake-provider pipeline checks from live answers and records context/
prompt/response sizes plus stage timings. No binary is executed or rebuilt.
See [M5 contracts](../../docs/M5_CHAT.md) for limitations and response semantics.


## M6 stripped function naming

`aire-server/tests/test_naming_integration.py` freshly indexes both simple-ELF
fixtures in an indexing child process, persists analysis and resolves the stripped
target by the debug partner's address. Only stripped evidence enters naming;
ground-truth target/callee labels are asserted absent from prompts. The fake
provider checks contracts, not model accuracy. ProgramIndex/database and fixture
hash comparisons enforce no mutation on both accepted and rejected responses;
naming never receives a Ghidra object.

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_NAMING_LIVE_TESTS=0 \
 AIRE_NAMING_REPORT=/tmp/aire-m6-report.json PYTHONPATH=aire-server/src \
 aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_naming_integration.py -v
```

The optional single-function live case uses `AIRE_RUN_NAMING_LIVE_TESTS=1`, local
`qwen2.5-coder:1.5b`, `AIRE_OLLAMA_NUM_CTX=4096` and a 5000-character evidence
cap with assembly explicitly omitted. Normal regression never requires Ollama.
An opted-in model/transport failure is an error, not silently counted as a skip.
No whole-binary live batch is tested. See [M6 naming](../../docs/M6_NAMING.md)
for the exact single-test command, current results and manual semantic review.


## M7 deterministic security rules

`aire-server/tests/test_security_integration.py` compiles three tiny dedicated
sources from `tests/fixtures/security_rules/` into a temporary directory and
statically indexes them with normal M1 (decompiler/assembly disabled). It never
executes these outputs or rebuilds the simple-ELF fixtures.

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_SECURITY_REPORT=/tmp/aire-m7-report.json \
 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover \
 -s aire-server/tests -p test_security_integration.py -v
```

Positive controls are strcpy/CWE-120 and gets/CWE-242, each expecting SIGNAL with
exact import, function and CALL/callsite provenance. The bounded memcpy control
expects NOT_APPLICABLE for both rules, not a general safety conclusion. Named
PLT thunk association is LOW evidence strength with an explicit missing-binding
limitation. Synthetic pure tests additionally exercise direct external calls,
unresolved context and failure isolation. No AI result is used as evidence.

The JSON report records per-rule/total scan times separately from indexing,
stable IDs, full findings and fixture hashes. Scans block process creation and
networking, enable SQLite query_only, compare stored ProgramIndex and database
hashes, and check unchanged fixture SHA-256. Repeat results must match excluding
timing. The expected gets linker warning is from compile-only fixture creation.
Missing GCC explicitly skips this integration; opted-in compilation/indexing
failures are errors. See [M7 rule contracts](../../docs/M7_SECURITY_RULES.md).
