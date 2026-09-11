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
