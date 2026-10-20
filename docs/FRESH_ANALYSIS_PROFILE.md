# Fresh analysis profiling

Instrumentation only: analyzer selection, decompilation settings, extraction,
snapshot schema, and integrity checks are unchanged. Measurements are opt-in,
request-local, and never added to ProgramIndex metadata. Normal requests emit no
profiling output. No target is executed or modified, and no dependency was added.

The runtime-independent collector is `aire.profiling`. Timers are exclusive:
child elapsed time is subtracted from the parent, including repeated/nested
stage names. Every request's rows sum to its measured wall time. Existing
indexer metadata timings remain inclusive and must not be added to this table.
Resource instrumentation includes eager `open_project()` and `load()` calls,
context-manager entry/exit, program/decompiler release, and temporary deletion.

## Reproduce

From the repository root, start a new Python process:

```bash
GHIDRA_INSTALL_DIR="$HOME/tools/ghidra" \
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
PYTHONPATH=aire-server/src \
aire-server/.venv/bin/python scripts/benchmark_analysis_cache.py \
  professor_samples/function_overloading/original/FunctionOverloading.exe \
  --profile --output /tmp/aire-fresh-profile.json \
  --xref-script scripts/demoL_function_overloading.py
```

A forces fresh analysis in the new Python/JVM. B forces another fresh analysis
in the same process/JVM and atomically replaces A's snapshot. C reopens SQLite
and loads B normally, with indexing patched to fail if attempted. The optional
xref experiment runs separately after C and is excluded from A/B/C totals.
The default benchmark without `--profile` keeps its existing miss/hit behavior.

## Measurements

Recorded on 2026-10-07 with Python 3.12.3 and Ghidra 12.1.3. All three requests
used the same process and default IndexOptions. Full-precision times, counters,
original indexing metadata, and per-function decompile call counts are in
[FRESH_ANALYSIS_PROFILE.json](FRESH_ANALYSIS_PROFILE.json).

| Exclusive stage, seconds | Cold fresh A | Warm fresh B | Cached C |
|---|---:|---:|---:|
| Hashing / validation | 0.000230 | 0.000374 | 0.000204 |
| Python setup / metadata | 0.169455 | 0.001300 | 0.000031 |
| PyGhidra/JVM startup | 3.614214 | 0.000101 | 0.000000 |
| Project creation | 0.495590 | 0.027333 | 0.000000 |
| Binary import/open | 2.693453 | 0.240919 | 0.000000 |
| Ghidra auto-analysis | 15.706840 | 10.747107 | 0.000000 |
| Function discovery | 0.065046 | 0.310581 | 0.000000 |
| Decompiler setup | 0.231903 | 0.471759 | 0.000000 |
| Decompilation | 5.068145 | 3.197794 | 0.000000 |
| Assembly / instruction metrics | 0.187032 | 0.077416 | 0.000000 |
| Basic-block metrics | 0.140836 | 0.055627 | 0.000000 |
| Function metadata | 0.161946 | 0.048270 | 0.000000 |
| Artifact setup | 0.017402 | 0.000210 | 0.000000 |
| Strings | 0.021785 | 0.017329 | 0.000000 |
| Imports / external symbols | 0.009046 | 0.002301 | 0.000000 |
| Exports | 0.001018 | 0.000169 | 0.000000 |
| Call graph | 0.028202 | 0.036291 | 0.000000 |
| Xref collection | 0.000000 | 0.000000 | 0.000000 |
| Serialization | 0.008268 | 0.007028 | 0.000000 |
| Database save | 0.022433 | 0.023037 | 0.000000 |
| Cache lookup / load | 0.000001 | 0.000000 | 0.004661 |
| Integrity verification | 0.000162 | 0.000145 | 0.000099 |
| Program/project cleanup | 0.012433 | 0.008312 | 0.000000 |
| Other / profiling overhead | 0.000009 | 0.000009 | 0.000006 |
| **TOTAL** | **28.655448** | **15.273411** | **0.005001** |

Row values are rounded to six decimals; JSON retains full precision. Total
includes hashing, static indexing, actual persistence serialization/save, and
per-request cleanup. It excludes interpreter/package imports before the request,
opening the database, report serialization/output, benchmark comparisons, and
process-exit JVM shutdown. Cold means a new Python/JVM, not flushed OS disk
caches. Warm measurements also reflect JIT/class/OS cache warming, so the full
13.382037-second cold/warm difference is not solely JVM startup.

This single run does not explain the previous 79.546433-second fresh result on
its own. No optimization was applied, and the difference is not an optimization
claim. Repeated measurements under controlled load are needed to characterize
that variation.

## Work counts and result integrity

| A.I.R.E. operation | Cold A | Warm B | Cached C |
|---|---:|---:|---:|
| index_binary | 1 | 1 | 0 |
| Runtime readiness checks | 1 | 1 | 0 |
| pyghidra.start | 0 | 0 | 0 |
| HeadlessPyGhidraLauncher.start | 1 | 0 | 0 |
| Ghidra projects created | 1 | 1 | 0 |
| Target imports | 1 | 1 | 0 |
| pyghidra.analyze | 1 | 1 | 0 |
| Functions discovered | 385 | 385 | 0 |
| DecompInterface instances | 1 | 1 | 0 |
| Explicit function decompile attempts / successes | 302 / 302 | 302 / 302 | 0 / 0 |
| collect_xrefs | 0 | 0 | 0 |
| Database saves | 1 | 1 | 0 |
| SHA-256 reads | 4 | 4 | 2 |

The launcher starts directly; A.I.R.E. does not call the `pyghidra.start()` API.
There are no repeated explicit function decompilations within either fresh
request. B deliberately decompiles again because it is a forced fresh request.
Ghidra analyzers' internal Java work, including any internal decompilation, is
inside auto-analysis and is not traced by the Python decompile counters.

Cold/warm snapshots have identical facts after excluding only the original
analysis timestamp and five original timing fields. Warm/cached snapshots are
exactly equal, including every metadata field. SHA-256 before and after all
experiments was:

```text
cfc8c5f031587c721d680d3dd9bd94bbc690667acf8651403fb8c7e70f2fab07
```

Fresh requests retain both layers' pre/post integrity hashing (four reads).
The cached request retains its pre/post hashing (two reads).

## Xref duplicate-work audit

`scripts/demoL_function_overloading.py:collect_xrefs()` was actually run after
C against the matching hash-pinned PE. Its separate exclusive measurements:

| Demo-only operation | Seconds |
|---|---:|
| Project creation | 0.039619 |
| Target import/open | 0.126326 |
| Second auto-analysis | 9.848812 |
| Xref/thunk/metadata collection | 0.050749 |
| Cleanup | 0.004659 |
| Python setup and other overhead | 0.000036 |
| **TOTAL** | **10.070201** |

Counters confirmed one additional project, import, and `pyghidra.analyze()`
call, with no additional launcher start or explicit function decompilation.
The xref helper itself performs no hashing; the benchmark's enclosing before/
after checks verify its input. The normal demo's main also checks integrity.

Thus a demo invocation that calls index_binary and then collect_xrefs creates
two projects, imports twice, and analyzes twice. Reusing the already started
JVM does not reuse the first analyzed Program. This duplicate work is absent
from the production analyze_binary/cache path and did not cause its earlier
79.546433-second benchmark.

The repository audit covered these identifiers, including hidden source files:

```bash
rg --hidden -n \
  'pyghidra\.(start\(|open_program\(|analyze\()|FlatProgramAPI|DecompilerInterface|DecompInterface|index_binary\(|collect_xrefs\(' \
  --glob '!.git/**' --glob '!*.json' --glob '!*.log' --glob '!*.txt' .
```

Production auto-analysis is in `aire/pyghidra/indexer.py`; explicit
DecompInterface usage is in `aire/pyghidra/extractor.py`. The cache and indexer
CLI call index_binary. `demo_readonly.py`, `scripts/validate_function_crosscheck.py`,
and the three professor demos also call index_binary. Indexer, database,
retrieval, context, chat, naming, security, agent, cache, and binary-format tests
exercise it; documentation contains usage examples. No production caller opens
a second project for function interactions; persisted functions/edges are used.

The three independent collect_xrefs implementations are in
`scripts/demo_function_overloading.py` (ELF),
`scripts/demoL_function_overloading.py` (PE), and
`scripts/demo_function_overloading_WINDOWS_backup.py` (PE). Each opens a second
project, imports the target, and calls analyze once. All three now have opt-in
timers/counters only; their collection logic is unchanged. The Java v1 plugin's
ContextExtractor also uses DecompInterface per context extraction, independently
of this Python pipeline. No repository call sites for `pyghidra.start()`,
`pyghidra.open_program()`, `FlatProgramAPI`, or `DecompilerInterface` were found;
the actual Ghidra class name is `DecompInterface`.

## Bottlenecks and recommended order

The largest cold-request stages are auto-analysis (15.706840 s, about 55%),
explicit decompilation (5.068145 s, about 18%), and runtime startup (3.614214 s,
about 13%). Warm analysis is dominated by auto-analysis (10.747107 s) and
decompilation (3.197794 s); startup readiness takes only 0.000101 s.

1. For demos, gather the same xref/thunk/metadata facts from the first analyzed
   Program before release. This is the safest concrete removal of duplicate
   work: keep all analyzers and extraction rules, verify equivalent facts, and
   remove only the second project/import/analysis. It cannot speed up the main
   cache API because that API already does just one analysis.
2. For production requests, keep a long-lived analysis process/JVM. The indexer
   already supports this; audit process lifetime before introducing a new
   mechanism. It avoids repeat startup without reducing analysis quality.
3. Investigate individual analyzer timings and per-function decompiler latency
   next, preserving all analyzers and decompilation. These are the dominant
   remaining fresh-work costs. This profile alone does not justify disabling
   analyzers, skipping functions, changing timeouts, or weakening integrity.

Database save, serialization, hashing, and project deletion are small here.
Assembly and call-graph extraction intentionally traverse instructions for
different facts; no duplicate binary import/analysis is caused by either stage.
No optimization has been implemented.

## Validation

65 targeted profiling/cache/indexer/database tests passed. Full pure-Python
discovery: 398 tests, 377 passed and 21 opt-in integration/live tests skipped.
All three Ghidra indexer/database/cache integration tests passed. The new tests
exercise exclusive accounting, repeated stage names, inactive timers, exceptions,
context-manager cleanup/suppression, decompile counts and duplicate detection,
unchanged snapshot persistence, runtime-free imports, and real Ghidra operation
counts. The security dependency-boundary regression test also passes.
