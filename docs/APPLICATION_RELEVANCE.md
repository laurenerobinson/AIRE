# Deterministic application relevance

Policy: `application-relevance-v2`. Static stored-fact analysis only; no target
execution, schema migration, re-indexing, Ghidra edits, binary changes, automatic
renaming, additional model classification or new model write capability.

Historical benchmark sections below describe the original v1 measurements.
The v2 increment and its actual test results are recorded in
[M9 implementation](M9_IMPLEMENTATION_2026-10-13.md).

## Root cause and integration

The professor PE was indexed correctly. Broad questions selected CRT functions
because startup/runtime fan-out won connectivity ranking and root/neighbor
selection. A small function budget then magnified that mistake. The tiny ELF
had clearly named application functions and much less competing scaffolding.

`ProgramQueryService.rank_functions` remains unchanged: its four metrics measure
connectivity, including external/thunk nodes, without establishing behavioral
importance. There is no `importance` metric. The separate
`ApplicationRelevanceService.rank_application_functions(binary_id, limit=10)`
returns transient JSON-serializable function metadata, classification, integer
score, deterministic reasons and bounded path references. M8 exposes it as the
thirteenth read-only tool, `rank_application_functions`. The score is neither ML
confidence nor a calibrated probability or proof of original source authorship.

CLI overview preflight and GUI workspace seeds use this API. M5 whole-binary
selection uses the same service inside its existing SQLite read snapshot.
Exact targeted M4 selection and M3 graph semantics remain unchanged. Six-function
M8 overview bundles prioritize selected application code; the model interprets
that evidence only after selection. The GUI retains its workspace, fingerprints,
cache limits, streaming, sessions, HTTP routes and read-only database connection.
Evidence/tool keys and normalized overview-answer keys include the policy version.
Repeated questions reuse successful validated answers without indexing or inference.

## Categories and rules

| Classification | Meaning |
| --- | --- |
| APPLICATION_CANDIDATE | Internal non-thunk symbol without a recognized runtime pattern; candidate only |
| UNKNOWN_INTERNAL | Generic `FUN_<hex>`, `sub_<hex>` or `fn_<hex>` symbol; still eligible |
| RUNTIME | Recognized compiler/runtime symbol or namespace family |
| STANDARD_LIBRARY | Recognized `std::` symbol/namespace or `__cxa_`, `__gxx_`, `_Unwind_` runtime symbol; heuristic only |
| RUNTIME_BRIDGE | Recognized startup wrapper; useful for traversal, demoted for behavioral evidence |
| EXTERNAL | Explicit stored external flag |
| THUNK | Explicit stored thunk flag; forwarding may be useful for traversal |

External/thunk flags take precedence. Symbol normalization removes Ghidra's exact
`FID_conflict:` prefix. One extra x86 underscore is normalized for recognized
MSVC bridge names; there is no general double-underscore exclusion.

Runtime families match `__scrt_*`, `__security_*`, `__acrt_*`, `__vcrt_*`,
`__crt_*`, `__libc_csu_*` (two or more leading underscores), and `_RTC_*` /
`__RTC_*`. The same strong family rules apply to namespace components.
Exact runtime symbols are `pre_c_initialization`, `pre_cpp_initialization`,
`post_pgo_initialization`, `__CheckForDebuggerJustMyCode`, `guard_check_icall`,
`__do_global_dtors_aux`, `frame_dummy`, `register_tm_clones`, and
`deregister_tm_clones`. These intentionally leave many unfamiliar functions
unclassified rather than declaring them runtime from weak names.

Bridge symbols are `_start`, `__libc_start_main`, `__scrt_common_main`,
`__scrt_common_main_seh`, `invoke_main`, `mainCRTStartup`, `wmainCRTStartup`,
`WinMainCRTStartup`, and `wWinMainCRTStartup`.

The extractor does **not** populate `is_library`; this feature ignores that field.
No names or addresses from the professor sample are special-cased in ranking.

## Ranking factors

Scores add the following deterministic contributions for eligible internals.
Ties use numeric stored addresses/address spaces, original address text, and ID.

| Factor | Contribution |
| --- | ---: |
| Internal non-thunk | +20 |
| Stored decompilation available | +8 |
| Stored assembly available | +4 |
| At least eight stored instructions | +4 |
| Multiple stored basic blocks | +2 |
| Exact `main`, `wmain`, `WinMain`, `wWinMain` symbol | +100 |
| Stored entry address or recognized entry EXPORT | +12 |
| Found by bounded entry/bridge traversal | +8 |
| First non-runtime internal after a runtime bridge | +70 |
| Application-path descendant at depth 1 / 2 / 3 | +32 / +24 / +16 |
| Distinct non-runtime internal callees, transparent supported thunks | +3 each, capped at four |
| Distinct non-runtime internal callers, transparent supported thunks | +2 each, capped at four |

Runtime bridges score -80, runtime and standard-library candidates -100, thunks -150 and externals -200.
Connectivity cannot override these classifications. Uncertainty about a generic
internal's purpose does not make it runtime. Symbol-less fallback still uses
code availability, structural metrics and non-runtime graph position.

Version 2 prefers persisted immediate thunk bindings over the legacy single-JMP
assembly recognizer. Paths label `THUNK_JUMP` only when direct jump verification
is stored, otherwise `THUNK_BINDING`. Ambiguous stored bindings are not replaced
with an assembly guess. No forwarding relationship becomes a direct CALL edge.
The ranking still returns demoted functions when requested with a sufficient limit.

## Traversal, bounded work and provenance

Starts prefer exact application entry symbols, then stored binary entry or
recognized entry EXPORT addresses. If neither exists, recognized bridge symbols
provide traversal roots. At most sixteen starts participate. The traversal is
limited to eight hops, 256 visited nodes and 1,024 scanned links. A separate
three-hop application-descendant walk has the same node/link caps. Diagnostics
report limits and truncation. A first eligible internal after a bridge receives
a boundary bonus; its eligible descendants can receive smaller bonuses.

Persisted Ghidra thunk bindings are preferred on all architectures, with their
direct-jump verification flag retained. For legacy facts without a binding, on
x86 only, an explicitly stored thunk with instruction_count=1 and exactly
one literal direct `JMP 0x...` at its own entry may supply a forwarding reference
to a unique stored function address. At most 160 assembly characters per such
thunk are inspected. Register/memory jumps, ambiguous targets, multi-instruction
thunks and unknown targets are not resolved. These references are `THUNK_JUMP`
path items, with the source function and instruction address, **never** CALL
edges. M3 and emitted evidence edges retain only original resolved CALL facts.

The ranker scans lightweight metadata and deduplicated CALL rows globally, with
stable sorting. This work scales with graph size; traversal/output are capped.
It queries code availability in SQL and never loads all function bodies into
Python. The overview selector loads only the requested bounded selected bodies
and uses lightweight references for edge endpoints. The 1,800-function synthetic
test verifies six body resolutions, bounded edges, no bulk ProgramIndex load,
no writes and bounded traversal counts.

Selected rows retain reasons, scores and path references in bundle metadata.
Function/edge provenance and truncation remain intact. Optional seed hints may
only promote eligible internals. Runtime code can remain as lower-priority
fallback evidence when application candidates are scarce.

Existing per-function and total character budgets remain. Overview code uses
explicit declaration/tail excerpts so long compiler setup does not hide a final
operation. Three priority functions share compact code admission. The GUI's
previous zero-character whole-binary assembly cap is corrected when assembly
is requested; the same total prompt budget then allocates 80% to code, 12% to
edges and 5% to artifacts, instead of 55% / 27% / 15%. Complete admitted blocks
alone receive citations. Exact targeted text selection remains unchanged.

## Real validation, October 7, 2026

The existing `analysis.sqlite` was opened read-only. No new indexing was needed.
The actual stored PE has generic application symbols, **not** functions named
`square_of_integer` or `square_of_double`. Those were descriptive names in an
earlier model answer. The stored function bodies demonstrate the operations.

| PE overview | Old workspace seeds | New workspace seeds / next candidate |
| --- | --- | --- |
| First | `pre_c_initialization` @ 00412c40 | `FUN_00412790` @ 00412790, score 120 |
| Second | `__scrt_common_main_seh` @ 00412d70 | `FUN_00412620` @ 00412620, score 81 |
| Third high-priority body | runtime neighbors dominated | `FUN_004126c0` @ 004126c0, score 81 |

The coordinator is reached through `invoke_main` and an exact stored thunk JMP.
Its two operation callees are promoted generically through transparent forwarding
references. The ordinary connectivity order still begins with CRT initialization.
The new six-function bundle additionally contains `FUN_00411840`, `FUN_00411c5a`
and `FUN_00411fd0`; generic library/template code can remain eligible.

The baseline live generic PE summary was:

> The binary appears to be a C++ program that initializes the runtime environment and calls the `invoke_main` function to execute the main program logic.

The final live generic PE summary was:

> The binary appears to be a simple program that takes an integer input, squares it, and then prints the result. It also pauses the program before exiting.

This verifies the shift to application behavior, but the model still gives an
incomplete interpretation: the evidence includes the double operation too, and
the coordinator supplies a constant integer rather than establishing interactive
input. Citation validation proves source existence, not semantic entailment.
These qualifications are retained rather than claiming perfect model accuracy.

The final directed query completed with:

> The binary appears to implement the same operation for different parameter types, specifically for integers and doubles.

Its explanations identify `FUN_00412620` and `FUN_004126c0` as integer/double
squaring routines and `FUN_00412790` as coordinator. Both bounded decompilation
and assembly reach this synthesis. Stored assembly independently shows integer
`IMUL` at 00412682 versus scalar-double `MULSD` at 0041272c, followed by an x87
return load. This supports a same-operation/different-types interpretation;
without original symbols it does not prove the original C++ source used one
overloaded identifier. The initial post-change experiment exposed missing GUI
assembly and an incorrect model comparison; the final experiment above followed
the bounded assembly/admission correction. That earlier result is not counted
as a successful comparison.

The controlled ELF workspace seeds remain `main` and `choose_operation`.
The new six-function bundle is `main`, `choose_operation`, `process_input`,
`print_result`, `initialize_app`, `secret_operation`. The baseline answer
described a simple calculator that initializes, processes input, chooses an
operation and prints a result. The final answer still describes command-line
input processing and addition/multiplication/secret-operation dispatch. No
application selection regression was observed; model prose remains advisory.

## Tests, performance and safety

- Final default suite: **326 run, 306 passed, 20 opt-in integration skips**,
  80.463 seconds while overlapping the final CLI inference; no failures. The
  preceding full run took 6.880 seconds. Skipped cases are the repository's Ghidra/static
  re-indexing and associated live-model integration gates. Real stored PE/ELF
  validation and local Ollama experiments were run separately.
- Focused retrieval (28), context builder (29), agent tools (9), agent runner
  (24), chat (26), application relevance (15) and GUI workspace (19) suites pass.
- The full suite includes GUI HTTP, session, streaming, cache, database/WAL
  invalidation, read-only and no-target-execution regressions.
- `git diff --check` and unchanged GUI JavaScript syntax validation pass.
- Relevance median over twenty runs: **5.78 ms PE**, **0.79 ms ELF**. Workspace
  preload: **56.66 ms PE**, **34.62 ms ELF**. No additional Ollama request.
- Final GUI live PE overview: 26.385 s; exact repeat: 14.93 ms with zero model
  requests. Directed PE: 46.792 s. ELF overview: 48.735 s; repeat: 17.74 ms,
  zero model requests. Baseline overview timings were 32.577 s PE and 14.696 s
  ELF. Different prompt evaluation/generation dominates these variable totals;
  they are observations, not a controlled inference-speed comparison.
- Existing `scripts/benchmark_gui_chat.py` warm-model run: all five requests
  completed; workspace preload 34.91 ms, overview 17.360 s, deterministic
  security question 29.66 ms, `process_input` explanation 19.657 s, repeated
  overview 27.94 ms with zero model calls, caller follow-up 36.59 ms with zero
  model calls. The database remained byte-identical. The prior cold-model
  benchmark remains historical; these runs are not comparable cold-start trials.

The ordinary CLI PE overview also completed with the same relevance seeds.
Its small-model prose still incorrectly introduced square-root behavior and
misstated a function's arguments. The stored double code multiplies the value
by itself. Those model statements are not verified facts or a ranking result;
the feature fixes evidence selection without claiming general semantic validation.
The ordinary CLI ELF overview completed too; its application selection remains
`main`, `choose_operation`, `process_input` and their application neighbors.
That additional model run produced an overly narrow answer about operation 1
instead of a whole-program summary. The successful GUI overview and deterministic
selection checks above establish the ELF evidence regression result, not uniform
prose quality across every local-model run.

PE SHA-256 before and after every validation run:
`cfc8c5f031587c721d680d3dd9bd94bbc690667acf8651403fb8c7e70f2fab07`.
ELF SHA-256 before/after:
`be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e`.
Analysis database bytes were unchanged. No target was executed, emulated,
patched or renamed; only stored static facts and a local model were consulted.

## Files in this change

Modified existing files (including newer local workspace files):

- `aire-server/src/aire/agent/runner.py`: relevance overview preflight and deterministic ranking display.
- `aire-server/src/aire/agent/tools.py`: thirteenth read-only relevance tool.
- `aire-server/src/aire/ai/evidence_selector.py`: common bounded application overview policy and excerpts.
- `aire-server/src/aire/ai/prompt_builder.py`: bounded three-function code admission; requested assembly allocation.
- `aire-server/src/aire/api/workspace.py`: shared relevance seeds, six-function bundle, policy cache keys, requested assembly.
- `aire-server/src/aire/api/server.py`: prepared overview action and versioned answer key.
- `aire-server/tests/test_agent_runner.py`: intentional preflight and action-schema changes.
- `aire-server/tests/test_agent_tools.py`: intentional tool-count change.
- `aire-server/tests/test_gui_workspace.py`: cache-version and requested-assembly regressions; cached relevance parity.
- `docs/M8_AGENT.md`, `docs/ARCHITECTURE.md`, `docs/CURRENT_STATE.md`, `docs/GUI_CHAT_PERFORMANCE.md`: current policy and integration.

Added:

- `aire-server/src/aire/knowledge/application_relevance.py`: separate transient relevance service.
- `aire-server/tests/test_application_relevance.py`: synthetic ordering, bridge, stripped, external/thunk, determinism, bounds, forwarding and code-admission tests.
- `scripts/validate_application_relevance.py`: reproducible read-only stored-fact/live validation and hash checks.
- `docs/APPLICATION_RELEVANCE.md`: this policy and validation report.

Unrelated pre-existing local changes remain in place. No repository reset,
history rewrite, commit or schema change occurred.

## Limitations

Heuristics can miss unknown runtime/library code or demote custom code whose
symbol happens to match a strong runtime rule. Generic internals remain unknown,
not proven application code. Code availability does not establish meaningful
semantics. Forwarding uses explicit persisted bindings, or a conservative
single-instruction x86 literal JMP fallback when no binding is stored.
Global metadata and graph sorting are not a constant-size database scan.

Missing direct paths do not establish global unreachability. Indirect calls are
not resolved or invented. Exact stored references now link function-local strings;
embedded literals in stored decompilation remain code evidence, not manufactured
string-artifact associations. Missing PDB/DLL diagnostics are not loader failures.
No model certainty, original source authorship or exact source-level overloading
is established by this score or a citation-valid response.

## Reproduction

From the existing repository; neither command below indexes or executes a target:

```bash
cd ~/aire
export PYTHONPATH="$PWD/aire-server/src"
export AIRE_OLLAMA_HOST=http://127.0.0.1:11434
export AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b
export AIRE_OLLAMA_NUM_CTX=4096

aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_application_relevance.py -v
aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_retrieval.py -v
aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_context_builder.py -v
aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_agent_tools.py -v
aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_agent_runner.py -v
aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p test_gui_workspace.py -v
aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v

sha256sum professor_samples/function_overloading/original/FunctionOverloading.exe
aire-server/.venv/bin/python scripts/validate_application_relevance.py \
  --database analysis.sqlite --output /tmp/aire-relevance.json --live --directed
aire-server/.venv/bin/python scripts/benchmark_gui_chat.py \
  --database analysis.sqlite --binary tests/fixtures/simple_elf/aire_test_binary \
  --function process_input --output /tmp/aire-relevance-gui-benchmark.json
sha256sum professor_samples/function_overloading/original/FunctionOverloading.exe

aire-server/.venv/bin/aire chat professor_samples/function_overloading/original/FunctionOverloading.exe \
  --database analysis.sqlite --question 'What does this binary do?' --timeout 600 --evidence-chars 8000
aire-server/.venv/bin/aire chat tests/fixtures/simple_elf/aire_test_binary \
  --database analysis.sqlite --question 'What does this binary do?' --timeout 600 --evidence-chars 8000
```

Omit `--live --directed` for metadata/evidence/performance/hash validation without
Ollama. `--binary` may be repeated to select other existing stored analyses.
The historical pre-change experiment was captured before editing in
`/tmp/aire-relevance-before.json`; the final live experiment is
`/tmp/aire-relevance-final.json`. These are local experiment outputs, not stored
program facts. Existing GUI benchmark output is separate from the prior
`docs/GUI_CHAT_BENCHMARK.json`, which is preserved as historical evidence.
