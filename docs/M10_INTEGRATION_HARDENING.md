# M1–M10 integration hardening — Phase 1

Date: 2026-11-17. Branch: `checkpoint/m10-pre-hardening`.
Preserved checkpoint: `60816837fd64d84ec718464c67e9654d3f9a9b44`. Changes in this phase are **uncommitted**; nothing was pushed.

## Readiness assessment

**PARTIAL: the tested static pipeline is suitable for a rehearsed, fixture-based defense demo,
with the fixes below, but the complete live application is not yet certified.** All
27 static integration tests passed. Across the final static and pure-test runs,
600 distinct tests actually passed and four live-model tests did not execute.
Two application correctness bugs were found outside the original passing suite and fixed.
Three evaluation defects were corrected without relaxing exact-target or fabricated-citation checks.

Unexplained scheduling pauses remain a live-demo risk. Live model inference, the interactive
browser workflow, and Java extension packaging are unverified in this phase. Use the small ELF
fixtures, pre-indexed facts, and deterministic chat (`AIRE_M10_NARRATION=0`) for rehearsal;
maintain saved evidence as a fallback. This is not a claim that all M1–M10 security hardening is complete.

## Environment

| Component | Observed value / status |
| --- | --- |
| OS | **Ubuntu 24.04.5 LTS**, x86-64; kernel 7.0.0-42-generic. This configured machine is not Kali; Kali compatibility was NOT TESTED. |
| Existing virtual environment | `aire-server/.venv/bin/python`, Python 3.12.3; older documentation says 3.11. |
| Dependencies | PyGhidra 3.1.0, JPype1 1.5.2, pytest 9.2.0; `pip check` passed. |
| Ghidra | 12.1.3 PUBLIC, revision `8b4c91d4d5bd1549622bfbade0df199585b98365`; configured `GHIDRA_INSTALL_DIR=~/tools/ghidra`. |
| Actual JVM | OpenJDK/Javac 21.0.13.0.3; runtime discovered `/usr/lib/jvm/java-21-openjdk-amd64` with JAVA_HOME initially unset. |
| Java compatibility | Ghidra requires compiler/minimum Java 21; actual startup and indexing succeeded. Measured heap cap 2048 MiB and 2 available processors under audit limits. |
| Gradle | Not on PATH. Ghidra requires >=8.5; its bundled wrapper advertises 9.6.1. The wrapper was not run or downloaded. Extension packaging remains NOT TESTED. |
| SQLite | 3.45.1; schema initialization and integrity check passed; fresh persisted indexes and instruction IR round-tripped. |
| Toolchain | GCC 13.3.0; GNU objdump 2.42. |
| Ollama | Local API and CLI 0.35.0 responded; installed `qwen2.5-coder:1.5b`, Q4_K_M (~986 MB). No model was loaded initially. Availability PASS; inference NOT TESTED. |
| Resources at inventory | 4 virtual CPUs, ~22.9 GiB total RAM, 1,231 MiB free disk. |

No packages, models, or tools were installed, upgraded, or reconfigured. The recurring
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` failure belonged to the command
sandbox; affected commands were retried through approved execution. It is not an A.I.R.E. test failure.

## Execution and counts

The original 29 skips were class-level `AIRE_RUN_GHIDRA_TESTS` opt-ins, including four tests
with additional model gates. Enabling Ghidra executed 25 previously skipped static tests;
two new real-Ghidra regressions bring current static integration coverage to 27.

| Run | Discovered | Passed | Failed | Errors | Skipped | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Checkpoint static suite, Ghidra enabled | 597 | 593 | 0 | 0 | 4 | 346.041 |
| Affected pure regressions after initial fixes | 19 | 19 | 0 | 0 | 0 | 0.009 |
| Affected real M10 regressions after fixes | 3 | 3 | 0 | 0 | 0 | 84.479 |
| Full static suite after application fixes | 603 | 599 | 0 | 0 | 4 | 326.111 |
| Latest default suite, all final evaluator regressions | 604 | 573 | 0 | 0 | 31 | 14.042 |

The static rerun discovered 603 tests before the final pure evaluator regression was added.
The latest default suite discovered 604. The additional evaluator regression also passed its
targeted run (three evaluator tests, zero failures/errors/skips). The union of the two final
suite result files is **604 distinct tests: 600 passed, four never executed**.
Repeated runs and evidence assertions are not added to unit-test totals.

Four remaining opt-ins: M5 debug/stripped live chat (`AIRE_RUN_OLLAMA_TESTS`), M6 live naming
(`AIRE_RUN_NAMING_LIVE_TESTS`), and M8 live agent (`AIRE_RUN_AGENT_LIVE_TESTS`). They were
deliberately left off given the observed pauses and prior documented inference stalls.
All four remain **NOT TESTED**, not passing. The latest default suite's 31 skips comprise
27 static integrations plus those four inference tests.

Discovery evidence retained separately: the first fresh-binary audit recorded **68 passing
and 11 failing assertions**. A first correction pass retained **25 passing and two failing
assertions**, identifying the literal-vs-address scanner issue and O2 fortified printf.
Final evidence recheck: **29 passed, zero failed**. Original raw reports were not overwritten.
The original stripped-name value-origin miss was a separate diagnostic field and is documented below.
New loop and tail-call unit regressions each failed before their application fix. The first
two evaluator regressions initially reported one failure and one error (the absent zero-valued
`valid` counter); final evaluator tests include rejection controls and pass.

## Commands and reproducibility

Reviewed `docs/DEVELOPMENT.md`, fixture ground truth, integration gates, M9 retry verification,
and M10 evaluation scripts. Environment inventory ran `java -version`, `javac -version`,
`gradle --offline --version` (missing executable), `ollama --version`, `gcc --version`,
`objdump --version`, `python -m pip check`, and local `/api/version`, `/api/tags`, `/api/ps` queries.

Audit subprocesses used `nice -n 10`, process-group timeouts (30 minutes for the full suite,
20 minutes for fresh indexes, 10 minutes for affected Ghidra tests), 1-second resource polling,
and guards at <2,048 MiB available RAM or <150 MiB free disk. No guard or timeout fired.

```bash
export PYTHONPATH=aire-server/src
export AIRE_RUN_GHIDRA_TESTS=1
export AIRE_RUN_OLLAMA_TESTS=0 AIRE_RUN_NAMING_LIVE_TESTS=0 AIRE_RUN_AGENT_LIVE_TESTS=0
export AIRE_DECOMPILE_WORKERS=2 AIRE_M10_NARRATION=0
export JAVA_TOOL_OPTIONS='-Xmx2048m -XX:ActiveProcessorCount=2 -Dcpu.core.limit=2'

# Full suite: custom unittest result recorder uses the same discover arguments.
aire-server/.venv/bin/python /tmp/aire_phase1_run.py --label integration --timeout 1800 -- \
  aire-server/.venv/bin/python /tmp/aire_phase1_suite.py
# Same command, --label integration-after, repeated after application fixes.

# Fresh static index/evidence audit; new SQLite store, not the old demo store.
aire-server/.venv/bin/python /tmp/aire_phase1_run.py --label binaries-before --timeout 1200 -- \
  aire-server/.venv/bin/python /tmp/aire_phase1_binary.py

PYTHONPATH=aire-server/src:aire-server/tests aire-server/.venv/bin/python -m unittest \
  test_m10_flow test_m10_crossval test_m10_evaluation -v
aire-server/.venv/bin/python /tmp/aire_phase1_run.py --label targeted-after --timeout 600 -- \
  aire-server/.venv/bin/python -m unittest discover -s aire-server/tests \
  -p test_m9_integration.py -k test_m10 -v
aire-server/.venv/bin/python /tmp/aire_phase1_run.py --label evidence-final-origins --timeout 300 -- \
  aire-server/.venv/bin/python /tmp/aire_phase1_recheck.py
aire-server/.venv/bin/python /tmp/aire_phase1_run.py --label default-final --timeout 120 --no-ghidra -- \
  aire-server/.venv/bin/python /tmp/aire_phase1_suite.py
git diff --check
```

Raw environment/runtime versions, per-test result JSONL, suite summaries, resource samples,
before/after evidence, diagnostics, fresh SQLite store, replay helpers, and a SHA-256 manifest
are preserved locally in **`demo_artifacts/m10/integration_hardening_20261117T125810/`** (ignored).
Helpers retain their original `/tmp` output location; copy them back to `/tmp` and use a new
empty output directory before replaying the fresh-index audit. Detailed actual commands and
exit statuses are in `*-run.json`; the full suite recorder was not fail-fast.

## Fresh binary analysis

| Fixture | All functions | Internal incl. thunks | CALL edges | Stored IR instructions | Objdump compared | Branch relations compared | Index seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| O0 | 34 | 29 | 29 | 395 | 395 | 24 | 11.209 |
| O0-stripped | 34 | 29 | 29 | 395 | 395 | 24 | 2.584 |
| O2 | 37 | 31 | 23 | 345 | 345 | 28 | 2.567 |
| aes_gcm | 350 | 299 | 541 | 26527 | 25230 | 1360 | 24.345 |
| sha256_hash | 344 | 294 | 564 | 26492 | 25195 | 1356 | 19.295 |
| ecdsa_sign | 359 | 303 | 546 | 26502 | 25205 | 1364 | 20.249 |

All six fresh indexes had no incomplete decompilations and no instruction-IR truncation.
Each source hash was unchanged, ProgramIndex and every collected IR document round-tripped,
and a repeated analysis hit the warm cache. SQLite integrity was `ok`.

The instruction oracle checked **76,765 instructions**, with 100% agreement on checked
boundaries/mnemonics, 9,925 direct targets, 10,365 comparable memory operands, and 4,156
eligible branch relations. The PE evaluator checks only the first 400 instructions per
function, excludes some memory forms, and has a deliberately limited nearest-flag-setter
oracle. It does not prove all 80,656 stored instructions semantically correct.

Both O0 ELF variants preserve all 12 application functions, all 14 distinct application
edges, and all 15 application callsites, including the repeated `choose_operation -> add_values`
call. Runtime/import/thunk functions account for higher whole-binary counts. `puts`, `strlen`,
and `printf` imports are namespace-qualified. O2 imports fortified `__printf_chk` instead of
`printf`; objdump corroborates the transformed calls. No call graph is claimed complete for
unresolved indirect targets, and `_start -> main` is not required as a direct call.

Source checks: both O0 variants match 12/12 parameter-use cases, 10/10 branch-constant checks,
5/5 applicable return-use pairs, and both value-origin cases (after correcting the stripped
oracle's name lookup). O2 matches 12/12 parameter cases and two applicable return-use pairs;
three return-use pairs have no direct call after inlining and are **not applicable**, not passes.
The original O0 source comparisons are intentionally retained: O2 reports 10/12 loop-presence
matches and 3/10 literal branch-constant matches. The existing ground-truth JSON explicitly
documents the extra inlined checksum loops and folded ranges. Against that supplied O2 truth,
all adjusted loop-presence cases, all four folded-range cases, and the folded length trace
back to `strlen` pass. Inlined-away origin questions are not counted as successful traces.

The full static suite also analyzed `tests/binaries/aire_test_stripped`, the existing professor
32-bit PE and 64-bit ELF, corrupt PE controls `corrupt_section_overlap` and
`corrupt_import_thunks_invalid`, and temporary compiled `unsafe_copy`, `safe_copy`, and
`dangerous_gets` security controls. Only trusted build/compiler, analyzer, and disassembler
tools executed; none of the analyzed executables ran.

## Findings, severity, and fixes

| Finding | Severity | Root cause / disposition |
| --- | --- | --- |
| Single-block loop body absorbs setup blocks | MEDIUM, application correctness | Backward predecessor traversal started at a header with a self-edge. Six real O2 loops included preheaders and sometimes false exits. Stop traversal at the header; pure and real O2 regressions now pass. |
| Valid tail calls called phantom decompiled calls | MEDIUM, application correctness | `_calls` handled `call` but omitted the existing `tail_call` category. Reproduced in O2 `print_banner`/`initialize_app`, AES cleanup, SHA printing, and ECDSA key finalization. Include tail calls while retaining missing-call/phantom-call rejection tests; real ELF/PE regressions pass. |
| CFG evaluator rejects valid terminal jumps | MEDIUM, evaluation correctness | Ghidra represents terminal JMPs as calls excluded from intraprocedural CFG edges. Compare the stored tail-call destination exactly with objdump; a wrong destination still fails. |
| Hex scanner confuses constants/data references with instruction citations | MEDIUM, evaluation correctness | Stripped runtime comparison immediate `0x404030` was reported as three invalid citations. Admit stored reference targets and function-local immediate literals, count literal occurrences separately, and continue rejecting invented `0xdeadbeef`. |
| Stripped origin oracle requires removed source names | LOW, evaluation correctness | It searched `add_values`/`calculate_checksum` names inside stripped tool output. Compare stored target addresses against debug-partner symbol ground truth; wrong targets remain failures. |
| Empty Ghidra decompilation of computational PE helper | MEDIUM, upstream limitation | At `004075e0`, three PEs contain branches and XMM computation but Ghidra emits an empty `void` body. A.I.R.E. continues to flag this discrepancy. No original binary, signature, or expected result was changed. |
| Scheduling pauses with sufficient resources | MEDIUM, environment reliability | Up to 12.938 seconds between supervisor samples in the first static run; 10.108 seconds in fresh indexing and 9.703 seconds in affected tests. Host/guest attribution is unresolved. |
| Platform/build gaps | LOW / defense-dependent | This is Ubuntu, not Kali. Gradle absent from PATH; extension build and Kali behavior not validated. |

Only application edits: `flow_analysis.py` loop boundary and `decompiler_crossval.py` tail-call
handling. `scripts/evaluate_m10_full.py` fixes the three evaluator issues. Seven targeted tests
were added across `test_m10_flow.py`, `test_m10_crossval.py`, `test_m10_evaluation.py`, and
`test_m9_integration.py`. No assertions were weakened, exceptions suppressed, failing tests
silently skipped, fixtures modified, or application features added. Final Python compile
checks and `git diff --check` passed.

Final sampled cross-validation verdicts (non-thunk functions; PE scope is ground-truth
functions plus the known helper, not all PE functions):

| Binary | CONSISTENT | INSUFFICIENT EVIDENCE | POTENTIAL DISCREPANCY |
| --- | ---: | ---: | ---: |
| O0 | 12 | 8 | 0 |
| O0-stripped | 16 | 4 | 0 |
| O2 | 12 | 8 | 0 |
| aes_gcm | 6 | 0 | 1 |
| sha256_hash | 3 | 1 | 1 |
| ecdsa_sign | 7 | 0 | 1 |

The three remaining discrepancies are the real helper limitations above. Insufficient
evidence remains visible. SIMD `PCMPEQD`/`PUNPCKLQDQ` and compound `SHRD`/`SHLD` are reported
as medium-confidence P-code steps, not complete source-level explanations.

## Capability assessment

PASS means the stated fixture checks actually ran; it is not a universal correctness claim.

| Capability | Status | Evidence / boundary |
| --- | --- | --- |
| M1 indexing, functions, assembly and decompilation | PASS | Real ELF/PE imports, hashes, stable extraction and repeated format isolation. |
| M2 SQLite, IR persistence and cache behavior | PASS | Initialization, reopen/round-trip, foreign-key tests, read-only queries, cold/warm paths. |
| M3 relationships, callers/callees, paths, ranking | PASS | Exact small-fixture graph and stored-edge provenance; indirect graphs remain limited. |
| M4 evidence/context retrieval | PASS | Real persisted evidence, bounded context and citation/provenance assertions. |
| M5 chat and M6 naming orchestration | PARTIAL | Real index plus fake-provider integrations pass; live inference NOT TESTED. |
| M7 security rules | PASS | Positive strcpy/gets and bounded-copy negative controls, no target execution or scan writes/network/process creation. Scope is the implemented rules, not general vulnerability detection. |
| M8 agent / GUI backend | PARTIAL | Real index with deterministic provider and HTTP/backend regression tests pass; live agent and interactive browser NOT TESTED. |
| M9 ELF/PE support and retry recovery | PASS | 32/64-bit controls, partial corruption, parallel equality, prewarm, real native-decompiler timeout recovery. |
| M10 IR extraction and instruction facts | PASS | Real P-code persisted; checked instruction/target/memory/branch comparisons agree. |
| M10 CFG and bounded data flow | PASS | Corrected O2 loop bodies, exact CFG/terminal targets, parameter/return/origin cases. |
| M10 decompiler cross-validation | PARTIAL | False tail-call alarms fixed; genuine decompiler limitation flagged; full equivalence is not established. |
| Local Ollama service/models | PASS | Version/tags connectivity only; generation NOT TESTED. |
| Complete M10 Phase 6 evaluation / large-PE stress | PARTIAL | This phase is a fresh scoped audit; no claim that the older interrupted full evaluation or `M10_EVALUATION.md` is complete. |
| Gradle extension build, Ghidra GUI integration, Kali | NOT TESTED | Required manual/environment-specific follow-up. |

## Resource evidence and remaining manual work

| Run | Wall seconds | Maximum supervisor interval seconds | Minimum available RAM MiB | Minimum free disk MiB |
| --- | ---: | ---: | ---: | ---: |
| integration | 346.85 | 12.938 | 19008 | 1077 |
| binaries-before | 140.71 | 10.108 | 20026 | 1148 |
| targeted-after | 85.11 | 9.703 | 20081 | 1114 |
| integration-after | 327.08 | 6.57 | 18120 | 1039 |
| default-final | 15.02 | 1.004 | 21526 | 1191 |

The supervisor expected ~1-second intervals. Longer gaps are observed scheduling pauses;
without independent host telemetry they cannot be attributed conclusively to a VM freeze.
The retry test's deliberate five-second SIGSTOP affects only its own native decompilers
and is separate from these supervisor gaps. No resource-limit stop, OOM, or wall timeout
occurred. Runtime-only artifacts remain ignored.

Before a live defense:

1. Rehearse the exact GUI path (import/open, function selection, assembly, branch paths,
   value tracing, cross-validation, chat, cancellation/reload, and links) on this machine.
2. Diagnose the observed pauses with host-side telemetry; keep the small pre-indexed
   fixture and deterministic narration-off workflow available. Avoid an unmeasured
   fresh-index or model load on stage.
3. Run the four live-model tests separately with measured budgets when VM behavior is
   understood. Connectivity does not establish latency, answer quality, or inference stability.
4. If Java extension packaging or Kali is part of the defense, validate those environments
   explicitly; no installation or upgrade was performed here.
5. Continue the separate security/regression phases: upload/path/session isolation,
   untrusted SQLite/IR and decompression limits, renderer safety, narration claims,
   malformed input, and larger-binary resource limits. Data flow remains intra-procedural,
   bounded, and register/frame-slot based; pointer aliasing and evolving RSP slots are not proven.
6. Finish the interrupted broader evaluation separately. O2 source-level metrics must
   remain distinguishable from the documented compiler-adjusted expectations.

No commit, reset, deletion of existing work, fixture execution, or push was performed.
