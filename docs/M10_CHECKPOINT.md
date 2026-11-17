# M10 checkpoint — Evidence-Grounded Assembly Intelligence

> Historical November 11 development log. “Nothing committed” and phase status
> below describe that run. The implementation was subsequently preserved in the
> [November 17 checkpoint](M10_PRE_HARDENING_CHECKPOINT.md) and hardened in
> [integration](M10_INTEGRATION_HARDENING.md), [security](M10_SECURITY_HARDENING.md)
> and [host-access](HOST_ACCESS_SECURITY_REVIEW.md) reviews. Current inference
> runs on Windows alongside isolated Chrome; static analysis remains in Ubuntu.
> The latest reported Codex audit is 649 executed / 645 passed / 4 live-model
> skipped, zero failed/errors, including Ghidra and Ubuntu headless Firefox.
> Full Phase 6 evaluation is still incomplete. `docs/m10/eval_full.json` and
> `docs/M10_EVALUATION.md` mentioned below are absent; `eval_full_run1_prefix.json`
> and the available per-unit reports are historical/partial evidence.
> GUI narration now defaults off and requires `AIRE_M10_NARRATION=1`; the
> “default on” statement below is historical. See the [current demo](DEMO_M10.md).

Baseline: commit `8e402e4` (M9). Nothing committed/pushed. Working store for M10:
`demo_artifacts/m10/m10.sqlite` (gitignored `*.sqlite`).

## Phase 0 — baseline (2026-11-11)

- Default suite at `8e402e4`: 518 tests, all pass, 28 skipped (`docs/m10/baseline_default_tests.txt`).
- Ghidra suite: the background baseline run was contaminated (M10 edits landed mid-run; one watchdog test saw
  extraction version 1 in-process vs 2 in its subprocess). The M9 final verification on the same commit
  (518/518, 4 live-model skipped) is the Ghidra baseline.
- Existing capabilities reused: `assembly_semantics`/`decompiler_semantics`/`function_crosscheck` (text-level
  local checks), `ProgramQueryService` (callers/callees/paths), references/thunks, crypto evidence, agent tool
  registry/runner, GUI tool cards.

## Phase 1 — Assembly Understanding Engine (COMPLETE)

**Extraction** (`aire/pyghidra/instruction_ir.py`, wired into the extractor's single instruction pass):
per function — instructions (address, mnemonic, text, length, typed operands with parsed memory structure,
flow type, targets, fall-through, normalized raw P-code), basic blocks with successor edges/flow types,
Ghidra-recovered calling convention, parameter/return storage, signature source, frame size. Bounded at 4,096
instructions/function (truncation flagged). Collected while decompilation runs in parallel; assembly text,
counts and block counts are byte-identical to M9.

**Persistence**: `function_ir` table (zlib JSON per function), created lazily on the first save with facts
(older stores are never migrated); excluded from `ProgramIndex` equality/`to_dict` (M9 digests unchanged);
loaded per function (`load_function_ir`). Cache identity: `EXTRACTION_VERSION` 1→2 plus required
`instruction_ir.version`; older snapshots show "refresh required". `AIRE_INSTRUCTION_IR=0` disables (A/B only).

**Semantics** (`aire/analysis/instruction_semantics.py`, `aire/analysis/assembly_intelligence.py`): category,
register/flag reads/writes, memory region (frame/stack/PC-relative/global/indexed/indirect), constants,
string/import references, branch target/fall-through, P-code-reconstructed flag predicate (normalized AST,
De Morgan), relation to the flag setter in the block or its unique predecessor (x86 CMP/SUB, TEST/AND/OR/XOR,
UCOMIS*/FUCOMI tables), CMOVcc as conditional moves, calls with callee name and Ghidra-recovered return
storage (ABI default explicitly labeled), returns, push/pop, LEA/address calculation. Non-x86: generic
P-code explanations. Legacy snapshots: assembly-text fallback marked low confidence.

**Validation vs independent ground truth** (GNU objdump; `aire/evaluation/objdump_truth.py`,
`scripts/evaluate_m10.py` → `docs/m10/eval_phase1.json`), 5 binaries (unstripped + stripped ELF, 3 CNG PEs):

| Check | Compared | Agreement |
|---|---:|---:|
| Instruction boundaries | 76,420 | 100 % |
| Mnemonics (normalized) | 76,420 | 100 % |
| Direct branch/call targets | 9,867 | 100 % |
| Memory operands (base/index/disp) | 10,318 | 100 % |
| Conditional-branch relations (operator, signedness, setter) | 4,128 | 100 % |

1,302 further relations (cross-block, float compares, etc.) are beyond the conservative oracle and not
independently verified. Harness bugs found and fixed during evaluation (all in the oracle/parser, none in
A.I.R.E.): PE target syntax, scaled-index base parsing, `0x8` read as a register, TEST signedness, x87
FUCOMI as flag setter. Real-binary coverage: 92 % of conditional branches and 93 % of CMOVcc get a stated
relation; the rest (e.g. after SBB) report flags only.

**Overhead** (`scripts/benchmark_m10_ir_overhead.py` → `docs/m10/ir_overhead.json`; host freezes again
contaminated runs): professor PE +0.6 s (+5 %) in the freeze-free pair; sleigh.exe cleanest run 140.6 s
freeze-adjusted vs M9 median 137.7 s (IR-off runs too frozen for a direct pair). Facts stage ≈59 s main-thread
on sleigh, largely overlapped with parallel decompilation. Storage: 9.4 MB (sleigh), 356 KB (professor PE).
One IR-off run with 588 s of freeze produced different non-IR facts (most likely decompile timeouts; not
verified — the harness did not record incomplete counts).

**Tests**: `tests/test_m10_semantics.py` (18), opt-in integration test (objdump agreement on the ELF).
Default suite: 536 tests, all pass, 29 skipped.

**Limitations**: x86/x86-64 only for named relations; no source-level meaning asserted; P-code is raw
(pcode, not high P-code); relation search covers same block or unique predecessor only.

Phase 1 also validated on the Ghidra-enabled suite: 536 tests, all pass, 4 live-model skipped (639.7 s;
`docs/m10/phase1_ghidra_tests.txt`). Later Phase 1 refinements (found while building Phases 2–3; Phase 1
evaluation re-run afterwards, still 100 %): relevance slicing (classify by P-code ops feeding non-flag
results; flag bookkeeping/address arithmetic excluded) fixed wrong verbs (PCMPEQD "multiplies", SHRD "ORs");
SIMD lane writes → `vector`, multi-op → `compound` (P-code steps listed, medium confidence); shift-count
masking ignored; PIECE/SUBPIECE moves; SETcc (`conditional_set`); generic "result == 0" only for
result-flag instructions; intra-instruction reads exclude values the instruction itself wrote; predicate
lookup position-aware (fixed real-binary recursion).

## Phase 2 — Decompiler cross-validation (COMPLETE)

`aire/analysis/decompiler_crossval.py` (+ `AssemblyIntelligence.crossvalidate`). Checks with evidence
(instruction addresses, decompiled line numbers): call targets (direct/import/tail; injected calls explained;
indirect calls matched to indirect C expressions; phantom calls to known functions flagged), string
references (content incl. C escapes, or address), control flow (presence of conditionals incl. comparisons;
`while(true)` excluded; loop back-edges via dominators), return value (DISCREPANCY only if no return-register
write anywhere and no call), constants and global data (supporting; absence = INSUFFICIENT), M9 arithmetic.
Thunks and missing text → INSUFFICIENT. Ghidra "unreachable/bad data/jumptable" warnings downgrade
discrepancies. Verdict: any check DISCREPANCY → POTENTIAL DISCREPANCY; core checks (calls, strings, control
flow, return) all CONSISTENT → CONSISTENT; else INSUFFICIENT EVIDENCE.

Survey of all 954 internal functions (5 binaries; `docs/m10/crossval_survey.json`): 612 CONSISTENT, 330
INSUFFICIENT, 12 POTENTIAL DISCREPANCY = 4 distinct functions × 3 PEs, each confirmed by manual review:
three compiler-runtime helpers that return in XMM0 but were decompiled as `void` with their computation and
branches discarded (e.g. FUN_004075e0), and one math helper storing the "__powil" string address into an
error structure the C never shows. 66 earlier flags were rule bugs fixed during review (thunk text,
PTR_ import calls, escaped strings, `while(true)`, boolean-expression conditions, merged-path returns,
indirect calls).

Mutation evaluation (`scripts/evaluate_m10.py:evaluate_phase2` → `docs/m10/eval_phase2.json`), ground truth
by construction on functions judged CONSISTENT: detected — remove call 440/452, empty body 583/589, phantom
call 583/586, remove string 26/27; benign rewrites (rename locals, reformat/strip comments, constant base)
**0 false alarms / 1,836**. Misses are by design: functions with decompiler unreachable-block warnings
(downgraded) and multiple indirect calls (any indirect expression matches).

## Phase 3 — Control-flow and data-flow reasoning (COMPLETE, evaluation in Phase 6)

`aire/analysis/flow_analysis.py` (+ service methods `cfg`, `branch`, `trace`, `parameters`,
`return_usage`, `function_evidence`): CFG with typed edges, dominators, back-edges, natural loops (body,
exits), unreachable blocks; branch paths (true/false, bounded to 24 instructions, calls, outcome);
block-level reaching definitions over x86 register families and frame-pointer stack slots (calls clobber
caller-saved registers); value-origin trace (constant / parameter per Ghidra storage / call result /
stack slot / global / pointer dereference / computed; data vs address registers separated; path-local loop
detection; depth 6; 160-node budget); parameter use (read-before-write); return-value usage at stored
callers' call sites (incl. via thunks). Verified on the ELF: calculate_checksum loop, validate_input
`length == 0` path → puts, `[RBP-0x10]` ← strlen result, validate_input result tested by process_input.

Tests: `test_m10_crossval.py` (10), `test_m10_flow.py` (5). Default suite: 551 tests, all pass, 29 skipped.

## Phase 4 — Evidence-grounded agent (COMPLETE)

- `aire/agent/assembly_answers.py`: deterministic routing (function / instructions / branch / trace /
  return_usage / crossvalidate / validation; the existing card prompts "Summarize this function" and "Explain
  this assembly" deliberately keep the M8 model pipeline), deterministic answers with binary identity,
  function name+address, instruction addresses, assembly/P-code-derived explanations, hedged evidence-derived
  purpose hints (each with addresses and basis), confidence and limitations; binary-wide input-validation
  candidates; `render_tool` compact renderings for model prompts; `validate_narration`.
- 8 agent tools registered (`explain_instructions`, `function_evidence`, `function_cfg`, `branch_paths`,
  `trace_value`, `parameter_use`, `return_usage`, `crossvalidate_function`); catalog 19→27, grammar 20→28.
- GUI `run_chat`: M10 fast path (`GuiApplication._assembly_answer`) before the agent. Optional local-model
  narration (`AIRE_M10_NARRATION`, default on; budget `AIRE_M10_NARRATION_SECONDS`, default 60) is appended only
  if every cited 0x-address appears in the deterministic answer/function and every mnemonic claim matches;
  otherwise rejected with the reason. Model unavailable/timeout → deterministic answer only (offline works).
- Real run on validate_input (`docs/m10/phase4_gui_transcript.txt`): evidence retrieval 2–130 ms per question;
  2 narrations accepted, others timed out. **Host freezes again**: kernel RCU stalls of 205–419 s at
  18:02/18:13/18:20/18:27 while Ollama loaded all vCPUs (load avg 14) — narration timing is host-bound;
  recommend `AIRE_M10_NARRATION=0` for demos on this VM. Earlier run showed the validator rejecting narrations
  that cited the function entry / SHA fragments → fixed (answer text is the citable evidence; only 0x tokens).
- Tests `test_m10_agent.py` (10). Default suite: 561 tests, all pass, 29 skipped.

## Phase 5 — GUI integration (COMPLETE)

- New tool card **Function explorer** (`app.js` `showExplorer*`, `index.html`, `app.css`): wide overlay with
  tabs Overview (calls, conditions, loops, strings, non-stack writes, parameters, cross-check verdict),
  Assembly (instruction + plain-English explanation + category/confidence badges, block separators, paged 200,
  inline **paths** for conditional jumps, **trace** buttons for data registers and frame slots — address
  registers excluded), Control flow (blocks, conditions, successors, loop headers, unreachable blocks), Data flow
  (parameter use, return-value use per caller), Decompiled vs assembly (findings with badges, Ghidra warnings,
  decompiled text / INCOMPLETE reason). Every address is a link that jumps to the instruction. Results cached
  client-side per function (64 entries). Reuses `/api/tool`; no new backend route.
- Firefox verification (`scripts/verify_m10_browser.py` → `docs/m10/browser_verification.json`, screenshots
  `docs/m10/browser_explorer_assembly.png`, `browser_explorer_decompiler.png`, `browser_chat.png`): PASSED —
  page 0.40 s, overview 0.23 s, assembly + paths + trace 0.66 s, all tabs, chat deterministic answer 0.24 s
  (narration off). Found and fixed: trace buttons offered the address register (RBP) instead of the slot.
- Default suite: 561 tests, all pass, 29 skipped.

## Phase 6 — Ground-truth evaluation (IN PROGRESS)

Done before the VirtualBox crash (2026-11-11, previous boot ended 21:17 with kernel RCU/NMI stall traces):

- Fixtures `tests/fixtures/m10/`: `-O2` build of the M9 ELF source (`build.sh`, `SHA256SUMS`, `TOOLCHAIN.txt`)
  and `GROUND_TRUTH_M10.json` (hand-derived from the C source: loops, callees, parameters used, compared
  constants, return-value use, value origins). Indexed into `demo_artifacts/m10/m10.sqlite`.
- Harness `scripts/evaluate_m10_full.py` (objdump-category table, call/loop/parameter/constant/return-use/origin
  checks, citation validity, latency, negative cases).
- First full run (18:37, **pre-fix, superseded**, `docs/m10/eval_full.json`) found real A.I.R.E. defects, all
  fixed at 18:39: NOP classified as address calculation; JMP to a thunk/function treated as a branch instead of a
  tail call; direct RAM varnode MOV classified as address calculation; ALU-with-memory-source wording; zeroing
  idioms counted as reads (parameter use); no "value held at address" trace for unread locations. Regression
  tests added (`EvaluationFindingRegressionTests`, not yet run before the crash).
- Harness bugs found and fixed (truth never adapted to A.I.R.E. output): call truth via symbols in stripped
  binaries, citation validity set, return-storage claims, PXOR table entry, integer constant matching,
  backward-jump loop proxy.
- Rerun (7000 s limit) was killed by the crash after O0 / O0-stripped / O2 explanations+citations
  (explanation categories 1.0 / 1.0 / 1.0; citations 1.0 / 0.9938 / 1.0 — preliminary, not final).
- Backup before resuming: `~/aire_backups/m10-pre-eval-20261111-212742/` (worktree tar of all 67 modified +
  untracked files, `tracked.diff`, gzipped working store, `SHA256SUMS`).

## Next steps

Resume Phase 6 one binary at a time with per-binary result files (resumable), then regression re-runs
(Phase 1 objdump, Phase 2 survey, Ghidra suite) → Phase 7 docs/demo.
