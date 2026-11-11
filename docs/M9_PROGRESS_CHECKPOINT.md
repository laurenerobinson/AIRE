# M9 progress checkpoint

> **Update 2026-11-11 00:40** — see the *Update log* at the end for the newest state.

Written 2026-11-10 23:58 (local), after recovery from the unexpected VM shutdown.
Nothing has been committed, pushed, reset or discarded. HEAD is still
`b4a6a8d` with all pre-M9 uncommitted work intact.

## Safety state

| Item | Location / status |
|---|---|
| Pre-M9 backup (git bundle, patches, status, full worktree copy) | `~/aire_backups/m9-pre-20261110-153900/` (947 MB) |
| "Before" source used for benchmarks | `~/aire_backups/m9-pre-20261110-153900/worktree/aire-server/src` |
| Only edit to a pre-existing user file | `scripts/verify_oct22_browser.py` line 68: `=== 13` → `>= 13` library rows (original saved as `verify_oct22_browser.py.before-m9-edit` in the backup folder) |
| Lost in the crash | `/tmp` scratchpad only: baseline test log (results recorded below), baseline-source snapshot (replaced by backup copy), the unfinished `decompile.exe` cold probe (no number produced) |
| Recovery check | `diff -rq backup/worktree repo` shows only the M9 files below; all compile; fixture hashes verified |

## Baseline (pre-M9 code, measured 2026-11-10 before changes)

- Default suite: 458 tests, 435 passed, 23 skipped (11.9 s).
- Ghidra-enabled suite (`AIRE_RUN_GHIDRA_TESTS=1`): 458 tests, 454 passed, 4 skipped (151.5 s, peak RSS 1.55 GB).

## Completed changes

### Phase 1 — performance (code complete; benchmark in progress)

| Change | Files |
|---|---|
| Parallel decompilation: N independent `DecompInterface` instances; results merged in original order so records and warning sequence are identical to serial. `AIRE_DECOMPILE_WORKERS` (default `min(4, cpus)`, `1` = original serial path). Not part of cache identity; recorded as metadata `decompile_workers`. | `aire/pyghidra/extractor.py`, `aire/pyghidra/indexer.py` |
| Metadata-first cache lookup: compatibility decided from `analysis_metadata`; stale snapshots are never fully loaded just to be discarded. | `aire/analysis/cache.py`, `aire/knowledge/database.py` (`load_analysis_metadata`, `load_warnings`) |
| Lightweight GUI-worker cache hit (`load_snapshot=False`): no full snapshot load; bounded warning payload (`warning_count` + first 50) instead of copying thousands of warnings into every 500 ms job poll. | `aire/api/index_worker.py`, `aire/api/static/app.js` |
| Codex P2 #1: Ghidra version for cache identity now follows the launcher's `ghidra/lastrun` fallback (previously `None` → perpetual cache misses when `GHIDRA_INSTALL_DIR` unset); memoized, keyed by file mtime. | `aire/analysis/versions.py` |
| Codex P2 #2: malformed optional demo binary no longer aborts `BinaryLibrary`/GUI startup. | `aire/api/binary_library.py` |
| Repeatable benchmark harness: new processes per repetition, cold/warm/cached, per-stage and per-analyzer timings, peak RSS, facts digests, crash-resilient per-rep JSONL. | `scripts/benchmark_m9.py`, `docs/m9/benchmarks/run_small.sh` |
| Large PE fixtures (Ghidra 12.1.3 Apache-2.0 builds, read-only copies + SHA256SUMS) | `tests/fixtures/m9/large_pe/{sleigh,decompile}.exe` |

### Phase 2 — corrupted PE (code complete; new tests not yet run)

- `aire/validation/pe_structure.py`: structured validator (format, architecture, `pe_valid`, `full`/`partial`/`none`, issues with severity/code/offset; DOS/PE/COFF/optional headers, section table, raw ranges, overlap, entry point, import descriptors/thunks/names, overlay). Never raises (fuzz test included).
- Intake: `none` → `BinaryValidationError` (HTTP 400 carries the `validation` report); `partial` accepted, issues travel with upload/job; ELF unchanged.
- GUI: structure report on upload, on rejection, in library rows (collapsible) and after partial analysis.
- Worker watchdog (`AIRE_ANALYSIS_TIMEOUT`, default 3600 s); next job respawns the worker.
- 18 deterministic fixtures (16 malformed, 2 unusual-but-valid) via `scripts/make_corrupt_pe_fixtures.py` (`--check` verifies); M9 library manifest `tests/fixtures/m9/manifest.json`. Manual verification: all 18 match expectations; 6 real PEs report `full` with no false positives.
- Docs: `docs/M9_CORRUPT_PE.md`.

### Phase 3 — security PE programs (sources written; not yet built)

- Toolchain: no MinGW/sudo; `ziglang==0.13.0` in `~/tools/zig-venv` (357 MB) cross-compiles x86-64 PE with MinGW `bcrypt` import libs. Smoke build verified (PE32+).
- Sources: `tests/fixtures/m9/crypto_pe/src/{aes_gcm,sha256_hash,ecdsa_sign}.c` (Windows CNG; no hand-written crypto); `build.sh` (stripped targets + unstripped twins).
- `scripts/crypto_ground_truth.py`: function addresses from twin COFF symbols, proof that loaded sections are identical, documented expected APIs/roles/calls.
- `aire/security/crypto_evidence.py` + agent tool `crypto_evidence` + GUI card "Crypto evidence" + runner rendering; GUI crypto question now seeds from callsite evidence (name regex is fallback); answer-cache key versioned.

### Test files added/changed

New: `tests/test_m9_performance.py` (18), `tests/test_m9_pe_validation.py`, `tests/test_m9_crypto_evidence.py`.
Changed: `test_binary_library.py` (+1 regression), `test_agent_tools.py` / `test_function_crosscheck.py` (tool count 18 → 19).

## Test results so far (M9 code)

| Run | Result |
|---|---|
| Default suite after Phase 1 (before Phase 2/3 edits) | 477 tests, 454 passed, 23 skipped, 0 failures (9.7 s) |
| Ghidra suite after Phase 1 | 477 tests, 473 passed, 4 skipped, 0 failures (171.4 s; peak RSS 3.2 GB) — log `docs/m9/after_phase1_ghidra_tests.txt` |
| Phase 2/3 tests and full suite after Phase 2/3 | **not yet run** (held so they do not disturb the benchmark) |

Note: the Ghidra suite was 20 s slower and used more memory than baseline. Probable causes are 4 decompiler processes on tiny test binaries and the freshly booted VM; this is unverified until the controlled benchmark finishes.

## Benchmark progress (controlled; nothing else running)

Raw per-repetition data: `docs/m9/benchmarks/progress.jsonl`; log `run_small.log`.
Environment: 4 vCPU VM, 22 GiB RAM, Python 3.12.3, Ghidra 12.1.3, PyGhidra 3.1.0, Java 21.
Cold = new Python/JVM process; warm = second forced fresh analysis in that JVM; cached = new process, SQLite reload with indexing patched to fail.

"Before" results recorded so far (seconds; facts digest identical across every repetition of a binary):

| Binary | Size | Functions | Cold (5 reps) | Warm | Cached |
|---|---:|---:|---|---|---|
| aire_test_binary (ELF) | 19.6 KB | 34 | 13.5–20.3 | 4.3–5.6 | 0.005–0.020 |
| TLS.exe (PE32) | 36.9 KB | — | 26.2–33.4 | 7.3–11.9 | 0.016–0.057 |
| FunctionOverloading.exe (PE32) | 49.7 KB | 385 | 31.6–33.9 | 12.2–15.2 | 0.018–0.047 |
| sleigh.exe (PE32+) | 844 KB | 2,384 | 227.7 (rep 0 of 5) | not run | 0.394 |

Remaining in this run: sleigh.exe before reps 1–4 (~15 min), then the full "after" set (~30–40 min).

### Large-PE bottleneck (sleigh.exe, before)

Cold 227.7 s = auto-analysis 114.0 s + A.I.R.E. decompilation 92.0 s + import 5.9 s + JVM 3.7 s + xrefs 3.3 s + rest. Inside auto-analysis: **Decompiler Parameter ID 43.0 s**, Decompiler Switch Analysis 16.2 s, Stack 15.6 s, x86 Constant Reference 11.2 s. Every function is therefore decompiled by Ghidra analyzers *and* again by extraction; both scale with function count. decompile.exe is ~3× larger → predicted 11–15 min cold (consistent with the >10 min probe before the crash). Parallel extraction addresses the 92 s; Parameter ID is a quality-affecting analyzer and is not changed without measurement and approval.

## Unresolved issues

1. Ghidra-suite slowdown/memory increase after Phase 1 — confirm with benchmark; consider `workers=1` for tiny binaries if parallel setup costs more than it saves.
2. decompile.exe benchmark: 5 reps × 2 conditions ≈ 2.5 h; needs a decision (see next steps).
3. Disk: 1.2 GB free (95 %). See cleanup candidates below (nothing deleted).
4. Phase 2/3 tests not yet executed; crypto builds and real A.I.R.E. analysis not yet done.
5. `BCRYPT_SHA256_ALG_HANDLE` pseudo-handle in `ecdsa_sign.c` must be confirmed in zig's MinGW headers at build time.
6. Short CNG identifiers (e.g. `L"AES"`, 3 chars) may fall below Ghidra's default string minimum length; algorithm attribution may then rely on APIs only — to be checked on real builds.

## Exact next steps

1. Let `run_small.sh` finish (before sleigh reps 1–4, then after set). Compare facts digests before vs after for every binary (must be identical) and compute medians.
2. If parallel decompilation is slower on tiny binaries, add a size threshold and re-measure.
3. Run the new Phase 2/3 unit tests, then build crypto PEs (`tests/fixtures/m9/crypto_pe/build.sh`), run `scripts/crypto_ground_truth.py`, index the three PEs and compare `crypto_evidence` against `GROUND_TRUTH.json`; add an opt-in Ghidra integration test.
4. Run partial corrupt fixtures through the real worker (no crash; completed or clear failure) and record outcomes.
5. decompile.exe: run reduced repetitions (e.g. 3 cold after + 1–2 before, or 5 after only) unless approved otherwise.
6. Full default + Ghidra suites; write `docs/M9_PERFORMANCE.md`, `docs/M9_CRYPTO_PE.md`, `docs/DEMO_M9_PROGRESS_CHECK.md` (Oct 22 docs untouched).

## Disk cleanup candidates (none deleted; approval required)

| Candidate | Size | Notes |
|---|---:|---|
| `~/Downloads/ghidra_12.1.3_PUBLIC_20260817.zip` | 544 MB | Installer archive; Ghidra is already extracted in `~/tools`. Re-downloadable. |
| systemd journal | 355 MB | `sudo journalctl --vacuum-size=50M` frees ~300 MB |
| apt package cache | 112 MB | `sudo apt clean` |
| Disabled snap revisions (snapd 27738, firmware-updater 226, snap-store 1390) | ~82 MB | `sudo snap remove <name> --revision <rev>` |
| `__pycache__` directories in repo | 16 MB | Regenerated automatically |
| `~/.cache/zig` | 60 MB | Keep until Phase 3 builds finish (rebuild cost) |

Not candidates (excluded by policy): source, `~/aire_backups`, `~/aire-backup-pre-agents-2026-11-10`, fixture binaries, SQLite stores (`analysis.sqlite`, `demo_artifacts/oct22/*.sqlite`), benchmark results.

## Update log

### 2026-11-11 00:40

- **Installer ZIP:** `/home/laurene/Downloads/ghidra_12.1.3_PUBLIC_20260817.zip` (569 MB) verified against
  `~/tools/ghidra_12.1.3_PUBLIC` (all 5,218 files present, sizes and CRC32 identical; Ghidra 12.1.3 in active
  use) and deleted with approval. Free space 1.2 GB → 1.8 GB.
- **Default suite:** 499 tests, all pass, 23 skipped (18.5 s). Two expected count updates (tool catalog 18→19,
  action grammar 19→20) and one fix (rejected library rows now carry the manifest SHA-256).
- **Crypto PEs built** (zig 0.13.0, x86_64-windows-gnu, -O1): `aes_gcm.exe` `90e403ba…`, `sha256_hash.exe`
  `9c5ac9cd…`, `ecdsa_sign.exe` `d52ad9d0…`. Ghidra MinGW headers lack `BCryptHash`; `hash_message` uses the
  classic CNG hash sequence. Targets contain no symbols; names exist only in `build/*.groundtruth.pdb`
  (renamed so Ghidra cannot auto-load them). `crypto_ground_truth.py` parses PDB procedure records and checks
  the PDB GUID against each PE CodeView record.
- **Real-pipeline acceptance** (`scripts/verify_m9_pipeline.py`, store `demo_artifacts/m9/m9.sqlite`, report
  `docs/m9/pipeline_verification*.json`): PASSED. 8/8 header-corrupt PEs rejected at intake with specific
  reasons; 8/8 partial + 2/2 unusual-valid analyzed without worker crash; valid analysis afterwards OK; worker
  exit 0; fixture hashes unchanged. Crypto: every ground-truth crypto function found at its exact address with
  all documented APIs; all `main` → crypto CALL relationships found; no false positives. Identifier strings
  recovered: `ChainingModeGCM`, `SHA256`, `ECDSA_P256`, `ECCPUBLICBLOB`. **Not recovered:** 3-char wide
  `L"AES"` (below Ghidra's default minimum string length).
- **Benchmark design change:** sequential before→after showed machine drift (sleigh before reps rising
  228→305 s; "after" slowdown entirely in unchanged Ghidra stages: import 3.95→10.5 s, auto-analysis
  7.0→8.8 s, while A.I.R.E. decompilation fell 0.39→0.15 s). Background services observed: update-manager,
  fwupd, tracker-extract. Sequential data is preserved (`progress.jsonl`, labels `before`/`after`).
  Replaced by an **interleaved** run (`docs/m9/benchmarks/run_interleaved.py`, labels `i-before`, `i-after`,
  `i-after-w1`; order rotates each repetition) — running now.
- New opt-in test `tests/test_m9_integration.py` (crypto ground truth, partial corrupt indexing,
  serial == parallel facts on a real PE) — written, not yet run.
- Parameter ID analyzer: unchanged, per user instruction.

### 2026-11-11 00:34 — tracker indexer paused (user-approved)

- GNOME `tracker-miner-fs-3` was restarting during benchmarks; individual Ghidra analyzers stalled 30–66 s
  (`Apply Data Archives` 66 s in i-after TLS rep 0; `WindowsResourceReference` 36 s and
  `Windows x86 PE Exception Handling` 52 s in i-after-w1 FunctionOverloading rep 0). Outliers kept in raw data.
- Paused at **00:33:50**: `tracker3 daemon --miner Files --pause "AIRE M9 benchmark"` → **cookie 1**.
- **Resume after benchmarks:** `tracker3 daemon --miner Files --resume 1`
- Interleaved repetition 0 (all conditions) ran before the pause; repetitions 1–4 run with it paused.

### 2026-11-11 (final for this stage) — benchmarks, tests and demo complete

- **Interleaved benchmark complete** (5 reps × before/after/after-w1 small set; 5 × before/after sleigh.exe) and
  **reduced decompile.exe** (user-approved 2 before + 3 after). Results: `docs/M9_PERFORMANCE.md`;
  summaries `docs/m9/benchmarks/summary_{small,sleigh}.md`. Freeze detector (`StallDetector`) added mid-run.
  Headline: sleigh.exe 178.3 → 137.7 s (−23 %), decompile.exe 430.2 → 260.8 s (−39 %), A.I.R.E. extraction
  −57 % (sleigh); small binaries no measurable end-to-end change; GUI cache hit sleigh 0.002 s.
- **Host VM freezes** confirmed in kernel log (RCU starvation 95 s; clocksource gap 392.7 s); up to 1,373 s
  frozen in one run. Decompile timeouts during freezes dropped 1–8 functions in some runs (pre-M9 and M9).
- Tracker indexer **resumed** (`--resume 1`; no miners paused).
- **Ghidra-enabled suite:** 502 tests, all pass, 4 skipped (264.0 s) — `docs/m9/final_ghidra_tests.txt`.
- **Demo:** `docs/DEMO_M9_PROGRESS_CHECK.md`; store `demo_artifacts/m9/m9.sqlite` (126 MB, 16 complete
  analyses); preparation timings `docs/m9/demo_preparation.json`; HTTP smoke test passed on port 8767.
- Docs: `docs/M9_PERFORMANCE.md`, `docs/M9_CORRUPT_PE.md`, `docs/M9_CRYPTO_PE.md`.

**Awaiting user decision (not implemented):** (1) retry timed-out decompilations once after the parallel pass
(recommended — parallel raises exposure per freeze); (2) pre-warm the GUI worker at launch; (3) optional
memory-only serial threshold for tiny binaries. Nothing committed/pushed.

### 2026-11-11 — final hardening pass (user-approved items 1–5), in progress

1. **Decompilation retry — DONE.** `extractor.py`: attempts return ok/timeout/failed (`DecompileResults.isTimedOut()`);
   after the main (parallel or serial) pass each timed-out function is retried once serially; successes are never
   re-decompiled; recovered functions produce warnings identical to a clean run; unrecovered functions get an explicit
   `… decompilation INCOMPLETE` warning and an entry in metadata `decompilation_incomplete` (reasons
   `timeout_after_retry`, `decompiler_error`, `decompiler_unavailable`); metadata `decompile_retry` lists
   timed_out/retried/recovered; counters `decompile_timeouts/retries/retry_recovered`. Surfaced in
   `get_decompiled_text` (`incomplete`), `binary_metadata` (`decompilation` summary), worker job summary and GUI.
   Tests: `test_m9_retry.py` (9). **Real JVM freeze injection** (`scripts/verify_m9_retry_real.py`, SIGSTOP of native
   decompilers for 5 s with a 2 s timeout): M9 — 4 timed out, 4 retried, 4 recovered, facts identical to clean run;
   pre-M9 control — 1 function lost, facts differ (`docs/m9/retry_real_*.json`). Added as opt-in integration test.
2. **Pre-warm — implemented**, benchmark running (`scripts/benchmark_m9_prewarm.py` → `docs/m9/benchmarks/prewarm.json`).
   `aire gui` spawns the worker at launch with `--prewarm=<uploads>/prewarm.json`; worker starts JVM/PyGhidra, loads
   loader/analysis/decompiler classes and opens/deletes an empty project (no binary, no model); status in
   `/api/library` → GUI note; `--no-prewarm` / `AIRE_PREWARM=0`; failure → lazy start (unchanged path).
   Tests: `test_m9_prewarm.py` (5) + opt-in integration test.
3. **Adaptive decompilation** — script ready (`scripts/benchmark_m9_adaptive.py`), not yet run.
4. **VirtualBox investigation — DONE** (read-only): `docs/M9_VIRTUALBOX_STABILITY.md`.
5. Final verification — pending.
Default suite after items 1–2: 511 → (re-run pending with prewarm tests).

### 2026-11-11 15:55 — hardening pass COMPLETE

All five approved items done; summary in `docs/M9_FINAL_REPORT.md`.
- Retry: implemented + verified (unit 9, real freeze injection 3/3, integration test; harness made deterministic
  after one timing-race failure in the full suite — rerun passed).
- Pre-warm: implemented, default on (`--no-prewarm`/`AIRE_PREWARM=0`); measured −11 % first-upload latency when the
  user waits ≥ 6 s, ≈ +2.8 s for an immediate upload (within spread), launch→first result unchanged, +258 MB idle.
- Adaptive serial < 32 functions: evaluated (10 pairs), −0.06 s / < 2 % → not adopted.
- VirtualBox: `docs/M9_VIRTUALBOX_STABILITY.md` (read-only; recommendations only).
- Final verification: default 518 OK (28 skipped); Ghidra 518 OK (4 skipped); fresh pipeline PASSED; Firefox PASSED.
- Oct 22 docs byte-identical; Oct 22 Firefox profile SQLite files differ only in unused preallocated space (benign).
- New files this pass: tests `test_m9_retry.py`, `test_m9_prewarm.py`; scripts `verify_m9_retry_real.py`,
  `benchmark_m9_prewarm.py`, `benchmark_m9_adaptive.py`, `verify_m9_browser.py`; docs `M9_VIRTUALBOX_STABILITY.md`,
  `M9_FINAL_REPORT.md`; data `docs/m9/benchmarks/{prewarm,adaptive}.json`, `docs/m9/*final*`, `browser_m9.png`.
Next: await user approval for commit; M10 not started.
