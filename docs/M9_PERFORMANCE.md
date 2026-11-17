# M9 Phase 1 — performance results

> Historical VM measurements; these are not split-host speedup results. For
> current deployment and scheduling caveats, see [architecture](ARCHITECTURE.md)
> and [VM diagnostics](VM_STABILITY_DIAGNOSTICS.md). Original timings remain unchanged.

Measured 2026-11-10/11 on the development VM. All raw data is preserved in
`docs/m9/benchmarks/progress.jsonl` (one JSON line per repetition, every request's
exclusive stage timings, Ghidra per-analyzer times, facts digest, peak RSS and, for
later runs, VM-freeze detector output). Tables are produced by
`docs/m9/benchmarks/summarize.py` (`summary_small.md`, `summary_sleigh.md`).

## Environment and method

- VirtualBox guest: 4 vCPU, 22 GiB RAM; Ubuntu 24.04 (kernel 7.0.0-38); Python 3.12.3;
  Ghidra 12.1.3; PyGhidra 3.1.0; OpenJDK 21. Default IndexOptions (decompile, assembly,
  references on). Parameter ID and all other analyzers unchanged.
- **Before** = pre-M9 source from `~/aire_backups/m9-pre-20261110-153900/worktree`.
  **After** = M9 source (4 decompile workers by default). **After-w1** = M9 source with
  `AIRE_DECOMPILE_WORKERS=1` (isolates the parallel-decompilation effect).
- `scripts/benchmark_m9.py`: each repetition is a new Python/JVM process. *Cold* = first
  forced fresh analysis in that process (includes JVM start); *warm* = second forced fresh
  analysis in the same JVM (the GUI worker's steady state); *cached* = new process, SQLite
  reload with indexing patched to fail. Targets are only read; SHA-256 verified before/after.
- **Interleaved design** (`run_interleaved.py`): every repetition runs each condition once,
  rotating order, so slow drift affects all conditions equally. An earlier sequential
  before→after run was abandoned because drift was visible (data kept, labels
  `before`/`after`).
- **Host VM freezes.** The host repeatedly descheduled the whole guest (kernel:
  `rcu_preempt kthread starved for 95403 jiffies`; `clocksource: Long readout interval …
  392.7 s`). A 0.5 s ticker thread (`StallDetector`) was added to the harness mid-run and
  records frozen time per request. "Freeze-adjusted" = wall time minus detected frozen
  time (gaps > 2 s); approximate. GNOME tracker indexing was paused (user-approved) from
  00:33:50; freezes continued, so they are host-side.

## Results

### Large PE: sleigh.exe (844 KB PE32+, 2,384 functions, 2,299 decompiled) — 5 interleaved repetitions each

| | Before | After | Change |
|---|---:|---:|---:|
| Cold, freeze-adjusted, median (range) | 178.3 s (172–230) | **137.7 s (125–149)** | **−23 % (−41 s)** |
| A.I.R.E. extraction (decompiler setup + decompilation + assembly + basic blocks), median | 77.7 s | **33.4 s** | **−57 %** |
| Decompilation stage alone, median | 73.6 s | **20.8 s** | **−72 %** |
| Ghidra auto-analysis, median (unchanged code) | 124.6 s | 91.6 s | noise (freezes) |
| Cold raw wall, median (range) | 220.1 s (205–595) | 227.8 s (138–248) | not comparable (unequal freeze time) |
| Cached reload, median | 0.70 s | 0.55 s | — |
| Peak RSS of Python+JVM process, median | 2.35 GB | 2.39 GB | unchanged (native decompilers are separate processes) |
| Distinct facts digests | 2 | **1** | see *Evidence consistency* |

### Small/medium binaries — 5 interleaved repetitions per condition

A.I.R.E. extraction stage medians (seconds; setup + decompilation + assembly + basic blocks):

| Binary | Cold before | Cold after | Cold after-w1 | Warm before | Warm after | Warm after-w1 |
|---|---:|---:|---:|---:|---:|---:|
| aire_test_binary (ELF, 29 internal functions) | 1.00 | 0.88 | 0.70 | 0.64 | 0.60 | 0.88 |
| TLS.exe (PE32) | 3.59 | **2.11** | 3.50 | 3.61 | **1.96** | 4.11 |
| FunctionOverloading.exe (PE32, 302 internal) | 4.82 | **3.06** | 6.01 | 4.65 | **2.19** | 4.06 |

End-to-end medians (raw, n=5; ranges show freeze contamination) are in
`summary_small.md`. Freeze-adjusted samples exist for only 2–3 repetitions per condition
(detector added mid-run): professor PE cold 23.4 s before vs 25.7 s after, warm 11.1 s vs
10.9 s. **On small binaries the end-to-end difference is within noise**: JVM start
(3–5 s), import (2.5–5 s) and Ghidra auto-analysis (7–17 s) are ~85–90 % of a cold
request and were not changed.

Cached reload: 0.004–0.04 s for every small binary and condition (unchanged; already fast).
The GUI worker additionally skips the full snapshot load on cache hits (not exercised by
this harness, which loads the full snapshot).

### Very large PE: decompile.exe (2.5 MB PE32+) — reduced sample

**Reduced sample (user-approved): 2 before + 3 after**, interleaved after/before/after/
before/after, cold only. 6,337 functions (6,255 internal), 213,827 references, 31,362
CALL edges; temporary SQLite store 262 MB (deleted after each repetition).

| | Before (n=2) | After (n=3) | Change |
|---|---:|---:|---:|
| Cold, freeze-adjusted, median (range) | 430.2 s (418–443) | **260.8 s (254–272)** | **−39 % (−169 s)** |
| Detected VM freeze per run | 347, 326 s | 22, 582, 1,373 s | host-side |
| Raw wall | 790, 744 s | 295, 843, 1,627 s | not comparable |
| Decompilation stage, median (includes freeze time) | 537.0 s | 99.5 s | — |
| Functions decompiled | 6,254; 6,254 | **6,255**; 6,252; 6,247 | timeouts during freezes |
| Cached reload | 1.41, 1.24 s | 1.27, 2.26, 2.36 s | full snapshot load |

Only the after run with little freezing (22 s) decompiled every function. All other runs
lost 1–8 functions to the 30 s per-function timeout while the guest was frozen. The cold
pre-crash probe (>10 min) is consistent with the before figures.

## What improved, what did not, and why

- **Improved:** A.I.R.E.'s own extraction. Parallel decompilation cuts the decompile stage
  by ~65–75 % on binaries with hundreds of functions; extraction overall by ~37 % (300
  functions) to ~57 % (2,300 functions). On sleigh.exe this is ~41 s of a ~178 s analysis.
  After-w1 matches before, confirming parallelism is the cause. Part of the saving
  reappears as slower assembly/basic-block extraction (it now overlaps the decompiler
  threads) and +0.1–0.4 s decompiler setup.
- **Not improved:** JVM startup, Ghidra import and Ghidra auto-analysis (dominant on all
  sizes; ~70 % of sleigh.exe). Auto-analysis includes Decompiler Parameter ID (36–43 s on
  sleigh.exe), which decompiles every function a first time; it is kept per user
  instruction to preserve recovered signatures.
- **Small binaries:** no measurable end-to-end change; parallel decompilation is *not*
  slower on the 29-function ELF (0.88 vs 1.00 s cold extraction; ±0.2 s noise). No adaptive
  worker rule is justified on speed; the only cost on tiny binaries is memory (4 native
  decompiler processes).
- **Other Phase 1 changes** (metadata-first cache check, lightweight worker cache hits,
  bounded warning payloads, Ghidra-version cache identity fix) remove avoidable work on
  cache hits/misses and in GUI polling; they are correctness/robustness-neutral and their
  effect is small at these sizes.

## Evidence consistency

- Every M9 request on the small/medium set and sleigh.exe produced the reference digest.
- Divergent requests all coincide with long host freezes and differ **only** by functions
  missing decompiled text (plus one warning each); every other count is identical:
  FunctionOverloading.exe before (1/302), sleigh.exe before (1/2,299), decompile.exe
  before ×2 (1/6,255 each) and decompile.exe after ×2 (3 and 8 of 6,255).
- Cause: a frozen guest pushes in-flight decompilations past the 30 s per-function
  timeout. Pre-existing behaviour, but parallel decompilation raises exposure per freeze
  (up to 4 in-flight functions can expire at once). **Fixed by the retry below.** (The
  divergent runs above predate the retry.)
- Digest excludes only timestamps/timing metadata, `decompile_workers`, and Ghidra's own
  `Analysis Times`/`Date Created` program-info fields (verified to be the only differences
  between otherwise identical runs).

## Hardening pass (user-approved)

### 1. Decompilation timeout retry — implemented

After the main (parallel or serial) pass, each function whose attempt timed out
(`DecompileResults.isTimedOut()`) is retried **once, serially**, with the same timeout.
Successful results are never re-decompiled or overwritten. A recovered function produces
exactly the evidence and warnings of a clean run; the retry is recorded in metadata
`decompile_retry` (timed_out / retried / recovered addresses) and counters. A function that
still has no decompiled text gets an explicit `… decompilation INCOMPLETE` warning and an
entry in metadata `decompilation_incomplete` (reason `timeout_after_retry`,
`decompiler_error` or `decompiler_unavailable`), shown in the GUI job summary, the
*Decompiled View* and `binary_metadata`. Deterministic decompiler errors are not retried.

Real-JVM verification (`scripts/verify_m9_retry_real.py`, sha256_hash.exe, 2 s timeout):
the first extraction attempt SIGSTOPs every native decompiler process for 5 s (a simulated
host freeze; real timeouts, process restarts and retries follow).

| Run | Frozen decompilers | Timed out | Retried | Recovered | Facts vs clean run |
|---|---:|---:|---:|---:|---|
| M9, 3 consecutive runs | 4 | 4 | 4 | 4 | **identical** (3/3) |
| Pre-M9 control (earlier race-timed trigger) | 1 | — | — | — | **differs**: 1 function silently lost |

Cost: none on clean runs (no timeouts → no retries; output unchanged). Tests:
`test_m9_retry.py` (9 unit tests), integration test (opt-in).

### 2. GUI analyzer pre-warming — implemented (default on; `--no-prewarm`, `AIRE_PREWARM=0`)

At `aire gui` launch the analysis worker is spawned in the background and starts the
JVM/PyGhidra, loads loader/analysis/decompiler classes and opens and deletes an empty
project. No binary is imported or analysed and no model is called. Status is shown in the
library view; on any failure the original lazy start-up remains (verified by tests).

Real GUI processes, fresh database per run, professor PE first upload, 5 interleaved
repetitions per condition (`scripts/benchmark_m9_prewarm.py` →
`docs/m9/benchmarks/prewarm.json`). Freeze-free medians (raw incl. freezes in the JSON):

| | No pre-warm (n=3) | Pre-warm, immediate upload (n=4) | Pre-warm, upload when ready (n=3) |
|---|---:|---:|---:|
| GUI responds (`/api/bootstrap`) | 0.25 s | 0.30 s | 0.33 s |
| Analyzer ready after launch | — | — | 5.97 s (5.86–6.55) |
| **First-upload latency** | **27.64 s** (27.46–31.48) | 30.40 s (27.96–31.92) | **24.68 s** (23.43–25.50) |
| Launch → first result | 27.96 s | 30.73 s | 30.57 s |
| Worker RSS idle after warm-up | 0 (not started) | — | 258 MB (249–268) |
| Worker peak RSS during job | 1,132 MB | 1,147 MB | 1,020 MB |

Pre-warm steps: JVM/PyGhidra start 4.0–5.3 s, class loading 0.14–0.24 s, empty project
0.3–0.5 s. **Pre-warming moves start-up overhead; it does not eliminate it**: launch→first
result is unchanged within noise. It shortens the first upload by ~3 s (−11 %) when the
user spends ≥ 6 s choosing a file, costs ~258 MB idle, keeps the GUI responsive
(+0.05–0.08 s), and gives no benefit (≈ +2.8 s median, within run-to-run spread) if a
file is uploaded immediately at launch, because that job waits for the warm-up.

### 3. Adaptive (serial below ~32 functions) — evaluated, **not adopted**

One warm JVM, 10 alternating pairs (`scripts/benchmark_m9_adaptive.py` →
`docs/m9/benchmarks/adaptive.json`; facts identical across worker counts in all 40 runs):

| Binary (internal functions) | Extraction, 1 worker | Extraction, 4 workers | Request, 1 / 4 workers |
|---|---:|---:|---:|
| aire_test_binary (29) | 0.435 s | 0.496 s | 3.83 / 3.94 s |
| section_offset_beyond_eof.exe (44) | 0.350 s | 0.415 s | 3.53 / 3.32 s |

Serial saves ~0.06 s (the setup of three extra decompiler processes, 0.27 vs 0.39 s) —
< 2 % of a request and not consistent at request level; native decompiler memory was
indistinguishable at 50 ms sampling (~31 MB). No meaningful benefit → parallel remains the
default for all sizes; `AIRE_DECOMPILE_WORKERS=1` forces serial.
