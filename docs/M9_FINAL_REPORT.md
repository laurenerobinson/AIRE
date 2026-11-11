# A.I.R.E. M9 — final comparison and readiness

2026-11-11. Nothing committed, pushed, reset or cleaned. Pre-M9 backup:
`~/aire_backups/m9-pre-20261110-153900/`. Details: `M9_PERFORMANCE.md`, `M9_CORRUPT_PE.md`,
`M9_CRYPTO_PE.md`, `M9_VIRTUALBOX_STABILITY.md`, runbook `DEMO_M9_PROGRESS_CHECK.md`.

## Speed (medians; raw data `docs/m9/benchmarks/`)

Raw wall times are kept separately; "freeze-adjusted" subtracts detected host-freeze time.

| Workload | Before M9 | After M9 | Change | Sample |
|---|---:|---:|---:|---|
| decompile.exe cold (6,255 functions), freeze-adjusted | 430.2 s | **260.8 s** | **−39 %** | 2 before / 3 after (reduced, approved) |
| sleigh.exe cold (2,299 functions), freeze-adjusted | 178.3 s | **137.7 s** | **−23 %** | 5 / 5 interleaved |
| A.I.R.E. extraction, sleigh.exe | 77.7 s | **33.4 s** | −57 % | 5 / 5 |
| A.I.R.E. extraction, professor PE (302 functions) | 4.82 s | **3.06 s** | −37 % | 5 / 5 |
| Small binaries end-to-end (ELF, TLS.exe, professor PE) | — | — | within noise | 5 / 5 / 5 |
| GUI cached reload, sleigh.exe (lightweight worker path) | 0.55 s (full load) | **0.002 s** | — | demo preparation |
| First upload, analyzer pre-warmed (user waits ≥ 6 s), freeze-free | 27.64 s | **24.68 s** | −11 % | 3 / 3 |
| First upload immediately at launch, pre-warm on | 27.64 s | 30.40 s | ≈ +2.8 s (within spread) | 3 / 4 |
| Launch → first result | 27.96 s | 30.57 s | unchanged (overhead moved, not removed) | 3 / 3 |
| Serial below 32 functions (adaptive) | 0.496 s (4 workers) | 0.435 s (1 worker) | −0.06 s, < 2 % → **not adopted** | 10 / 10 pairs |

Not changed: JVM start, Ghidra import and auto-analysis (85–90 % of small-binary time; Parameter
ID kept by instruction).

## Memory

| Item | Value |
|---|---:|
| Python + JVM peak, sleigh.exe cold (before → after) | 2.35 → 2.39 GB |
| Worker peak, professor PE first upload (no pre-warm / pre-warmed) | 1,132 / 1,020 MB |
| Idle pre-warmed worker | 258 MB (249–268) |
| GUI server process | 29 MB (no pre-warm) / 44 MB (pre-warm) |
| Native decompiler process | ~31 MB each, short-lived on small binaries |
| Full Ghidra test suite peak | 2.96 GB |

## Retries and evidence completeness

| Check | Result |
|---|---|
| Benchmark runs before the retry fix (host freezes) | 6 runs lost 1–8 decompiled functions (pre-M9 and early M9) |
| Simulated freeze, M9 with retry (3 runs) | 4 timed out → 4 retried → **4 recovered**; facts **identical** to clean run |
| Simulated freeze, pre-M9 control | 1 function silently lost; facts differ |
| Fresh acceptance run (19 analyses, new DB) | 0 retries needed, **0 incomplete** functions |
| Demo store (16 analyses) | every internal function decompiled |
| Parallel vs serial (40 adaptive runs + integration test) | facts identical |
| Corrupt PE pipeline | 8/8 header-corrupt rejected with specific reasons; 8 partial + 2 unusual-valid analysed; no worker crash; GUI usable afterwards |
| Crypto PEs (AES-256-GCM, SHA-256, ECDSA P-256) | every ground-truth crypto function at its exact address, all APIs, all `main` relationships, no false positives |

## Verification (final)

| Suite / check | Result |
|---|---|
| Default suite | 518 tests, all pass, 28 opt-in skipped |
| Ghidra-enabled suite | 518 tests, all pass, 4 live-model skipped (459.3 s); 5/5 M9 integration tests |
| Fresh real-pipeline acceptance | PASSED |
| Freeze-injection retry | PASSED 3/3 |
| Firefox GUI (library, rejection, partial, cached large PE 0.24 s, crypto panel) | PASSED, screenshot `docs/m9/browser_m9.png` |
| October 22 docs/artifacts | 9/9 docs byte-identical; `analysis.sqlite` unchanged; Oct 22 Firefox profile: two SQLite files differ only in unused preallocated space (used pages identical, integrity ok, timestamps unchanged since 2026-10-21) |
| Fixture hashes | professor PE, large PEs, crypto PEs, 18 corrupt fixtures verified |

## Remaining limitations

- Host VM freezes (up to 393 s single gap) make live timings unpredictable; a freeze longer
  than the retry's 30 s timeout can still leave a function explicitly INCOMPLETE. Host-side
  fixes are recommended in `M9_VIRTUALBOX_STABILITY.md` (not applied).
- Small-binary analysis time is dominated by JVM/Ghidra start-up and auto-analysis; M9 does
  not change it. Pre-warming only moves ~5 s of start-up.
- Reduced decompile.exe sample (2 + 3); freeze-adjusted values are approximate.
- Crypto evidence is static API-callsite evidence; `L"AES"` (3 chars) is not recovered;
  crypto PEs were never executed (no Windows/Wine).
- Partial analysis of damaged PEs covers only what Ghidra could load.
- Disk: 1.5 GB free (94 %); the virtual disk should be enlarged.

## Readiness

M9 is ready for the progress check, with the demo run from the pre-indexed store and live
analysis kept to small binaries (see runbook). Readiness is conditional on the host not
freezing the VM during the session: keep the host on AC power with sleep disabled.
