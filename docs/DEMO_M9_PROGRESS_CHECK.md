# A.I.R.E. — M9 progress-check demonstration

> Historical November 11 VM-local runbook. Port 8767, bare-URL login and timings
> below belong to that run. Current launches require the printed tokenized URL.
> For Windows Chrome/Ollama and Ubuntu API on host port 8770, use the
> [current workflow](../README.md#running-aire-with-windows-host-inference)
> and [M10 demo](DEMO_M10.md). Historical Firefox helpers need authentication
> handling before reuse; never save tokens in output reports.

Prepared 2026-11-11. The October 22 runbook (`docs/DEMO_2026-10-22.md`) and its artifacts are
unchanged; this demo uses its own store `demo_artifacts/m9/m9.sqlite` (126 MB). No target is
ever executed. All numbers below are measured on the development VM; see the limitations.

## Launch

```bash
cd /home/laurene/aire
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PYTHONPATH=aire-server/src
aire-server/.venv/bin/aire gui \
  --database demo_artifacts/m9/m9.sqlite \
  --session-dir demo_artifacts/m9/sessions \
  --upload-dir demo_artifacts/m9/uploads \
  --port 8767 --no-browser
```

Open **http://127.0.0.1:8767/**. The analyzer pre-warms in the background at launch
(JVM/PyGhidra start only — no binary analysis, no model); the library shows
*Analyzer ready (pre-warmed in N s)* after ~5–6 s. Wait for it before the live upload.
Add `--no-prewarm` to disable. Verified: HTTP smoke test (library 36 rows in 0.052 s,
bootstrap 0.006 s, 19 tools incl. `crypto_evidence`) and real headless Firefox
(`scripts/verify_m9_browser.py` → `docs/m9/browser_verification.json`,
screenshot `docs/m9/browser_m9.png`): page ready 0.47 s, analyzer pre-warmed in 3.2 s,
cached sleigh.exe opened in 0.24 s in the browser.

Rebuild the store from scratch if needed (≈5–8 min; Ghidra runs):
`PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/verify_m9_pipeline.py --database demo_artifacts/m9/m9.sqlite --output docs/m9/pipeline_verification.json`
then `aire-server/.venv/bin/python scripts/prepare_m9_demo.py` (same exports).

## Pre-indexed contents (all complete: every internal function decompiled)

| Binary | Role | Functions decompiled |
|---|---|---:|
| `tests/fixtures/m9/large_pe/sleigh.exe` (844 KB PE32+) | large cached PE | 2,299 / 2,299 |
| `professor_samples/.../FunctionOverloading.exe` | professor PE | 302 / 302 |
| `tests/fixtures/m9/crypto_pe/{aes_gcm,sha256_hash,ecdsa_sign}.exe` | CNG crypto | 299 / 294 / 303 |
| 8 partial + 2 unusual-valid corrupt fixtures | malformed PE handling | all |
| `tests/fixtures/simple_elf/aire_test_binary` | small ELF | 29 / 29 |

## Sequence (≈8 minutes)

1. **Large PE from cache (0:00–1:00).** *Binary Library / Upload* → `large_pe_sleigh`
   (*M9 large PE*, Cached) → **Open cached analysis**. Measured through the GUI worker:
   **0.002 s** processing (0.005 s job total) vs **115.4 s** fresh in a warm worker. Show the
   function count and *Call Graph*.
2. **Small binary live (1:00–2:30).** Upload `tests/fixtures/external/angr/brancher/brancher`
   (not in this store, so it is analysed fresh; with the analyzer pre-warmed the first
   upload is ~3 s faster). Show validated format/architecture/SHA-256,
   *Structure: Valid ELF headers*, the timestamped phases, then repeat for a cache hit. For
   reference, the 19.6 KB test ELF measured 11.5–25 s cold in this VM; brancher measured
   11.6 s fresh in the October 22 demo (host-dependent, see limitations).
3. **Corrupted executable (2:30–4:00).** Upload
   `tests/fixtures/m9/corrupt_pe/pe_signature_invalid.exe`: rejected before analysis —
   *Invalid PE signature b'PX\0\0' at 0x80*, *PE structure INVALID · No analysis possible*,
   with file offsets. Then upload `corrupt_pe/import_dll_name_invalid.exe`: accepted as
   **Partial analysis only** (`import_dll_name` at its descriptor offset); analysis completes
   with *Evidence may be incomplete*. In the library, expand a red `corrupt_*` row's
   *structure issues*. Point out `valid_overlay_appended` / `valid_renamed_sections`:
   unusual but valid, reported as such (no false positive).
4. **Crypto with function-level evidence (4:00–6:30).** Open `crypto_aes_gcm` → *Analysis
   Tools* → **Crypto evidence** (0.17 s). The binary has no symbols, yet the panel shows:
   `0041d080` key handling (`BCryptOpenAlgorithmProvider`, `BCryptSetProperty`,
   `BCryptGenerateSymmetricKey`; identifier strings `ChainingMode`, `ChainingModeGCM`),
   `0041d160` **encryption** (`BCryptEncrypt` callsite), `0041d1e0` **decryption**
   (`BCryptDecrypt`), `0041d270` cleanup, each with exact callsite addresses and the caller
   `0041d2a0` (main). Click a row → *Assembly* to show the `CALL` at the cited address.
   Repeat with `crypto_ecdsa_sign`: signing `0041d1b0` (`BCryptSignHash`), verification
   `0041d1f0` (`BCryptVerifySignature`), key handling separated into generate/export/import.
   Compare with `tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json` and `src/*.c`.
5. **Performance results (6:30–8:00).** Show `docs/M9_PERFORMANCE.md`: sleigh.exe cold
   137.7 s vs 178.3 s (−23 %, freeze-adjusted medians, 5 interleaved reps); decompile.exe
   260.8 s vs 430.2 s (−39 %, reduced 3+2 sample); A.I.R.E. extraction −57 % on sleigh;
   cached reloads 0.002–0.005 s in the GUI. Small binaries: no measurable change (Ghidra
   startup/analysis dominate). Reliability: timed-out decompilations are retried once and
   any unrecovered function is listed as INCOMPLETE (simulated freeze: 4/4 recovered,
   facts identical to a clean run). Pre-warming moves ~5 s of start-up off the first upload
   (−11 % first-upload latency when the user takes ≥ 6 s), it does not remove it.

## Test results (this checkout, 2026-11-11 final)

| Check | Result |
|---|---|
| Default suite (`unittest discover`) | 518 tests, all pass, 28 opt-in skipped (16.4 s) — `docs/m9/final2_default_tests.txt` |
| Ghidra-enabled (`AIRE_RUN_GHIDRA_TESTS=1`) | 518 tests, all pass, 4 live-model skipped (459.3 s; all 5 M9 integration tests ok) — `docs/m9/final3_ghidra_tests.txt` |
| Fresh real-pipeline acceptance (`scripts/verify_m9_pipeline.py`, new DB) | PASSED: 8/8 corrupt headers rejected, 10/10 others analysed, 3/3 crypto PEs match ground truth, worker exit 0, fixtures unchanged — `docs/m9/pipeline_verification_final.json` |
| Freeze-injection retry check (`scripts/verify_m9_retry_real.py`) | PASSED 3/3: 4 timed out → 4 recovered, facts identical — `docs/m9/retry_real_verification.json` |
| Firefox GUI (`scripts/verify_m9_browser.py`) | PASSED — `docs/m9/browser_verification.json`, `docs/m9/browser_m9.png` |

## Limitations

- **Host VM freezes**: the guest is periodically descheduled by the host (kernel RCU-stall
  and clocksource messages; single freezes of 95–400 s; see `docs/M9_VIRTUALBOX_STABILITY.md`).
  Live timings during the demo may be much longer than quoted; use cached binaries if a
  fresh job stalls. Timed-out decompilations are now retried once; a function that still
  fails is reported as INCOMPLETE (never silently omitted). A freeze longer than the retry's
  30 s timeout can still leave a function incomplete. Keep the host awake and on AC power.
- Crypto evidence is static API-callsite evidence; it does not prove runtime reachability,
  parameter correctness or key secrecy. The 3-character CNG identifier `L"AES"` is below
  Ghidra's default string length and is not recovered (GCM mode and the API calls are).
  Calls through computed pointers without an import binding are not attributed.
- Partial analysis of damaged PEs reflects what Ghidra could load; missing regions are
  absent, not reconstructed.
- The crypto programs were cross-compiled with zig 0.13.0 (MinGW) and never executed (no
  Windows/Wine); behaviour claims come from source and static evidence only.
- The small model (`qwen2.5-coder:1.5b`) limitations from the October demo still apply to
  chat answers; the deterministic panels are the authority.
