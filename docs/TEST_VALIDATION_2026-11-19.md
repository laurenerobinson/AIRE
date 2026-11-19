# Test and validation report — 2026-11-19

Everything in this report was **executed on 2026-11-19** by the repository
audit, except where it is explicitly labeled HISTORICAL. No application
source, fixture or analysis database was modified. Results apply to the
working tree on branch `docs/aire-full-audit-2026-11-19`. That tree is HEAD
`ebacf4d` plus three pre-existing uncommitted test edits. Those edits change
only opt-in live-Ollama tests, and all three were skipped in these runs.

## 1. Environment

| Item | Value |
|---|---|
| OS / kernel | Ubuntu 24.04.5 LTS, Linux 7.0.0-43-generic (VirtualBox guest), 6 vCPU, 17 GiB RAM, 53 GB free disk |
| Python | 3.12.3 (`aire-server/.venv`) |
| PyGhidra / JPype | 3.1.0 / 1.5.2 |
| Ghidra | 12.1.3 (`GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra`) |
| JDK | OpenJDK 21.0.13.0.3 |
| Test runner | `unittest` (pytest 9.2.0 installed but not used) |
| Ollama | Guest `ollama serve` listening on `127.0.0.1:11434`. **Deliberately not used.** See the safety controls |
| Gradle | Not installed, so the Java extension cannot be built |

## 2. Safety controls applied

These controls applied to every run:

- `ulimit -c 0` (no core dumps), `nice -n 10`, and a `timeout` bound.
- `AIRE_OLLAMA_MODEL`, `AIRE_OLLAMA_HOST`, `AIRE_OLLAMA_NUM_CTX` and
  `AIRE_OLLAMA_ALLOW_REMOTE` were **unset**, and every live-model gate was
  left off. No model inference could run, because the client raises
  without a model.
- Probes used a model stub that raises if called, and counted calls.
- The live GUI smoke test pointed `AIRE_OLLAMA_HOST` at a closed port
  (`127.0.0.1:9`).
- Analysis stores were opened read-only (`mode=ro`). The GUI smoke test and
  the cached-job test used a **scratch copy** of the defense store.
- No target binary was executed. No fixture was rebuilt, because
  `build.sh` would execute the fixtures.
- Before/after checks: SHA-256 of `demo_artifacts/m10/m10.sqlite`
  (`25ac802a…`) and of `demo_artifacts/m10/defense_20261117/demo.sqlite`
  (`f88fa14e…`), the `git ls-files -s` digest of `tests/fixtures` and
  `professor_samples`, the `~/.aire/gui-sessions` count (32), and
  `git status`. **All unchanged.** No new `/var/crash` reports appeared.

## 3. Executed runs

### Run A — default suite (no Ghidra, no model, no browser)

```bash
ulimit -c 0
timeout 1500 env -u AIRE_OLLAMA_MODEL -u AIRE_OLLAMA_HOST -u AIRE_OLLAMA_NUM_CTX \
  -u AIRE_OLLAMA_ALLOW_REMOTE PYTHONPATH=aire-server/src nice -n 10 \
  aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

- **Result:** `Ran 649 tests in 37.1s — OK (skipped=32)`, so **617 passed,
  0 failed, 0 errors**. The run was executed twice with identical results.
- **Skips, all opt-in gates:**
  - 17 × "Opt-in Ghidra integration";
  - 8 × "set AIRE_RUN_GHIDRA_TESTS=1";
  - 3 × "Opt-in static security integration";
  - 3 × "Opt-in Ghidra naming integration";
  - 1 × real-browser XSS.
- **Peak RSS:** 114 MB.

### Run B — Ghidra-enabled suite (live model and browser off)

```bash
ulimit -c 0
timeout 1500 env -u AIRE_OLLAMA_MODEL -u AIRE_OLLAMA_HOST -u AIRE_OLLAMA_NUM_CTX \
  -u AIRE_OLLAMA_ALLOW_REMOTE AIRE_RUN_GHIDRA_TESTS=1 PYTHONPATH=aire-server/src \
  nice -n 10 aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

- **Result:** `Ran 649 tests in 659.1s — OK (skipped=5)`, so **644 passed,
  0 failed, 0 errors**. Wall time 11:00. Peak RSS 2.9 GB. Started
  06:01:18, finished 06:12:18 CST.
- **Skipped (5):**
  - `test_agent_integration…test_live_demo`;
  - `test_chat_integration…test_debug_live_ollama`;
  - `test_chat_integration…test_stripped_live_ollama`;
  - `test_naming_integration…test_stripped_live_naming` (the four live-model
    tests);
  - `test_host_access_security.BrowserXssTests.test_payloads_render_as_literal_text`
    (browser).
- **Real PyGhidra indexing exercised:**
  - `tests/binaries/aire_test_stripped`;
  - both `tests/fixtures/simple_elf` binaries;
  - `tests/fixtures/m10/aire_test_binary_O2`;
  - the three `tests/fixtures/m9/crypto_pe` PEs and two corrupt PEs;
  - the professor ELF and PE;
  - the M7 security controls under `tests/fixtures/security_rules`.

  All analysis went to temporary stores.

### Run C — read-only audit probe

The probe script is kept in the session scratchpad and is not part of the
repository. It opened `demo_artifacts/m10/m10.sqlite` read-only and used a
fail-if-called model.

| Check | Result |
|---|---|
| Registered tools | **27**: `binary_metadata`, `list_functions`, `get_function`, `get_callers`, `get_callees`, `get_xrefs`, `get_function_strings`, `get_thunk_target`, `classify_function`, `find_call_path`, `rank_functions`, `rank_application_functions`, `get_artifacts`, `get_decompiled_text`, `get_assembly`, `crosscheck_function`, `retrieve_evidence`, `security_findings`, `crypto_evidence`, `explain_instructions`, `function_evidence`, `function_cfg`, `branch_paths`, `trace_value`, `parameter_use`, `return_usage`, `crossvalidate_function` |
| Invalid tool / argument | `run_shell` → `unknown_tool`. `list_functions limit=5000` → `invalid_arguments` |
| Caller/callee direction vs raw SQL | Matched for `validate_input` (callers `process_input`; callees `puts`, `strlen`, `calculate_checksum`), `process_input` (caller `main`; callees `validate_input`, `transform_input`) and `failwithmessage` in `FunctionOverloading.exe` (4 `_RTC_*` callers; 6 callees). `_RTC_StackFailure` is reported as ambiguous (2 matches), as designed |
| M10 on `validate_input` | `explain_instructions` evidence source `ghidra_pcode`. `crossvalidate_function` verdict **CONSISTENT** (call targets, strings, control flow, return value, constants, globals CONSISTENT; arithmetic INSUFFICIENT EVIDENCE). CFG: 11 blocks, 1 back-edge, 1 loop |
| Application relevance (debug ELF) | `main` 150, `choose_operation` 89, `process_input` 86, `print_result` 78, `initialize_app` 77 (all `APPLICATION_CANDIDATE`) |
| CWE rules on simple ELF | Both NOT_APPLICABLE |
| Crypto evidence `aes_gcm.exe` | 7/7 crypto imports called; 4 functions; `FUN_0041d160` encryption, `FUN_0041d1e0` decryption, `FUN_0041d080` provider/configuration/key handling, `FUN_0041d270` cleanup; family `cng` |
| Ollama host policy (constructor only) | Accepted: `127.0.0.1`, `localhost`, `[::1]`. Rejected: `[::ffff:127.0.0.1]`, `10.0.2.2`, `example.com`. `10.0.2.2` is accepted with `allow_remote_host=True` |
| GUI bind policy | `127.0.0.1` and `::1` are accepted. `10.0.2.15` is rejected without opt-in and accepted with it. `192.168.1.5` is accepted with opt-in (see BR-08). `0.0.0.0` and `8.8.8.8` are rejected even with opt-in |
| Legacy `analysis.sqlite` | No `function_ir`, so `explain_instructions` uses the `assembly_text` fallback. `compatible_metadata` = False (BR-05) |

**Deterministic chat routing** (`GuiApplication.run_chat`, model stub):

| Binary | Question | Path | Model calls | Time |
|---|---|---|---|---|
| aire_test_binary | What is this file? | deterministic_facts | 0 | 16 ms |
| aire_test_binary | Who calls validate_input? | deterministic_facts | 0 | 4 ms |
| aire_test_binary | What does process_input call? | deterministic_facts | 0 | 5 ms |
| aire_test_binary | Explain the instructions in validate_input | m10_assembly | 0 | 15 ms |
| aire_test_binary | Cross-check the decompiler for validate_input | m10_assembly | 0 | 20 ms |
| aire_test_binary | Is this file corrupted? | deterministic_facts | 0 | 12 ms |
| aire_test_binary | Show the evidence for validate_input | deterministic_facts | 0 | 39 ms |
| aire_test_binary | What does this binary do? | agent/model → **partial** (tool facts kept) | 1 (stub raised) | 133 ms |
| aire_test_binary_stripped | What is this file? | deterministic_facts | 0 | 20 ms |
| aire_test_binary_stripped | Who calls FUN_004011bc? | deterministic_facts | 0 | 4 ms |
| aire_test_binary_stripped | What does FUN_004011bc call? | deterministic_facts | 0 | 6 ms |
| aes_gcm.exe | Which functions perform encryption? | deterministic_facts | 0 | 56 ms |
| aes_gcm.exe | Which functions call BCryptEncrypt? | deterministic_facts | 0 | 5 ms |

On the defense store copy, with `validate_input` selected, these questions
all routed to `m10_assembly` with no model calls, in 21–74 ms:

- "What happens when the branch at 0x004011e1 is true?"
- "What does this function do?"
- "How is the return value used?"
- "Where is input validated?"
- "Where does the value of [RBP-0x10] at 0x004011e1 come from?"

These timings are single-run wall-clock measurements on this VM. They are
**not benchmarks**.

## 4. Live HTTP smoke test

The real entry point was launched against a scratch copy of the defense
store. It bound to loopback and shut itself down after 90 s:

```bash
timeout -s INT 90 env AIRE_OLLAMA_HOST=http://127.0.0.1:9 AIRE_OLLAMA_MODEL=probe-none \
  AIRE_M10_NARRATION=0 aire-server/.venv/bin/aire gui --database <scratch>/demo_copy.sqlite \
  --session-dir <scratch>/sessions --upload-dir <scratch>/uploads --port 8791 --no-browser --no-prewarm
```

| Request | Expected | Observed |
|---|---|---|
| `GET /api/bootstrap` without token | 401 | **401** |
| `Host: evil.example:8791` + token | 403 | **403** |
| `POST /api/sessions` with `Origin: http://evil.example` + token | 403 | **403** |
| `GET /?token=…` | 303 + cookie | **303** |
| `GET /api/bootstrap` (token header) | binaries, tools | 7 binaries, **27 tools**, model `probe-none` |
| `GET /api/health` | `ok:false` (no model) | `ok:false`, "Connection refused" (no crash) |
| `POST /api/sessions` | 201 + 32-hex id | OK |
| `POST /api/chat` "Who calls validate_input?" | NDJSON, verified | 7 records (`event` + `result`), status `completed`, `verified: true` |
| `POST /api/tool security_findings` on `unsafe_copy` / `dangerous_gets` / `safe_copy` | SIGNAL / SIGNAL / none | CWE-120 SIGNAL at `00401183` (LOW) / CWE-242 SIGNAL at `00401178` (LOW) / no findings |
| `GET /api/library` | fixtures, 32 MiB limit | 36 fixtures, `max_upload_bytes` 33554432, analyzer `not_started` |
| Unknown `GET /api/nonexistent` | not 200 | 404 |
| Ctrl-C (SIGINT) | clean stop | "A.I.R.E. GUI stopped.", port closed |
| Scratch store SHA-256 afterwards | unchanged | **unchanged** (`f88fa14e…`) |
| Session files | 0700 dir / 0600 files | **0700 / 0600** |

A cached-fixture analysis job was run through `BinaryLibrary.start(fixture_id='local:simple-elf')`
on the scratch copy. It completed with `cache_hit: True` in 0.21 s, and the
store was unchanged.

## 5. What these results establish

- **Correctness, for covered behavior:**
  - deterministic graph queries and their direction;
  - exact tool validation;
  - CWE signal and no-signal controls;
  - crypto-role attribution on the crypto fixture;
  - M10 semantics, CFG, flow and cross-validation, as asserted by unit and
    integration tests;
  - HTTP security gates;
  - read-only behavior during the audit.
- **Basic functionality:** GUI startup, the NDJSON chat stream, session
  creation and cached analysis jobs.
- **Not established:**
  - quality or latency of live model answers (BR-02);
  - Windows Chrome, NAT and listener confinement (BR-03);
  - real-browser rendering and XSS behavior (that test is opt-in and was
    skipped);
  - Java extension behavior (cannot be built, BR-20);
  - large-binary latency (not re-measured);
  - cold indexing through the GUI (only covered by the integration tests'
    direct indexing).

## 6. Not run, with reasons

| Test / validation | Reason |
|---|---|
| `AIRE_RUN_OLLAMA_TESTS`, `AIRE_RUN_AGENT_LIVE_TESTS`, `AIRE_RUN_NAMING_LIVE_TESTS` | Only a guest model is reachable. In-VM inference has frozen this VM before (`docs/chatperf/README.md`). Windows Ollama is not reachable from this audit |
| `AIRE_RUN_BROWSER_TESTS=1` | Would launch Firefox in the VM. Skipped to keep the run bounded. HISTORICAL pass recorded on Nov 17 (`docs/HOST_ACCESS_SECURITY_REVIEW.md`) |
| Java extension build / tests | Gradle absent. No Java unit tests exist |
| `scripts/evaluate_m10*.py` (objdump ground truth) | Long-running, and its results are already committed (`docs/m10/eval_*.json`, HISTORICAL) |
| Benchmarks (`scripts/benchmark_*.py`), num_thread comparisons | Excluded by the user's earlier restriction and by VM stability concerns |
| Windows-side checks | No access to the Windows host |

## 7. Historical results (not re-run; kept for comparison)

| Date | Scope | Result | Source |
|---|---|---|---|
| 2026-11-17 | Full suite with Ghidra + browser | 649 run / 645 passed / 4 live-model skips (604 s) | `docs/HOST_ACCESS_SECURITY_REVIEW.md` |
| 2026-11-17 | Phase 2 Ghidra suite | 625 run / 621 passed / 4 skips | `docs/M10_SECURITY_HARDENING.md` |
| 2026-11-17 | Default suite | 649 run / 617 passed / 32 skips | `docs/DEFENSE_EVIDENCE_PACKET.md` (untracked) |
| 2026-11-11 | M10 vs objdump | 100% on 76,420 instruction boundaries/mnemonics (5 binaries) | `docs/M10_CHECKPOINT.md` |
| Oct–Nov | M1–M9 milestone runs | various | `docs/CURRENT_STATE.md`, milestone docs |

The Nov 17 "645 passed" and today's "644 passed" differ by exactly one test,
the browser XSS test. It ran on Nov 17 and was skipped today. The total of
649 tests is identical.
