# M1–M10 hardening — Phase 2: security and reliability

Date: 2026-11-17. Branch: `checkpoint/m10-pre-hardening`.
Phase 1 committed separately as `87f87b1` (`fix(m10): harden Ghidra integration and analysis correctness`; not pushed).
**Phase 2 changes are uncommitted.** Nothing was pushed, reset, or force-written.

## Defense-readiness assessment

**PARTIAL — secure enough for a rehearsed loopback demonstration; not yet reliable enough to improvise on.**

* Security: nine issues were found and fixed (three MEDIUM, six LOW), each with a regression test. No remotely
  reachable vulnerability was found. The binding and Host checks keep the GUI loopback-only. The agent cannot execute
  commands, mutate facts, or cite evidence that does not exist. The most serious finding (S3) was a **process crash**
  that tampered IR could cause; it is fixed and verified with the JVM in-process.
* Reliability: the long pauses are **host-level VM descheduling**, not A.I.R.E. code (see performance findings). They
  are still unresolved, can last more than a minute, and cannot be fixed inside the guest.
* Blockers before the defense:
  1. Free disk is **~255 MB (99%)**. Remove the ~396 MB crash report from the S3 crash (R3).
  2. Mitigate host-side VM freezes (performance findings): close host workloads, give the VM dedicated cores, keep saved evidence as a fallback.
  3. Don't ask the binary-wide "Where is input validated?" question live on the crypto PEs (8–11 s) or `sleigh.exe` (~90 s). Use the small ELF fixtures (≤0.1 s) or pre-recorded answers.
  4. Live-model behavior (including prompt-injection resistance) and the interactive browser path are **NOT TESTED**. Keep `AIRE_M10_NARRATION=0` and present deterministic answers.

## Scope and method

| Kind | What ran | Model / browser involvement |
| --- | --- | --- |
| Static unit/regression | `aire-server/tests` (default + `AIRE_RUN_GHIDRA_TESTS=1`), new `test_m10_security.py` (21 tests) | None (fake/deterministic model clients) |
| Dynamic HTTP probes | Throwaway loopback servers on random ports with fixture or read-only M10 data | None; the user's GUI on port 8767 was not touched |
| Real-Ghidra | Ghidra 12.1.3 headless via PyGhidra in the full suite and the JVM crash reproduction | None |
| Frontend | `renderMarkdown` executed in Node.js `vm` against 16 hostile payloads; static review of every `innerHTML` sink | No browser was launched |
| Live model | **NOT TESTED.** No Ollama inference was run (prior VM freezes during local inference; restriction on stress tests) | — |
| Interactive browser | **NOT TESTED** in this phase | — |

All adversarial inputs were synthetic (fixture ProgramIndex, crafted JSON/zlib blobs, harmless injection text that asks for
`touch /tmp/aire_pwned`). No unknown binary was executed or indexed.

## Threat model

A.I.R.E. is a single-user, loopback-only static-analysis assistant.

| Asset | Trust boundary | Adversary considered |
| --- | --- | --- |
| Analyst's files outside the project | HTTP API → filesystem | A local web page/other local process sending requests to 127.0.0.1; DNS rebinding |
| Analysis database (SQLite facts) | Read-only GUI store; separate writer worker | A tampered or corrupted `.sqlite` received from elsewhere |
| Agent/tool layer | Model output → tool registry | Prompt injection embedded in binary strings, symbols, decompiled comments |
| Analyst's browser | API JSON → DOM | Hostile function names, strings and model text (XSS) |
| Session transcripts | GUI session store | Other sessions, other local OS users |
| Availability during the defense | All of the above | Malformed/oversized inputs, decompression bombs, stalled clients |

Out of scope / accepted by design: authentication between local OS users of the same machine (no per-user token; see
remaining risks), dynamic execution of targets (never performed), and the Ollama service's own security.

## Vulnerabilities identified and fixed

Severity reflects the loopback-only deployment. Every fix has a regression test that was confirmed to fail on the pre-fix
code (run against a `git archive HEAD` copy), except where noted.

| ID | Severity | Issue and reproduction | Root cause | Fix | Regression |
| --- | --- | --- | --- | --- | --- |
| S1 | MEDIUM | `GET /api/bootstrap?binary_id=/etc/shadow` → `400 PermissionError: [Errno 13] Permission denied: '/etc/shadow'`; readable paths were hashed in full on request. File-existence/permission oracle and I/O DoS via any loopback request. | `resolve_binary` (CLI helper accepting paths) reused for HTTP selectors | `resolve_binary(..., allow_paths=False)` for HTTP; non-string selectors rejected. CLI `initial_binary` path/hash resolution preserved | `test_http_binary_selector_never_reads_filesystem_paths` (patches `Path.open` to fail on any read) |
| S2 | MEDIUM | A 510 KB tampered `function_ir` blob inflated to ~1 GB RSS in 1.7 s (measured in an isolated process). | `zlib.decompress` without an output bound | Bounded `decompressobj` (32 MiB; largest real document 1.85 MB); truncated streams rejected | `test_malformed_and_oversized_ir_raise_value_error[bomb, truncated]` |
| S3 | MEDIUM | **Process crash (SIGSEGV).** Deeply nested IR JSON (100,000 levels) crashed the full Ghidra-enabled test process; reproduced in isolation after `_start_runtime()` (rc 139) while the same input raised `RecursionError` without a JVM. A core dump followed (see remaining risks). | CPython's recursion guard does not protect the C JSON decoder when the JVM shares the process; it accepted 5,000 levels and overflowed at 100,000 | Explicit nesting bound (64; real maximum 7) checked before `json.loads`; non-object documents, bad zlib, non-UTF-8 → `ValueError` → `PersistedDataError` | `test_nesting_bound_ignores_brackets_inside_strings`, `[nesting 65]`, `[deep]`, `test_tampered_store_ir_is_a_persisted_data_error`; JVM reproduction re-run: 5k/100k/1M levels → `ValueError`, rc 0 |
| S4 | LOW | `POST /api/sessions` with 200,000 nested `[` → `500 RecursionError` | `_body` caught `ValueError`/`UnicodeError` only | Also catch `RecursionError` → `400 Malformed JSON request` | `test_deeply_nested_json_is_a_client_error` |
| S5 | LOW | Unhandled exceptions returned `str(exc)` (500 responses and chat `error` packets); `OSError` messages carried absolute paths. | Generic handlers reflected exception text | `_public_error`: curated `GuiError`/`ValueError`/`KnowledgeStoreError` messages kept; `OSError` → `strerror` only; others → generic message, traceback logged server-side | `test_internal_errors_do_not_disclose_details` |
| S6 | LOW | A client declaring `Content-Length: 1000` and sending 5 bytes held a handler thread indefinitely (no response in 45 s). | `http.server` default: no socket timeout | `AireRequestHandler.timeout = 60` (uploads keep their 30 s) | `test_stalled_request_body_releases_handler` (passed pre-fix only because it patches the timeout; the added default-timeout assertion fails pre-fix) |
| S7 | LOW | `Origin: http://localhost:9999` was accepted for POSTs: any other local web page could create sessions, upload, and queue analysis jobs cross-origin (responses unreadable; side effects real). | Origin check accepted any loopback host and port | Origin, when present, must equal the request `Host` (same origin). Requests without `Origin` (CLI/tests) unchanged; Host allowlist unchanged | `test_origin_must_match_host` |
| S8 | LOW (defense in depth) | Stored instruction addresses/categories were interpolated unescaped into the assembly-table markup (`id`, `data-*`, `class`). Requires a tampered DB; CSP `script-src 'self'` already blocks inline handlers. | Missing `escapeHtml` on 5 interpolations | Escaped (values are hex/identifiers, so rendering is unchanged) | `test_stored_addresses_are_escaped_in_markup` |
| S9 | LOW | Session directory created with the default umask (transcripts readable by other local users where the home directory permits). | `mkdir` without mode | Created `0700` (existing directories are not re-permissioned) | `test_session_directory_is_owner_only` |

Files changed for fixes: `aire/agent/binary_scope.py`, `aire/api/server.py`, `aire/pyghidra/instruction_ir.py`,
`aire/api/static/app.js`. New: `tests/test_m10_security.py`, `scripts/stall_monitor.py`,
`scripts/measure_gui_responsiveness.py`, this document.

## Security category results

| Category | Result | Evidence |
| --- | --- | --- |
| Path traversal / directory escape (static files) | PASS | `/../`, `%2e%2e`, `%2f`, `//etc/passwd`, NUL → 400/404, no source or `/etc` content |
| Filesystem probing through API selectors | PASS after S1 | Previously FAIL |
| Unsafe upload names / extensions | PASS | Names are display labels; storage is `uploads/<sha256>/<sanitized>`; `..`, `/`, NUL, `C:\`, dotfiles, 300×`é` tested; extensions untrusted (header validation) |
| Symlink manipulation of upload storage | PASS | Existing `test_symlink_storage_escape_is_rejected`; directories `0700`, files `0600` |
| Malformed JSON / oversized payloads | PASS after S4 | Arrays, NaN, wrong types, text/form content types, 2 MB body, 33 MiB declared upload, deep nesting |
| Unhandled exceptions / information disclosure | PASS after S5 | Generic 500s; no paths in OS errors |
| Slow/stalled clients | PASS after S6 | Handler released within the timeout |
| Session isolation | PASS | 128-bit random IDs, strict regex, binary scoping of tools (existing tests + traversal IDs); see remaining risk R1 |
| Unauthorized file access / deletion / modification | PASS | No delete endpoints; uploads only create files in the upload store; DB bytes unchanged across all tool and injection tests; read-only SQLite (`mode=ro`, `query_only`) rejects `UPDATE` |
| HTTP origin and localhost binding | PASS after S7 | Non-loopback bind rejected; Host allowlist (DNS rebinding: `evil.com`, `127.0.0.1.evil.com`, `127.1`, `0x7f000001` → 403) |
| Agent cannot execute shell commands | PASS | No subprocess/`os.system`/`eval` reachable from tools; injected `run_shell`/`__import__`/`save_program_index` → `unknown_tool` with process creation patched to fail |
| Untrusted data cannot override system instructions | PASS (static) / NOT TESTED (live model) | Payloads appear only in user prompts beneath explicit "untrusted data" system instructions; a real model's compliance was not exercised |
| Tool argument validation | PASS | Unknown/extra args, wrong types, out-of-range ints, >500-char strings rejected before execution |
| Read-only tools cannot modify binaries/DB | PASS | Byte-identical DB after every test; Phase 1 SHA-256 checks of fixtures |
| Cross-session private data | PASS | Session state bound to one binary; foreign function IDs rejected |
| Fabricated tool results / evidence | PASS | Tool results originate only from the registry; a model answer citing non-existent `E9999` is rejected (claim absent from answer, status not `completed`) |
| Evidence references identify stored facts | PASS | Citation validation (existing) + Phase 1 evaluation 100% citation validity |
| SQL parameterization | PASS | All dynamic SQL identifiers are constants; values bound; `' OR 1=1 --`, `%`, `_`, `DROP TABLE` selectors → not found |
| Database path validation / corrupted database | PASS | Garbage, empty, truncated, page-damaged DBs fail closed with `KnowledgeStoreError`, never modified/created |
| SQLite integrity / foreign keys | PARTIAL | Writer enables and verifies `foreign_keys`; the read-only GUI store does not run `PRAGMA integrity_check` at open (corruption is detected lazily by SQLite) |
| Instruction IR parsing / decompression limits | PASS after S2/S3 | Previously FAIL (memory exhaustion; process crash) |
| Memory/CPU bounds on large strings/functions/instructions | PASS | Chat question ≤2,000 chars; tool strings ≤500; tool results ≤100 KB; IR ≤4,096 instructions/function, ≤32 MiB decoded, ≤64 nesting; transcripts ≤80 messages/4 MB; upload ≤32 MiB; analysis watchdog |
| Unsupported architectures / malformed binaries | PASS | Existing intake/PE-validation suites (corrupt PE fixtures, near-miss signatures); no execution |
| XSS via function names / model responses | PASS | 16 hostile payloads through `renderMarkdown`: only allowlisted tags, no attributes beyond `class`/`data-lang`; all other sinks `escapeHtml` or `textContent`; CSP forbids inline script |
| Malformed API responses in the browser | PARTIAL | Code review: `api()` surfaces non-OK statuses and chat stream errors via `textContent`; not exercised in a browser |
| Browser session handling | PARTIAL | No cookies or credentials exist; session IDs only in memory/URLs; not exercised in a browser |
| Upload restrictions / unsupported file types (UI) | PASS (server) / NOT TESTED (browser) | Server rejects non-ELF/PE with a structured report |

## Test results

| Run | Tests | Passed | Failed | Errors | Skipped | Time |
| --- | --- | --- | --- | --- | --- | --- |
| Phase 1 regressions before commit (pure) | 20 | 20 | 0 | 0 | 0 | 0.015 s |
| Phase 1 real-Ghidra `-k test_m10` before commit | 3 | 3 | 0 | 0 | 0 | 107 s |
| `test_m10_security` (final) | 21 | 21 | 0 | 0 | 0 | 5.5 s |
| Affected modules (GUI, library, agent, M10, database) | 151 | 151 | 0 | 0 | 0 | 10.2 s |
| `test_m10_security` against pre-fix code (`git archive HEAD`) | 20 | — | 7 | 8 | — | expected failures; 3 errors were copy-path artifacts |
| **Full suite, `AIRE_RUN_GHIDRA_TESTS=1` (run 1)** | — | — | — | — | — | **crashed (SIGSEGV) in the S3 test; led to the S3 fix** |
| **Full suite, `AIRE_RUN_GHIDRA_TESTS=1` (final)** | **625** | **621** | **0** | **0** | **4** | **369 s** |

The four skips are live-model opt-ins (`AIRE_RUN_OLLAMA_TESTS` ×2, `AIRE_RUN_NAMING_LIVE_TESTS`,
`AIRE_RUN_AGENT_LIVE_TESTS`). They are **NOT TESTED**, not passing. 625 = Phase 1's 604 + 21 new tests. Command
(core dumps disabled, `nice -n 10`, 30-minute timeout):

```bash
ulimit -c 0
export PYTHONPATH=aire-server/src:aire-server/tests AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=0 \
  AIRE_RUN_NAMING_LIVE_TESTS=0 AIRE_RUN_AGENT_LIVE_TESTS=0 AIRE_DECOMPILE_WORKERS=2 AIRE_M10_NARRATION=0 \
  JAVA_TOOL_OPTIONS='-Xmx2048m -XX:ActiveProcessorCount=2 -Dcpu.core.limit=2'
timeout --kill-after=30 1800 nice -n 10 aire-server/.venv/bin/python -m unittest discover \
  -s aire-server/tests -t aire-server/tests -v
```

Raw logs and monitor JSONL are in `demo_artifacts/m10/security_phase2/` (git-ignored).

## Remaining risks

| ID | Risk | Severity | Disposition |
| --- | --- | --- | --- |
| R1 | No authentication: any process of **any local OS user** can reach 127.0.0.1 and list/read all sessions (`GET /api/sessions` without `binary_id`). | LOW for a single-user demo VM | Accepted by design; adding auth tokens would be a new feature |
| R2 | Live-model prompt injection resistance is unmeasured; static tests prove only that a compliant model cannot reach a shell, mutate data, or cite non-existent evidence. | MEDIUM | Keep `AIRE_M10_NARRATION=0`; present model text as interpretation (existing badges) |
| R3 | A `/var/crash/_usr_lib_python3.12_unittest___init__.py.1000.crash` (~396 MB) was produced by the S3 crash. Free disk is now ~255 MB (99%). Deleting it was not permitted to the assistant. | HIGH for VM stability | **User action:** remove it (`rm /var/crash/_usr_lib_python3.12_unittest___init__.py.1000.crash`) before the defense |
| R4 | The read-only store does not verify integrity at open; a damaged page can surface mid-request as a clean 400 error. | LOW | Acceptable; the demo uses known stores |
| R5 | Interactive browser behaviour (malformed responses, upload dialog) not exercised in this phase. | LOW | Rehearse with the demo script |
| R7 | Host-level VM freezes (up to 73.9 s observed) during heavy work. | HIGH for a live demo | Host-side mitigation; rehearse with fallbacks |
| R8 | Binary-wide validation answers take 8–90 s on PE binaries. | MEDIUM | Avoid live, or use small ELF fixtures |
| R6 | The IR nesting check adds ≤85 ms (mean 2.3 ms) per decoded function document (decoded once per request per function). | LOW | Measured on all 3,284 stored M10 documents |

## Performance and reliability findings (Step 6)

**Method.** `scripts/stall_monitor.py` is a separate, read-only process. It wakes every 100 ms, and a wake-up more
than 0.5 s late counts as a stall. For each stall it records what the guest kernel accounted during the gap: CPU
states, PSI cpu/io/memory, major faults, swap, and the busiest processes. Per-process scans run on a helper thread:
the first monitor version also read `/proc/<pid>` in its timing loop, and one 19.1 s event coincided with `apport`
dumping the crashed suite, so that event is excluded as a possible measurement artifact. Conditions: Ubuntu 24.04.5
VirtualBox guest, 4 vCPUs, 23 GB RAM (≥15 GB free), 4 GB swap (unused), TSC clocksource, mq-deadline scheduler, disk
97–99% full. Ollama was idle with no model loaded. No browser was running.

| Condition | Duration | Stalls >0.5 s | Stalls >5 s | Worst | Wall time lost |
| --- | --- | --- | --- | --- | --- |
| Idle guest | 180 s | 0 | 0 | 0.11 s late | 0 s |
| Full Ghidra suite (final run) | 344 s | 9 | 2 | 42.3 s | 54 s |
| Full Ghidra suite (crashed run, monitor ran to its end) | ~1,850 s | 55 | 20 | — | — |
| GUI + M10 requests on `sleigh.exe` | 580 s | 39 | 17 | **73.9 s** | 413 s |

**Attribution.** In every stall over 5 s across all runs:
* the guest CPUs were **≥99.4% idle** during the gap. This rules out CPU contention, Ghidra/JVM work and synchronous app code as the direct cause, because none of them can stop an idle guest from waking a sleeping process;
* PSI I/O pressure was ≤12 ms per gap, with zero major faults and zero swap. This rules out memory pressure and SQLite or disk I/O;
* the guest kernel accounted only ~75% of each gap. Time that goes missing from guest accounting is the signature of the
  **hypervisor descheduling the whole VM**. This matches M9's record of host freezes of up to 393 s.

Stalls happen only under load: none at idle, many during heavy guest work. That is consistent with the host
throttling or preempting a busy VM. Host-side telemetry was not available in this phase, so the *host* cause is
unverified. **The stalls are not resolved.**

**Category verdicts:** CPU/memory pressure in the guest: ruled out. Ghidra/JVM: it triggers load, but it is not what
freezes the guest. SQLite: ruled out. Synchronous app code: a separate latency issue (below), not the source of the
stalls. Agent execution: deterministic paths take ≤0.3 s. Ollama: NOT TESTED (no inference). Browser rendering:
NOT TESTED.

**App-side latency (CPU time, which host freezes don't inflate).** Deterministic fact answers took a median of 5 ms
and at most 311 ms over 36 requests. Function-level M10 routes (document/CFG/explain/cross-validate) took ≤0.07 s even
on `sleigh.exe`'s largest function. The binary-wide `answer_validation` ("Where is input validated?") is the outlier:
0.04–0.09 s on the ELF fixtures, **7.8–8.4 s** on each crypto PE, and **88.8 s** on `sleigh.exe`. It isn't cached
between requests. During an 11.3 s validation chat on `aes_gcm.exe`, a separate probe process still got
`/api/binaries` back with median 18 ms, p95 114 ms, max 281 ms, so the server does not freeze. No optimization was
made in this phase, because that would change product behavior beyond a security fix.
Reproduce with `scripts/measure_gui_responsiveness.py demo_artifacts/m10/m10.sqlite OUT --rounds 1` (private random
port, model disabled).
