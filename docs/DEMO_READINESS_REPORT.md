# Defense readiness checkpoint — November 17, 2026

Target defense: November 20, 2026. **NO-GO for final defense sign-off at this
checkpoint.** The pre-indexed deterministic demonstration passed in guest Firefox
across two clean application launches. Windows Chrome/NAT security verification,
adequate disk headroom, the final Ghidra-enabled regression run and live-model
validation remain outstanding. Work stopped at the user's request before those
longer runs. This is a checkpoint, not a completed release certification.

## Repository and evidence

Branch at entry: `m10-host-access-hardening`; HEAD `ebacf4d`
(`docs(m10): update split-host deployment and defense evidence`). The entry
worktree was clean. No critical input files were missing. No application runtime
code changed, no packages were installed, no files were deleted, and no new
commit or push was made during this readiness work.

Uncommitted work consists of these three readiness documents, the walkthrough
script `scripts/verify_defense_demo.py`, and explicit remote-Ollama opt-in support
in the existing chat, naming and agent live integration tests. Assertions and
expected model results were preserved; those four live tests have not yet run
with the changes. Existing Phase 2 and host-access controls were preserved.

Machine-local evidence is under ignored `demo_artifacts/m10/defense_20261117/`:
`inventory.json`, `preparation.json`, `default-clean-tests.json`,
`default-clean-run.json`, `browser-report.json`, `walkthrough-ready-run.json`,
logs, the compact database and 15 sanitized PNGs. The evidence directory has
mode 0700; generated sessions have mode 0600. An isolated browser profile was
used. Do not distribute its cookies, session files or browser history.

## Acceptance matrix

| Requirement | Status | Actual evidence and remaining boundary |
|---|---|---|
| Production CLI startup | PASS | Two independent launches on spare port 18770; startup 0.372 s and 0.451 s; both shut down afterward. |
| Intended Windows local-only path | NOT TESTED | Guest-loopback relay modeled the HTTP path; Windows NAT and Chrome were unavailable to control. |
| Authentication and host checks | PARTIAL | Real browser login, unauthenticated API 401, foreign Host 403, HttpOnly/Strict cookie hidden from JavaScript, token removed from URL, old token rejected after relaunch. Windows checks pending. |
| Fixture identity and database integrity | PASS | Four existing fixture hashes match Git HEAD; source store integrity and foreign keys checked; separate compact store checked. |
| Complete A–J walkthrough | PARTIAL | All 37 recorded actions passed on each of two guest Firefox launches; Windows Chrome rehearsal pending. |
| Inspectable analysis evidence | PASS | Instructions, branches, value trace, callsite, citations and decompiler verdict inspected in real GUI. Fixture-specific evidence only. |
| Live AI validated or excluded | PARTIAL | Deterministic question path passed with narration off. Windows model metadata reachable; no generation or live-model tests run here. Avoid model-dependent cards during defense. |
| Responsiveness | PARTIAL | Short guest-browser rehearsal timings below; no Windows timings or extended scheduling test. |
| Two clean launches | PASS | Same walkthrough, new authentication token, unchanged demo database bytes. |
| Backup for every critical step | PARTIAL | 15 guest-local screenshots and pre-indexed store exist. Copy sanitized backups to Windows and verify offline access before defense. No recording created. |
| Final regression coverage | PARTIAL | Default suite passed; gated Ghidra/security-browser/live runs remain outstanding. |

## Actual browser walkthrough

Browser: Firefox 155.0.1 headless inside Ubuntu. The harness clicks visible GUI
controls and asserts rendered results; these passes are not inferred from unit
tests. A loopback-only relay forwarded its requests to the private guest API on
port 18770. This does not establish Windows port exposure or Chrome behavior.
`browser-report.json` records each exact action, expected and actual output,
status, API timings and UI timings. All rows below passed twice in that scope.

| Step | Action and expected result | Actual result |
|---|---|---|
| A | Start production CLI; open private token URL | Login and access-control assertions passed; token cleared from displayed URL. |
| B | Open Library; select indexed `aire_test_binary` | Stored ELF loaded. |
| C | Investigate binary; look up `validate_input` | Selected address `004011bc`. |
| D | Open imports, strings and calls | `strlen`/`puts`, known ASCII validation string, caller/callee relationships displayed. |
| E | Switch decompiled and assembly views | Both stored views displayed. |
| F | Inspect semantics, branch `004011e1`, value at `004011dc`, CFG, data flow and decompiler check | Branch path reaches `puts`; stack value traces to `strlen`; fixture verdict `CONSISTENT`. |
| G | Select `unsafe_copy`; inspect Findings and `copy_input` calls | CWE-120 `SIGNAL`, LOW evidence strength, `strcpy` callsite `00401183`; `safe_copy` negative control is `NOT_APPLICABLE`. |
| H | Ask “What does this function do?” for `validate_input` | Deterministic evidence answer, repeated three times per launch. |
| I | Expand evidence, provenance and activity | Citations and tool results visible; sampled answer had 20 citations. |
| J | Switch safe/stripped/O2/PE binaries, return, restore Recent Chat, reload and restore | Function and answer recovered; database unchanged. |

Reload/session recovery was exercised. Recovery after an explicitly injected
failed API request was not tested. A negative security rule result is not proof
that a program is safe; a SIGNAL is not proof of exploitability. A CONSISTENT
decompiler comparison is a scoped check, not proof of semantic equivalence.

## Tests and measurements

| Run | Executed | Passed | Failed/errors | Skipped | Attribution |
|---|---:|---:|---:|---:|---|
| Default regression, this checkpoint | 649 | 617 | 0/0 | 32 | Python 3.12.3; 25.594 s; Ghidra, live-model and browser gates disabled. |
| Earlier November 17 host-access audit | 649 | 645 | 0/0 | 4 | Previously reported Codex audit, not independently repeated by this checkpoint. |

The current 32 skips comprise 27 other gated integration tests, four live-model
tests and one browser test. The separate real-browser walkthrough is not added
to the unittest totals. Three trusted security controls were freshly indexed
through Ghidra 12.1.3/PyGhidra 3.1.0 (12.441, 3.479 and 3.781 seconds), but the
complete Ghidra-enabled suite was not run. A separate final host-access/security
run and the supported browser XSS test were not run before stopping.

An initial default-suite invocation incorrectly supplied the Windows endpoint
to a loopback-only CLI test: 616 passed, one failed, 32 skipped. The supervisor's
environment was corrected; the clean run above passed without an application
change. Initial browser harness iterations also had synchronization/assertion
issues; their logs and report archives remain available. The final report is
`browser-report.json` with `database_unchanged: true`.

| Guest GUI action | Samples | Median end-to-end ms | p95 ms |
|---|---:|---:|---:|
| Imports | 6 | 56 | 75 |
| Strings | 6 | 58.5 | 72 |
| Calls | 6 | 56.5 | 95 |
| Decompiled view | 6 | 68.5 | 304 |
| Assembly | 6 | 61.5 | 92 |
| CFG | 6 | 47.5 | 65 |
| Data flow | 6 | 44 | 93 |
| Decompiler check | 6 | 51.5 | 72 |
| Deterministic question | 6 | 177.5 | 352 |
| Findings | 6 | 52 | 103 |
| Reload/session recovery | 2 | 193.5 | 208 |

These are bounded rehearsal observations, not a performance benchmark. p95 uses
nearest rank and is the maximum for these small samples. Resource Timing API
request durations are recorded separately per request in `browser-report.json`.
End-to-end timing covers the action through its rendered predicate and two
animation frames. Pure browser render time was not isolated (`null`); the
post-response interval includes polling and UI settling. There were no supervisor
sampling gaps over one second during the 22.682-second successful run (sampling
approximately every 0.5 seconds). Shorter stalls and future VM interruptions are
not excluded. No quantified Windows Chrome speed advantage is claimed.

## Environment and deployment blockers

Root filesystem is approximately 100% full, with about 123 MiB free after this
rehearsal. RAM was not pressured (about 14 GiB available; swap unused); six
vCPUs were visible and load was low. Historic NEM/resource-allocation and VM
scheduling problems remain relevant: moving Chrome and inference to Windows
reduces guest contention but cannot guarantee scheduling stability.

No cleanup was approved or performed. Candidate review items are the roughly
80 MiB Zig cache, 127 MiB Python crash report (diagnostic evidence), and roughly
113 MiB root-owned APT caches. Preserve files until approval. Do not remove
the active API's Ghidra runtime directory. No snapshot/disk/hypervisor changes
were attempted. Avoid further indexing until headroom is restored.

Guest API on `10.0.2.15:8770` was already running and left untouched. Its bare
bootstrap request with the intended Host was rejected with 401. Guest Ollama
also listens at `127.0.0.1:11434`. Windows Ollama tags were reachable through
`10.0.2.2:11434` and included `qwen2.5-coder:1.5b` (Q4_K_M); metadata is not an
inference test. Adapter 2 is active at `10.0.3.15` with another default route;
its VirtualBox attachment and host exposure require review. Adapter 1 is
`10.0.2.15`, default via `10.0.2.2`. Verify addresses before reuse.

Remaining required Windows checks: listeners on 8770/11434; NAT forwarding
restricted to `127.0.0.1`; Adapter 2 attachment; rejection from an external
device; actual isolated Chrome token authentication. Do not expose either
service to LAN or internet. See the [runbook](DEMO_READY_RUNBOOK.md).

## Resume work and manual review

1. Approve a specific safe cleanup or otherwise restore disk headroom.
2. Complete Windows listener/NAT/Adapter 2/Chrome/external-device checks.
3. Run gated Ghidra, host-access/security and supported browser regressions.
4. Run the four live tests separately using their existing opt-ins and the
   explicit remote-host environment. Measure actual generation, grounding,
   citations, unsupported claims, failure behavior and prompt-injection handling.
   Until validated, exclude inference from the critical demonstration path.
5. Rehearse the Windows path twice and copy sanitized backups to Windows.

Review the new test opt-in changes and walkthrough harness before committing.
No finished PowerPoint/PDF was modified. Defense slide/notes claims should be
checked against this scoped checkpoint; M10 evaluation and merged Phase 6 reports
remain absent as recorded in [DEMO_M10.md](DEMO_M10.md). No accuracy metrics or
completed experiments have been inferred.
