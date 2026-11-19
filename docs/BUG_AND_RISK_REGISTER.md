# Bug and risk register

Created **2026-11-19** during the repository audit
([REPOSITORY_AUDIT_2026-11-19.md](REPOSITORY_AUDIT_2026-11-19.md)). **No
application code was changed.** Every entry is a record for future work.

## Status values

| Status | Meaning |
|---|---|
| **CONFIRMED-REPRO** | Reproduced by a command in this audit |
| **CONFIRMED-SOURCE** | The defect follows directly from the current source. It was not executed, usually because the component cannot run here |
| **OBSERVED-ENV** | A fact about this machine or environment, not about the code |
| **UNVERIFIED** | Plausible, but could not be checked here. The reason is given |
| **RESOLVED** | A historical lead whose fix and regression coverage were found |
| **DOC-FIXED** | A documentation defect corrected by this audit's commit |

Severity is rated for the project and for the **November 20 defense demo**
separately.

## Summary

| ID | Severity | Category | Status | Title | Blocks demo? |
|---|---|---|---|---|---|
| BR-01 | High (demo) | Environment / config | OBSERVED-ENV | Shell and guest Ollama make in-VM inference the default | Yes, if not overridden |
| BR-02 | High (claims) | Verification gap | UNVERIFIED | No live model generation verified in this audit | No; avoid live-model claims |
| BR-03 | High (demo) | Deployment | UNVERIFIED | Windows host / NAT / Chrome checks never performed | Conditional |
| BR-04 | Medium | Docs | DOC-FIXED | README and M8 doc say 18 tools; the registry has 27 | No |
| BR-05 | Medium | Docs / demo | CONFIRMED-REPRO | Documented example database `analysis.sqlite` has no M10 facts | Only if that store is used |
| BR-06 | Medium | Performance | CONFIRMED-SOURCE | "Where is input validated?" scans every function synchronously, with no deadline | Only on large binaries |
| BR-07 | Medium | Robustness | CONFIRMED-SOURCE | Cancellation is incomplete for chats and analysis jobs | No |
| BR-08 | Medium | Security config | CONFIRMED-REPRO | Non-loopback opt-in accepts any private IPv4, including LAN addresses | No (NAT use only) |
| BR-09 | Medium | Java v1 | CONFIRMED-SOURCE | Decompiler timeout constant named `_MS` is passed as seconds | No |
| BR-10 | Medium | Java v1 | CONFIRMED-SOURCE | Suggestion rows are not cleared when the active Ghidra program changes | No |
| BR-11 | Medium | Process | OBSERVED-ENV | Pre-existing uncommitted test and defense-doc work | No |
| BR-12 | Low | Security rule accuracy | CONFIRMED-REPRO | M7 rules ignore persisted thunk bindings; ELF PLT signals are LOW strength | No |
| BR-13 | Low | Java v1 | CONFIRMED-SOURCE | Cancelled extraction steps are swallowed, so evidence can be partial | No |
| BR-14 | Low | Data naming | CONFIRMED-SOURCE | `analysis_metadata.schema_version = 1` while the DB schema is 2 | No |
| BR-15 | Low | Performance | CONFIRMED-SOURCE | Full-snapshot materialization on CLI cache hits and relevance ranking | No |
| BR-16 | Low | Safety (procedure) | CONFIRMED-SOURCE | `tests/fixtures/simple_elf/build.sh` executes the fixtures it builds | Yes, if run during demo |
| BR-17 | Low | CLI | CONFIRMED-SOURCE | `aire chat` has no remote-Ollama opt-in | No (GUI has it) |
| BR-18 | Info | Behavior | CONFIRMED-REPRO | Whole-binary overview needs the model; without it the result is `partial` | No (fallback works) |
| BR-19 | Low | Environment | OBSERVED-ENV | Crash reports for system daemons in `/var/crash` | Watch |
| BR-20 | Low | Build | OBSERVED-ENV | Gradle is absent, so the Java extension cannot be rebuilt here | No |
| BR-21 | — | Historical lead | RESOLVED | IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) | — |
| BR-22 | — | Historical lead | RESOLVED (not reproducible) | Caller/callee direction for `failwithmessage` | — |
| BR-23 | — | Historical lead | RESOLVED | Python decompiler timeout units | — |
| BR-24 | — | Historical lead | RESOLVED | README M8 "implemented" vs "not started" contradiction | — |

---

## Confirmed defects and risks

### BR-01 — In-VM inference is one keystroke away

- **Severity:** High for the demo. **Category:** environment. **Status:**
  OBSERVED-ENV.
- **Symptoms.**
  - The login shell exports `AIRE_OLLAMA_HOST=http://127.0.0.1:11434` and
    `AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b`.
  - `ollama serve` (pid 1520 at audit time) listens on the guest's
    `127.0.0.1:11434`.
- **Affected.** `ai/ollama_client.py` (env defaults) and every model-backed
  chat path.
- **Evidence.** `env | grep AIRE_` and `ss -ltnp` (audit run).
  `docs/chatperf/README.md:14,31` records that guest freezes happen during
  in-VM inference; a benchmark was stopped after 7 of 16 cases.
  `docs/VM_STABILITY_DIAGNOSTICS.md` analyzes the freezes.
- **Reproduction.** Do not reproduce; it risks freezing the VM.
- **Expected vs actual.**
  - Expected: the demo points at Windows Ollama
    (`AIRE_OLLAMA_HOST=http://10.0.2.2:11434` + `AIRE_OLLAMA_ALLOW_REMOTE=1`)
    or at no model at all.
  - Actual: any GUI or CLI launched from this shell without overrides would
    infer inside the guest.
- **Impact.** The VM may freeze mid-demo.
- **Suggested action.** Export the Windows endpoint explicitly (see the
  [runbook](DEFENSE_DEMO_RUNBOOK_2026-11-20.md)). Consider stopping guest
  `ollama serve` before the defense. Avoid model-backed questions unless
  Windows Ollama is verified.
- **Blocks demo:** yes, if not overridden.

### BR-02 — Live model generation is unverified

- **Severity:** High for claims. **Category:** verification gap. **Status:**
  UNVERIFIED.
- **Symptoms.** This audit ran no generation, by design: the VM-freeze risk
  in BR-01 made it unsafe. The Nov 17 packet also records that no live
  generation was run. Historically:
  - M5 targeted live runs passed with `qwen2.5-coder:1.5b`, `num_ctx` 4096;
  - M5 binary-summary validation stayed pending after timeouts
    (`docs/M5_VALIDATION.md`);
  - an earlier stripped interpretation was wrong despite valid citations
    (`docs/ROADMAP.md`).
- **Impact.** Model-backed answers ("What does this binary do?", "Explain
  this function" via the model path, naming) may time out or be weak. Their
  quality is unmeasured.
- **Suggested action.** Before the defense, run one model-backed question
  against **Windows** Ollama. If it fails, present only the deterministic
  paths.
- **Blocks demo:** no, as long as the demo relies on the deterministic paths.

### BR-03 — Windows-side deployment checks are unverified

- **Severity:** High for the demo. **Status:** UNVERIFIED, because this audit
  has no access to the Windows host.
- **Unverified items.**
  - the VirtualBox NAT rule Host IP `127.0.0.1:8770`;
  - the Windows listeners on 8770/11434;
  - Adapter 2 state;
  - firewall behavior and unreachability from another device;
  - Chrome token login and rejection of an old token.

  All of these are listed as pending in `README.md` and
  `docs/HOST_ACCESS_SECURITY_REVIEW.md`.
- **What is verified (guest side, this audit).** Every guest-side gate works
  on a loopback instance; see the test report §4:
  - a bare API call gets 401;
  - a foreign Host gets 403;
  - a cross-origin POST gets 403;
  - token login gets 303 plus the cookie.
- **Suggested action.** Run the Windows checklist in the runbook. If it fails,
  demo from guest Firefox over loopback.
- **Blocks demo:** conditional. A guest-only fallback exists.

### BR-04 — Tool count drift in documentation

- **Severity:** Medium. **Status:** DOC-FIXED.
- **Problem.** `README.md` said "M8 adds 18 read-only tools" and
  `docs/M8_AGENT.md` said "The current catalog contains 18 tools".
- **Fact.** `AgentTools.registry.catalog()` returns **27** names (probe
  output in the test report). The breakdown is 18 M8 + October M9 tools,
  `crypto_evidence`, and 8 M10 tools.
- **Fix.** Both documents now state 27, with the breakdown.

### BR-05 — `analysis.sqlite` example store predates M10

- **Severity:** Medium. **Status:** CONFIRMED-REPRO.
- **Symptoms.** `docs/GUI.md` and `aire-server/README.md` launch
  `aire gui … --database analysis.sqlite`. That root store (Oct 8) has no
  `function_ir` table. On it, `explain_instructions` reports
  `evidence_source: assembly_text` (lower confidence) and
  `compatible_metadata` is `False`, so intake would re-index.
- **Evidence.** Probe commands in the test report §3.
- **Impact.** The M10 explorer works with degraded fidelity. A first upload
  of a known binary triggers a full Ghidra run.
- **Suggested action.** Use
  `demo_artifacts/m10/defense_20261117/demo.sqlite` (or `m10.sqlite`). A note
  was added to `GUI.md` and `aire-server/README.md`.

### BR-06 — Unbounded binary-wide input-validation scan

- **Severity:** Medium. **Status:** CONFIRMED-SOURCE.
- **Location.** `agent/assembly_answers.py:231 answer_validation`, routed for
  questions matching `input validation|where .*validat|validate[sd]? (the )?input`.
- **Behavior.** It calls `AssemblyIntelligence.function_evidence` for every
  internal function, synchronously in the HTTP handler thread, while holding
  the session lock. There is no deadline or result cache.
- **Historical measurement.** `docs/M10_SECURITY_HARDENING.md:195-196`
  records 0.04–0.09 s on the ELF fixtures, 7.8–8.4 s per crypto PE, and
  88.8 s on `sleigh.exe`. This audit did not re-measure.
- **Impact.** Long stalls on large binaries. Small fixtures are fast.
- **Suggested action.** Add a deadline/limit and caching. In the demo, ask
  this only on the small ELF.

### BR-07 — Incomplete cancellation

- **Severity:** Medium. **Status:** CONFIRMED-SOURCE.
- **Behavior.**
  - `_chat` reports a client disconnect through `cancelled()`.
    `AgentRunner.check()` polls it only *between* steps.
  - The deterministic `FactAnswerer` and M10 paths never poll it.
  - An in-flight Ollama request continues until its socket timeout. That
    timeout applies per socket operation, not as a total deadline
    (`ai/ollama_client.py` docstring). `_DeadlineModel` shrinks it to the
    remaining agent budget.
  - Analysis jobs have no user cancel route. Only the watchdog stops them
    (`AIRE_ANALYSIS_TIMEOUT`, default 3600 s).
- **Impact.** Abandoned work keeps consuming CPU. A hung analysis blocks the
  single analysis queue for up to an hour.
- **Suggested action.** Add an explicit cancel endpoint for jobs and
  streaming cancellation for model calls.

### BR-08 — Broad non-loopback bind opt-in

- **Severity:** Medium. **Status:** CONFIRMED-REPRO.
- **Behavior.** `_validate_bind_host('192.168.1.5', True)` is accepted (probe).
  The rule is "any single private IPv4", not specifically the NAT address.
  The Host/Origin allowlist protects against browsers. A non-browser client on
  the LAN can still send `Host: 127.0.0.1`, which leaves the per-launch token
  as the only barrier.
- **Mitigations present.**
  - Opt-in is required.
  - A loud startup warning is printed.
  - The token is mandatory.
  - Wildcard, public, link-local and IPv6 binds are refused (probe).
- **Suggested action.** Bind only to the NAT address `10.0.2.15`, as
  documented. Consider restricting the opt-in to an explicit allowlist.

### BR-09 — Java v1 decompiler timeout units

- **Severity:** Medium for the Java extension only. **Status:**
  CONFIRMED-SOURCE.
- **Location.** `ghidra-plugin/src/main/java/aire/services/ContextExtractor.java:33,80`.
- **Behavior.** `MAX_DECOMPILE_MS = 3000` is passed to
  `DecompInterface.decompileFunction(Function, int timeoutSecs, TaskMonitor)`.
  The parameter is in seconds, so the effective limit is about 50 minutes,
  not 3 s.
- **Not reproduced.** Gradle is absent, so the extension cannot be built here
  (BR-20).
- **Impact.** A pathological function can block the Java Suggest task far
  longer than intended.
- **Suggested action.** Rename the constant and pass `3`. Add a test.
- **Python side.** The Python indexer uses `decompile_timeout_seconds=30`
  correctly (BR-23).

### BR-10 — Java v1 stale state across program switches

- **Severity:** Medium for the Java extension only. **Status:**
  CONFIRMED-SOURCE.
- **Location.** `AireSuggestionsProvider.java`:
  - Refresh (`~:271-295`) stores `Function` objects in table rows;
  - Apply (`~:425-450`) opens a transaction on `getCurrentProgram()` and then
    calls `row.function.setName(...)`.
- **Behavior.** Neither `AirePlugin` nor the provider handles program
  activation events (no `ProgramActivatedPluginEvent`/`processEvent`).
- **Expected vs actual.**
  - Expected: switching programs clears or reloads the rows.
  - Actual: rows from the previous program stay. Apply would open a
    transaction on the new program while renaming a function of the old one.
    Ghidra then raises an error, which the code catches and shows. A rename
    of the wrong program is not expected, because no transaction is open on
    it.
- **Not reproduced.** The extension cannot be built here (BR-20).
- **Suggested action.** Listen for program activation, clear the rows, and
  open the transaction on `row.function.getProgram()`.

### BR-11 — Pre-existing uncommitted work

- **Status:** OBSERVED-ENV. These changes existed before the audit:
  - modified: `aire-server/tests/test_agent_integration.py`,
    `test_chat_integration.py`, `test_naming_integration.py`. These are
    live-test remote-Ollama opt-ins; all three run only behind opt-in gates;
  - modified: `docs/DEMO_M10.md`;
  - untracked: `docs/DEFENSE_DEMO_RUNBOOK.md`, `DEFENSE_EVIDENCE_PACKET.md`,
    `DEFENSE_FEATURE_MATRIX.md`, `DEMO_BACKUP_CHECKLIST.md`,
    `DEMO_READINESS_REPORT.md`, `DEMO_READY_RUNBOOK.md`,
    `docs/defense_assets/` and `scripts/verify_defense_demo.py`.
- **What the audit did.** Preserved all of it and left it out of the audit
  commit.
- **Risk.** Loss if the VM fails.
- **Suggested action.** Review and commit, or back it up, before Nov 20.

### BR-12 — M7 rules do not use persisted thunk bindings

- **Severity:** Low. **Status:** CONFIRMED-REPRO.
- **Behavior.** `security/rules/api_calls.py` labels thunk-path signals
  `LOW` and adds the limitation *"Thunk-to-external binding is not persisted;
  no such edge is inferred"*. Schema v2 now persists `thunk_relations`, but
  the rule never reads them.
- **Live API.** `unsafe_copy` gives CWE-120 SIGNAL at `00401183` with
  strength `LOW`. `dangerous_gets` gives CWE-242 SIGNAL at `00401178`,
  `LOW`. `safe_copy` gives no signal.
- **Impact.** The limitation text is stale, and strength is understated for
  ELF PLT calls.
- **Suggested action.** Consume `thunk_relations` as corroboration and
  update the text. Strength must stay a SIGNAL, not a confirmed
  vulnerability.

### BR-13 — Java v1 swallows cancellation

- **Severity:** Low. **Status:** CONFIRMED-SOURCE.
- **Location.** `ContextExtractor.java` catches `CancelledException` at
  lines ~122, 168, 191, 262 and 273, logs at debug level, and continues. A
  cancelled Suggest can therefore produce partial evidence that looks
  complete.

### BR-14 — Ambiguous `schema_version` metadata key

- **Severity:** Low. **Status:** CONFIRMED-SOURCE.
- **Behavior.** `index_binary` writes `analysis_metadata.schema_version = 1`.
  That number describes the ProgramIndex metadata format.
  `schema_metadata.schema_version` is `2`, the database schema.
- **Impact.** It is easy to misread during review.
- **Suggested action.** Rename the key in a future format version.

### BR-15 — Whole-snapshot materialization

- **Severity:** Low. **Status:** CONFIRMED-SOURCE.
- **Behavior.**
  - `analyze_binary(load_snapshot=True)`, the default outside the GUI
    worker, calls `load_program_index` on a cache hit. That loads every
    body and all references (67,147 reference rows for `sleigh.exe`).
  - `ApplicationRelevanceService` loads all function rows and edges of a
    binary per ranking.
- **Mitigations.** The GUI worker passes `load_snapshot=False`. Workspaces
  memoize tool results (`api/workspace.py`).
- **Impact.** Memory and latency on large binaries outside the GUI.

### BR-16 — Fixture build script executes binaries

- **Severity:** Low for code, high as a procedure. **Status:**
  CONFIRMED-SOURCE.
- **Behavior.** `tests/fixtures/simple_elf/build.sh` compiles and then *runs*
  both fixtures to check their output (`GROUND_TRUTH.md`, "Build and run").
- **Suggested action.** Never run it during the defense. The demo uses the
  pre-built, hash-verified binaries and an already indexed store.

### BR-17 — `aire chat` is loopback-only

- **Severity:** Low. **Status:** CONFIRMED-SOURCE.
- **Behavior.** `agent/cli.py` builds `OllamaClient(host=args.host, …)`
  without `allow_remote_host`. A Windows endpoint therefore raises
  "Non-loopback Ollama host rejected". This is documented in
  `aire-server/README.md`. The GUI is the supported split-host interface.

### BR-18 — Overview questions require the model

- **Severity:** Info. **Status:** CONFIRMED-REPRO.
- **Behavior.** "What does this binary do?" goes to
  `AgentRunner` → `AireChatService`. With the model unavailable, the probe
  returned status `partial` with the deterministic tool facts and the text
  *"Agent could not complete the request (RuntimeError)"*.
- **Impact.** This is the correct graceful degradation, but there is no
  grounded prose summary without a model.

### BR-19 — VM crash reports

- **Status:** OBSERVED-ENV.
- **Contents.** `/var/crash` holds reports dated Nov 10–17, 2026, for
  `systemd-journald`, `systemd-oomd`, `systemd-logind`, `systemd-resolved`,
  `udevadm`, `gnome-shell` and `python3.12` (a 133 MB report from
  Nov 17 13:22). The audit's test runs created no new reports. Earlier notes record a crash dump filling
  the disk and VirtualBox descheduling the guest for up to 393 s.
- **Current state.** Disk has 53 GB free, so it is no longer blocking.
- **Suggested action.** Have the user review and remove old reports. Run
  defense rehearsals with nothing else heavy running.

### BR-20 — Java extension cannot be rebuilt here

- **Status:** OBSERVED-ENV.
- **Facts.** `javac` exists (OpenJDK 21.0.13), but `gradle` is not on PATH.
  `ghidra-plugin/scripts/build_extension.sh` needs Ghidra's Gradle build.
- **Impact.** Java v1 behavior is documented from source only.

---

## Resolved or non-reproducible historical leads

### BR-21 — IPv4-mapped IPv6 loopback (RESOLVED)

- **Ollama client.** `OllamaClient` rejects `http://[::ffff:127.0.0.1]:11434`
  unless `allow_remote_host=True`. `[::1]`, `127.0.0.1` and `localhost` are
  accepted (probe).
- **GUI Host header.** The allowlist accepts only literal
  `localhost`/`127.0.0.1`.
- **Regression tests.**
  - `test_ollama_client.py::test_mapped_ipv6_policy_independent_of_python_loopback_classification`;
  - `test_ollama_client.py::test_loopback_ipv6`;
  - `test_host_access_security.py::test_ipv4_mapped_loopback_rejected_without_opt_in`.

  All pass in the default suite run of 2026-11-19.

### BR-22 — `failwithmessage` caller/callee direction (NOT REPRODUCIBLE)

- **Probe.** It compared `get_callers`/`get_callees` with raw SQL over
  `function_edges` for `failwithmessage` in `FunctionOverloading.exe`
  (`m10.sqlite`):
  - callers: `_RTC_AllocaFailure`, `_RTC_Failure`, `_RTC_StackFailure`,
    `__RTC_UninitUse`;
  - callees: `thunk_FUN_00413d50`, `thunk_FUN_00413d60`,
    `__security_check_cookie`, `_RTC_GetSrcLine`, `DebuggerProbe`,
    `DebuggerRuntime`.

  Both match SQL.
- **Storage.** `graph_builder.py` stores the containing function as the
  caller.
- **Rendering.** `render_tool_facts`, `FactAnswerer._graph` and `showCallGraph`
  all render caller → callee.
- **Coverage.** Exact graph questions bypass model prose ("exact stored
  results, not prose that can reverse edge direction", `agent/runner.py`).
  `test_chat_fact_answers.py::test_callers_and_callees_match_ground_truth_driver`
  covers this.

### BR-23 — Python decompiler timeout units (RESOLVED)

`IndexOptions.decompile_timeout_seconds = 30` is passed to
`decompileFunction`'s `timeoutSecs`. It is validated to fit a Java int.
Timeouts are retried once serially and recorded in
`analysis_metadata.decompile_retry` and `decompilation_incomplete`.

### BR-24 — README M8 status contradiction (RESOLVED)

The current README describes M8 as implemented throughout. No "M8 not
started" text remains in `README.md`, `docs/CURRENT_STATE.md` or
`docs/ROADMAP.md` (grep). `CURRENT_STATE.md` explicitly says its older
milestone sections are historical.
