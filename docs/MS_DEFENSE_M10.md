# MS defense — current M1–M10 notes, runbook and fact-check ledger

Documentation source updated November 17, 2026. This is a speaker-note and
rehearsal source, not evidence that a defense rehearsal or missing experiment
has completed. Current code and repository audit reports take precedence over
the historical v1 presentation in [AIRE_DEMO_SCRIPT.md](AIRE_DEMO_SCRIPT.md).

## Opening and system scope

“A.I.R.E. assists static binary investigation. Ghidra supplies program evidence,
SQLite preserves it, deterministic analysis exposes relationships and assembly
facts, and a bounded read-only agent helps an analyst query that evidence.
Model interpretation remains separate from stored facts and requires review.”

The original Java extension remains an analyst-operated, per-function naming
workflow. The Python implementation now includes a browser GUI and API,
whole-binary analysis and assembly intelligence. Do not present the whole
project as only the original naming extension.

| Milestone | Implemented scope to describe |
| --- | --- |
| M1 | Read-only Ghidra/PyGhidra indexing: metadata, functions, decompilation, assembly, artifacts and resolved direct calls |
| M2 | Atomic SQLite snapshot persistence and reload |
| M3 | Callers, callees, callsites, bounded paths/reachability and connectivity ranking |
| M4 | Bounded evidence selection with source identity, provenance and explicit truncation |
| M5 | Ollama chat, structured-response/citation validation and separate interpretation |
| M6 | Advisory naming suggestions for analyst review; no Python rename/write-back |
| M7 | Deterministic strcpy/CWE-120 and gets/CWE-242 signals; no vulnerability confirmation |
| M8 | Fixed read-only tools, bounded agent orchestration, sessions, CLI and shared GUI/API workflow |
| M9 | References/thunks, format-aware ELF/PE intake, crypto API evidence, cache/parallel decompilation and timeout recovery |
| M10 | Stored instruction IR/P-code, instruction explanations, CFG/loops, bounded data flow, decompiler cross-validation and Function explorer |

Implementation is distinct from evaluation completion. Full M10 Phase 6 and
live-model robustness are not complete.

## Architecture speaker notes

Show the [split-host diagram](ARCHITECTURE.md).

“The laptop hosts two environments. Windows 11 runs Google Chrome in a dedicated
profile and Ollama inference with selected `qwen2.5-coder:1.5b`, context 4096.
Ubuntu in VirtualBox runs the Python API, Ghidra/PyGhidra, SQLite, instruction
IR, call/control-flow and bounded data-flow analysis, decompiler checks, CWE
rules and the read-only conversational agent. Inference is local to the laptop,
outside the VM. Binary evidence and model output cross the VM boundary.”

For this NAT configuration, Chrome uses host `127.0.0.1:8770`, forwarded to
guest `10.0.2.15:8770`. The API reaches Windows Ollama through
`http://10.0.2.2:11434`. Verify addresses before reuse. Local-only host forwarding
and loopback Ollama are required, but final Windows checks are outstanding.
Neither opt-in configures the Windows firewall or NAT rule automatically.

ELF x86-64, professor PE32/x86, and crypto/large PE x86-64 use their detected
Ghidra language/compiler specification. Do not reuse one fixture's ABI, base
address or source map across formats/builds. Damaged PEs can yield partial or
no analysis. Named M10 branch relations/register-frame flow are x86/x86-64
specific; generic P-code explanations are not broad architecture validation.

## Assembly intelligence and read-only agent speaker notes

“During indexing, A.I.R.E. collects bounded structured instruction facts and raw
P-code from the analyzed Ghidra Program. Read-only services explain instructions,
show blocks, branch paths and loops, trace bounded register/frame-slot origins,
and compare selected observations with decompiled C. Every result exposes its
evidence and limits. CONSISTENT means checked properties agree; it does not
prove semantic equivalence. POTENTIAL DISCREPANCY calls for review, and
INSUFFICIENT EVIDENCE remains visible.”

The agent has no shell, arbitrary-file, target-execution or mutation tool. Its
fixed registry validates tools/arguments and preserves binary scope. Model text
does not become a program fact. Explicit upload/index jobs write separate intake
data and analysis snapshots; “read-only agent” does not mean the entire service
never writes files. Session files are separate from SQLite facts.

M10 narration defaults off. `AIRE_M10_NARRATION=0` leaves deterministic M10
answers available, while ordinary M8 prompt cards may still invoke the model.
Enabling narration is experimental model behavior with citation/mnemonic checks,
not proof that the prose is correct or injection-resistant.

## Security and validation speaker notes

“The November 17 Codex host-access audit reports 649 tests executed, 645 passed,
zero failures or errors, and four live-model tests skipped. It used Python
3.12.3 with Ghidra integration and headless Firefox 155.0.1 inside Ubuntu. The
browser test used a temporary local server/profile, synthetic hostile text and
a fake model. It exercised token login and escaped rendering. This does not
independently verify Windows Chrome or host network confinement.”

Earlier Phase 2 is a separate result: 625 executed, 621 passed, zero failures or
errors, four live-model skipped. Do not add the two suite totals or count skips
as passes. These are attributed audit results, not new documentation-update runs.

Implemented controls include fresh launch tokens; HttpOnly, SameSite=Strict
cookies; exact Host/port, Origin and fetch-metadata checks; explicit private-IPv4
bind and Windows Ollama opt-ins; owner-only session files; four concurrent chats;
input/path validation; bounded IR decompression/nesting; escaped frontend text
and restrictive response headers. Manual audit probes verified spare-port
guest listeners and HTTP refusals, plus Windows Ollama metadata connectivity.
They did not verify the final Windows port bindings or model generation.

Accepted limits: plain HTTP under intended local confinement; cookies shared
across ports; token visibility in terminal/history; no global HTTP connection
cap; unmeasured live-model prompt-injection resistance; dependency audit absent.
Do not say the service is generally safe for LAN or internet exposure.

## Demonstration runbook

1. Complete and record the pending host checks below. Confirm disk headroom,
   existing demo SQLite/fixtures and the Windows model before presenting.
2. Use [the README's complete host-inference launch](../README.md#running-aire-with-windows-host-inference).
   Launch isolated Windows Chrome, start the Ubuntu API on 8770 and open the
   printed tokenized Host-side URL. Keep tokens off screenshots and recordings.
3. Follow [DEMO_M10.md](DEMO_M10.md): choose `aire_test_binary` and
   `validate_input`, open Function explorer and show cited assembly, a branch
   path, `[RBP-0x10]` tracing to `strlen`, return usage and decompiler checks.
   Addresses in that runbook belong to that stored fixture/build.
4. Optionally show the crypto PE helper discrepancy and API provenance. Explain
   that crypto evidence identifies calls, not algorithm recovery or executed
   cryptographic behavior. Keep large-PE binary-wide validation off the live path;
   earlier measurements were seconds to roughly 90 seconds under those conditions.
5. Demonstrate model chat only after a separate rehearsal with the Windows model.
   The audit's four live-model skips remain skips; avoid an unmeasured model load
   or large fresh index on stage. Use saved source/evidence as a fallback.
6. Rehearse selection, citation links, cancel/reload, session restoration and
   shutdown. Stop the API with Ctrl-C and confirm its guest listener has closed.

Reported GUI responsiveness improved after Chrome/Ollama moved to Windows.
There is no controlled split-host benchmark. Reducing guest contention does
not prove that historical scheduling stalls, NEM/backend limitations or nearly
full guest storage are resolved. See [VM diagnostics](VM_STABILITY_DIAGNOSTICS.md).

## Fact-check ledger

| Claim | Evidence and presentation boundary |
| --- | --- |
| Implemented M1–M10 static pipeline | [Current state](CURRENT_STATE.md), [architecture](ARCHITECTURE.md), [integration audit](M10_INTEGRATION_HARDENING.md); scoped fixture checks, not universal recovery |
| GUI/API and Function explorer | [GUI](GUI.md), [M10 overview](M10_ASSEMBLY_INTELLIGENCE.md), historical [browser report](m10/browser_verification.json); Windows Chrome rehearsal pending |
| Read-only agent | `aire-server/src/aire/agent/tools.py`, `runner.py`, [M8 contracts](M8_AGENT.md); explicit intake writer is separate |
| Host-access protections and latest regression counts | [Codex host-access review](HOST_ACCESS_SECURITY_REVIEW.md), `test_host_access_security.py`; attributed 645 passes/4 skips |
| Earlier Phase 2 protections/counts | [Phase 2 report](M10_SECURITY_HARDENING.md); 621 passes/4 skips, historical scope |
| ELF/PE and architecture differences | [Format verification](BINARY_FORMAT_SUPPORT.md), [PE corruption policy](M9_CORRUPT_PE.md), [crypto fixtures](M9_CRYPTO_PE.md); no universal format/ABI claim |
| Performance improvements previously measured | [M9 results](M9_FINAL_REPORT.md), [chat measurements](chatperf/README.md); historical conditions, raw versus adjusted timings retained |
| Better split-host responsiveness | Operator-reported observation in this maintenance brief; no speedup number or causal benchmark |
| Vulnerability detection or decompiler equivalence | Not established; narrow CWE signals and consistency heuristics require analyst review |
| Broad model accuracy, confidence calibration, 10× analyst speed | Not established; do not reuse those historical presentation claims |

## Evaluation gaps and manual review

| Phase 6 artifact | Observed state on November 17 |
| --- | --- |
| `docs/m10/eval_phase1.json`, `eval_phase2.json`, `crossval_survey.json`, `ir_overhead.json` | Present, historical scoped evidence; not a completed current-code evaluation |
| `docs/m10/eval_full/O0.json`, `O0-stripped.json`, `O2.json` | Present with saved completion markers; historical steps, not rerun here |
| `docs/m10/eval_full/aes_gcm.json` | Partial: identity, phase1, explanations; no completion marker |
| `sha256_hash`, `ecdsa_sign`, `negatives`, `latency_large_pe`, `phase2_mutation_O2` per-unit JSON | Missing from `docs/m10/eval_full/` |
| `docs/m10/eval_full_run1_prefix.json` | Present, earlier pre-fix evidence; retain original numbers and scope |
| `docs/m10/eval_full.json` | Missing merged report |
| `docs/M10_EVALUATION.md` | Missing narrative evaluation report |

Fresh evaluation needs new ignored output paths: the resumable evaluator skips
existing step names, and the shell wrapper writes into historical docs paths.
Preserve original results and produce any new publishable report only after
reviewing all completed units. Do not merge partial metrics into invented totals.

Before defense sign-off, independently verify Windows listeners 8770/11434,
NAT forwarding Host IP `127.0.0.1`, external-device rejection, isolated Chrome
token/cookie behavior and Adapter 2. Record the final VM allocation, backend,
disk headroom and host scheduling observations separately. Full Windows
model-generation/quality and dependency checks remain additional follow-up.

No PPT/PPTX, PDF, ODP, Keynote, speaker-note or fact-check-ledger binary file
was found in the repository inventory (including ignored files, excluding
dependency/profile trees). No finished presentation binary was overwritten.
Any external finished defense deck/PDF requires manual review and regeneration
from these notes and the architecture diagram, with explicit approval before
overwriting it. Rehearse the final deck and verify every number against its
dated source; replace VM-only inference diagrams, old ports/models and v1-only
scope claims. No new slide/PDF artifact was generated or added to Git.
