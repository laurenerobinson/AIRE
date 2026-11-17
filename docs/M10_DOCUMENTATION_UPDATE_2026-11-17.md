# M10 documentation update — November 17, 2026

Documentation maintenance only. No application behavior, historical measured
results, fixtures or finished presentation binaries were changed. No packages
were installed and nothing was committed or pushed. The working branch was
`m10-host-access-hardening`, rather than the requested reference branch
`checkpoint/m10-pre-hardening`; it was preserved without checkout or reset.
The working tree was clean at the start of this audit.

## 1. Files updated

Thirty-four Markdown files, including this report and the new defense source:

| Area | Files |
| --- | --- |
| Entry points and development | [README](../README.md), [backend README](../aire-server/README.md), [DEVELOPMENT](DEVELOPMENT.md), [CURRENT_STATE](CURRENT_STATE.md), [ROADMAP](ROADMAP.md) |
| Architecture and interface | [ARCHITECTURE](ARCHITECTURE.md), [GUI](GUI.md), [M8_AGENT](M8_AGENT.md) |
| Host/security evidence | [HOST_ACCESS_SECURITY_REVIEW](HOST_ACCESS_SECURITY_REVIEW.md), [M10_SECURITY_HARDENING](M10_SECURITY_HARDENING.md), [M10_INTEGRATION_HARDENING](M10_INTEGRATION_HARDENING.md), [VERIFICATION](VERIFICATION.md) |
| M10 implementation/history | [M10_ASSEMBLY_INTELLIGENCE](M10_ASSEMBLY_INTELLIGENCE.md), [M10_CHECKPOINT](M10_CHECKPOINT.md), [M10_PRE_HARDENING_CHECKPOINT](M10_PRE_HARDENING_CHECKPOINT.md) |
| Demonstration and defense | [DEMO_M10](DEMO_M10.md), [MS_DEFENSE_M10](MS_DEFENSE_M10.md) (new), [AIRE_DEMO_SCRIPT](AIRE_DEMO_SCRIPT.md), [DEMO_M9_PROGRESS_CHECK](DEMO_M9_PROGRESS_CHECK.md), [DEMO_2026-10-22](DEMO_2026-10-22.md) |
| Performance and VM history | [VM_STABILITY_DIAGNOSTICS](VM_STABILITY_DIAGNOSTICS.md), [M9_VIRTUALBOX_STABILITY](M9_VIRTUALBOX_STABILITY.md), [M9_PERFORMANCE](M9_PERFORMANCE.md), [M9_FINAL_REPORT](M9_FINAL_REPORT.md), [GUI_CHAT_PERFORMANCE](GUI_CHAT_PERFORMANCE.md), [chatperf README](chatperf/README.md) |
| Older scope claims | [M5_CHAT](M5_CHAT.md), [M5_VALIDATION](M5_VALIDATION.md), [M7_SECURITY_RULES](M7_SECURITY_RULES.md), [M9_PROGRESS_CHECKPOINT](M9_PROGRESS_CHECKPOINT.md), [October 13 research plan](../AIRE_competitive_research_and_implementation_plan_2026-10-13.md) |
| Test/corpus guidance | [tests README](../tests/README.md), [integration README](../tests/integration/README.md) |
| Audit record | This file (new) |

The raw M9/M10 JSON, text logs, metrics and benchmark figures remain unchanged.
Historical reports received dated scope notes where needed rather than new
numbers or rewritten experiments.

## 2. Documentation inaccuracies corrected

- Replaced the root README's M1–M8-only summary, “M8 has not started” and
  dynamic-validation M10 roadmap with the implemented M1–M10 static pipeline.
- Corrected current GUI/API, intake/indexing and session descriptions. Kept
  the separate Java v1 naming workflow and its actual defaults distinct.
- Replaced VM-only inference assumptions with Windows inference/Chrome and
  Ubuntu analysis. Clarified model selection versus installation/generation proof.
- Replaced current host launch instructions with port 8770 and mandatory
  per-launch authentication. Port 8767/8768 reports remain labeled historical.
- Corrected “loopback-only” as a universal bind claim: defaults remain loopback,
  but one private IPv4 guest bind is supported with explicit opt-in and a token.
- Updated current Python environment to the reported/locally confirmed 3.12.3;
  preserved Python 3.11 as historical M1 evidence. Ghidra 12.1.3/PyGhidra 3.1.0
  and Java 21 audit versions remain distinct from the archived v1 12.0.1 target.
- Removed current links/promises to the absent final M10 evaluation report;
  enumerated partial/missing artifacts in the defense ledger.
- Corrected M10 narration to default off with exact `AIRE_M10_NARRATION=1`
  enablement. Narration-off does not disable ordinary M8 model chat/cards.
- Qualified unsupported host-cause, immunity-to-stalls and speed claims. Historical
  v1 confidence calibration, zero-exfiltration and 10× analyst claims are flagged
  as unsupported presentation material.
- Clarified per-binary architecture/ABI/build and format validation; read-only
  agent tools versus explicit upload/index writers; citation validity versus
  semantic correctness; consistency heuristics versus equivalence proofs.

## 3. Current architecture summary

Windows 11 runs Google Chrome with a dedicated profile and local Ollama
inference, selected model `qwen2.5-coder:1.5b`, context 4096, port 11434.
Ubuntu VirtualBox runs the Python API, Ghidra/PyGhidra static analyzer, SQLite
knowledge store/instruction IR, assembly/CFG/call-graph and bounded flow
services, decompiler cross-validation, CWE rules and read-only agent.

The intended NAT paths are Windows `127.0.0.1:8770` → guest
`10.0.2.15:8770`, and guest → Windows Ollama `http://10.0.2.2:11434`.
The updated Mermaid diagram shows both environments, laptop/VM boundaries,
evidence/model traffic and separate intake/session writes. These IPs describe
the current NAT configuration and require verification before reuse.
Local inference on the laptop is outside the VM; targets are never executed.

The move reduces guest resource contention and reportedly improved GUI
responsiveness. There is no measured split-host speedup. Historical NEM
limitations, excessive VM allocation, nearly full root storage and scheduling
stalls are documented without claiming their causes or resolution were proven.

## 4. Deployment and security instruction changes

The README now contains **Running A.I.R.E. with Windows Host Inference**, covering
Windows Ollama startup/model presence, NAT configuration, the supplied Ubuntu
command, guest-to-host tags check, isolated Chrome, printed token URL, listener
verification, Ctrl-C shutdown and common 401/403/connectivity failures.

Current instructions preserve explicit private-IPv4 bind and remote-Ollama
opt-ins and context 4096. `--public-port` affects the exact Host allowlist;
it does not create a NAT rule. Windows loopback reachability is an explicit
VirtualBox configuration with access to other host loopback services as a
trade-off; widening Ollama to all interfaces is not the documented fix.

The security review separates reported automated control checks, manual guest
HTTP/listener probes, outstanding Windows verification and accepted limitations.
It covers launch tokens; HttpOnly/SameSite=Strict cookies; exact Host/Origin/
fetch-metadata gates; read-only tools; 0700 new session directories/0600 files;
four concurrent chats; path/input validation; 32 MiB/64-level IR decode bounds;
and safe escaped frontend rendering. Plain HTTP, port-shared cookies, token
history/terminal exposure, no global connection cap and unmeasured live-model
injection resistance remain explicit limits. No general LAN/internet safety
claim is made.

## 5. Testing evidence incorporated

No separate *A.I.R.E. Host-Access Change Audit* document was located by the
workspace inventory. This update uses the corresponding
[repository review](HOST_ACCESS_SECURITY_REVIEW.md), implementation and tests.

| Attributed evidence | Executed | Passed | Failed / errors | Skipped | Conditions |
| --- | ---: | ---: | --- | ---: | --- |
| November 17 Codex host-access audit | 649 | 645 | 0 / 0 | 4 | Python 3.12.3, Ghidra enabled, browser enabled; reported 604 s |
| Earlier November 17 Phase 2 | 625 | 621 | 0 / 0 | 4 | Ghidra enabled, no interactive browser; reported 369 s |

The host-access browser evidence used Firefox 155.0.1 **headless inside Ubuntu**,
a temporary local server/profile, synthetic hostile data and a fake model
provider, including real token login and literal-text rendering. It did not
test Windows Chrome, final NAT bindings or live-model output quality. The four
live-model skips did not pass. Documentation maintenance did not independently
rerun the full suite or browser/model tests.

Earlier M9 measurements, M10 phase results, scoped integration checks, original
source-based versus compiler-adjusted O2 expectations and partial evaluation
JSON remain separately attributed. The [defense ledger](MS_DEFENSE_M10.md)
lists the complete saved ELF units, partial AES unit, five missing units and
absent merged/narrative reports; no aggregate benchmark was fabricated.

## 6. Outstanding verification requirements

1. Inspect Windows listener addresses/processes for 8770 and 11434.
2. Verify VirtualBox NAT forwarding explicitly binds host `127.0.0.1` only.
3. Test rejection from another network device against relevant host LAN/IPv6
   addresses on both ports.
4. Rehearse isolated Chrome authentication, cookie attributes and old-token
   rejection after restart, without capturing credentials.
5. Inspect Adapter 2's saved enabled state/network attachment and guest addresses.
6. Confirm Windows Qwen installation and separately test generation, latency,
   answer quality and model robustness; metadata connectivity is insufficient.
7. Review dependencies separately; no dependency scanner was installed/run here.
8. Finish M10 evaluation and rehearse the final defense; record current disk,
   VM allocation/backend and scheduling observations with host evidence.

## 7. Files needing manual review

- [MS_DEFENSE_M10.md](MS_DEFENSE_M10.md) is the new current speaker-note,
  fact-check and runbook source. Rehearse it with the actual defense deck.
- No finished PPT/PPTX, PDF, ODP, Keynote or Word presentation file was found
  in the repository inventory, including ignored files outside dependency/profile
  trees. Any external deck/PDF requires review and regeneration from current
  sources; obtain explicit approval before overwriting a finished binary artifact.
- The v1 [AIRE_DEMO_SCRIPT.md](AIRE_DEMO_SCRIPT.md), October 22 and M9 runbooks
  retain their old commands/results under historical banners. Do not reuse
  unsupported confidence, safety or performance claims in the defense.
- `scripts/verify_m10_browser.py` and related historical browser helpers require
  authentication-aware review before reuse. The M10 helper persists its URL;
  passing a real token there would leak it to the report. No script was edited.
- `scripts/run_m10_eval_resumable.sh` writes into historical result paths and
  the evaluator skips prior steps. Future evaluation must use new ignored
  outputs and distinguish current-code results from saved runs.
- Final `docs/M10_EVALUATION.md` and `docs/m10/eval_full.json` still need to be
  produced after missing evaluation work, not synthesized from incomplete data.

## 8. Documentation consistency findings and validation

Repository searches covered stale ports/models, GUI/API absence, VM-only
inference, M8/M10 status, environment versions, complete-security claims and
demo commands, plus presentation/speaker/runbook/ledger names and binary formats.
Old models and ports remain where they describe v1 defaults, old fixture runs
or spare-port security probes. The historical research snapshot is explicitly
separated from current code. Raw measured reports were not rewritten.

Source checks covered `agent/cli.py`, `api/server.py`, `api/binary_library.py`,
`agent/session.py`, `agent/tools.py`, `ai/ollama_client.py`, instruction-IR
decoding, the host-access regressions and evaluation/browser helpers. The actual
`aire gui --help` confirms the documented flags; local Python reports 3.12.3.
No running service or Windows configuration was changed.

Documentation validation completed:

- All 34 changed/new repository files are Markdown. Git diff inspection confirms
  no Python, JavaScript, HTML, Java, shell, configuration, fixture or binary
  changes. No generated runtime artifact was added to Git.
- Structural Markdown checks found no unclosed fences or invalid trailing
  whitespace; local Markdown destination and heading-anchor checks passed.
  The architecture diagram was reviewed against the launch/configuration and
  writer/read-only code paths; no rendered Mermaid test is claimed.
- **57 Bash/shell fenced blocks passed `bash -n`**. This checks syntax only;
  deployment commands were not executed. Six PowerShell blocks were reviewed
  as Windows instructions; Windows/PowerShell execution was unavailable.
- The exact supplied Ubuntu configuration and launch flags match current
  `agent/cli.py`, `GuiModelConfig`, `OllamaClient` and actual `aire gui --help`.
  The checks do not independently validate VirtualBox/Chrome Windows CLI behavior.
- Added-text secret-pattern checks and manual diff review found no credentials
  or real launch tokens. Existing audit examples use redactions/invalid inputs.
  Tokens, cookie values and runtime profiles were not collected for this task.
- `git diff --check` passed. The temporary documentation checker and JSON output
  are under `/tmp`, outside the repository; no package was installed for linting.
- Existing Git ignore rules cover the host-access log and suggested new M10
  runtime output directory. Historical raw results were not overwritten.

The 649-test result above remains an attributed prior audit result; this
documentation-only validation did not run the application regression suite.
