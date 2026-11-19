# Defense backup checklist — November 17 checkpoint

The guest-local assets below exist under ignored
`demo_artifacts/m10/defense_20261117/`. They are not included in Git. Copy the
sanitized PNGs and necessary non-secret evidence to Windows and test offline
access before claiming a VM-independent backup. That transfer is **pending**.
Do not copy the browser profile, authentication cookies, session files or live
token URLs into a presentation bundle.

## Available assets

| Demonstration step | Sanitized PNG backup |
|---|---|
| Authenticated library / ELF selection | `01-library.png` |
| Functions and overview | `06-overview.png` |
| Imports / strings / calls | `02-imports.png`, `03-strings.png`, `04-calls.png` |
| Decompiled code / instruction semantics | `05-decompiled.png`, `07-assembly.png` |
| CFG / data flow / decompiler check | `08-cfg.png`, `08-dataflow.png`, `08-decompiler.png` |
| Deterministic question / citations and activity | `09-question.png`, `10-evidence.png` |
| CWE SIGNAL / supporting callsite | `11-cwe.png`, `12-cwe-callsite.png` |
| Restored function and conversation | `13-restored.png` |

All 15 were generated after token removal and DOM path sanitization. Assembly,
CWE and restored-answer images were additionally inspected visually. Review the
entire portable bundle manually before presenting. No screen recording was
created; recording tooling was unavailable and work stopped at this checkpoint.

## Prepared results and identity

- [ ] Retain `demo.sqlite` (6,619,136 bytes) and `preparation.json` locally.
  Integrity and foreign keys passed; bytes were unchanged across both rehearsals.
  Recorded final SHA-256:
  `f88fa14e2e1098fd0459e16aad23a855583ad2966b80911b7c46a8fa22b1d379`.
- [ ] Preserve the original M10 store; it was not overwritten. Recorded SHA-256:
  `25ac802afd92dd1d9d611fd12e64bfa967f44bf35025389248e4d078e0af95cc`.
- [ ] Keep `inventory.json`, `preparation.json`, `browser-report.json` and
  `default-clean-tests.json` as evidence, outside Git and outside shared screens.
- [ ] Verify four existing fixtures against the recorded hashes in `inventory.json`:
  debug ELF, stripped ELF, O2 ELF and `FunctionOverloading.exe` PE32.
- [ ] Keep the three locally built trusted CWE controls and their hashes in
  `preparation.json`; do not execute them. `unsafe_copy` has one CWE-120 SIGNAL,
  `dangerous_gets` one CWE-242 SIGNAL, and `safe_copy` no finding for these rules.

## Verified example and startup prerequisites

- [ ] Primary question: “What does this function do?” with debug ELF
  `validate_input` at `004011bc`. It passed six deterministic browser submissions.
- [ ] Branch `004011e1` and stack-value origin at `004011dc` were inspected via
  explorer controls. Do not replace these with unvalidated model prompts.
- [ ] Review [launch instructions](DEMO_READY_RUNBOOK.md), disk headroom,
  Ghidra/Java paths, model tags, two active adapters and the existing API listener.
- [ ] Complete Windows listener/NAT/external-device/Chrome authentication checks.
- [ ] Rehearse Windows Chrome twice; do not equate the guest-loopback relay with
  verified Windows forwarding.
- [ ] Complete gated regression checks, or explicitly disclose their absence.
- [ ] Keep narration off; exclude live inference until its separate validation.

## Emergency sequence

1. Failed UI request: reload once, select cached binary, restore Recent Chat.
   Do not re-index. This session recovery worked in the guest rehearsal.
2. Authentication failure: use the fresh launch's private login URL. Never
   display, record or bypass it. Check forwarding/Host if access is rejected.
3. Model unavailable: use the deterministic fixture question and evidence views.
4. API unavailable: show the sanitized screenshot sequence and explain that it
   is a previously validated result, not a live execution.
5. VM unavailable: use the Windows-local backup bundle. Until that bundle is
   copied and opened successfully, this fallback is incomplete.
6. Do not improvise LAN exposure, disable controls, delete files, restart
   analysis or change VM storage/hypervisor settings during the defense.

See [DEMO_READINESS_REPORT.md](DEMO_READINESS_REPORT.md) for the exact evidence
scope and outstanding sign-off blockers. No finished PPTX/PDF was overwritten;
review slide and speaker-note claims against that report before regeneration.
