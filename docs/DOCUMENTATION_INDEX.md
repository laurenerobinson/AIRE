# Documentation index

Updated **2026-11-19**. Documents are grouped by purpose. *Current* means the
document describes today's code and was reconciled in the 2026-11-19 audit.
*Historical* means it records an earlier milestone or measurement as it was
at that time. **Uncommitted** marks the author's Nov 17 drafts, which are not
in Git yet.

## Start here

| Document | What it is |
|---|---|
| [../README.md](../README.md) | Project overview, capabilities, split-host launch procedure |
| [REPOSITORY_AUDIT_2026-11-19.md](REPOSITORY_AUDIT_2026-11-19.md) | Master audit: baseline, inventory, findings, historical leads, readiness |
| [DEFENSE_TECHNICAL_BRIEF.md](DEFENSE_TECHNICAL_BRIEF.md) | How the whole system works, for the defense, with likely questions |
| [DEFENSE_DEMO_RUNBOOK_2026-11-20.md](DEFENSE_DEMO_RUNBOOK_2026-11-20.md) | Verified demo procedure for Nov 20 |

## Current implementation reference

| Document | Scope |
|---|---|
| [SYSTEM_DATA_FLOW.md](SYSTEM_DATA_FLOW.md) | End-to-end diagrams: intake → Ghidra → SQLite → tools → routing → Ollama → validation → GUI |
| [API_AND_DATA_REFERENCE.md](API_AND_DATA_REFERENCE.md) | CLI, environment variables, HTTP routes, NDJSON stream, SQLite schema, data models, 27 tools |
| [FEATURE_TRACEABILITY.md](FEATURE_TRACEABILITY.md) | Each feature → source → tests → status |
| [BUG_AND_RISK_REGISTER.md](BUG_AND_RISK_REGISTER.md) | Defects, risks, verification gaps, resolved historical leads |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Deployment and trust model, milestone architecture (M1–M7 sections are detailed) |
| [CURRENT_STATE.md](CURRENT_STATE.md) | Capability narrative per milestone (2026-11-19 status note on top; body preserves earlier measurements) |
| [GUI.md](GUI.md) | GUI launch, interface, session storage, service boundary |
| [../aire-server/README.md](../aire-server/README.md) | Backend usage per milestone (CLI and Python examples) |
| [M8_AGENT.md](M8_AGENT.md) | Agent architecture, tool catalog, activity, sessions |
| [M10_ASSEMBLY_INTELLIGENCE.md](M10_ASSEMBLY_INTELLIGENCE.md) | M10 instruction IR, semantics, flow and cross-validation design |
| [REFERENCE_FACTS.md](REFERENCE_FACTS.md) | Reference, xref and thunk evidence |
| [APPLICATION_RELEVANCE.md](APPLICATION_RELEVANCE.md) | Relevance policy v2 and its validation |
| [BINARY_FORMAT_SUPPORT.md](BINARY_FORMAT_SUPPORT.md) | ELF/PE format evidence |
| [HOST_ACCESS_SECURITY_REVIEW.md](HOST_ACCESS_SECURITY_REVIEW.md) | Token, Host and Origin design; Windows checks still pending |
| [M7_SECURITY_RULES.md](M7_SECURITY_RULES.md) | CWE rule contracts and validation |
| [M5_CHAT.md](M5_CHAT.md) / [M6_NAMING.md](M6_NAMING.md) | Chat and naming contracts |
| [../aire-server/src/aire/security/rules/README.md](../aire-server/src/aire/security/rules/README.md), [../aire-server/src/aire/validation/README.md](../aire-server/src/aire/validation/README.md) | Package notes |
| [../ghidra-plugin/README.md](../ghidra-plugin/README.md) | Legacy Java v1 extension (separate from the Python platform) |

## Verification and testing

| Document | Kind |
|---|---|
| [TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md) | **Fresh** test runs, probes and HTTP smoke test |
| [VERIFICATION.md](VERIFICATION.md) | Historical reconstruction verification, with a fresh-results note |
| [M5_VALIDATION.md](M5_VALIDATION.md) | Historical M5 live-model validation |
| [M10_CHECKPOINT.md](M10_CHECKPOINT.md) | M10 phase status, objdump ground-truth results (historical) |
| [M10_INTEGRATION_HARDENING.md](M10_INTEGRATION_HARDENING.md), [M10_SECURITY_HARDENING.md](M10_SECURITY_HARDENING.md) | Nov 17 hardening phases 1–2 (historical results) |
| [M9_PERFORMANCE.md](M9_PERFORMANCE.md), [M9_FINAL_REPORT.md](M9_FINAL_REPORT.md), [M9_CORRUPT_PE.md](M9_CORRUPT_PE.md), [M9_CRYPTO_PE.md](M9_CRYPTO_PE.md) | M9 measurements and fixtures (historical) |
| [EXTERNAL_BINARY_BENCHMARKS.md](EXTERNAL_BINARY_BENCHMARKS.md), [FRESH_ANALYSIS_PROFILE.md](FRESH_ANALYSIS_PROFILE.md), [GUI_CHAT_PERFORMANCE.md](GUI_CHAT_PERFORMANCE.md), [chatperf/README.md](chatperf/README.md) | Performance measurements (historical) |
| [M9_VIRTUALBOX_STABILITY.md](M9_VIRTUALBOX_STABILITY.md), [VM_STABILITY_DIAGNOSTICS.md](VM_STABILITY_DIAGNOSTICS.md) | VM freeze investigations |
| [../tests/README.md](../tests/README.md), [../tests/integration/README.md](../tests/integration/README.md), [../tests/fixtures/simple_elf/GROUND_TRUTH.md](../tests/fixtures/simple_elf/GROUND_TRUTH.md), [../tests/fixtures/security_rules/GROUND_TRUTH.md](../tests/fixtures/security_rules/GROUND_TRUTH.md) | Test corpus and ground truth |

## Development

| Document | Use |
|---|---|
| [DEVELOPMENT.md](DEVELOPMENT.md) | Ghidra, JDK, Gradle, venv and test commands, including the safe no-model test environment |
| [ROADMAP.md](ROADMAP.md) | Milestones M0–M12 and next work |
| [M9_PROGRESS_CHECKPOINT.md](M9_PROGRESS_CHECKPOINT.md), [M10_PRE_HARDENING_CHECKPOINT.md](M10_PRE_HARDENING_CHECKPOINT.md), [chatperf/GUIUX_CHECKPOINT.md](chatperf/GUIUX_CHECKPOINT.md) | Resume checkpoints (historical) |
| [M10_DOCUMENTATION_UPDATE_2026-11-17.md](M10_DOCUMENTATION_UPDATE_2026-11-17.md) | Previous documentation audit (Nov 17) |
| [../LICENSE-TODO.md](../LICENSE-TODO.md) | License decision pending |

## Defense preparation

| Document | Status |
|---|---|
| [DEFENSE_TECHNICAL_BRIEF.md](DEFENSE_TECHNICAL_BRIEF.md), [DEFENSE_DEMO_RUNBOOK_2026-11-20.md](DEFENSE_DEMO_RUNBOOK_2026-11-20.md) | Current (2026-11-19) |
| [MS_DEFENSE_M10.md](MS_DEFENSE_M10.md) | Nov 17 defense notes and fact-check ledger (committed) |
| [DEFENSE_DEMO_RUNBOOK.md](DEFENSE_DEMO_RUNBOOK.md), [DEFENSE_EVIDENCE_PACKET.md](DEFENSE_EVIDENCE_PACKET.md), [DEFENSE_FEATURE_MATRIX.md](DEFENSE_FEATURE_MATRIX.md), [DEMO_READY_RUNBOOK.md](DEMO_READY_RUNBOOK.md), [DEMO_READINESS_REPORT.md](DEMO_READINESS_REPORT.md), [DEMO_BACKUP_CHECKLIST.md](DEMO_BACKUP_CHECKLIST.md), `defense_assets/` | **Uncommitted** Nov 17 drafts. These links work only in the author's working tree |
| [DEMO_M10.md](DEMO_M10.md) | M10 demo walkthrough (has an uncommitted Nov 17 pointer edit) |

## Historical demonstrations and archives

| Document | Note |
|---|---|
| [AIRE_DEMO_SCRIPT.md](AIRE_DEMO_SCRIPT.md) | v1 Java presentation script, not the current demo |
| [DEMO_2026-10-22.md](DEMO_2026-10-22.md), [DEMO_M9_PROGRESS_CHECK.md](DEMO_M9_PROGRESS_CHECK.md) | Earlier professor demos |
| [M9_IMPLEMENTATION_2026-10-13.md](M9_IMPLEMENTATION_2026-10-13.md) | October 13 implementation record |
| [AUDIT.md](AUDIT.md) | M0 archive reconstruction and migration audit; `recovery/` holds the archive |
| [../AIRE_competitive_research_and_implementation_plan_2026-10-13.md](../AIRE_competitive_research_and_implementation_plan_2026-10-13.md) | Research plan: proposals, not implementation status |
| [../professor_samples/function_overloading/README.md](../professor_samples/function_overloading/README.md) | Professor sample and its evidence |
