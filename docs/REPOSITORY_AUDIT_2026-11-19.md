# A.I.R.E. repository audit — 2026-11-19

This audit was a documentation and verification pass. **No application code,
fixture or analysis database was changed.** The live filesystem was treated
as the source of truth. Earlier documentation was used as context, not as
proof.

Companion documents:

- [FEATURE_TRACEABILITY.md](FEATURE_TRACEABILITY.md)
- [SYSTEM_DATA_FLOW.md](SYSTEM_DATA_FLOW.md)
- [API_AND_DATA_REFERENCE.md](API_AND_DATA_REFERENCE.md)
- [BUG_AND_RISK_REGISTER.md](BUG_AND_RISK_REGISTER.md)
- [TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md)
- [DEFENSE_TECHNICAL_BRIEF.md](DEFENSE_TECHNICAL_BRIEF.md)
- [DEFENSE_DEMO_RUNBOOK_2026-11-20.md](DEFENSE_DEMO_RUNBOOK_2026-11-20.md)
- [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)

## 1. Baseline

| Item | Value |
|---|---|
| Repository | `~/aire` (remote `origin` = `github.com:laurenerobinson/AIRE.git`) |
| Date | 2026-11-19 (CST) |
| Branch at entry | `m10-host-access-hardening` |
| HEAD at entry | `ebacf4d680f6921a3e303fae7f1ea599ddd54f57`, "docs(m10): update split-host deployment and defense evidence" |
| Audit branch | `docs/aire-full-audit-2026-11-19`, created from that HEAD with `git switch -c`. The working tree was carried over untouched |
| Local branches | `main`, `m10-host-access-hardening`, `checkpoint/m10-pre-hardening`, `pre-gui-integration`, `aire-safety-before-workspace-20261005` |
| Remote branches | `origin/main`, `origin/m10-host-access-hardening` |
| Stashes | none |
| Pre-existing modified files | `aire-server/tests/test_agent_integration.py`, `test_chat_integration.py`, `test_naming_integration.py`. These add the `AIRE_OLLAMA_ALLOW_REMOTE` opt-in to the live tests. `docs/DEMO_M10.md` gained a pointer to the Nov 17 defense docs |
| Pre-existing untracked files | `docs/DEFENSE_DEMO_RUNBOOK.md`, `DEFENSE_EVIDENCE_PACKET.md`, `DEFENSE_FEATURE_MATRIX.md`, `DEMO_BACKUP_CHECKLIST.md`, `DEMO_READINESS_REPORT.md`, `DEMO_READY_RUNBOOK.md`, `docs/defense_assets/` (5 files), `scripts/verify_defense_demo.py` |
| Treatment | All pre-existing changes were preserved and **excluded from the audit commit** (BR-11) |

**Environment:**

- Ubuntu 24.04.5 (VirtualBox guest), kernel 7.0.0-43, 6 vCPU, 17 GiB RAM,
  53 GB free disk;
- Python 3.12.3 (`aire-server/.venv`), PyGhidra 3.1.0, JPype 1.5.2;
- Ghidra 12.1.3 at `/home/laurene/tools/ghidra`;
- OpenJDK 21.0.13.0.3 (`javac` present; **Gradle absent**);
- objdump and gcc present;
- guest Ollama running on `127.0.0.1:11434`, deliberately not used;
- Firefox present.

## 2. Inventory

**488 tracked files**, broken down as follows:

| Area | Files | Classification |
|---|---|---|
| `aire-server/src/aire/` | 73 (68 `.py`, 3 static web files, 2 READMEs) | **Active**: the Python platform (M1–M10) |
| `aire-server/tests/` | 52 | **Active**: 649 unittest cases |
| `ghidra-plugin/` | 35 (11 Java + build/metadata, Gson jar, template SLEIGH skeleton) | **Legacy but usable**: Java v1 extension. The skeleton language files are template assets, disabled in `skel.ldefs` |
| `docs/` | 108 (42 Markdown + JSON/TXT/PNG evidence, recovery archive) | Mix of current and historical, see [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) |
| `scripts/` | 37 | Benchmarks, demo preparation and verification, evaluation, fixture builders. `demo_function_overloading_WINDOWS_backup.py` and `demoL_function_overloading.py` are near-duplicate **legacy** variants of `demo_function_overloading.py` |
| `tests/` | 149 (fixtures 130: external 75, m9 38, simple_elf 5, m10 5, security_rules 5, chatperf 2; preserved corpus binaries 8, sources 6, ground truth 3) | **Active** fixtures and preserved corpus |
| `professor_samples/` | 17 | Active demo sample (PE32 + ELF) with analysis evidence |
| Repository root | 12 (README, LICENSE-TODO, research plan, `ORIGINAL_BINARY_SHA256SUMS`, `demo_readonly.py`, `board_demo_verification_2026-10-08.txt`, `FunctionOverloading{,.cpp,.exe,.zip}`, `UltraGpsXY`, `.gitignore`) | Historical demo material. Note that binaries are tracked at the root |

**Ignored or generated, inventoried but not read in full:**

- `aire-server/.venv` (30 MB);
- `__pycache__`, `*.egg-info`, `.pytest_cache`;
- `analysis.sqlite` (205 MB, Oct 8, pre-M10);
- `demo_artifacts/` (1.2 GB): `m10/m10.sqlite`,
  `m10/defense_20261117/demo.sqlite`, `m9/m9.sqlite`, three
  `oct22/*.sqlite`, Firefox profiles, sessions, uploads, logs;
- `docs/chatperf/baseline_2026-11-11/run1.*`.

**Module responsibilities.** Full detail is in
[SYSTEM_DATA_FLOW.md](SYSTEM_DATA_FLOW.md) and
[API_AND_DATA_REFERENCE.md](API_AND_DATA_REFERENCE.md).

| Package | Responsibility | Key symbols |
|---|---|---|
| `aire.pyghidra` | Ghidra lifecycle and fact extraction | `indexer.index_binary`, `extractor.extract_functions/_DecompilerPool/extract_artifacts`, `graph_builder.build_call_edges`, `references.extract_references`, `instruction_ir.FunctionCollector/encode/decode`, `options.IndexOptions` |
| `aire.knowledge` | Records, persistence, queries, evidence, relevance | `models.*`, `database.BinaryKnowledgeStore`, `retrieval.ProgramQueryService`, `evidence.EvidenceRequest/EvidenceBundle`, `investigation.InvestigationService`, `application_relevance.ApplicationRelevanceService`, `reference_views` |
| `aire.analysis` | Cache orchestration and deterministic analyses | `cache.analyze_binary/compatible_metadata`, `versions.analyzer_versions`, `instruction_semantics`, `flow_analysis`, `decompiler_crossval`, `function_crosscheck`, `assembly_semantics`, `decompiler_semantics`, `assembly_intelligence.AssemblyIntelligence`, `file_structure.assess`, `progress` |
| `aire.ai` | Evidence context, prompts, Ollama, chat, naming | `context_builder.ContextBuilder`, `evidence_selector.OverviewContextBuilder`, `prompt_builder.build_prompt/parse_response`, `ollama_client.OllamaClient`, `chat.AireChatService`, `naming.NamingService` |
| `aire.agent` | Tools, routing, runner, sessions, CLI | `tools.ToolRegistry/AgentTools`, `runner.AgentRunner`, `fact_answers.classify/FactAnswerer`, `assembly_answers.route`, `session.AgentSession`, `events.EventStream`, `binary_scope.resolve_binary`, `cli.main` |
| `aire.security` | Deterministic rules and crypto evidence | `rule_engine.RuleEngine/_ReadOnlyRuleStore`, `rules.api_calls.UnboundedCopyRule/DangerousApiRule`, `contracts`, `facts`, `findings`, `crypto_evidence` |
| `aire.validation` | PE structure validation | `pe_structure.validate_pe` |
| `aire.api` | HTTP server, GUI, intake, worker | `server.GuiApplication/AireRequestHandler/serve`, `binary_library.BinaryLibrary/inspect_binary`, `index_worker`, `workspace.BinaryWorkspace`, `chat_presentation.present`, `static/*` |
| `aire.evaluation` | Independent objdump ground truth | `objdump_truth` |
| `aire.profiling` | Stage timing and counters | `profiled`, `stage`, `AnalysisProfile` |

## 3. Architecture (verified)

The current platform is a **whole-binary, read-only reverse-engineering
service with a browser GUI**:

```text
ELF/PE ─► upload + header/PE validation ─► serialized index worker (subprocess)
        ─► PyGhidra disposable project: auto-analysis, functions, decompiler pool,
           assembly + P-code IR, strings/imports/exports, direct CALL edges,
           references, thunks ─► one atomic SQLite save (schema v2 + function_ir)
GUI/CLI ─► read-only SQLite ─► 27 validated tools ─► routing:
           (1) deterministic facts  (2) M10 assembly intelligence
           (3) agent: prepared/model-selected tools → evidence bundle →
               [exact graph answer | Ollama + strict citation validation]
        ─► Markdown answer + provenance + "verified" or "AI interpretation" badge
```

The Java extension (`ghidra-plugin/`) is a **separate** per-function Ghidra
UI. It shares no code or execution path with the Python platform. It is the
only component that can rename, and only on the analyst's Apply.

## 4. Important implementation details discovered

- **Edge direction.** The caller is the function containing the CALL
  instruction. Only resolved, non-computed CALL references to known function
  entries become edges. Computed calls produce warnings (`graph_builder.py`).
- **Identity.**
  - `binary_id` = lowercase SHA-256;
  - `function_id` = `"<sha>:<address>"`;
  - artifact and reference IDs are SHA-256 hashes of their JSON identity
    tuple.
- **Integrity.** The input SHA-256 is checked before and after indexing and
  each analysis request. The Ghidra project is a `TemporaryDirectory`, and
  the program is released without saving.
- **Cache identity** requires exact analyzer versions (Ghidra/PyGhidra
  read from install properties without starting the JVM), options, IR
  version 1 and reference-facts version 2.
- **The GUI reads only through `_ReadOnlyRuleStore`** (`mode=ro`,
  `query_only`). Workspaces are invalidated by a database/WAL stamp.
- **Agent budgets:** 6 iterations, 8 tool calls, 180 s, 12,000-character
  planning payload, 8,000-character evidence. One slot is reserved for
  `retrieve_evidence`.
- **Model contract.**
  - No default model is configured.
  - Temperature is 0.1.
  - The JSON schema enumerates the allowed evidence IDs.
  - One retry is allowed.
  - Fixed caveats are appended by code.
  - Confidence is a 3-level label, **not calibrated**.
- **M10 narration** exists but is **off by default** (`AIRE_M10_NARRATION`).
- **`is_library` is never populated**, so it is always NULL.
- **`analysis_metadata.schema_version = 1`** is the ProgramIndex metadata
  format, not the DB schema (BR-14).

## 5. Documentation discrepancies found and corrected

| Document | Problem | Correction |
|---|---|---|
| `README.md` | "M8 adds 18 read-only tools" | 27 tools with breakdown. Fresh test results added, plus a link to the documentation index |
| `docs/M8_AGENT.md` | "The current catalog contains 18 tools" | Dated note: 18 at M8 + October tools; 27 now; lists the 9 additional tools |
| `docs/GUI.md`, `aire-server/README.md` | Examples launch with `analysis.sqlite`, which has no M10 facts | Note recommending the M10 / defense stores (BR-05) |
| `docs/ROADMAP.md` | "First address persisted thunk binding" (already persisted since schema v2, but unused by M7 rules) | Clarified (BR-12). Status note dated 2026-11-19 |
| `docs/CURRENT_STATE.md`, `docs/VERIFICATION.md`, `docs/DEVELOPMENT.md` | Latest results quoted were Nov 17 and attributed ("not a fresh run") | Dated 2026-11-19 status with fresh counts, keeping the historical text |
| `docs/AUDIT.md` | Archive/migration audit easily mistaken for the current audit | Header note pointing here |
| `docs/ARCHITECTURE.md` | No pointer to the detailed flow and API reference | Cross-references added |
| `aire-server/src/aire/validation/README.md` | "Reserved for M10. No … validation API is implemented" (the package now contains `pe_structure.validate_pe`, and M10 did not add dynamic validation) | Rewritten: static PE validation implemented; dynamic validation not implemented |
| `tests/README.md` | "No integration suite existed… The opt-in real Ghidra integration test…" (singular) | Dated note: 13 Ghidra-gated integration modules now exist |

**Checked and not found:** the historical "M8 implemented" versus "M8 not
started" contradiction no longer exists (BR-24).

## 6. Historical investigation leads

| # | Lead | Current evidence | Status |
|---|---|---|---|
| 1 | Uncommitted changes / regressions | Small pre-existing diffs (3 live-test opt-ins, 1 doc pointer) plus untracked defense docs. All committed source passes both suites | Present, low risk. Preserved (BR-11) |
| 2 | VM freezes during tests | Both suites completed (37 s; 11 min) with no new crash reports. Old crash reports from Nov 10–17 remain. Chat stress and thread comparisons were not re-run, per the user's restriction | Not reproduced. Environment risk remains (BR-19) |
| 3 | Host/VM split, port 8770 | CLI flags and guest-side gates verified. The Windows side cannot be checked from the guest. No server is currently on 8770 | Partially verified (BR-03) |
| 4 | `::ffff:127.0.0.1` handling | Rejected by default. Three regression tests pass | **Resolved** (BR-21) |
| 5 | `failwithmessage` direction | Tool output matches SQL. Exact graph answers bypass prose | **Not reproducible** (BR-22) |
| 6 | Timeout units, cancellation, graph materialization | Python timeout is correct (seconds). Java passes 3000 as seconds. Cancellation is incomplete. Full-snapshot loads occur outside the GUI | Mixed: BR-23 resolved; BR-09, BR-07, BR-15 open |
| 7 | Java GUI stale state on program switch | No program-activation handling; rows keep old `Function` objects | **Confirmed by source** (BR-10) |
| 8 | Documentation contradictions | 18-vs-27 tools; legacy store in examples; thunk wording | Corrected (§5) |
| 9 | AI performance and reliability | FRESH: deterministic paths 4–74 ms with no model. Live model not run. Historical measurements are labeled in `docs/GUI_CHAT_PERFORMANCE.md` and `docs/chatperf/` | Deterministic VERIFIED; model UNVERIFIED (BR-02) |
| 10 | Advanced analysis status | P-code IR and semantics: implemented. Instruction-cited explanations: implemented (deterministic), model narration opt-in. Assembly/decompiler cross-check: implemented (two layers). Function reports: interactive summaries only, no export. Richer source/sink rules: absent. Dynamic validation: absent. CVE matching: absent | See [FEATURE_TRACEABILITY.md](FEATURE_TRACEABILITY.md) |
| 11 | "645 / 0 / 4" Nov 17 claim | Today: Ghidra suite 649 / 644 / 5 skips. The difference is the browser test, opt-in and not run today | Historical result kept separately, fresh result recorded |

## 7. Verified capabilities (summary)

These were verified on 2026-11-19 by passing tests and/or fresh probes:

- intake validation;
- the cached analysis path;
- real PyGhidra indexing of the small fixtures (Ghidra suite);
- SQLite persistence;
- exact graph queries and direction;
- reference, string and thunk facts;
- application relevance;
- evidence bundles;
- M10 explanations, CFG/loops, branch paths, value tracing, parameter and
  return use, decompiler cross-validation;
- CWE-120/CWE-242 signals and the negative control;
- crypto-role attribution;
- the 27-tool validated registry;
- deterministic chat routing;
- HTTP token, Host and Origin gates;
- NDJSON streaming;
- session file permissions;
- clean shutdown.

## 8. Technical risks

The highest risks are BR-01 (in-VM inference default), BR-02 (live model
unverified), BR-03 (Windows side unverified), BR-06 (unbounded binary-wide
scan) and BR-07 (cancellation). See
[BUG_AND_RISK_REGISTER.md](BUG_AND_RISK_REGISTER.md).

## 9. Inspection limitations

- **Not executed:** the Java extension (Gradle absent), live model tests,
  the browser XSS test and Windows checks.
- **Not re-run:** benchmarks and the objdump evaluation. Their historical
  numbers are labeled as such.
- **Read in full:** the core source (`pyghidra`, `knowledge`, `agent`,
  `api/server.py`, `api/binary_library.py`, `security`, `ai/chat.py`,
  `ai/ollama_client.py`).
- **Skimmed** through signatures, docstrings and key branches:
  `instruction_semantics.py`, `flow_analysis.py`, `decompiler_crossval.py`,
  `prompt_builder.py`, `naming.py` and most of `app.js`.
- **Generated artifacts:** large JSON evidence and recovery archives were
  inventoried, not read.

## 10. Open questions for the author

1. Should guest `ollama serve` keep running during the defense (BR-01)?
2. Should the pre-existing defense docs and live-test edits be committed
   before Nov 20 (BR-11)?
3. Is the Windows NAT/Chrome checklist complete? It cannot be verified from
   the guest.
4. Will the demo include any model-backed answer? If so, run one test
   generation against Windows Ollama beforehand.

## 11. Defense readiness

**READY.** These are backed by implementation, passing tests and fresh
probes, with no model dependence:

- browsing binaries and metadata in the pre-indexed store;
- deterministic answers: file identity/corruption, callers/callees,
  evidence view, crypto roles (crypto store);
- Function explorer and M10 questions: instruction explanations, CFG/loops,
  branch outcome, value origin, return use, decompiler cross-validation;
- stripped-binary relationships (`FUN_004011bc` ↔ `validate_input`);
- CWE-120/CWE-242 SIGNALs with the negative control, plus limitations;
- the safety story: read-only store, no execution, token/Host/Origin gates
  (each demonstrable with `curl`);
- the terminal fallback (runbook §6).

**CONDITIONAL.** These depend on environment or unverified integration:

- split-host Windows Chrome over NAT (Windows checks pending);
- any model-backed answer ("What does this binary do?", agent-planned
  tools, naming), which depends on Windows Ollama availability and
  unmeasured quality and latency;
- live indexing of a new binary: tested by the integration suite, but slow
  and freeze-prone on this VM. Prefer the cache-hit demonstration;
- browser rendering details (last real-browser run was Nov 17).

**NOT READY / do not claim:**

- vulnerability confirmation, exploitability, CVE matching, dynamic
  validation or execution, taint/source-sink analysis;
- calibrated confidence;
- autonomous analysis;
- automatic renaming in the Python platform;
- full decompiler equivalence;
- indirect-call resolution;
- completed M10 Phase 6/M11 evaluation;
- Java extension behavior beyond source description (unbuilt; BR-09/BR-10).

**Assessment.** The verified functionality forms a coherent, defensible
graduate project. It is a deterministic, provenance-first static analysis
platform with an honest, bounded use of a local model. The strongest
demonstration keeps the model optional and shows *why* the answers can be
trusted: exact stored facts, cited addresses, three-valued verdicts,
explicit limitations and a read-only boundary.

## 12. Most distinctive contributions (code-supported)

1. Deterministic-first routing, so graph and crypto-role answers never pass
   through model prose.
2. Citation-enumerated JSON schemas plus post-generation claim validators.
3. P-code-derived instruction semantics with evidence-source labeling.
4. Decompiler-versus-assembly cross-validation with an explicit
   INSUFFICIENT EVIDENCE outcome.
5. Provenance-validated, versioned CWE signals with negative controls.
6. A hardened local web boundary over a read-only SQLite fact base.

Details are in [DEFENSE_TECHNICAL_BRIEF.md](DEFENSE_TECHNICAL_BRIEF.md).
