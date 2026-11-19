# A.I.R.E. defense feature matrix

Prepared 2026-11-17 from the code on branch `m10-host-access-hardening`
(HEAD `ebacf4d`, uncommitted test/doc changes listed in the evidence packet §0).
Every row was checked against source, not just documentation.

## Status vocabulary

| Status | Meaning used in this matrix |
|---|---|
| **VERIFIED** | Implemented, covered by passing automated tests, **and** re-exercised in this session (2026-11-17) or in a dated, recorded real run |
| **PARTIAL** | Implemented; some real validation exists but an important part (live model, Windows path, full evaluation) is unvalidated or failed |
| **NOT DEMONSTRATED** | Implemented in code with unit tests, but no successful real/live run is recorded |
| **PLANNED / NOT IMPLEMENTED** | Not in the code |

"Fresh" = reproduced in this session on 2026-11-17 (outputs in
`docs/defense_assets/fresh_outputs_20261117/`). "Historical" = recorded
earlier; date and source given. Fresh runs used Python 3.12.3, Ghidra 12.1.3,
PyGhidra 3.1.0, OpenJDK 21.0.13 on Ubuntu 24.04.5 (VirtualBox guest).

Demo readiness: **LIVE** = safe for live defense; **LIVE+FALLBACK** = show live
but have a saved output ready; **BACKUP ONLY** = show saved genuine output;
**DO NOT DEMO** = avoid.

## 1. Python backend (`aire-server/`) — analysis and knowledge

| # | Feature | What it does | Entry point (file:line) | Tests | Evidence | Status | Demo |
|---|---|---|---|---|---|---|---|
| 1 | Whole-binary indexing (M1) | Imports a binary into a disposable headless Ghidra project, auto-analyzes, extracts all facts into a `ProgramIndex` | `aire/pyghidra/indexer.py:115-252`; CLI `python -m aire.pyghidra.indexer` (`:255-288`) | `test_indexer.py` (11), `test_indexer_integration.py` (Ghidra) | **Fresh:** integration test OK (17.3 s); report on `tests/binaries/aire_test_stripped`: 106 functions, 81 decompiled, 132 strings, 25 imports, 8 exports, 134 call edges, 26 warnings — identical to the historical M1 run (`docs/CURRENT_STATE.md:159-162`). **Fresh:** indexer CLI on `simple_elf/aire_test_binary_stripped` ×3: 34 functions / 29 decompiled / 29 edges, 8.48–8.60 s | VERIFIED | LIVE+FALLBACK (~9 s) |
| 2 | Input integrity (SHA-256 before/after) | Hashes target before import and after release; mismatch raises `IndexingError` | `indexer.py:124-133`, `:242-250` | `test_indexer.py:117` `test_setup_error_checks_integrity` | **Fresh:** hashes of all 4 fixtures unchanged after indexing (`fresh_outputs…/sha256_after_checks.txt`); `input_sha256_unchanged: true` stored for all 7 demo binaries | VERIFIED | LIVE |
| 3 | Decompiled C extraction | Per-function decompilation, parallel workers, one retry on timeout, incomplete list recorded | `aire/pyghidra/extractor.py` (`decompile_workers`, `extract_functions`); `indexer.py:183-193,226-228` | `test_m9_retry.py`, `test_m9_performance.py` | Fresh counts above; `decompilation_incomplete: []` for all demo binaries | VERIFIED | LIVE (GUI Decompiled View) |
| 4 | Bounded assembly | Stored per-function assembly with truncation flag | `extractor.py`; `IndexOptions.max_assembly_instructions` | `test_indexer.py` | Fresh probe `get_function`: `assembly_truncated: false` for `validate_input` | VERIFIED | LIVE |
| 5 | Instruction IR + P-code (M10) | Structured instruction facts and raw P-code per function | `aire/pyghidra/instruction_ir.py`; `indexer.py:187-191,230-235` | `test_m10_semantics.py`, `test_m10_evaluation.py` | **Historical (Nov 11):** objdump agreement 100 % on 76,420 instruction boundaries/mnemonics, 9,867 direct targets, 10,318 memory operands, 4,128 branch relations over 5 binaries (`docs/M10_CHECKPOINT.md:52-63`, `docs/m10/eval_phase1.json`). **Fresh:** demo store holds 395 IR instructions for each simple ELF build | VERIFIED (decoding scope only) | LIVE (Assembly tab) |
| 6 | Function identification | Internal + external functions from Ghidra's FunctionManager | `indexer.py:177-181` | integration tests | **Fresh:** all 12 ground-truth application functions present at the `nm` addresses in both debug and stripped builds; stripped build shows `FUN_<addr>` names | VERIFIED | LIVE |
| 7 | Strings / imports / exports | Defined strings, import and export artifacts | `extractor.extract_artifacts`; `indexer.py:195-197` | `test_indexer.py`, integration | Fresh counts (rows 1, 23) | VERIFIED | LIVE |
| 8 | Direct call graph | Resolved CALL edges with exact callsite; computed calls warned and omitted | `aire/pyghidra/graph_builder.py:8-28` | `test_retrieval*.py` | **Fresh:** debug fixture stores 29 edges; the application-only subset is **14 distinct edges / 15 callsites**, exactly matching `tests/fixtures/simple_elf/GROUND_TRUTH.md:3-5` | VERIFIED | LIVE (Call Graph lists) |
| 9 | Call-graph visualization | — | — | — | GUI "Call Graph" view is caller/callee **lists**; interactive node graph is unimplemented (`docs/CURRENT_STATE.md:407`) | PLANNED | Use Mermaid/slide figure instead |
| 10 | References, thunks (M9, schema v2) | Exact string/data refs with source instruction, bounded thunk chains | `aire/pyghidra/references.py`; tools `get_xrefs`, `get_function_strings`, `get_thunk_target` (`agent/tools.py:134-140`) | `test_references.py`, `test_references_integration.py` | Fresh: 342 refs / 9 thunks stored for debug ELF; `get_function_strings` OK in probe | VERIFIED | LIVE |
| 11 | Format-aware ELF/PE intake, corrupt-PE handling (M9) | PE structure validation, partial-analysis policy | `aire/validation/pe_structure.py`, `aire/analysis/file_structure.py` | `test_m9_pe_validation.py`, `test_binary_formats_integration.py` | Historical: `docs/M9_CORRUPT_PE.md`, `docs/BINARY_FORMAT_SUPPORT.md`; professor PE32 stored (385 functions) | VERIFIED (historical) | BACKUP ONLY for corrupt PE; PE32 switch is LIVE |
| 12 | Crypto API evidence (M9) | Functions calling CNG/CryptoAPI/OpenSSL with callsites and algorithm strings | `aire/security/crypto_evidence.py`; tool `crypto_evidence` | `test_m9_crypto_evidence.py` | Historical `docs/M9_CRYPTO_PE.md`; crypto PEs are in `m10.sqlite`, **not** in the compact demo store | VERIFIED (historical) | BACKUP ONLY |
| 13 | Caching, pre-warm, parallel decompile (M9) | Cached snapshots, background JVM warm-up | `aire/analysis/cache.py`, `indexer.py:85-111` | `test_analysis_cache*.py`, `test_m9_prewarm.py` | Historical medians (`docs/M9_FINAL_REPORT.md:13-30`), e.g. sleigh.exe extraction 77.7 → 33.4 s | VERIFIED (historical) | Not shown |
| 14 | SQLite persistence (M2) | Atomic replace-per-binary snapshot save/reload, schema v2 with v1 migration | `aire/knowledge/database.py:202-212` (`BEGIN IMMEDIATE`/rollback), `:262-267` | `test_database.py` (25), `test_database_integration.py` | Historical M2 round-trip: all fields equal, save 0.53 s / load 0.0016 s (`docs/CURRENT_STATE.md:188-196`); fresh suite passes the 25 unit tests | VERIFIED | Not shown directly |
| 15 | Read-only store access | All analysis reads use `mode=ro` + `PRAGMA query_only=ON` | `aire/security/rule_engine.py:135-149` | `test_agent_tools.py:76`, `test_gui_server.py:133` | **Fresh:** demo DB SHA-256 `f88fa14e…d379` identical before/after probe, CLI scans and naming discovery | VERIFIED | LIVE (state it) |
| 16 | Relationship queries (M3) | callers, callees, callsites, bounded BFS, shortest path, rankings | `aire/knowledge/retrieval.py`; tools `get_callers`/`get_callees`/`find_call_path`/`rank_functions` | `test_retrieval.py`, `test_retrieval_integration.py` | **Fresh probe:** 0.2–0.8 ms per tool call; `main → … → calculate_checksum` path found (depth ≤ 4) | VERIFIED | LIVE |
| 17 | Evidence retrieval (M4) | Bounded EvidenceBundle with provenance and explicit truncations | `aire/ai/context_builder.py`, `aire/knowledge/evidence.py`; tool `retrieve_evidence` | `test_context_builder.py`, `…_integration.py` | Historical M4 measurements (`docs/CURRENT_STATE.md:264-276`) | VERIFIED | LIVE (evidence panel) |

## 2. AI-assisted features

| # | Feature | What it does | Entry point | Tests | Evidence | Status | Demo |
|---|---|---|---|---|---|---|---|
| 18 | Ollama client | Loopback-default; remote host needs explicit opt-in; proxies and redirects disabled; explicit `num_ctx` | `aire/ai/ollama_client.py:59-115,169` | `test_ollama_client.py` | Fresh: Windows endpoint `10.0.2.2:11434` reachable, Ollama 0.40.16, models `qwen2.5-coder:1.5b` (Q4_K_M), `llama3.2:latest`. **Metadata only — no generation sent this session** | VERIFIED (client contract) | — |
| 19 | Grounded chat (M5) | Bounded evidence → model → strict JSON; citation IDs must exist; interpretation kept separate; fixed caveats appended | `aire/ai/chat.py:154-324`; `aire/ai/prompt_builder.py:295-335` | `test_chat.py:125` `test_nonexistent_citation`, `test_chat_structure.py`, `test_chat_integration.py` (live opt-in) | Historical (Oct): 2 targeted live requests accepted with qwen2.5-coder:1.5b @ 4096; binary-summary timed out; one earlier stripped answer had valid citations but **wrong interpretation** (`docs/CURRENT_STATE.md:314-336`). Latest audits: 4 live tests **skipped** | PARTIAL | DO NOT DEMO live unless rehearsed; BACKUP ONLY |
| 20 | Naming candidate discovery (M6) | Deterministic selection of generic-named, high-connectivity functions; skips runtime/library/thunks | `aire/ai/naming.py:69-93`; CLI `python -m aire.ai.naming … --candidates` | `test_naming.py:79` | **Fresh:** 8 candidates on stripped ELF, all 8 are ground-truth application functions (`fresh_outputs…/naming_candidates_stripped.txt`) | VERIFIED | LIVE (terminal, no model) |
| 21 | AI naming suggestions (M6) | Model proposes names; parser rejects non-snake_case, generic, address-bearing names, and invalid citations; no write-back | `aire/ai/naming.py:94-169`; `aire/ai/naming_prompt.py:61-95` | `test_naming.py:151,160,167`, `test_naming_integration.py` (live opt-in) | Historical live run: 1.5B output **rejected** (address-bearing names, invented citation IDs); **no live suggestion has ever been accepted** (`docs/CURRENT_STATE.md:356-367`) | NOT DEMONSTRATED (success path); rejection path VERIFIED historically | DO NOT DEMO live; describe rejection as a safety result |
| 22 | Conversational agent (M8) | Bounded loop; model picks one registered tool per step; deterministic preflight/routing; final evidence slot reserved | `aire/agent/runner.py:261-510`; `aire chat <binary>` via `aire/agent/cli.py:26-125` | `test_agent_runner.py` (24) incl. `:197` malformed actions, `:223` cancellation/deadline; `test_agent_integration.py` | Historical final 5-question live run: 1 rejected (`unsupported_grounding`), 1 deterministic success, 3 **timeouts** (`docs/M8_AGENT.md:270-283`) | PARTIAL | Deterministic GUI questions LIVE; model-planned questions DO NOT DEMO |
| 23 | Tool registry | 27 registered read-only tools; type/bound/enum validation; unknown tool rejected; 100 kB result cap | `aire/agent/tools.py:37-100,124-188` | `test_agent_tools.py` | **Fresh:** 27 tools listed; `run_shell` → `unknown_tool`; `limit: 5000` → `invalid_arguments`; unknown function → `FunctionNotFoundError` | VERIFIED | LIVE (terminal probe) or describe |
| 24 | Deterministic GUI answers | Fact / M10 questions answered from stored facts without a model | `aire/agent/fact_answers.py:150,665`; `aire/agent/assembly_answers.py:33-41,91-255`; `aire/api/server.py:511-526,575-623` | `test_chat_fact_answers.py`, `test_m10_agent.py` | **Fresh:** probe answers for `validate_input` (function 34 ms / 20 citations; branch; trace; return usage; cross-validation). Nov 17 guest-Firefox walkthrough: 37/37 actions passed on 2 launches (`docs/DEMO_READINESS_REPORT.md:31-67`) | VERIFIED | LIVE |
| 25 | M10 narration | Optional model summary appended after deterministic answer; rejected if it cites an address not in evidence or misnames an instruction | `aire/api/server.py:626-640`; `assembly_answers.py:257-272` | `test_m10_agent.py` | Off by default (`AIRE_M10_NARRATION` ≠ 1); no validated live run | NOT DEMONSTRATED | DO NOT DEMO |

## 3. Assembly intelligence (M10)

| # | Feature | Entry point | Tests | Evidence | Status | Demo |
|---|---|---|---|---|---|---|
| 26 | Instruction explanations | `aire/analysis/instruction_semantics.py`; tool `explain_instructions` | `test_m10_semantics.py` | Fresh: `004011dc CMP` / `004011e1 JZ` explanations match `objdump` (`cmp QWORD PTR [rbp-0x10],0x0` / `je 4011ea`) | VERIFIED | LIVE |
| 27 | CFG / loops | `aire/analysis/flow_analysis.py`; tool `function_cfg` | `test_m10_flow.py` | Fresh: 1 loop headed at `00401238` in `validate_input` (source has one validation loop) | VERIFIED (fixture) | LIVE |
| 28 | Branch paths | tool `branch_paths` | `test_m10_flow.py` | Fresh: `004011e1` true → error string + `puts`; false → `CMP …,0x1f` | VERIFIED (fixture) | LIVE |
| 29 | Value trace | tool `trace_value` | `test_m10_flow.py` | Fresh: `[RBP-0x10]` @ `004011dc` ← `MOV` @ `004011d8` ← `CALL strlen` @ `004011d3` (same on stripped). **Pitfall:** unbracketed `RBP-0x10` traced to "function entry" | VERIFIED (fixture); input-syntax risk | LIVE with exact syntax |
| 30 | Return-value usage | tool `return_usage` | `test_m10_flow.py` | Fresh: `process_input` tests EAX at `0040131b` after call at `00401316` | VERIFIED (fixture) | LIVE |
| 31 | Decompiler cross-validation | `aire/analysis/decompiler_crossval.py`; tool `crossvalidate_function` | `test_m10_crossval.py:59` | Fresh: `validate_input` **CONSISTENT** (debug and stripped). Historical: `aes_gcm.exe FUN_004075e0` **POTENTIAL DISCREPANCY** (`docs/DEMO_M10.md`) | VERIFIED (fixture); M10 Phase 6 evaluation **incomplete** | LIVE (CONSISTENT); discrepancy BACKUP ONLY |

## 4. Security analysis

| # | Feature | Entry point | Tests | Evidence | Status | Demo |
|---|---|---|---|---|---|---|
| 32 | CWE-120 strcpy signal | `aire/security/rules/api_calls.py:90-96` | `test_security_rules.py` (19), `test_security_integration.py` | **Fresh:** integration OK (3 tests, 13.6 s; controls rebuilt with identical hashes). CLI: `unsafe_copy` → SIGNAL, LOW, `copy_input` → `strcpy` @ `00401183` | VERIFIED | LIVE |
| 33 | CWE-242 gets signal | `api_calls.py:99-105` | same | **Fresh:** `dangerous_gets` → SIGNAL, LOW, @ `00401178` | VERIFIED | LIVE |
| 34 | Negative / insufficient states | `api_calls.py:29-31,45-46,85-87` | `test_security_rules.py:84,128,139` | **Fresh:** `safe_copy` and simple ELF → NOT_APPLICABLE for both rules, with "not a safety assessment" limit | VERIFIED | LIVE |
| 35 | Vulnerability confirmation, CVE matching, taint, exploitability | — | — | Absent by design; `CONFIRMED` state does not exist (`docs/CURRENT_STATE.md:379-380`) | NOT IMPLEMENTED | State explicitly |

## 5. Interfaces, sessions, safety boundaries

| # | Feature | Entry point | Tests | Evidence | Status | Demo |
|---|---|---|---|---|---|---|
| 36 | Browser GUI / API | `aire gui` → `aire/api/server.py`; static UI `aire/api/static/` | `test_gui_server.py` (7), `test_gui_workspace.py`, `test_binary_library.py` | Nov 17: guest Firefox walkthrough passed twice. **Windows Chrome path not yet rehearsed.** A GUI instance is running now on `127.0.0.1:8770` (pid 9388, demo store) | PARTIAL (Windows path) | LIVE after rehearsal; else BACKUP |
| 37 | Host-access security | `server.py:55-59,798-841,1077` | `test_host_access_security.py` (24) | **Fresh probe of running server:** no token → 401; foreign Host → 403; POST without Origin → 403; CSP/nosniff/no-referrer headers present. Historical Codex audit 649/645/4 skipped | VERIFIED (guest); Windows listeners/NAT/Adapter 2 PENDING | LIVE (second browser profile → 401) |
| 38 | Sessions | `aire/agent/session.py`; GUI session dir | `test_agent_session.py`, `test_gui_workspace.py` | Nov 17 walkthrough: reload + Recent Chats restore passed | VERIFIED | LIVE |
| 39 | CLI agent `aire chat <binary>` | `aire/agent/cli.py:28-40,90-120` | `test_agent_cli.py` | Requires a model for planning on most questions | PARTIAL | DO NOT DEMO |
| 40 | Upload / index job from GUI | `aire/api/binary_library.py:341-346`, `aire/api/index_worker.py` | `test_binary_library.py`, `test_m9_integration.py` | Historical M9 first-upload ≈ 24.7–30.4 s (`docs/M9_FINAL_REPORT.md`) | VERIFIED (historical) | Avoid live (use pre-indexed store) |
| 41 | Analyst approval | Python: advisory only, no rename/comment/patch path. Java: explicit Apply per function | Python: absence of write paths (`agent/tools.py:111`); Java `AireSuggestionsProvider.java:432-445` | `test_gui_server.py:133` `…reject_mutations` | VERIFIED (Python) | State it |
| 42 | No target execution | Ghidra static analysis only; index worker never launches the target | `indexer.py:117-119`; `index_worker.py:1-5` | `test_security_integration.py` report: `target_executed: false`, process creation blocked during scan | VERIFIED | State it |

## 6. Java v1 Ghidra extension (`ghidra-plugin/`) — separate workflow

| # | Feature | Entry point | Tests | Evidence | Status | Demo |
|---|---|---|---|---|---|---|
| 43 | Dockable suggestions panel (≤250 functions) | `AirePlugin.java`, `AireSuggestionsProvider.java` (873 lines) | **None** (no Java test tree) | Source restored byte-for-byte (`docs/VERIFICATION.md:357`); archive contained 14 historical extension zips | NOT DEMONSTRATED in current environment | DO NOT DEMO unless rebuilt |
| 44 | Per-function evidence extraction + Ollama naming | `services/ContextExtractor.java` (538), `services/OllamaSuggestionProvider.java` (839); default `http://localhost:11434`, `gemma3:4b` (`AirePlugin.java:21-22`) | None | `gemma3:4b` is **not installed** on either Ollama instance (guest: qwen2.5-coder:1.5b; Windows: qwen2.5-coder:1.5b, llama3.2) | NOT DEMONSTRATED | DO NOT DEMO |
| 45 | Analyst-applied rename | `AireSuggestionsProvider.java:432-445` (`setName(…, USER_DEFINED)` inside a transaction; rollback on failure) | None | Source inspection only | NOT DEMONSTRATED | Describe |
| 46 | Build | `ghidra-plugin/scripts/build_extension.sh`, `build.gradle` | — | Archived target Ghidra 12.0.1 + JDK 21. Current env: Ghidra 12.1.3 needs Gradle ≥ 8.5 (`application.gradle.min=8.5`); **Gradle not installed**; no extension installed in user Ghidra config | NOT VERIFIED here | — |

## 7. Not implemented (state plainly on the limitations slide)

Semantic/vector retrieval and embeddings · vulnerability confirmation · CVE
matching · taint / source-sink / argument-size analysis · dynamic execution or
sandboxing · exploit generation · autonomous actions · Python-side rename,
comments or signature write-back · interactive call-graph visualization ·
unified Java-plugin ↔ Python-backend interface · M11 benchmark/evaluation and
M12 reporting milestones · completed M10 Phase 6 evaluation
(`docs/m10/eval_full.json` and `docs/M10_EVALUATION.md` absent).
