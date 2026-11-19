# Feature traceability matrix

Audit date **2026-11-19**. Paths are relative to `aire-server/src/aire/`.
Tests live in `aire-server/tests/`.

## Status definitions

| Status | Meaning |
|---|---|
| **VERIFIED** | Supporting tests passed in the 2026-11-19 runs (default and/or Ghidra suite), or a fresh audit probe exercised the feature |
| **PARTIAL** | Implemented, but a material part is unverified or limited |
| **IMPLEMENTED-UNTESTED** | Code exists, but nothing exercised it in this audit |
| **PLANNED** | Described in the roadmap only |
| **ABSENT** | Not in the code |

Run labels:

- **A** — default suite: 617 passed / 32 skipped;
- **B** — Ghidra suite: 644 passed / 5 skipped;
- **P** — read-only probe;
- **H** — live HTTP smoke test.

Details are in [TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md).
A feature is never marked VERIFIED on the basis of roadmap text or
historical reports alone.

## 1. Intake and static analysis

| Feature | Status | Entry point | Source | Dependencies | Data flow | Tests | Verification | Limitations | User impact |
|---|---|---|---|---|---|---|---|---|---|
| Binary upload (bounded, octet-stream) | VERIFIED | GUI Library → `POST /api/uploads` | `api/server.py:do_POST`, `api/binary_library.py:BinaryLibrary.upload` | stdlib | bytes → temp file → `inspect_binary` → `<sha>/<name>` 0600 | `test_binary_library.py`, `test_host_access_security.py::test_body_size_limit` | A, B pass | 32 MiB max; no chunked uploads; 128 remembered uploads | Upload ELF/PE safely without execution |
| ELF header validation | VERIFIED | upload / fixture start | `api/binary_library.py:inspect_binary` | — | header fields → accept/reject | `test_binary_library.py`, `test_binary_formats_integration.py` | A, B | Accepts ET_EXEC/ET_DYN only; no section-content checks | Malformed ELF rejected with a reason |
| PE structure validation (full/partial/none) | VERIFIED | upload / fixture | `validation/pe_structure.py:validate_pe` | — | bytes → `PeReport(issues, analysis level)` | `test_m9_pe_validation.py` (15), `test_m9_integration.py::test_partial_corrupt_pes_index_without_crashing` | A, B | Heuristic structural checks, not a full loader | Damaged PEs analyzed partially and labeled |
| Repository fixture library | VERIFIED | `GET /api/library` | `BinaryLibrary._load_fixtures`, `list` | manifests in `tests/fixtures/{external,m9}` | manifest + SHA check → rows | `test_binary_library.py`, `test_external_fixtures.py` | A, H (36 fixtures) | Unavailable or mismatched fixtures are disabled, not hidden | One-click analysis of known samples |
| Serialized analysis worker, watchdog, prewarm | VERIFIED | `POST /api/analysis` | `BinaryLibrary.start/_run_analysis/prewarm`, `api/index_worker.py` | subprocess | job queue (≤8) → worker stdin/stdout JSON | `test_binary_library.py`, `test_m9_prewarm.py` | A; P (cached job 0.21 s) | No user cancel; 3600 s watchdog (BR-07) | Long analyses don't freeze the GUI |
| SHA/option-aware analysis cache | VERIFIED | worker / `analyze_binary` | `analysis/cache.py:analyze_binary`, `compatible_metadata` | — | metadata-only check → hit or index+save | `test_analysis_cache.py` (20), `test_analysis_cache_integration.py` | A, B, P | Any version or option change triggers a full re-index | Re-opening a known binary is instant |
| Whole-binary PyGhidra indexing | VERIFIED | worker; `python -m aire.pyghidra.indexer` | `pyghidra/indexer.py:index_binary` | PyGhidra 3.1.0, Ghidra 12.1.3, JDK 21 | file → disposable project → ProgramIndex | `test_indexer.py`, `test_indexer_integration.py`, `test_binary_formats_integration.py`, `test_m9_integration.py` | B | Serialized per process; static only | Complete fact base per binary |
| Parallel decompilation + timeout retry | VERIFIED | indexing | `pyghidra/extractor.py:_DecompilerPool`, `extract_functions` | Ghidra decompiler | pool (≤4) → outcomes → 1 serial retry | `test_m9_performance.py`, `test_m9_retry.py` | A, B | Unrecovered functions are listed in `decompilation_incomplete` | Fewer silently missing decompilations |
| Direct CALL graph extraction | VERIFIED | indexing | `pyghidra/graph_builder.py:build_call_edges` | Ghidra references | CALL refs → `FunctionEdge` | `test_indexer_integration.py`, `test_retrieval_integration.py` | B; P (direction) | Computed/indirect calls omitted (warnings) | Trustworthy caller/callee facts |
| References, string xrefs, thunk bindings | VERIFIED | indexing | `pyghidra/references.py:extract_references` | Ghidra ReferenceManager | refs → `ReferenceRecord`, `ThunkRecord` | `test_references.py`, `test_references_integration.py` | A, B | Computed targets stay unresolved | "Which instruction uses this string?" |
| M10 instruction IR (operands, flow, raw P-code, blocks) | VERIFIED | indexing | `pyghidra/instruction_ir.py:FunctionCollector` | Ghidra P-code | instructions → compressed JSON blob | `test_m10_semantics.py`, `test_m10_security.py`, B integrations | A, B | ≤4096 instructions per function; x86-specific naming | Enables instruction-level reasoning |

## 2. Knowledge store and retrieval

| Feature | Status | Entry point | Source | Tests | Verification | Limitations |
|---|---|---|---|---|---|---|
| SQLite schema v2, atomic save, v1 upgrade, typed errors | VERIFIED | internal | `knowledge/database.py:BinaryKnowledgeStore` | `test_database.py` (25), `test_database_integration.py` | A, B | One writer; whole-binary replacement only |
| Read-only store for GUI/CLI | VERIFIED | GUI, `aire chat`, rule CLI | `security/rule_engine.py:_ReadOnlyRuleStore` | `test_gui_server.py`, `test_agent_tools.py::test_security_artifacts_and_read_only` | A; H (hash unchanged) | — |
| Exact selector resolution (ID/address/name; ambiguity error) | VERIFIED | all tools | `knowledge/retrieval.py:ProgramQueryService._resolve` | `test_retrieval.py::test_ambiguous_name`, `…test_selector_kind_collision_is_ambiguous` | A; P | Names must match exactly |
| Callers / callees / callsites | VERIFIED | tools, GUI Call Graph, chat | `get_callers`, `get_callees`, `get_callsites` | `test_retrieval.py::test_direct_callers`, `…test_direct_callees_numeric_order` | A, B, P, H | Stored resolved CALLs only |
| Reachability, shortest path (bounded BFS) | VERIFIED | `find_call_path` tool | `get_reachable`, `find_call_path` | `test_retrieval.py::test_shortest_path_and_tie_break`, `…test_path_not_found_within_bound` | A | Tool depth ≤8; "not found" is not proof of unreachability |
| Connectivity ranking | VERIFIED | `rank_functions` | `rank_functions` | `test_retrieval.py::test_ranking_*` | A | Not semantic importance |
| Application relevance ranking | VERIFIED | `rank_application_functions` | `knowledge/application_relevance.py` (`application-relevance-v2`) | `test_application_relevance.py` (15) | A; P | Name/structure heuristic; not proof of authorship |
| Bounded evidence bundles with provenance/truncations (M4) | VERIFIED | `retrieve_evidence` | `ai/context_builder.py:ContextBuilder`, `ai/evidence_selector.py` | `test_context_builder.py` (29), `test_context_builder_integration.py` | A, B | Character budgets, not tokens |
| Semantic / vector retrieval, embeddings | ABSENT | — | — | — | grep | Not implemented |

## 3. Reverse-engineering analysis (M9/M10)

| Feature | Status | Entry point | Source | Tests | Verification | Limitations |
|---|---|---|---|---|---|---|
| Instruction explanations from P-code | VERIFIED | `explain_instructions`; chat "Explain the instructions…" | `analysis/instruction_semantics.py:analyze_function`, `analysis/assembly_intelligence.py:explain` | `test_m10_semantics.py` (22), `test_m10_agent.py` | A, B, P | Machine-level only; generic for non-x86 |
| Function evidence summary | VERIFIED | `function_evidence`; "What does this function do?" (M10 route) | `AssemblyIntelligence.function_evidence`, `agent/assembly_answers.py:answer_function`, `purpose_hints` | `test_m10_agent.py::test_function_answer_has_identity_evidence_confidence_limits` | A, P | Purpose hints are rule-derived and hedged |
| CFG, dominator loops, unreachable blocks | VERIFIED | `function_cfg`; explorer CFG tab | `analysis/flow_analysis.py:control_flow_graph` | `test_m10_flow.py` | A; P (11 blocks/1 loop) | Intra-procedural |
| Branch taken/not-taken paths | VERIFIED | `branch_paths`; chat "what happens when the branch at 0x… is true" | `flow_analysis.branch_paths` | `test_m10_agent.py::test_branch_trace_return_and_crossvalidate_answers` | A, P | ≤24 instructions per path |
| Value origin tracing (registers, frame slots) | VERIFIED | `trace_value`; chat "where does the value of [RBP-0x10] at 0x… come from" | `flow_analysis.trace_value` | `test_m10_flow.py`, `test_m10_agent.py` | A, P | Depth ≤6; RSP-relative slots not tracked; x86 families |
| Parameter use vs signature | VERIFIED | `parameter_use` | `flow_analysis.parameter_use` | `test_m10_flow.py` | A | SysV64/Win64 argument registers |
| Return-value usage at callers | VERIFIED | `return_usage`; "How is the return value used?" | `flow_analysis.return_usage_at_callsite` | `test_m10_agent.py` | A, P | Stored callers only |
| Decompiler ↔ assembly/P-code cross-validation | VERIFIED | `crossvalidate_function`; explorer Decompiler tab | `analysis/decompiler_crossval.py:crossvalidate` | `test_m10_crossval.py` (11) | A; P (CONSISTENT) | Not formal equivalence |
| Text-level local assembly/decompiler crosscheck | VERIFIED | `crosscheck_function` | `analysis/function_crosscheck.py`, `assembly_semantics.py`, `decompiler_semantics.py` | `test_function_crosscheck.py` (44) | A | Short straight-line windows |
| Binary-wide input-validation candidates | VERIFIED (small binaries) | "Where is input validated?" | `agent/assembly_answers.py:answer_validation` | `test_m10_agent.py::test_intents_and_arguments` | A; P (74 ms on simple ELF) | Unbounded on large binaries (BR-06) |
| Objdump ground-truth evaluator | IMPLEMENTED-UNTESTED (this run) | `scripts/evaluate_m10.py` | `evaluation/objdump_truth.py` | `test_m10_evaluation.py` (3, unit) | A (unit only); evaluation HISTORICAL | Full evaluation not re-run |
| Structural condition answers ("Is this file corrupted?") | VERIFIED | chat | `analysis/file_structure.py:assess`, `FactAnswerer._answer_file_identity` | `test_chat_structure.py` (10) | A, P | Needs the original file at its stored path; otherwise reports `unverified` |
| Assembly-vs-decompiler instruction-cited explanation by model | PARTIAL | `AIRE_M10_NARRATION=1` | `api/server.py:_assembly_answer`, `assembly_answers.validate_narration` | `test_m10_agent.py::test_narration_validation`, `…test_valid_narration_is_appended`, `…test_invalid_narration_is_rejected_and_evidence_stands` | A (fake model) | Off by default; live model unverified |
| P-code data-flow beyond bounded intra-procedural | ABSENT | — | — | — | — | Future work |
| Taint / source-sink analysis | ABSENT / PLANNED | — | — | — | — | `docs/ROADMAP.md` next work |

## 4. Security

| Feature | Status | Entry point | Source | Tests | Verification | Limitations |
|---|---|---|---|---|---|---|
| CWE-120 strcpy signal | VERIFIED | `security_findings`; GUI Findings; rule CLI | `security/rules/api_calls.py:UnboundedCopyRule` | `test_security_rules.py` (19), `test_security_integration.py` | A, B, H (`unsafe_copy` SIGNAL @ `00401183`) | SIGNAL only; no size or taint proof; thunk path LOW (BR-12) |
| CWE-242 gets signal | VERIFIED | same | `DangerousApiRule` | same | A, B, H (`dangerous_gets` SIGNAL @ `00401178`) | same |
| Negative control (bounded memcpy) | VERIFIED | same | — | `test_security_integration.py` | B, H (`safe_copy` none) | — |
| Rule engine contracts, evidence validation | VERIFIED | internal | `security/rule_engine.py:RuleEngine`, `_validate` | `test_rule_engine.py` (20) | A | Registered rules are trusted code |
| Crypto API evidence | VERIFIED | `crypto_evidence`; chat "Which functions perform encryption?" | `security/crypto_evidence.py` | `test_m9_crypto_evidence.py` (7), `test_chat_fact_answers.py` (20) | A, B, P | Static API use; not strength or reachability |
| CVE matching | ABSENT | — | — | — | grep | — |
| Vulnerability confirmation / exploitability | ABSENT | — | no CONFIRMED state in `EvaluationState` | — | source | By design |
| Dynamic / runtime validation | ABSENT | — | — | — | grep (no execution code) | Future, isolated, analyst-authorized only |

## 5. AI, chat and agent

| Feature | Status | Entry point | Source | Tests | Verification | Limitations |
|---|---|---|---|---|---|---|
| Deterministic fact routing (no model) | VERIFIED | GUI chat | `agent/fact_answers.py:classify`, `FactAnswerer` | `test_chat_fact_answers.py` (20) | A; P (13/14 questions, 0 model calls); H | Regex phrasing coverage |
| M10 assembly routing (no model) | VERIFIED | GUI chat | `agent/assembly_answers.py:route` | `test_m10_agent.py` (11) | A, P | Needs a selected or named function |
| 27-tool read-only registry with validation | VERIFIED | `/api/tool`, agent | `agent/tools.py:ToolRegistry`, `AgentTools` | `test_agent_tools.py` (9) | A, P, H | 100 KB result cap |
| Bounded agent loop (model-selected tools) | PARTIAL | `aire chat`, GUI | `agent/runner.py:AgentRunner.run`, `action_schema`, `parse_action` | `test_agent_runner.py` (24), `test_agent_integration.py::test_debug_and_stripped_deterministic` | A, B (fake/no model) | Live tool selection by a real model unverified (BR-02) |
| Grounded chat with citation validation (M5) | PARTIAL | agent synthesis; `python -m aire.ai.chat` | `ai/chat.py:AireChatService.ask`, `ai/prompt_builder.py` | `test_chat.py` (26), `test_chat_integration.py` deterministic tests | A, B | Live model quality and latency unverified; prose is interpretation |
| Overview answer cache | VERIFIED | GUI | `GuiApplication.run_chat` (`overview_answers`) | `test_gui_workspace.py` (22) | A | Key includes policy versions and model |
| Ollama transport (loopback default, opt-in remote, no proxy/redirect, streaming) | VERIFIED | internal | `ai/ollama_client.py:OllamaClient` | `test_ollama_client.py` (33) | A; P (host policy) | Socket timeout, not total deadline |
| Advisory function naming (M6) | PARTIAL | `python -m aire.ai.naming` | `ai/naming.py:NamingService` | `test_naming.py` (33), `test_naming_integration.py` (fake) | A, B | Live naming skipped; HISTORICAL: live 1.5B names were rejected; no write-back |
| Conversation sessions / follow-ups | VERIFIED | GUI, CLI `--session` | `agent/session.py`, `api/server.py:GuiSessionStore` | `test_agent_session.py`, `test_chat_fact_answers.py::test_follow_up_uses_function_selected_by_previous_answer` | A, H (0600 files) | Bounded history |
| Public activity events | VERIFIED | NDJSON `event` | `agent/events.py:EventStream` | `test_agent_events.py` | A, H | No chain-of-thought exposed |
| `aire chat` CLI | VERIFIED (fake model) | terminal | `agent/cli.py:main` | `test_agent_cli.py` | A | Loopback Ollama only (BR-17) |

## 6. GUI and HTTP

| Feature | Status | Entry point | Source | Tests | Verification | Limitations |
|---|---|---|---|---|---|---|
| Static SPA (chat, library, tools panel, recent, about) | PARTIAL | browser | `api/static/index.html`, `app.js`, `app.css` | `test_gui_server.py::test_http_serves_static_frontend_and_json_api`; browser XSS test (skipped) | A, H (served); no browser run today | Real-browser rendering HISTORICAL (Nov 17 guest Firefox) |
| Function explorer (overview, assembly, CFG, data flow, decompiler tabs) | PARTIAL | GUI | `app.js:showExplorer*` → M10 tools | tool tests above | A, P (tools); UI not exercised today | Visual check needed in rehearsal |
| Per-launch token + HttpOnly cookie | VERIFIED | all `/api/*` | `api/server.py:_authorized`, `_token_login`, `serve` | `test_host_access_security.py::test_per_launch_token_required_for_api`, `…test_loopback_serve_generates_a_fresh_token` | A, B, H | Token printed to the terminal; treat as a secret |
| Host / Origin / fetch-metadata gates, CSP, no CORS | VERIFIED | all requests | `_trusted_request`, `end_headers` | `test_host_access_security.py` (24) | A, H | Host check does not stop non-browser LAN clients if bound to a LAN IP (BR-08) |
| Bind policy (loopback default; opt-in private IPv4) | VERIFIED | `aire gui --bind` | `_validate_bind_host`, `create_server` | `…test_wildcard_and_public_binds_refused_even_with_opt_in`, `…test_nat_address_requires_opt_in_and_token` | A, P | Any private IPv4 accepted with opt-in |
| Chat concurrency limit (4 → 429), body limits | VERIFIED | `/api/chat` | `AireHttpServer.chat_slots` | `…test_chat_concurrency_is_bounded`, `…test_body_size_limit` | A | Doesn't cap all connections |
| Split-host Windows Chrome ↔ VM ↔ Windows Ollama | PARTIAL | README procedure | CLI flags + `allow_remote_host` | `…test_virtualbox_host_requires_explicit_opt_in`, `…test_cli_flag_and_environment_set_the_opt_in` | A (guest-side logic only) | Windows-side checks unverified (BR-03) |
| Interactive call-graph visualization | ABSENT | — | Call Graph panel is a list | — | — | — |

## 7. Legacy Java extension (`ghidra-plugin/`)

| Feature | Status | Source | Verification | Limitations |
|---|---|---|---|---|
| Dockable suggestions panel, Refresh (≤250 functions) | IMPLEMENTED-UNTESTED | `AireSuggestionsProvider.java` | Source inspection only (Gradle absent) | Stale rows across program switches (BR-10) |
| Evidence extraction (decompiler ≤12k chars, ≤40 asm lines, strings, callees, callers, imports, heuristics) | IMPLEMENTED-UNTESTED | `services/ContextExtractor.java` | Source inspection | Timeout passed as 3000 *seconds* (BR-09); swallowed cancellation (BR-13) |
| Ollama naming candidates, heuristic confidence filter (≥0.55), diversity filter (≤3) | IMPLEMENTED-UNTESTED | `services/OllamaSuggestionProvider.java` | Source inspection | Endpoint unrestricted; confidence not calibrated |
| Analyst-approved rename (USER_DEFINED, in a transaction) | IMPLEMENTED-UNTESTED | `AireSuggestionsProvider.java` (Apply) | Source inspection | **The only state-changing feature in the repository**; separate from the Python platform |

## 8. Roadmap items not implemented

| Item | Status | Evidence |
|---|---|---|
| M11 benchmark/evaluation | PLANNED | `docs/ROADMAP.md` |
| M12 reporting/final integration | PLANNED | `docs/ROADMAP.md` |
| M10 Phase 6 evaluation completion | PARTIAL | `docs/M10_CHECKPOINT.md`, `docs/ROADMAP.md` |
| Richer source/sink rules, argument/size facts | PLANNED | `docs/ROADMAP.md` "Next work" |
| Function reports (export) | ABSENT | No report generator in the source; `function_evidence` is an interactive summary |
| Dynamic validation, CVE matching, exploit generation, autonomous actions, Python write-back | ABSENT | grep; `docs/CURRENT_STATE.md` "Not implemented" |
