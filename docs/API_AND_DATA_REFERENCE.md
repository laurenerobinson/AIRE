# A.I.R.E. API and data reference

Audit date **2026-11-19**. This document lists only routes, fields and
interfaces that appear in the current source. Paths are relative to
`aire-server/src/aire/`. The source of truth is `api/server.py`,
`knowledge/database.py`, `knowledge/models.py` and `agent/tools.py`. A live
smoke test of these routes is recorded in
[TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md#4-live-http-smoke-test).

## 1. Command-line entry points

The console script `aire` is declared in `aire-server/pyproject.toml` as
`aire.agent.cli:main`.

| Command | Purpose | Key options (defaults) |
|---|---|---|
| `aire gui [binary]` | Start the browser workspace (`api/server.py:serve`) | `--database` (`$AIRE_DATABASE` or `analysis.sqlite`; **created empty if missing**), `--session-dir` (`~/.aire/gui-sessions`), `--upload-dir` (`<db dir>/.aire-uploads`), `--bind 127.0.0.1`, `--allow-non-loopback-bind`, `--port 8765`, `--public-port`, `--no-browser`, `--model`, `--ollama-host`, `--allow-remote-ollama` (or `AIRE_OLLAMA_ALLOW_REMOTE=1`), `--num-ctx`, `--max-iterations 6`, `--max-tool-calls 8`, `--timeout 180`, `--evidence-chars 8000`, `--no-prewarm` (or `AIRE_PREWARM=0`) |
| `aire chat <binary>` | Terminal agent over an existing database (read-only) | `--database`, `--session` (separate JSON file), `--question` (one-shot), `--model`, `--host`, `--num-ctx`, the same limits. **No remote-Ollama opt-in:** only a loopback host works |
| `python -m aire.pyghidra.indexer <path>` | One-off index, printed or `--json` (no database write) | `--no-decompile`, `--no-assembly`, `--max-assembly-instructions 200` |
| `python -m aire.ai.chat …` | M5 single-question development CLI | see `ai/chat.py:367` |
| `python -m aire.ai.naming …` | M6 advisory naming CLI (no write-back) | see `ai/naming.py:231` |
| `python -m aire.security.rule_engine <db> <binary_id>` | M7 deterministic scan, read-only | `--rule`, `--list-rules`, `--json` |
| `python -m aire.api.index_worker <db>` | Internal analyzer subprocess, spawned by `BinaryLibrary` | `--prewarm=<status path>` |

### Environment variables read by the source

| Variable | Read in | Effect |
|---|---|---|
| `AIRE_DATABASE` | `agent/cli.py` | Default database path |
| `AIRE_OLLAMA_HOST` | `ai/ollama_client.py` | Ollama origin (default `http://127.0.0.1:11434`) |
| `AIRE_OLLAMA_MODEL` | `ai/ollama_client.py`, `api/server.py` | Model name. **No default.** Generation raises if unset |
| `AIRE_OLLAMA_NUM_CTX` | `ai/ollama_client.py` | Context size (default 32768) |
| `AIRE_OLLAMA_ALLOW_REMOTE` | `agent/cli.py` (gui only) | `1` sets the default for `--allow-remote-ollama` |
| `AIRE_M10_NARRATION`, `AIRE_M10_NARRATION_SECONDS` | `api/server.py` | Opt-in model narration of M10 answers (default off; 60 s budget) |
| `AIRE_PREWARM` | `agent/cli.py` | `0` disables JVM prewarm |
| `AIRE_ANALYSIS_TIMEOUT` | `api/binary_library.py` | Watchdog seconds per analysis job (default 3600) |
| `AIRE_DECOMPILE_WORKERS` | `pyghidra/extractor.py` | Decompiler pool size (default min(4, CPUs), max 32) |
| `AIRE_INSTRUCTION_IR` | `pyghidra/indexer.py` | `0` disables M10 IR collection (benchmark only; breaks cache compatibility) |
| `AIRE_GUI_PERFORMANCE` | `api/server.py` | `1` logs per-chat timing JSON |
| `AIRE_GUI_PUBLIC_PORT` | `agent/cli.py` | Default for `--public-port` |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` / `JAVA_HOME_OVERRIDE` | PyGhidra launcher, `analysis/versions.py`, `pyghidra/indexer.py` | Ghidra install and JDK used by indexing |

Test-only gates: `AIRE_RUN_GHIDRA_TESTS`, `AIRE_RUN_OLLAMA_TESTS`,
`AIRE_RUN_AGENT_LIVE_TESTS`, `AIRE_RUN_NAMING_LIVE_TESTS` and
`AIRE_RUN_BROWSER_TESTS`.

## 2. HTTP API (`api/server.py`)

### Common rules

- **Gate 1, `_trusted_request`** (`:802`). This applies to every request,
  including static files:
  - the `Host` header must match `^(localhost|127\.0\.0\.1)(:port)?$` and the
    port must be the bound port or `--public-port`;
  - `Sec-Fetch-Site`, when present, must be `same-origin` or `none`;
  - `Origin`, when present, must be `http://` plus the same allowed authority;
  - a POST without `Origin` must carry `X-AIRE-Token`.

  Failure returns **403** `{"error":"Forbidden",…}`.
- **Gate 2, `_authorized`** (`:798`). This applies to `/api/*` and all POSTs.
  The request must carry either the cookie `aire_token_<port>` or the header
  `X-AIRE-Token` matching the per-launch token (`secrets.token_urlsafe(32)`),
  compared in constant time. Failure returns **401**.
- **Login.** `GET /?token=<t>` returns 303 to `/` with
  `Set-Cookie: aire_token_<port>=<t>; Path=/; HttpOnly; SameSite=Strict`.
- **Bodies.** JSON bodies require `Content-Type: application/json` and must
  be 1 byte to 1,000,000 bytes, with an object at the top level.
- **Errors.** `{"error": <name>, "message": <redacted text>}`. Absolute
  repository and home paths are replaced with `<repo>` and `~`.
- **Headers on every response:** `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and a strict
  `Content-Security-Policy` (`default-src 'self'`, no inline script,
  `frame-ancestors 'none'`). No CORS headers are sent.

### Routes

| Method & path | Request | Success response | Handler → service |
|---|---|---|---|
| `GET /` (and static files) | — | `index.html`, `app.js`, `app.css` | `SimpleHTTPRequestHandler` over `api/static/` |
| `GET /?token=…` | query `token` | 303 + cookie | `_token_login` |
| `GET /api/bootstrap?binary_id=` | optional `binary_id` (ID or stored name, not a path) | `{product, subtitle, database (file name), selected_binary_id, binary_metadata, binaries[], model, sessions[], tool_names[]}` | `GuiApplication.bootstrap` |
| `GET /api/binaries` | — | `{binaries: [BinaryRecord…]}` | `list_binaries` |
| `GET /api/library` | — | `{fixtures: [...], max_upload_bytes: 33554432, analyzer: {status,…}}` | `BinaryLibrary.list`, `analyzer_status` |
| `GET /api/analysis/<32 hex>` | job ID | job record: `status` (`queued`/`running`/`completed`/`failed`), `phase`, `events[]`, `elapsed_seconds`, `binary_id`, `cache_hit`, `warning_count`, `warnings[≤50]`, `decompile_*`, `error` | `BinaryLibrary.job` |
| `GET /api/sessions?binary_id=` | optional filter | `{sessions: [...]}` | `GuiSessionStore.list` |
| `GET /api/sessions/<32 hex>` | session ID | session with transcript | `GuiApplication.session` |
| `GET /api/health` | — | `{ok: true, host, models[], selected_model}` or `{ok: false, selected_model, message}` (HTTP 200 in both cases) | `OllamaClient.health` (`/api/tags` only) |
| `POST /api/uploads?filename=` | raw bytes, `Content-Type: application/octet-stream`, `Content-Length` 1 B–32 MiB, no chunked encoding | **201** `{upload_id, filename, sha256, format, architecture, bits, size, pe_valid, analysis_level, structure_summary, structure_issue_count, structure_issues[]}`. A rejected file returns 400 plus a `validation` report | `BinaryLibrary.upload` |
| `POST /api/analysis` | `{upload_id}` **or** `{fixture_id}` (exactly one) | **202** job record | `BinaryLibrary.start` |
| `POST /api/sessions` | `{binary_id}` | **201** session | `GuiApplication.new_session` |
| `POST /api/sessions/<id>/select-function` | `{function}` (ID, exact name, or address) | `{selected_function: {...}}` | `select_function` → `get_function` tool |
| `POST /api/tool` | `{session_id, tool, arguments}`. `function`/`source`/`target` may be `"it"`, meaning the selected function | **200** `{ok:true, tool, data}` or **400** `{ok:false, tool, error:{code,message}}` | `run_tool` → `ToolRegistry.run` |
| `POST /api/chat` | `{session_id, question}` | **200** NDJSON stream (below). **429** if 4 chats are already running | `_chat` → `run_chat` |
| any other `/api/*` POST | — | **404** `{error:"NotFound"}` | — |
| `HEAD /api/*` | — | **405** | `do_HEAD` |

### `/api/chat` NDJSON stream

Each line is `{"type": T, "data": D}`.

| `type` | `data` |
|---|---|
| `event` | `AgentEvent.to_dict()`. Event kinds (`agent/events.py:6`): `agent_started`, `request_received`, `tool_started`, `tool_completed`, `evidence_found`, `function_selected`, `progress`, `warning`, `answer_started`, `answer_completed`, `error`, `agent_finished`. Metadata keys are allow-listed (`iteration`, `tool_calls`, `ok`, `code`, `count`, `status`, `truncated`) |
| `text` | `{text, provisional: true}`: streamed summary preview while a model generates |
| `context` | `{text}`: deterministic overview preview shown before model synthesis |
| `result` | `AgentResult.to_dict()`: `{status, answer (Markdown), events[], tool_results[], response (ChatResponse or null), presentation}`. `status` is one of `completed`, `partial`, `error`, `cancelled`, `deadline`, `max_tool_calls`, `planning_budget`, `evidence_failure`, `no_current_function` |
| `error` | `{error, message}` |

`presentation.verified = true` means the deterministic fact path; no model was
used. `presentation.interpretation = true` means validated model output.

## 3. SQLite schema

`knowledge/database.py`. `SCHEMA_VERSION = 2`. Versions 1 and 2 are readable,
and v1 is upgraded in place by adding the reference tables.
`schema_metadata(key PRIMARY KEY, value)` holds `schema_version`. Foreign keys
are enforced (`PRAGMA foreign_keys = ON`). Every child table cascades on
deleting the `binaries` row.

| Table | Key | Columns | Notes |
|---|---|---|---|
| `binaries` | `binary_id` (= lowercase SHA-256) | `path, sha256, format, architecture, image_base, analyzed_at, compiler_spec, endianness, pointer_size, entry_point, executable_size, program_name` | `path` is the analyzed file's absolute path (display/re-validation only; never opened by the store) |
| `functions` | `function_id` (`"<sha>:<address>"`); `UNIQUE(binary_id, ordinal)` | `binary_id, ordinal, address, current_name, signature, decompiled_text, assembly, instruction_count, basic_block_count, branch_count, is_external, is_thunk, is_library, namespace, calling_convention, assembly_truncated` | Indexes on `address` and `current_name`. `is_library` is always NULL (never set by the extractor) |
| `artifacts` | `artifact_id` (`"<sha>:artifact:<sha256([kind,address,value])>"`) | `binary_id, ordinal, type ∈ {STRING, IMPORT, EXPORT}, address, value` | Indexes on `type` and `value`. Unique index on `(binary_id, artifact_id)` |
| `function_edges` | `(binary_id, ordinal)` | `caller_function_id, callee_function_id, callsite_address, edge_type ('CALL')` | Composite foreign keys to `functions`. Indexes on caller and on callee |
| `binary_references` | `reference_id` (`"<sha>:reference:<sha256([src,dst,type,operand])>"`) | `binary_id, ordinal, source_address, target_address, reference_type, source_function_id?, target_function_id?, target_artifact_id?, source_instruction, operand_index, is_call, is_indirect, is_read, data_hex (≤8 bytes)` | `target_function_id` is NULL for computed flows |
| `thunk_relations` | `(binary_id, ordinal)` | `thunk_function_id, target_function_id, source_address, target_address, source_instruction, is_direct_jump` | Immediate Ghidra thunk binding. Never a CALL edge |
| `program_information` | `(binary_id, key)` | `value` | Ghidra "Program Information" options, plus `ELF DF_1_PIE` and `ELF interpreter` |
| `warnings` | `id`; `UNIQUE(binary_id, ordinal)` | `warning_text` | Loader and analysis logs, skipped indirect calls, extraction failures |
| `analysis_metadata` | `(binary_id, key)` | `value` (JSON) | Keys written by `index_binary`: `schema_version` (**1**, the ProgramIndex metadata format, not the DB schema), `ghidra_version`, `analyzer_versions`, `analysis_completed`, `ghidra_function_count`, `options`, timing keys, `decompile_workers`, `decompile_retry`, `decompilation_incomplete`, `reference_facts_version` (2), `instruction_ir` `{version, functions, instructions, truncated_functions}`, `input_sha256_unchanged`, `total_seconds`, plus definition notes |
| `function_ir` (created lazily) | `(binary_id, function_id)` | `ir_version (1), data BLOB` | zlib-compressed JSON (`pyghidra/instruction_ir.py: encode/decode`). Decode checks nesting depth. Stores without this table make M10 tools fall back to the lower-confidence `assembly_text` source |

**Lifecycle.** A re-analysis of the same SHA-256 replaces every row
atomically. `delete_binary` removes database rows only, never files. GUI
sessions, transcripts, uploads and job timing files live outside the
database.

### Stores found locally (read-only inspection, 2026-11-19)

| Store (ignored by Git) | Schema | Binaries | `function_ir` |
|---|---|---|---|
| `demo_artifacts/m10/defense_20261117/demo.sqlite` (SHA-256 `f88fa14e…`) | 2 | `aire_test_binary`, `aire_test_binary_stripped`, `aire_test_binary_O2`, `FunctionOverloading.exe`, `unsafe_copy`, `safe_copy`, `dangerous_gets` | yes |
| `demo_artifacts/m10/m10.sqlite` (SHA-256 `25ac802a…`) | 2 | both simple ELFs, O2 ELF, 3 crypto PEs, `sleigh.exe`, `FunctionOverloading.exe` | yes |
| `analysis.sqlite` (repository root, Oct 8) | 2 | `aire_test_binary`, `FunctionOverloading.exe`, `UltraGpsXY` | **no** (pre-M10). Cache-incompatible, M10 answers are lower confidence |

## 4. Python data models

Persisted records (`knowledge/models.py`): `BinaryRecord`, `FunctionRecord`,
`ArtifactRecord`, `FunctionEdge`, `ReferenceRecord`, `ThunkRecord`, and
`ProgramIndex`. `ProgramIndex.function_ir` is excluded from equality and from
`to_dict()`.

Transient records:

- graph: `knowledge/graph.py` — `CallRelationship`, `TraversalNode`,
  `CallPath`, `FunctionRelationshipSummary`;
- evidence: `knowledge/evidence.py` — `EvidenceRequest` with validated caps,
  `EvidenceBundle` with `Provenance` and `Truncation`;
- chat: `ai/chat_models.py` — `ChatRequest`, `Claim`, `ChatResponse`,
  `ChatError(code)`;
- security: `security/findings.py` — `EvaluationState` (exactly `NOT_APPLICABLE`,
  `INSUFFICIENT_EVIDENCE`, `SIGNAL`, `CANDIDATE`; there is no CONFIRMED
  state),
  `EvidenceStrength`, `SecurityEvidence`, `SecurityFinding`,
  `RuleEvaluation`, `SecurityScanResult`;
- agent: `agent/session.py: AgentSession` (`binary_id`,
  `current_function_id`, bounded history/evidence/results) and
  `agent/runner.py: AgentLimits`, `AgentResult`.

## 5. Agent tool catalog (27 tools, `agent/tools.py:124-188`)

Every tool is read-only. Arguments are validated by `ToolRegistry.run`:

- strings are 1–500 characters;
- integers must fall within declared bounds;
- enums must match;
- unknown argument names are rejected.

Results are capped at 100,000 serialized characters.

| Tool | Arguments | Backed by |
|---|---|---|
| `binary_metadata` | — | `binaries` row, table counts, decompilation incompleteness |
| `list_functions` | `limit≤100`, `offset` | `functions` (bodies omitted in SQL) |
| `get_function` | `function` | `ProgramQueryService.resolve_function` |
| `get_callers` / `get_callees` | `function`, `limit≤100` | `get_callers` / `get_callees` |
| `get_xrefs` | `function`, `direction ∈ {outgoing, incoming}`, `limit`, `offset` | `InvestigationService.references` |
| `get_function_strings` | `function`, `limit`, `offset` | string references only |
| `get_thunk_target` | `function`, `max_depth 0–16` | `InvestigationService.thunk_chain` |
| `classify_function` | `function` | `InvestigationService.classification` |
| `find_call_path` | `source`, `target`, `max_depth 0–8` | `find_call_path` (BFS) |
| `rank_functions` | `metric`, `limit` | `rank_functions` (connectivity only) |
| `rank_application_functions` | `limit` | `ApplicationRelevanceService` (`application-relevance-v2` heuristic) |
| `get_artifacts` | `kind ∈ {STRING, IMPORT, EXPORT}`, `limit` | `ContextBuilder` artifact selection |
| `get_decompiled_text` / `get_assembly` | `function`, `max_chars≤8000` | stored text + truncation flags |
| `crosscheck_function` | `function` | `FunctionCrossCheckService` (text-level local agreement) |
| `retrieve_evidence` | `function?`, `max_chars 1000–16000` | `ContextBuilder` / `OverviewContextBuilder` |
| `security_findings` | — | `RuleEngine.scan_binary` |
| `crypto_evidence` | `limit≤100` | `security/crypto_evidence.crypto_evidence` |
| `explain_instructions` | `function`, `start?`, `limit≤200` | `AssemblyIntelligence.explain` |
| `function_evidence` | `function` | `AssemblyIntelligence.function_evidence` |
| `function_cfg` | `function` | `flow_analysis.control_flow_graph` (dominator back-edges) |
| `branch_paths` | `function`, `address` | `flow_analysis.branch_paths` |
| `trace_value` | `function`, `address`, `location` | `flow_analysis.trace_value` (depth ≤6) |
| `parameter_use` | `function` | `flow_analysis.parameter_use` |
| `return_usage` | `function` | `flow_analysis.return_usage_at_callsite` over stored callers |
| `crossvalidate_function` | `function` | `decompiler_crossval.crossvalidate` → `CONSISTENT` / `POTENTIAL DISCREPANCY` / `INSUFFICIENT EVIDENCE` per check |

## 6. Major service interfaces

| Interface | Signature | Contract |
|---|---|---|
| `index_binary` | `(path, options=IndexOptions()) -> ProgramIndex` | Static analysis in a disposable project. Raises `IndexingError`. Verifies input SHA-256 before and after |
| `analyze_binary` | `(path, store, options=None, force=False, load_snapshot=True) -> AnalysisResult` | Cache-or-index-and-save. Single writer |
| `BinaryKnowledgeStore` | `save_program_index`, `load_program_index`, `load_analysis_metadata`, `load_function_ir`, `load_warnings`, `list_binaries`, `has_binary`, `delete_binary` | Atomic replacement, typed errors |
| `ProgramQueryService` | `find_functions`, `resolve_function`, `get_callers`, `get_callees`, `get_callsites`, `get_reachable`, `get_reverse_reachable`, `find_call_path`, `get_summary`, `rank_functions`, `get_function_references`, `get_function_referrers`, `get_artifact_references`, `get_thunk_bindings` | Exact, binary-scoped, deterministic |
| `ContextBuilder.build` | `(EvidenceRequest) -> EvidenceBundle` | Bounded, provenance-labeled, explicit truncations |
| `AireChatService.ask` | `(request=ChatRequest, evidence_bundle=?, compact=?, on_text=?, require_behavior_grounding=?) -> ChatResponse` | One model call plus one retry. Strict parse and citation validation |
| `AgentRunner.run` | `(session, question, on_event, cancelled, tools, prepared_actions, compact, on_text, deterministic, performance) -> AgentResult` | Bounded by `AgentLimits` |
| `RuleEngine.scan_binary` | `(binary_id, rule_ids=None) -> SecurityScanResult` | Immutable fact snapshot. Rule failures are isolated |
| `AssemblyIntelligence` | `explain`, `function_evidence`, `cfg`, `branch`, `trace`, `parameters`, `return_usage`, `crossvalidate` | Deterministic. Every result names its `evidence_source` (`ghidra_pcode` or `assembly_text`) |
| `OllamaClient` | `generate(prompt, system, response_schema, on_chunk)`, `list_models`, `health`, `warm` | Loopback-only unless explicitly opted in. No proxies or redirects |
