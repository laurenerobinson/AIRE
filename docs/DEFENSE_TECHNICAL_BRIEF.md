# A.I.R.E. defense technical brief

Prepared **2026-11-19** for the **November 20, 2026** graduate defense. The
brief is based on the live source on branch `docs/aire-full-audit-2026-11-19`
(HEAD `ebacf4d` + docs) and on the fresh results in
[TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md). Paths are
relative to `aire-server/src/aire/`. Two labels mark the provenance of every
number:

- **FRESH** means it was measured on 2026-11-19;
- **HISTORICAL** means it comes from earlier reports and was not re-run.

---

## 1. What problem A.I.R.E. solves

Ghidra exposes a huge amount of static detail, but an analyst still has to
answer questions like these manually:

- *who calls this?*
- *which function encrypts?*
- *what does this branch do when true?*
- *does the decompiled C actually match the instructions?*

General chatbots are bad at this. They invent function names, reverse call
directions, and cannot show *where* a claim comes from.

A.I.R.E. turns a binary into a **persistent, queryable fact base** and
answers questions from that fact base with **citations to stored evidence**
(function IDs, call sites, instruction addresses). Its policy is
**deterministic first**: if a question can be answered exactly from stored
facts, no language model is involved. A local model is used only to
*explain* bounded evidence, and its output is validated and labeled as
interpretation.

## 2. How it differs from Ghidra alone

| Ghidra alone | A.I.R.E. adds |
|---|---|
| Interactive, per-session program database | A **whole-binary snapshot in SQLite**, keyed by SHA-256, reusable without Ghidra (`knowledge/database.py`) |
| Cross-references browsed by hand | Exact **graph queries**: callers, callees, call sites, BFS reachability, shortest path, connectivity ranking (`knowledge/retrieval.py`) |
| Raw P-code, unexplained | **Instruction explanations** derived from P-code, CFG with dominator-based loops, branch-outcome paths, bounded value tracing (`analysis/instruction_semantics.py`, `analysis/flow_analysis.py`) |
| Decompiler output taken on trust | **Decompiler cross-validation** against assembly/P-code: per-check CONSISTENT / POTENTIAL DISCREPANCY / INSUFFICIENT EVIDENCE (`analysis/decompiler_crossval.py`) |
| No security triage layer | **Versioned deterministic CWE rules** and **crypto-API evidence** with provenance (`security/`) |
| No conversational interface | A **read-only agent** with 27 validated tools, deterministic intent routing, and a browser GUI with streaming activity (`agent/`, `api/`) |
| Scripts can modify the program | The Python platform **never writes back** to the program. The Ghidra project is disposable and never saved, and the input hash is checked before and after |

## 3. What I built versus what Ghidra and Ollama provide

| Provided by Ghidra / PyGhidra | Provided by Ollama | Built in A.I.R.E. |
|---|---|---|
| Loading, auto-analysis, function discovery, decompiler, listing/instructions, raw P-code, basic-block model, references, symbols, thunk resolution | Local model inference (`/api/generate`, `/api/tags`), JSON-schema-constrained output | Indexer orchestration and fact extraction (`pyghidra/`); stable IDs; decompiler worker pool + timeout retry; compact instruction IR; SQLite schema, migration, atomic persistence; deterministic graph queries; evidence bundling with provenance and truncation accounting; application-relevance heuristic; instruction semantics, CFG/loops, value-flow; decompiler cross-validation; CWE rule engine; crypto evidence; intent routers; bounded agent loop; prompt/citation validation; HTTP server with token/Host/Origin gates; GUI; intake validation (ELF headers, PE structure); objdump ground-truth evaluator |

Ghidra is the **source of program facts**. Ollama is an **optional
explainer**. Everything in between, which is where correctness, grounding
and safety are decided, is A.I.R.E. code.

## 4. What happens when a binary is uploaded

Code path: `static/app.js: validateUpload` → `POST /api/uploads` →
`api/binary_library.py: BinaryLibrary.upload` → `POST /api/analysis` →
`BinaryLibrary.start` → `_run_analysis` → subprocess
`api/index_worker.py: run_analysis` → `analysis/cache.py: analyze_binary` →
`pyghidra/indexer.py: index_binary`.

1. **Bounded transfer.** The upload must be raw octet-stream, at most
   32 MiB, not chunked, with a 30 s socket timeout. The filename is only a
   display label (sanitized, no directories).
2. **Format validation without execution.** `inspect_binary` parses real ELF
   header fields and checks that program headers lie inside the file. For
   PE files, `validation/pe_structure.validate_pe` checks the DOS/PE
   signatures, optional header, section table and import directory.
   Damage a loader tolerates is accepted as *partial*. Header-level
   corruption is rejected with a structured report. Extensions are never
   trusted.
3. **Content-addressed storage.** The file is stored at
   `<upload-dir>/<sha256>/<name>` with mode 0600. It is re-hashed when the
   job starts and again before analysis; any change aborts.
4. **Cache check.** If the database already holds this SHA-256 with
   *identical* analyzer versions, Ghidra version, options, IR version 1 and
   reference-facts version 2, the job finishes without starting Ghidra
   (`compatible_metadata`).
5. **Static analysis in a disposable project.**
   - **Setup.** `index_binary` starts or reuses one JVM, creates a temporary
     Ghidra project, imports and auto-analyzes the binary.
   - **Single extraction pass.** One pass over each function produces the
     assembly text, the counts and the IR. Up to 4 decompiler processes run
     in parallel; timeouts are retried once serially.
   - **Remaining facts.** Strings, imports, exports, resolved direct CALL
     edges, references and thunk bindings are extracted next.
   - **Teardown.** The program is released **unsaved**, and the input
     SHA-256 must be unchanged.
6. **Watchdog.** A hung analyzer is killed after `AIRE_ANALYSIS_TIMEOUT`
   (default 3600 s). The next job starts a fresh worker.

## 5. How results reach SQLite and the GUI

`BinaryKnowledgeStore.save_program_index` writes everything for the binary
in **one transaction**. The old rows are deleted with cascade, and new rows
are inserted in ordinal order. Any error rolls back the whole save. IR goes
into `function_ir` as zlib-compressed JSON.

The GUI never writes analysis facts. Its connections are opened by
`_ReadOnlyRuleStore` with `mode=ro` and `PRAGMA query_only=ON`. Workspaces
are cached per binary and invalidated by a database *stamp*: inode, size and
nanosecond mtime/ctime of the database and its WAL. A request that sees the
database change mid-flight is told to retry rather than mixing snapshots.

## 6. How the chatbot decides which evidence or tools to use

`GuiApplication.run_chat` (`api/server.py:404`) tries three routes, in
order. The first match wins.

1. **Deterministic fact router**, `agent/fact_answers.py: classify`. This is
   a pure regex classifier for *factual* phrasings ("which / what / where /
   list / show / does …") about:
   - crypto operations;
   - specific APIs and imports;
   - callers and callees;
   - file identity or corruption;
   - "show the evidence".

   Evaluative words (why, how, explain, secure, vulnerable, weak, …) make it
   return `None` on purpose, so those questions are never answered by
   pattern-matching. **No model call.**
2. **M10 assembly router**, `agent/assembly_answers.py: route`. It handles
   instruction explanations, "what does this function do", branch outcomes,
   value origin, return-value use, decompiler checks, and binary-wide input
   validation. These are answered from `AssemblyIntelligence`. **No model
   call** unless `AIRE_M10_NARRATION=1`.
3. **Agent**, `agent/runner.py: AgentRunner.run`. It proceeds as follows:
   1. It verifies the binary scope.
   2. For overview questions it collects a fixed skeleton: metadata, top
      relevance-ranked functions, callees of the top seed, imports and
      security findings.
   3. It resolves exact function names that appear in the question by SQL
      lookup, not by guessing.
   4. It routes strings, xrefs and thunk questions by regex.
   5. It runs cross-checks for explain/compare questions.
   6. **Only if nothing above applied**, it asks the model to pick a tool.
      The model output is constrained to a JSON schema built from the
      registry (`action_schema`) and parsed strictly (`parse_action`). Every
      action goes through `ToolRegistry.run`'s type, bound and enum
      validation.

   Budgets are 6 iterations, 8 tool calls and a 180 s deadline. One tool
   slot is always reserved for the final `retrieve_evidence`.

**FRESH result.** In the audit probe, 13 of 14 representative questions
across the debug ELF, the stripped ELF and `aes_gcm.exe` were answered with
**zero model requests**. The model stub raises if it is called. The
exception was "What does this binary do?", which needs the model.

## 7. How grounded answers are produced and validated

- **Evidence.** `ContextBuilder` / `OverviewContextBuilder` build an
  `EvidenceBundle`. Every function, edge, artifact, reference and warning
  carries `Provenance(source_table, source_id, binary_id, address)`. Every
  omission is recorded as a `Truncation`.
- **Prompt.** `ai/prompt_builder.py: build_prompt` gives each evidence item a
  citation ID (FUNC/EDGE/ART/…). It declares binary-derived text to be
  untrusted data, not instructions.
- **Constrained output.** `AireChatService.ask` (`ai/chat.py:161`) narrows
  the response JSON schema so `evidence_ids` must be one of the supplied IDs.
  For behavior questions, the IDs must be code-bearing FUNC or CALL EDGE IDs.
- **Validation.** This runs after generation, because providers may ignore
  the schema:
  - `parse_response` checks for exact keys, known IDs, and confidence in
    {low, medium, high};
  - `check_operation_contradictions` drops interpretations that contradict
    deterministic operation observations;
  - `validate_multiply_register_claims` rejects register names absent from
    the cited assembly;
  - `validate_compact_claims` rejects "main is the entry point" or named
    call claims without a matching stored edge.

  One format-correction retry is allowed, then `ChatError`.
- **Fixed caveats.** These are appended by code: static only; *citation
  existence is validated; prose is interpretation, not verified fact*;
  context was bounded.
- **Exact graph questions bypass prose entirely.** The code comments that
  this is because model prose "can reverse edge direction or invent
  relationships".

## 8. How the system handles uncertainty

- **Three-valued and four-valued outcomes, not booleans.** Cross-validation
  returns CONSISTENT / POTENTIAL DISCREPANCY / INSUFFICIENT EVIDENCE. CWE
  rules return NOT_APPLICABLE / INSUFFICIENT_EVIDENCE / SIGNAL / CANDIDATE.
  There is **no** CONFIRMED state.
- **Absence is qualified.**
  - "No stored callers. Indirect, computed or runtime calls are not
    excluded."
  - "No path within bound does not prove global unreachability."
- **Coverage is explicit.**
  - assembly truncation flags;
  - `decompilation_incomplete` with the reason;
  - IR truncation at 4096 instructions;
  - M10 `evidence_source` = `ghidra_pcode` or the lower-confidence
    `assembly_text`;
  - structural condition of damaged PEs, which is prefixed to model answers
    (`_structure_banner`).
- **Model confidence** is a low/medium/high *label*, checked only for
  membership in that set. It is **not a calibrated probability**. Relevance
  scores are ordered heuristics, not ML confidence.

## 9. Which security checks are deterministic

All of them. There are no model-created findings.

- **CWE-120 unbounded-copy signal** (`strcpy`) and **CWE-242
  dangerous-API signal** (`gets`) (`security/rules/api_calls.py`). Each
  requires:
  - coverage metadata showing analysis completed, imports and direct calls
    were enabled;
  - an exact import artifact and matching external function;
  - a resolved internal CALL edge to it, or to an import-named thunk.

  Output is a **SIGNAL** with evidence IDs, assumptions and limitations
  ("destination capacity and source length have not been proven…").
- **FRESH, via the live API.** `unsafe_copy` gives CWE-120 SIGNAL at
  `0x00401183`. `dangerous_gets` gives CWE-242 SIGNAL at `0x00401178`.
  `safe_copy` (bounded memcpy) gives none. The simple ELF gives
  NOT_APPLICABLE for both rules.
- **Crypto evidence** (`security/crypto_evidence.py`). It finds exact call
  references to a fixed table of CNG, NCrypt, CryptoAPI and OpenSSL APIs.
  The operation category (encryption, decryption, hashing, …) comes from
  *which API is called*, never from function names. Algorithm identifier
  strings such as `"SHA256"` or `"ChainingModeGCM"` must be referenced from
  the same function.

  **FRESH** for `aes_gcm.exe`: 7 of 7 crypto imports are called from 4
  functions. `FUN_0041d160` is attributed encryption (BCryptEncrypt) and
  `FUN_0041d1e0` decryption.
- **Structural validation** of PE files (`validation/pe_structure.py`) and
  the per-answer structural condition (`analysis/file_structure.py`).

**Not implemented:** taint or source/sink flow, argument or size proofs, CVE
matching, exploitability, dynamic validation.

## 10. How the architecture protects user control and avoids unsafe execution

- **No target execution anywhere in the Python platform.** The only
  subprocesses are the A.I.R.E. index worker and, in evaluation scripts,
  `objdump -d` (static disassembly). No `exec`, `ptrace`, emulator or
  sandbox runner exists (audit grep).
- **Read-only investigation.** Tools cannot mutate. The GUI's SQLite
  connections are read-only at the engine level. Model actions can only
  select registered read-only tools with validated arguments.
- **No write-back.** The Python side never renames, comments or patches.
  Naming (M6) returns advisory candidates only. The Java v1 extension is
  the *only* component that renames, and only when the analyst selects a
  candidate and presses Apply, inside a Ghidra transaction.
- **Input integrity.** The SHA-256 is checked before and after indexing and
  analysis. The Ghidra project is disposable and never saved.
- **Network boundary.**
  - The default bind is loopback.
  - A non-loopback bind needs an explicit opt-in and a private IPv4
    address, and the token is mandatory.
  - The per-launch token is exchanged for an HttpOnly SameSite=Strict
    cookie.
  - The Host header is exact; same-origin `Origin`/`Sec-Fetch-Site` are
    required.
  - CSP has no inline script, and no CORS headers are sent.
  - Ollama is loopback-only unless remote access is opted in at launch.
    Proxies and redirects are disabled.

  **FRESH:** 401 / 403 / 403 / 303 for a bare request, a foreign Host, a
  cross-origin POST, and token login.
- **Bounded resources.**
  - 4 concurrent chats (more get 429);
  - 1 MB JSON bodies;
  - 100 KB tool results;
  - 1 MB model responses;
  - 8 queued jobs;
  - session files mode 0600.

## 11. Important performance and design tradeoffs

| Decision | Benefit | Cost |
|---|---|---|
| Persist a full snapshot per SHA-256 | Instant reuse and Ghidra-free querying | Large stores (`m10.sqlite` ≈133 MB for 8 binaries) |
| Deterministic routing before the model | Exact, fast, reproducible. **FRESH:** deterministic answers took 4–56 ms in the probe | Regex routers cover phrasings they were written for; other wording falls through to the model path |
| Small local model (`qwen2.5-coder:1.5b`, ctx 4096) | Runs offline on a laptop | Weak reasoning; live quality unmeasured in this audit (BR-02) |
| Parallel decompiler pool + single serial retry | Throughput; recovers from VM-induced timeouts (HISTORICAL M9) | More native processes |
| Compressed per-function IR, loaded on demand | Enables M10 without loading everything | IR capped at 4096 instructions/function |
| Separate analyzer subprocess | Ghidra/JVM crashes cannot take down the GUI; single SQLite writer | IPC; first job pays JVM start (prewarm mitigates) |
| x86/x86-64 specific condition naming and register families | Precise explanations for the target architecture | Other architectures get generic P-code explanations only |

## 12. Current limitations and honest future work

- **Model path unverified.** Live model synthesis was not exercised in this
  audit or freshly on Nov 17. Small-model answers can be wrong even when the
  citations are valid; citation validity is not semantic truth.
- **Static call graph only.** Only resolved direct CALLs. Computed calls,
  callbacks, vtables and dynamically resolved imports are not edges.
- **Value flow is intra-procedural and bounded.** It covers register
  families and frame-pointer-relative slots only, with depth 6.
- **Security rules are narrow.** Two API rules plus crypto evidence. No
  taint, source/sink, size or argument reasoning.
- **Evaluation is incomplete.** M10 Phase 6 is incomplete (`docs/ROADMAP.md`).
  M11 (evaluation) and M12 (reporting) are planned.
- **Split-host deployment** is verified on the guest side only (BR-03).
- **The Java v1 extension** is preserved but unbuilt here. It has two
  source-level defects (BR-09, BR-10).
- **Absent by design or not yet built:** semantic/vector retrieval, CVE
  matching, dynamic validation, exploit generation, autonomous actions,
  automatic renaming in the Python platform, and an interactive graph
  visualization.

---

## Distinctive technical contributions (supported by code)

1. **Deterministic-first question answering** with explicit routing tiers
   and a hard guarantee that exact graph and crypto-role answers never pass
   through model prose (`fact_answers.py`, `runner.py`).
2. **Citation-constrained generation.** The JSON schema enumerates the exact
   evidence IDs, and post-generation validators check the claims
   (`chat.py`, `prompt_builder.py`).
3. **P-code-derived instruction semantics** with machine-level explanations
   and evidence-source labeling (`instruction_semantics.py`).
4. **Decompiler-versus-assembly cross-validation** that refuses to call
   equivalent-but-different forms discrepancies
   (`decompiler_crossval.py`). FRESH: `validate_input` is CONSISTENT on
   call targets, strings, control flow, return value, constants and
   globals, and INSUFFICIENT EVIDENCE on arithmetic.
5. **Provenance-validated security signals.** The rule engine rejects any
   evidence that is not an exact item of the fact snapshot (`rule_engine._validate`).
6. **Defense-in-depth local web boundary**: token, exact Host, Origin and
   fetch-metadata gates, CSP, and read-only SQLite (`api/server.py`).

---

## Likely questions and answers

**Q: Is this just ChatGPT on top of Ghidra?**
No. Most questions never reach a model. In the audit probe, 13 of 14 demo
questions were answered deterministically with the model disabled. When a
model is used, it sees only a bounded evidence bundle. Its output must cite
IDs from that bundle and is validated, and it is labeled as interpretation.

**Q: How do you know the call graph is right?**
Edges come from Ghidra's resolved CALL references only, with caller defined
as the function containing the instruction (`graph_builder.py`). For the
simple ELF, the ground truth (`tests/fixtures/simple_elf/GROUND_TRUTH.md`) is
12 application functions, 14 distinct edges and 15 call sites. The Nov 17
packet records an exact match (HISTORICAL). Today the tool output was compared with raw
SQL for several functions, and direction matched. Computed calls are
reported as warnings, not guessed.

**Q: How do you know the instruction explanations are right?**
They are generated from Ghidra's P-code, not from the model. The objdump
ground-truth evaluator (`evaluation/objdump_truth.py`, `scripts/evaluate_m10.py`)
is independent of Ghidra and the model. It reported 100% agreement on instruction
boundaries and mnemonics for 76,420 instructions across 5 binaries
(HISTORICAL, `docs/M10_CHECKPOINT.md:52-63`, not re-run today). Unit tests cover the semantics
(`test_m10_semantics.py`).

**Q: Does it find vulnerabilities?**
It finds *signals*. For example, a resolved call to `strcpy` is a CWE-120
SIGNAL with evidence and explicit limitations. It never claims an overflow
or exploitability, and there is no CONFIRMED state in the code.

**Q: What stops the model from making things up?**
Four things:
- schema-enumerated citation IDs;
- strict parsing;
- contradiction and register checks against deterministic observations;
- one retry, then failure.

Exact questions bypass the model. Fixed caveats are appended by code. What
it *cannot* guarantee is that prose citing a real ID is semantically
correct, and the UI says so.

**Q: Could a malicious binary attack the system?**
- The binary is never executed.
- Strings and decompiled text are treated as untrusted data in prompts and
  HTML-escaped in the UI. The browser XSS test is opt-in and was not run
  today; a guest Firefox run is recorded as HISTORICAL.
- Ghidra parses the file in a separate worker process with a watchdog.
- PE structure validation rejects header-level corruption.

**Q: What if the model or network is down?**
Deterministic answers, the Function explorer, findings and crypto evidence
all work without a model. Model-path questions return `partial` with the
retrieved tool facts (FRESH, reproduced).

**Q: Why SQLite and not a graph database?**
It is a single-file, transactional, standard-library store. The query
workloads (one-hop neighbors, bounded BFS, aggregates) fit indexed SQL, and
snapshots can be copied and hash-verified for a reproducible demo.

**Q: How does the Java plugin relate to the Python platform?**
They are separate. The Java v1 extension suggests per-function names inside
Ghidra and can rename on analyst approval. The Python platform is
whole-binary, read-only and browser-based. They share no execution path.

**Q: What would you do next?**
- taint/source-sink facts with positive and negative controls;
- use persisted thunk bindings in rules;
- cancellation and deadlines for long analyses;
- a measured live-model evaluation;
- M11 evaluation across more binaries;
- fixing the two Java defects.
