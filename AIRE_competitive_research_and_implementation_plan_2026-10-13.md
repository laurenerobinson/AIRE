# A.I.R.E. Competitive Research and Implementation Plan

**Research date:** October 13, 2026  
**Subject:** A.I.R.E. — AI-Assisted Reverse Engineering  
**Basis:** Uploaded `AIRE-main.zip` snapshot (archive header commit `f29db6606c8eff84af140dd409db2202bf9000d2`, stamped October 5, 2026), current publicly accessible competitor GitHub documentation, and local Python unit test execution.  
**Repository note:** `https://github.com/laurenerobinson/AIRE` displayed an empty public repository when checked. The uploaded archive, not a confirmed remote branch, is the basis for statements about A.I.R.E. implementation. No code modifications, Git operations, target-binary execution, or competing-product hands-on benchmarks were performed.

## Executive conclusion

A.I.R.E. is not a prototype consisting only of an LLM prompt. The supplied source includes deterministic whole-binary indexing, persisted program facts, direct-call relationship queries, evidence provenance, a local-LLM grounded chat pipeline, analyst-review naming suggestions, deterministic but narrow CWE signals, and a 12-tool read-only conversational agent. The strongest opportunity is **better factual context and reliable interactive investigation**, not more autonomous write actions or a larger language model.

The recommended next production focus is **M9: Provenance-rich relationships and evidence-backed disassembly analysis**: function-to-string xrefs; jump/thunk resolution represented explicitly, separately from direct CALL edges; useful entry-point and internal/runtime classifications; control-flow and P-code def-use slices; a decompiler/assembly consistency reviewer; and transparent analytical ranking. Follow with a single `aire analyze --then-chat` workflow, analyst-friendly evidence UI, testing, and deferred optional dynamic validation.

## A. Verified current A.I.R.E. features and gaps

| Area | Current source evidence | Assessment |
|---|---|---|
| Binary indexing | `aire-server/src/aire/pyghidra/indexer.py`, `extractor.py`, `graph_builder.py`, `options.py` | Reads binary metadata, functions, signatures, decompilation, bounded assembly, strings, imports, exports, direct resolved CALLs, warnings; supports Ghidra-importable formats including demonstrated ELF and professor PE sample. |
| Persistence | `aire-server/src/aire/knowledge/database.py`, `models.py` | SQLite schema version 1 persists `ProgramIndex`. No persisted `xrefs`, `thunk_targets`, `P-code`, per-function code block associations, execution traces, or embeddings. |
| Graph analysis | `aire-server/src/aire/knowledge/retrieval.py` | Exact direct CALL traversal, callers, callees, paths, four degree-based rankings. Indirect call targets intentionally remain unresolved. |
| Evidence and LLM | `aire-server/src/aire/knowledge/evidence.py`, `aire-server/src/aire/ai/chat.py`, `context_builder.py` | Bounded evidence bundles and citation/format validation. Citations demonstrate traceability to available records but do not establish semantic truth. |
| Naming | `aire-server/src/aire/ai/naming.py` | Advisory candidate selection and grounding. No persistent analyst-reviewed name database or automatic Ghidra writeback from the Python pipeline. |
| Security | `aire-server/src/aire/security/rules/api_calls.py` | Two API-use signal rules: `strcpy`/CWE-120 and `gets`/CWE-242. They do **not** prove a vulnerability or trace input to a sink. |
| Agent | `aire-server/src/aire/agent/tools.py`, `runner.py`, `session.py`, `cli.py` | 12 read-only tools; persisted binary-scoped sessions; bounded calls/context/time; no live indexing, cross-reference lookup or on-demand P-code analysis in the agent. |
| GUI | `ghidra-plugin/src/main/java/aire/...` | Preserved Java v1 naming-suggestion panel, distinct from Python M8 agent. No unified agent/call-graph/security/evidence panel. |
| PE professor fixture | `professor_samples/function_overloading/README.md`, `scripts/demo_function_overloading.py` | A separate demo obtains string xrefs and thunk jumps from a live disposable Ghidra session. These are precisely the facts the Python knowledge store still lacks. |
| API | `aire-server/src/aire/api/server.py` | Placeholder, not a running local HTTP API. |
| Validation | `docs/M8_AGENT.md` | Live small-model output historically included valid citations but wrong interpretations/relationships, followed by deterministic graph-answer fixes. Several live questions timed out. |

### Test execution in this research session

Command:

```bash
cd AIRE-main
PYTHONPATH=aire-server/src python -m pytest -q aire-server/tests
```

Results: **261 passed, 16 skipped, 1 failed** (145 subtests passed), approximately 7.3 seconds. The failing case is `OllamaClientTests.test_remote_hosts_rejected_without_dns`, case `http://[::ffff:127.0.0.1]` (`aire-server/tests/test_ollama_client.py:175`). `OllamaClient.__init__` tests `.is_loopback`, so Python classifies this IPv4-mapped IPv6 form as loopback; the test expects the URL to be rejected (`aire-server/src/aire/ai/ollama_client.py:84-100`). This is an **allowlist-policy/test disagreement**, not by itself proof of an externally reachable vulnerability. Either formally allow IPv4-mapped loopback with an updated contract and test, or reject mapped addresses explicitly to honor the present test and simpler accepted host syntax. The safer and simpler fix is to reject mapped IPv6 (`isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None`) unless a deliberate acceptance policy is documented.

Skipped tests were opt-in integrations; this research environment did not verify live PyGhidra, a running Ollama model, Java plugin builds, or Windows PE execution. Archived documentation describes prior separate live runs and their limitations; those are not substituted for new measurements.

## B. Competitor features worth learning from

**1. GhidrAssist — semantic knowledge and analyst context.**
- Source: https://github.com/symgraph/GhidrAssist and https://github.com/symgraph/GhidrAssist/blob/master/README.md
- Documented features: a statement-to-binary semantic hierarchy, cached function summaries, graph communities, FTS5 summary search, security API activity classification, visual graph, interactive chat, analyst-edited summaries, contextual RAG and a ReAct agent.
- A.I.R.E. adoption: **persist relevant typed structural relationships first**, then cached summaries and local FTS5; add simple deterministic module clustering before considering community-detection dependencies; preserve manual overrides and source provenance. Avoid treating model-generated modules or summaries as observed facts.

**2. LaurieWired/GhidraMCP — live navigation and PyGhidra headless MCP.**
- Source: https://github.com/LaurieWired/GhidraMCP
- Documented features: Ghidra read/write tools for LLMs and headless operation using PyGhidra.
- A.I.R.E. adoption: create narrowly scoped read-only live-analysis adapters, first on-demand xrefs/P-code and reanalysis status. Expose an optional localhost-only MCP interface once the internal tool contracts are stable. Do not expose unrestricted script execution or auto-write as defaults. The upstream current README targets Ghidra 12.1.4; A.I.R.E. local documentation says 12.1.3, so test compatibility separately.

**3. bethington/ghidra-mcp — deep evidence and efficient tools.**
- Source: https://github.com/bethington/ghidra-mcp
- Documented features: 200+ MCP tools, P-code data-flow, xrefs, memory inspection, function hashing, cross-version matching, lazy tool discovery, GUI/headless, optional debugger/emulation, batch annotation.
- A.I.R.E. adoption: prioritize structured `get_xrefs`, `trace_dataflow`, `explain_asm_block`, `get_function_context`, and `compare_function_versions`. In A.I.R.E. this requires a smaller curated toolset rather than reproducing 200+ API endpoints. On-demand tool categories prevent a small local model from being overwhelmed.

**4. RevEng.AI plugin — similarity and defensible function identification.**
- Source: https://github.com/RevEngAI/plugin-ghidra
- Documented features: matches against a server-side function dataset, bulk renaming, similarity diffs, decompilation, analyst review and agent chat.
- A.I.R.E. adoption: start with **local deterministic function fingerprints and cross-build matches**, disclosing build/compiler sensitivity and match ambiguity. Do not imply A.I.R.E. has an industry-size reference corpus. Remote binary submission should be an explicit, separate opt-in (or omitted to preserve offline operation).

**5. angr — independent advanced static/symbolic analysis.**
- Sources: https://github.com/angr/angr ; https://github.com/angr/angr-doc/blob/master/docs/analyses/cfg.md
- A.I.R.E. adoption: optional secondary CFG/dataflow validation or later targeted symbolic checks. Avoid making angr mandatory: nontrivial dependency and environment cost, especially for offline, restricted systems. It is not a replacement for provenance directly from Ghidra.

### Beware misleading comparison claims

An MCP bridge is not a standalone reasoning model. Feature lists do not prove a product is accurate on an unseen binary. Licensing varies (GhidrAssist MIT, two GhidraMCP projects Apache-2.0; the A.I.R.E. repository license is still undecided). Study approaches and adapt concepts, but do not paste code or redistribute compiled extensions without meeting their license obligations. RevEng.AI service capabilities may depend on API access, connectivity or pricing; do not treat a GitHub plugin alone as a fully local open model.

## C. Prioritized feature backlog

Prioritization: P0 = unblock trust/reproducibility, P1 = main differentiation before deadline, P2 = valuable after core acceptance, P3 = postpone. Estimates are rough development effort **for one developer familiar with the code**, not delivery promises.

| ID | Priority | Feature | Why it matters | Rough effort |
|---|---|---|---|---|
| P0-A | P0 | Fix Ollama host test and clarify accepted URLs | Red test + security contract ambiguity | 0.5–1 day |
| P0-B | P0 | Reconcile README, M8 status, and current CLI/demo commands; verify reproducible installs | Root README contradicts implemented M8 state; lowers confidence in project demo | 0.5–1 day |
| M9-A | P1 | Persist function↔string DATA references with instruction address, type and string ID | Converts currently binary-global strings into exact, citable function evidence; demonstrated in professor PE sample | 2–4 days |
| M9-B | P1 | Persist explicit thunk/JMP target relations alongside direct CALLs | Prevents “missing caller” for Windows C++ overloads without inventing direct CALL edges | 2–4 days |
| M9-C | P1 | Persist entry point(s), initialization roots, internal/external/thunk/library classification and provenance | Stops `main` heuristics and CRT noise from dominating relevance | 1–3 days |
| M9-D | P1 | Add function-context/audit tool to agent | One deterministic answer combining caller/callee/callsite/string/assembly/code evidence | 1–2 days after A–C |
| M9-E | P1 | Add limited P-code and CFG facts for 1–2 selected functions on demand | Enables supported def-use and assembly/decompiler consistency checking | 4–8 days |
| M9-F | P1 | English assembly annotations tied to addresses, with contradictions/unknowns | Clear distinctive analyst-facing functionality, not just paraphrased pseudo-C | 2–5 days after E |
| M9-G | P1 | Semantic relevance ranking (not just call degree) and CRT suppression | Helps select actionable business/application code, protects important low-degree routines | 2–4 days |
| M9-H | P1 | Deterministic question routing / retrieval planning before LLM synthesis | Addresses small-model tool selection failure and token exhaustion | 1–3 days |
| M10-A | P2 | Safe, one-command analysis+chat pipeline with resumable cache | Eliminates manual two-stage CLI friction | 2–4 days |
| M10-B | P2 | Ghidra dockable investigation panel or local evidence report | Analyst usability: functions, cross refs, evidence, confidence, citations | 4–10 days |
| M10-C | P2 | Local FTS5 indexing of strings and analyst-approved summaries; semantic search as optional | Faster whole-binary navigation without extra inference calls | 2–4 days |
| M11-A | P1 | Controlled comparative benchmark and reproducible results | Essential to substantiate claimed A.I.R.E. improvements | 3–6 days plus competitor setup |
| Future | P2 | Source/sink facts + narrowly scoped deterministic rules, with positive and negative controls | Make CWE findings substantially more informative without unsupported vulnerability labels | 5–10+ days |
| Future | P3 | Optional offline function similarity corpus / fuzzy hash | Efficient recognition of changed or known routines | 4–10+ days |
| Future | P3 | Optional instrumented dynamic testing / symbolic execution in an isolated VM | Independent confirmation, but higher risk and time cost | separate research milestone |
| Future | P3 | Unrestricted write-capable MCP, large multiagent system, direct automatic renames | Increases safety and testing burden before enough evidence quality exists | postpone |

## D. Detailed engineering design for the highest-value changes

### D1. Evidence-rich cross-reference model

Propose immutable records, e.g.:

```text
XrefRecord(
    xref_id, binary_id,
    from_function_id, from_address, to_address,
    target_artifact_id=None, reference_type='DATA',
    resolution='EXACT', provenance='GHIDRA_REFERENCE'
)
ThunkTargetRecord(
    binary_id, thunk_function_id, target_function_id,
    jump_instruction_address, resolution='EXACT_GHIDRA_OR_VERIFIED_JMP'
)
```

Do not reuse the `FunctionEdge` table for thunk JMPs and do not report virtual relationships as encoded direct calls. Keep `direct_calls` and `effective_reachability` separately labeled, each with a provenance path.

Likely files: `knowledge/models.py` (records); `pyghidra/extractor.py` + a new `pyghidra/xref_builder.py`; `pyghidra/graph_builder.py` (don't change direct-call behavior); `knowledge/database.py` (schema v2 migration and atomic upgrades); `knowledge/retrieval.py` (typed joins); `agent/tools.py` (`get_function_strings`, `get_xrefs`, `get_effective_callees`); `ai/context_builder.py` (priority evidence).

Acceptance on `FunctionOverloading.exe`:
- Preserve the exact 3 observed data references documented in `professor_samples/function_overloading/README.md`: `FUN_00412620` at `00412653` to string `00419b38`, `FUN_004126c0` at `004126fc` to string `00419b50`, and `FUN_00412790` at `00412857` to `PAUSE` at `00419b68`.
- Preserve direct calls from `004127ba` to `00411028` and `00412802` to `004110cd` (thunks), and JUMPs from respective thunks to the two implementation functions. Queries must never fabricate a direct CALL from the common caller to either implementation body.
- Repeat indexing and schema reload produces identical typed relationships (apart from timestamps), address provenance and original SHA-256.
- Unresolved/indirect calls stay explicitly unknown.

### D2. Disassembly-explaining evidence checker

Propose method: for a selected function, capture actual assembly instructions (addresses, operand types/registers, mnemonic), bounded basic blocks, Ghidra P-code ops and def-use traces when available, and the decompiler's rendered pseudo-C. Build an evidence table for register loads, arithmetic, branch conditions, calls, pointer dereferences and returns. The local LLM explains the **structured evidence** with references to actual addresses. A deterministic layer identifies unsupported or contradictory claims when feasible.

Do **not** claim to mathematically prove decompiler correctness. High P-code itself is derived from Ghidra's lifter/decompiler and can share upstream errors. Improve reliability by additionally checking machine-instruction semantics/flow and, when feasible, independent disassembly or alternate analyses. Output categories: `CORROBORATED`, `UNRESOLVED`, `POTENTIAL_MISMATCH`, never `VERIFIED_CORRECT` without stronger proof. Cite the source instruction, P-code record and decompiler span separately.

For the C++ overload example, use `IMUL` as evidence for the integer multiplication and `MOVSD`+`MULSD` as scalar double-precision evidence. `CONCAT44` and `float10` are decompiler representation details rather than source-level C++ proof.

Likely files: new `pyghidra/pcode_builder.py`, `analysis/instruction_semantics.py`, `knowledge/models.py`/schema migration, `agent/tools.py` with `get_basic_blocks`, `trace_value`, `explain_instructions`, `compare_decompiler_assembly`, and dedicated tests. Begin with x86-64/x86 evidence and explicitly label unsupported architectures.

Official Ghidra APIs: https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html and https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html

### D3. Relevance ranking without losing important low-degree code

Current ranking: `unique_callers`, `unique_callees`, `incoming_callsites`, `outgoing_callsites` (`agent/tools.py:130-133`). Degree is not semantics. Create a *transparent user-configurable heuristic* with separately visible signals rather than an uncalibrated 'risk score' or black-box probability.

Suggested components: non-CRT application function indicator, in-degree/out-degree, entry-point proximity with distance and bounds disclosed, exact string-xref distinctiveness, API activity signals, error/branch complexity, reaching a security signal, user focus, and a bounded caller/callee neighborhood. The score must carry individual contributions and a list of missing features. Library/runtime functions may be deprioritized, **not erased**, especially when a function has meaningful application callers/callees. Preserve a toggle for 'show all'.

For C++ routines, distinguish standard C++/CRT functions from application logic; do not suppress one merely because it has a demangled C++ name or a callsite. Be able to surface the common app caller and both overload implementations even if they have low degrees.

### D4. Deterministic routing and smaller-model success

Before asking the LLM to choose tools, route common intent patterns to deterministic retrieval: WHO-CALLS, WHAT-IT-CALLS, SHOW-EVIDENCE, STRING-USAGE, FIND-CALL-PATH, SECURITY-SIGNALS, COMPARE-VIEWS, OVERVIEW. The LLM should handle ambiguity and explanation rather than inventing graph structure. Retain trace events. Add per-tool output paging, caching, and an enforced approximate token budget (context characters alone are insufficient). Keep a final cited answer with explicit omitted-evidence counts.

The M8 agent already has deterministic fallbacks for certain graph questions and binary overviews. Extend this design; do not replace it with an unrelated framework.

### D5. Analyst-facing evidence report

Simple report shape per function:

```text
Name / address / status / is_thunk
Why selected: transparent ranking contributions
Plain-English summary: advisory
Observed calls: direct CALLs with callsites
Resolved thunk hops: separate JMP edges and chains
String uses: exact source instruction -> data address
Dataflow: parameter/reg -> operations -> calls/returns where traced
Assembly/C comparison: supported/uncertain/disagreement
Security indicators: SIGNAL only, never confirmed vulnerability by default
Evidence refs: exact IDs, source tables, address and model/version
Coverage: truncated areas and unavailable analyses
Actions: navigation, export, copy references, request more evidence
```

The existing Java panel should be extended or bridged to Python using a narrow localhost IPC/API (after security review). Do not build an elaborate UI before core evidence correctness is demonstrated. A static HTML or Markdown report generated locally from structured facts can be a lower-risk interim deliverable.

## E. Comparative benchmark design

### Systems

Run A.I.R.E. and relevant comparable paths of GhidrAssist and LaurieWired/GhidraMCP. Use bethington/ghidra-mcp as an additional *analysis tool API* reference; RevEng.AI only where service access and data-handling terms are acceptable. Treat the same locally hosted model and same inference context as a controlled baseline when possible, and report unavoidable differences (some systems use service-hosted models or a different agent architecture).

### Data

1. A.I.R.E. unstripped ELF (controlled ground truth): source-based expected functions, calls, semantic task interpretations.
2. The same stripped ELF: symbol recovery/naming and evidence under uncertainty.
3. Professor's `FunctionOverloading.exe` (PE32 x86 C++): exact known xrefs, overload arithmetic, CRT thunks, and caller-vs-implementation distinctions.
4. A small purpose-built negative-control corpus: similar API presence but safe bounded sizes, unreachable functions, no copied external user input, indirect calls, stripped symbols, deliberately confusing strings.
5. Optionally one larger legally obtained, non-sensitive sample for performance scaling.

Keep golden answers outside model context. Disclose model, version, model options, Ghidra version, machine hardware, binary SHA-256, analysis flags, and timeouts.

### Tasks and metrics

| Task | Metric | Failure of interest |
|---|---|---|
| Function inventory | precision/recall vs annotated ground truth (recognize disassembler coverage limitations) | Unrecognized and fake functions |
| Direct calls | edge precision/recall, site accuracy | Conflated JMP/thunk with CALL; hallucinated indirect targets |
| String/function links | exact xref match accuracy | Treat global string as local evidence |
| C++ overload understanding | correct operation/argument/result explanation | Confusing `float10`, `CONCAT44`, `MOVSD` forms |
| Naming suggestions | human-reviewed top-1/top-3 usefulness, no-ground-truth-in-prompt | generic or misleading names |
| Grounded explanations | rate of claims with supporting evidence **and** independently correct interpretations | citation ID exists but statement is wrong |
| Security signals | detection on positives, false positive rate on controls, evidence completeness | API presence falsely labeled vulnerability |
| Agent orchestration | task completion, wrong tool, timeout, invalid JSON, incomplete answer | small LLM fails despite stored facts |
| Performance | cold/warm indexing time, response latency, memory, model calls/tokens | worst-case regressions |
| Safety | original hash unchanged, no execution, no auto-write, no unexpected connections | cross-binary leakage, unreviewed edits |

At least 3 repeated runs for any stochastic answer and paired identical tasks for every comparison. Report raw counts, not just percentages. Do not advertise a speedup/accuracy improvement until statistically meaningful enough results exist for the claim.

## F. Proposed order before end-of-November milestone

**Phase 0 (reliability):** get tests green, reconcile current docs, make ELF/PE repeatable, preserve binary hashes; perform smoke checks in original isolated Kali environment.

**Phase 1 (highest leverage):** create typed function-to-string xrefs and thunk associations; SQLite migration; add read-only agent tools and deterministic rendering; prove against professor's overload sample.

**Phase 2 (distinctive accuracy):** add focused assembly/P-code context, a verification-aware plain-English instruction explorer, deterministic routing, and transparent rank + CRT filtering.

**Phase 3 (analyst experience):** produce concise evidence report, basic graph/navigation, use persistent analyst notes/summaries only as non-factual annotations, optional Ghidra panel integration.

**Phase 4 (research claims):** independent repeatable comparison against at least two other assistants; publish test fixtures, score rubric, method, limitations, and observed data. Defer independent dynamic execution and CVE lookup until source/sink/provenance quality is stronger.

## G. Codex-ready initial implementation prompt

> You are working in existing project `~/aire` (lowercase). Do not start from scratch. Preserve M1–M8 behavior, keep all target analysis read-only, and do not execute or modify any analyzed binary. Use test binaries under `tests/` and the professor-provided `FunctionOverloading.exe`; prefer small fixtures before large samples. Read `docs/CURRENT_STATE.md`, `docs/M8_AGENT.md`, `docs/ARCHITECTURE.md`, `professor_samples/function_overloading/README.md`, and relevant source before coding.
>
> **Task:** Implement M9-A and M9-B: exact typed function→string/data cross-reference storage and verified thunk→target jump relationships. Add schema migration, read-only query API, corresponding narrowly scoped M8 tools (`get_function_strings`, `get_xrefs`, `get_thunk_target`), provenance/truncation/ambiguity handling, and regression/integration tests. Preserve direct CALL edges exactly as encoded; never silently turn a JMP hop into a CALL. Persist references with source instruction address, target address/artifact ID, function ID, and evidence category. Extend deterministic evidence retrieval to place a selected function's true local string references ahead of unrelated global artifacts. Ensure duplicate indexing is deterministic. Demonstrate professor PE relationships including two overload functions through thunks and their strings. Add an explicit regression control for unresolved/indirect calls and ensure no fabricated edges. After code tests, report test commands/results, changed files, analysis correctness, and limits. Do not commit/push or modify the canonical Java plugin without explicit approval.
>
> **Pre-task fix:** The current snapshot's unit suite has a host-validation policy mismatch for `http://[::ffff:127.0.0.1]`. Resolve that discrepancy with minimal scope, and get the pure-Python test suite green first.

## H. References and research limitations

- A.I.R.E. uploaded archive: inspected repository files and docs cited above.
- GhidrAssist: https://github.com/symgraph/GhidrAssist
- LaurieWired GhidraMCP: https://github.com/LaurieWired/GhidraMCP
- bethington GhidraMCP: https://github.com/bethington/ghidra-mcp
- RevEng.AI Ghidra plugin: https://github.com/RevEngAI/plugin-ghidra
- Gepetto (traditional IDA LLM-baseline concept): https://github.com/JusticeRage/Gepetto
- angr: https://github.com/angr/angr
- Official Ghidra HighFunction/PcodeOp API pages linked above.

All competitor capabilities are **developer-documented**, not independently benchmarked. This report is a source-based engineering plan, **not** evidence A.I.R.E. currently outperforms any competitor. No user GitHub history or latest private/unpushed files were authenticated. All implementation status statements refer to the supplied October 5 snapshot.
