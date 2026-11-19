# A.I.R.E. graduate defense — verified evidence packet

Prepared 2026-11-17 for Laurene Robinson's M.S. Cybersecurity comprehensive
project defense, St. Mary's University, Fall 2026. Source material for building
the PowerPoint — **no slides were created**. Companion files:

- [DEFENSE_FEATURE_MATRIX.md](DEFENSE_FEATURE_MATRIX.md) — every feature, status, entry point, test, demo readiness
- [DEFENSE_DEMO_RUNBOOK.md](DEFENSE_DEMO_RUNBOOK.md) — exact live-demo commands, expected output, fallbacks
- [defense_assets/](defense_assets/) — three Mermaid diagrams, screenshot checklist, fresh genuine outputs

**How to read the evidence labels**

- **FRESH** — reproduced by me in this session on 2026-11-17 (outputs saved in
  `docs/defense_assets/fresh_outputs_20261117/`).
- **HISTORICAL (date, file)** — recorded earlier in the repository; not re-run today.
- **BACKGROUND** — general reverse-engineering knowledge, not an A.I.R.E. result.

Nothing in this packet is an accuracy percentage for AI output, a detection
rate, or a time-savings figure, because none has been measured.

---

## 0. Repository and environment state (verified 2026-11-17)

| Item | Observed |
|---|---|
| Repository | `/home/laurene/aire` |
| Branch / HEAD | `m10-host-access-hardening` / `ebacf4d` "docs(m10): update split-host deployment and defense evidence" (on top of `f33ee23`, `87f87b1`, `6081683`, `8e402e4`) |
| Uncommitted at start | Modified: `aire-server/tests/test_{agent,chat,naming}_integration.py` (remote-Ollama opt-in for live tests only), `docs/DEMO_M10.md`. Untracked: `docs/DEMO_BACKUP_CHECKLIST.md`, `docs/DEMO_READINESS_REPORT.md`, `docs/DEMO_READY_RUNBOOK.md`, `scripts/verify_defense_demo.py` |
| Added by this task | `docs/DEFENSE_EVIDENCE_PACKET.md`, `docs/DEFENSE_DEMO_RUNBOOK.md`, `docs/DEFENSE_FEATURE_MATRIX.md`, `docs/defense_assets/**`. No application source changed; nothing committed |
| OS / VM | Ubuntu 24.04.5 LTS, kernel 7.0.0-43, 6 vCPU, 17 GiB RAM (14 GiB available), 4 GiB swap, 80 GB disk with **53 GB free** (earlier readiness notes' "~123 MiB free" blocker is resolved) |
| Python backend | `aire-server/.venv`: Python 3.12.3, `aire-server` 0.0.1 (editable), `pyghidra` 3.1.0, `jpype1` 1.5.2, `pytest` 9.2.0. `pyproject.toml`: `requires-python >=3.10`, no runtime deps, optional `indexing = ["pyghidra==3.1.0"]`, console script `aire = aire.agent.cli:main` |
| Ghidra | `/home/laurene/tools/ghidra` → `ghidra_12.1.3_PUBLIC` (`application.version=12.1.3`); `GHIDRA_INSTALL_DIR` set in shell |
| Java | OpenJDK 21.0.13.0.3 (`/usr/lib/jvm/java-21-openjdk-amd64`); `JAVA_HOME` **not** set in shell (pass it explicitly) |
| Gradle | **Not installed** (Ghidra 12.1.3 requires ≥ 8.5) — Java extension cannot be rebuilt here without installing it |
| Guest Ollama | 0.35.0 at `127.0.0.1:11434`, model `qwen2.5-coder:1.5b` |
| Windows Ollama | reachable from guest at `10.0.2.2:11434`, version 0.40.16, models `qwen2.5-coder:1.5b` (Q4_K_M, 986 MB) and `llama3.2:latest`; none loaded. **No generation was sent in this session** |
| Shell env | `AIRE_OLLAMA_HOST=http://127.0.0.1:11434` (guest!), `AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b`, `AIRE_OLLAMA_NUM_CTX=4096` — see runbook warning |
| Running service | An `aire gui` (pid 9388) on **127.0.0.1:8770** with `demo_artifacts/m10/defense_20261117/demo.sqlite`, launched without `--bind 10.0.2.15`; left untouched |
| Demo store | `demo_artifacts/m10/defense_20261117/demo.sqlite`, 6,619,136 B, SHA-256 `f88fa14e…d379` — matches the recorded value and was unchanged by every check below |

---

## 1. Phase 1 — actual project state

### 1.1 What A.I.R.E. does today (one paragraph, verified)

A.I.R.E. statically analyzes ELF and PE binaries with headless Ghidra via
PyGhidra, stores every function, decompilation, assembly, instruction-level
P-code facts, strings, imports, exports, direct call edges, references and
thunks in a SQLite knowledge store, and lets an analyst investigate that
evidence through a browser workspace, a CLI agent, or standalone CLIs.
Deterministic services answer relationship, control-flow, value-origin and
decompiler-consistency questions and evaluate two CWE API rules without a
model. A local Ollama model can be asked to explain bounded evidence; its
output is accepted only as strict JSON whose citations exist in that evidence,
and it is always shown as interpretation, never as fact. The target binary is
never executed and is hash-checked before and after analysis. A separate,
older Java Ghidra extension suggests function names per function and renames
only when the analyst clicks Apply.

### 1.2 Two separate products in one repository

| | Java v1 Ghidra extension (`ghidra-plugin/`) | Python 2.0 backend (`aire-server/`) |
|---|---|---|
| Runs inside | Ghidra desktop (CodeBrowser), user's program | Its own process: headless Ghidra via PyGhidra + stdlib HTTP server |
| Scope | One selected function at a time; lists ≤ 250 functions | Whole binary, persisted |
| Model | Ollama `/api/generate`, default `http://localhost:11434`, `gemma3:4b` (`AirePlugin.java:21-22`) | Ollama, explicit model, loopback default, remote opt-in (`ollama_client.py:59-115`) |
| Writes | **Renames** a function (`setName(…, USER_DEFINED)`) when analyst presses Apply (`AireSuggestionsProvider.java:432-445`) | Never renames/comments/patches; writes only its own SQLite snapshots and session files |
| Tests | None (no Java test tree) | 649 unittest cases |
| Current-env status | Source restored byte-for-byte; **not rebuilt** (no Gradle); `gemma3:4b` not installed anywhere checked | Verified (see §1.4) |
| Integration | **None.** No shared code, IPC or store between the two | — |

Present them as two workflows. Do not show one diagram box labeled "A.I.R.E."
that contains both as if unified.

### 1.3 Documentation contradictions reconciled against code

| Documentation says | Code / fresh evidence shows | Use on slides |
|---|---|---|
| README: M8 adds **18** read-only tools; ROADMAP: "initial twelve" | `AgentTools` registers **27** (19 M8/M9 + 8 M10) — fresh `registry.catalog()` (`agent/tools.py:124-188`) | "27 registered read-only tools" |
| M1 results "106 functions, 134 edges" | Those are for `tests/binaries/aire_test_stripped` (PIE, base `00100000`). The demo fixture `tests/fixtures/simple_elf/aire_test_binary_stripped` is a **different, non-PIE build**: 34 functions, 29 edges, base `00400000` | Always name which fixture a number belongs to |
| Readiness report: disk ~123 MiB free, "avoid further indexing" | 53 GB free now | Blocker resolved; indexing is safe again |
| Readiness report: API on `10.0.2.15:8770` | Current GUI listens on `127.0.0.1:8770` only (Windows Chrome cannot reach it through the NAT rule) | Relaunch per runbook before the Windows rehearsal |
| README setup: Java extension "Ghidra 12.0.1 PUBLIC and JDK 21" | Backend uses Ghidra 12.1.3; Java plugin was never built against 12.1.3 here | List versions separately per component |
| CURRENT_STATE M1: Python 3.11 | Current venv 3.12.3 (`requires-python >=3.10`) | "Developed on 3.11, current 3.12.3" |
| Historical v1 demo script claims (naming accuracy, 10× speed) | No measurement exists (`docs/MS_DEFENSE_M10.md:144-145`) | Do not use |
| `extension.properties`: "MVP plugin proof-of-life", v0.1 | Accurate for the Java plugin | Call it "v1 prototype extension" |
| Call Graph "view" | List of callers/callees; interactive graph unimplemented (`docs/CURRENT_STATE.md:407`) | Draw graphs on slides from stored edges; label as figure |

### 1.4 Verification performed in this session (FRESH)

| Check | Command / method | Result |
|---|---|---|
| Default regression suite (no Ghidra, no model) | `PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests` with Ollama env unset | **649 run, 617 passed, 32 skipped, 0 failures/errors, 24.2 s** (same as the Nov 17 checkpoint) |
| M1 Ghidra integration | `AIRE_RUN_GHIDRA_TESTS=1 … -p test_indexer_integration.py` | OK, 17.3 s. Report: 106 functions / 81 decompiled / 132 strings / 25 imports / 8 exports / 134 edges / 26 warnings / 1,176 references / 47 thunks / 1,600 IR instructions; 14.08 s total; hash `157c7089…6de` unchanged — **identical counts to the historical M1 run** |
| M7 Ghidra integration | `… -p test_security_integration.py` | OK, 3 tests, 13.6 s; controls recompiled with **byte-identical hashes** to those in the demo store; `target_executed: false`; database unchanged |
| Indexer CLI ×3 on stripped simple ELF | `python -m aire.pyghidra.indexer tests/fixtures/simple_elf/aire_test_binary_stripped` | 34 / 29 / 48 / 5 / 7 / 29 edges / 6 warnings each time; 8.48–8.60 s internal, 9.0–9.1 s wall, ~650 MB peak RSS; hash unchanged |
| Ground-truth call graph | SQL over demo store vs `GROUND_TRUTH.md` | 12/12 application functions at `nm` addresses; **14 distinct application edges, 15 callsites** = ground truth |
| Deterministic agent tools | `docs/defense_assets/fresh_outputs_20261117/deterministic_tool_probe.py` (no model client constructed) | 27 tools; graph tools 0.2–0.8 ms; invalid inputs rejected (unknown tool, out-of-bound limit, unknown function); M10 answers for `validate_input` correct vs objdump; DB hash unchanged |
| CWE CLI scans | `python -m aire.security.rule_engine <db> <binary_id>` | `unsafe_copy` CWE-120 SIGNAL/LOW @ `00401183`; `dangerous_gets` CWE-242 SIGNAL/LOW @ `00401178`; `safe_copy` and simple ELF NOT_APPLICABLE; 50 ms per scan process |
| Naming candidates (no model) | `python -m aire.ai.naming <db> <stripped id> --candidates --limit 8` | 8 `FUN_…` candidates, all ground-truth application functions |
| GUI access control | `curl` to running server without token | `/api/health` 401; foreign `Host` 403; `POST /api/chat` without Origin 403; CSP / nosniff / no-referrer headers |
| Independent disassembler | `objdump -d -M intel … \| grep -A2 4011dc` | `cmp QWORD PTR [rbp-0x10],0x0` / `je 4011ea` — matches A.I.R.E.'s stored instruction and explanation |

**Not run (and why):** the full Ghidra-enabled suite (~10 min; avoided
contending with your running GUI — recommended before sign-off); the four
live-model tests and any model generation (not requested, and historical VM
freezes under inference — they are the top rehearsal measurement, see §15);
the Java extension build (Gradle absent); any Windows-side check (not
reachable from this session).

---

## 2. Slide 1 — Project introduction

- **Name:** A.I.R.E. — AI-Assisted Reverse Engineering
- **Author:** Laurene Robinson · **Program:** M.S. in Cybersecurity, comprehensive project · **Institution:** St. Mary's University · **Semester:** Fall 2026
- **One-sentence description:** A.I.R.E. is a static binary-analysis system that
  turns Ghidra's analysis of a compiled program into a persistent, queryable
  evidence base, and lets an analyst ask questions whose answers are either
  computed deterministically or produced by a local language model and
  validated against that evidence.
- **Purpose:** reduce the manual effort of locating, connecting and checking
  evidence in stripped binaries, while keeping every AI statement attributable
  and every change under analyst control.

**Tagline options** (pick one):

1. *"Evidence first, AI second: grounded, read-only assistance for binary analysis."*
2. *"Every answer cites the binary."*
3. *"Ghidra supplies the facts, rules find the signals, the model explains — the analyst decides."*

Option 3 mirrors the project's own architecture statement (`README.md:68-69`).

**Visual:** title slide with the split-host diagram thumbnail, or the
`aire_test_binary_stripped` function list showing `FUN_004011bc`.

---

## 3. Slide 2 — Problem and solution

### 3.1 Background (BACKGROUND — general knowledge, not A.I.R.E. results)

- **Compilation discards intent.** Variable names, types, comments and much
  structure are lost; inlining and optimization (`-O2`) reshape code so that
  source functions do not map one-to-one to machine functions.
- **Stripped symbols.** `strip --strip-all` removes the symbol table, so tools
  show placeholder names such as `FUN_004011bc`; analysts must infer purpose
  from instructions, strings, calls and data use.
- **Manual function identification is slow and error-prone** — hundreds to
  thousands of functions (e.g. 2,299 in `sleigh.exe`, 6,255 in `decompile.exe`
  per `docs/M9_FINAL_REPORT.md:18-19`), most of them runtime/library code.
- **Relationships are hard to hold in your head.** Purpose often emerges only
  from callers, callees, shared helpers and data references across functions;
  indirect calls and thunks hide edges.
- **Spotting insecure code.** Risky APIs (`strcpy`, `gets`) are easy to grep in
  source but in a binary must be tied to imports, thunks and actual callsites;
  presence of an import is not proof of use, and use is not proof of a bug.
- **Decompiler output is itself a model.** Decompiled C can omit or
  mis-type computations (A.I.R.E. found one such case — §11.6).
- **Unverified AI explanations are a new risk.** LLMs produce fluent but
  unsupported claims (invented callers, reversed edge directions) and can be
  steered by text inside the binary (prompt injection).

### 3.2 What A.I.R.E. does about each (VERIFIED capabilities only)

| Challenge | A.I.R.E. mechanism | Evidence |
|---|---|---|
| Stripped names | Same deterministic facts for stripped and debug builds; naming-candidate discovery for generic `FUN_` names | FRESH: stripped and debug simple ELF both 34 functions / 29 edges / 395 IR instructions; 8 candidates all application functions |
| Manual identification | Whole-binary index with application-relevance ranking that demotes runtime scaffolding | FRESH: candidate list excludes `_start`, `frame_dummy`, etc. |
| Relationships | Persisted CALL graph with exact callsites; callers/callees/paths in < 1 ms | FRESH: 14/15 ground-truth edges/callsites; probe timings |
| Insecure code | Deterministic CWE-120/242 rules requiring import + external function + resolved call | FRESH: positive and negative controls |
| Decompiler trust | Assembly/P-code vs decompiled-C cross-validation | FRESH CONSISTENT; HISTORICAL POTENTIAL DISCREPANCY on `aes_gcm.exe` |
| Unverified AI | Strict JSON + citation existence + behavior-grounding checks; deterministic answers for graph questions | Unit tests; HISTORICAL live rejections (M6, M8) |

### 3.3 Statements for the slide

- **Problem statement:** Analysts reverse-engineering stripped binaries must
  manually rebuild function purpose and relationships from low-level evidence,
  and AI assistants that could help produce claims that are not tied to that
  evidence.
- **Solution statement:** A.I.R.E. indexes the whole binary once with Ghidra,
  stores the facts, answers structural questions deterministically, and admits
  model explanations only when they cite stored evidence — without executing or
  modifying the target.
- **Value proposition:** faster navigation to the relevant functions and
  relationships, with every statement traceable to an address, and an explicit
  line between fact, signal and interpretation. (Do not quantify "faster":
  no analyst-time study exists.)

---

## 4. Slides 3–4 — System requirements

### 4.1 Python analysis backend (verified environment, not minimums)

| Component | Version in use | Source |
|---|---|---|
| OS | Ubuntu 24.04.5 LTS (VirtualBox guest on Windows 11 laptop) | `/etc/os-release` |
| Python | 3.12.3 (package requires ≥ 3.10; historical M1 used 3.11) | `.venv`, `pyproject.toml:9` |
| PyGhidra | 3.1.0 (pinned in `indexing` extra) | `pyproject.toml:17`, `pip list` |
| JPype1 | 1.5.2 (PyGhidra dependency) | `pip list` |
| Ghidra | 12.1.3 PUBLIC, headless | `application.properties` |
| JDK | OpenJDK 21.0.13.0.3 | `java -version` |
| SQLite | Python standard-library `sqlite3` (no server) | `knowledge/database.py` |
| HTTP/UI | Python standard library HTTP server + static HTML/CSS/JS; no web framework | `pyproject.toml:10` (`dependencies = []`), `api/server.py` |
| Test runner | `unittest` (pytest 9.2.0 also installed) | `docs/DEVELOPMENT.md:65` |
| GCC, binutils | Only for rebuilding fixtures / independent `objdump` ground truth | `tests/fixtures/simple_elf/build.sh` |

### 4.2 Local inference

| Item | Value |
|---|---|
| Runtime | Ollama — Windows 0.40.16 (current deployment); guest 0.35.0 also installed |
| Model used in validation | `qwen2.5-coder:1.5b`, Q4_K_M, 986 MB, `AIRE_OLLAMA_NUM_CTX=4096` |
| Why 4096 | At the code default 32768 the guest ran out of memory; 4096 cut KV cache 896 → 112 MiB (HISTORICAL, `docs/CURRENT_STATE.md:314-322`) |
| Other models | `llama3.2:latest` present on Windows, not validated. Java plugin default `gemma3:4b` not installed |
| Required? | **No** for indexing, queries, rules, M10 analyses, naming-candidate discovery and the deterministic GUI answers. **Yes** for M5 chat, M6 suggestions, model-planned agent steps, M10 narration |

### 4.3 Java v1 extension

Ghidra (archived target 12.0.1 PUBLIC) · JDK 21 · Gradle matching the Ghidra
install (12.1.3 needs ≥ 8.5) · bundled Gson 2.10.1 (`ghidra-plugin/lib/`) ·
local Ollama with a pulled model · build with
`./ghidra-plugin/scripts/build_extension.sh` after setting
`GHIDRA_INSTALL_DIR`/`JAVA_HOME`, then install the zip via Ghidra
File → Install Extensions. **Not reproduced in this environment.**

### 4.4 Hardware — observed, not minimum

| Observation | Value | Source |
|---|---|---|
| Dev VM | 6 vCPU, 17 GiB RAM, 80 GB disk | FRESH |
| Indexer peak RSS, small ELF | ~650 MB | FRESH (`/usr/bin/time`) |
| Python+JVM peak, `sleigh.exe` cold | 2.39 GB | HISTORICAL `docs/M9_FINAL_REPORT.md:34-41` |
| Full Ghidra test suite peak | 2.96 GB | same |
| Demo store size | 6.6 MB (7 binaries); `m10.sqlite` 133 MB | FRESH |

Say "observed on the development VM"; no minimum specification has been tested.

### 4.5 Install / configure / start (verified commands)

```bash
cd ~/aire
# existing venv; nothing is installed automatically
aire-server/.venv/bin/pip list | grep -i -E 'pyghidra|aire'
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
# index one binary (read-only; prints counts)
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/fixtures/simple_elf/aire_test_binary_stripped
# deterministic CWE scan of a stored binary
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.security.rule_engine <db> <binary_id>
# browser workspace (see runbook for the split-host variant)
aire-server/.venv/bin/aire gui --database demo_artifacts/m10/defense_20261117/demo.sqlite --no-browser --no-prewarm
# CLI agent (needs a model for planning)
aire-server/.venv/bin/aire chat aire_test_binary --database <db> --question '...'
```

---

## 5. Slide 5 — Functional requirements matrix (slide-sized)

Full detail with file:line and tests is in the
[feature matrix](DEFENSE_FEATURE_MATRIX.md). Slide version:

| Requirement | How accessed | Status |
|---|---|---|
| Load and index a binary (ELF/PE) | indexer CLI; GUI upload | Verified (fresh) |
| Decompiled code + bounded assembly | GUI Decompiled View / Function explorer; tools | Verified (fresh) |
| Instruction-level facts (P-code) | Function explorer Assembly tab | Verified (objdump 100 % on 76,420 instr., historical) |
| Function identification | Functions list; `list_functions` | Verified (12/12 ground truth) |
| Imports / exports / strings | GUI tabs; `get_artifacts` | Verified (fresh) |
| Call graph (direct CALLs) | Call Graph lists; `get_callers`/`get_callees` | Verified (14/15 ground truth) |
| SQLite persistence | automatic | Verified (round-trip tests) |
| Relationship queries | tools, paths, rankings | Verified (fresh, < 1 ms) |
| Evidence retrieval with provenance | Evidence panel; `retrieve_evidence` | Verified |
| AI explanation | GUI chat cards; `aire chat` | **Partial** (live model largely timeouts/rejections) |
| AI function naming | `python -m aire.ai.naming` | Candidates verified; suggestions **not demonstrated** |
| CWE checks | Findings view; rule CLI | Verified (fresh controls) |
| Conversational agent | GUI chat; `aire chat` | Deterministic paths verified; model planning **partial** |
| Session management | Recent Chats; `--session` | Verified |
| Analyst review and approval | Python advisory only; Java Apply | Verified (Python); Java not demonstrated |
| Read-only / integrity | SHA-256 before/after; `mode=ro` | Verified (fresh) |
| Error and insufficient-evidence states | structured errors; `INSUFFICIENT_EVIDENCE`, `NOT_APPLICABLE` | Verified (fresh) |

---

## 6. Slides 6–8 — System design (diagram sources)

All three are Mermaid source files; render at <https://mermaid.live> or with
`@mermaid-js/mermaid-cli` (not installed — no packages were added).

| Slide | File | Key talking points |
|---|---|---|
| 6 | [`diagram1_end_to_end_architecture.mmd`](defense_assets/diagram1_end_to_end_architecture.mmd) | Windows hosts Chrome + Ollama; Ubuntu VM hosts everything analytical; only one writer (index worker subprocess); Java plugin is a separate box with its own Ollama path and the only rename arrow |
| 7 | [`diagram2_analysis_knowledge_pipeline.mmd`](defense_assets/diagram2_analysis_knowledge_pipeline.mmd) | hash → disposable project → auto-analysis → extraction → `ProgramIndex` → release unsaved → hash check → atomic save → M3/M4 consumers |
| 8 | [`diagram3_agent_security_validation.mmd`](defense_assets/diagram3_agent_security_validation.mmd) | deterministic route first; bounded tool loop; rules need no model; model output passes strict validation or is withheld; analyst decides |

Speaker line for slide 6: "The browser and the model run on Windows; every
fact is computed inside the Ubuntu VM. The Java extension on the right is the
original prototype — a separate workflow, not connected to the backend."

---

## 7. Slides 9–11 — Important code

Excerpts are copied verbatim. Leading indentation is reduced for slide width
only; no token was changed.

### 7.1 Whole-binary indexing with PyGhidra — `aire-server/src/aire/pyghidra/indexer.py:164-181`

```python
stage = 'analysis initialization/completion'
report_progress('Running Ghidra static auto-analysis')
tick = time.perf_counter()
with profile_stage('auto_analysis'):
    count('analyze_calls')
    analysis_log = pyghidra.analyze(program)
analysis_seconds = time.perf_counter() - tick
if analysis_log:
    warnings.append(f'Analysis: {analysis_log}')
monitor = pyghidra.task_monitor()
stage = 'fact extraction'
report_progress('Extracting functions, decompilation and assembly')
binary = extract_binary(program, path, before, warnings)
with profile_stage('function_discovery'):
    manager = program.getFunctionManager()
    functions = list(manager.getFunctions(True)) + list(manager.getExternalFunctions())
    functions.sort(key=lambda f: (bool(f.isExternal()), str(f.getEntryPoint())))
    count('functions_discovered', len(functions))
```

Paired integrity check, `indexer.py:242-250`:

```python
finally:
    with profile_stage('integrity'):
        try:
            after = sha256_file(path)
        except OSError as exc:
            raise IndexingError(f'Cannot verify input integrity for {path}: {exc}') from exc
        if after != before:
            raise IndexingError(f'Input SHA-256 changed during indexing: {path}')
result.metadata['input_sha256_unchanged'] = True
```

- **Plain English:** run Ghidra's analyzers on a throw-away copy of the program,
  keep the analyzer's log as a warning instead of hiding it, then collect every
  internal and external function in a stable order. After everything, hash the
  file again; if one byte changed, the whole result is rejected.
- **Technical purpose:** single entry point that converts Ghidra's in-memory
  program model into an immutable `ProgramIndex`; deterministic ordering gives
  stable function IDs (`<sha256>:<address>`).
- **Why it matters:** one analysis pass feeds every later feature; warnings are
  preserved as evidence of incompleteness; integrity is enforced, not assumed.
- **Architecture fit:** Diagram 2, boxes "auto-analysis" → "Fact extraction"
  and "SHA-256 after".
- **Verify:** `AIRE_RUN_GHIDRA_TESTS=1 … -p test_indexer_integration.py`
  (FRESH OK) or the indexer CLI in the runbook (FRESH: 34 functions, hash unchanged).

### 7.2 Deterministic CWE rule — `aire-server/src/aire/security/rules/api_calls.py:48-65`

```python
for call in facts.calls:
    caller, callee = by_id[call.caller_function_id], by_id[call.callee_function_id]
    if caller.is_external or caller.is_thunk or callee.current_name != self.api:
        continue
    matches = [(f, a) for f, a in pairs if f.function_id == callee.function_id or
               (callee.is_thunk and not callee.is_external and callee.namespace
                and callee.namespace != 'Global' and callee.namespace == f.namespace)]
    if not matches:
        continue
    # Deterministic canonical external/import pair; no synthesized edge.
    external, artifact = sorted(matches, key=lambda pair: (pair[0].function_id, pair[1].artifact_id))[0]
    evidence = [facts.source('functions', caller.function_id),
                facts.source('functions', callee.function_id),
                facts.source('function_edges', call.source_id),
                facts.source('artifacts', artifact.artifact_id)]
    local_limits = list(LIMITATIONS)
    local_assumptions = list(assumptions)
    if callee.is_external:
```

- **Plain English:** for every stored call, keep only calls from real program
  code to a function named `strcpy` (or `gets`) that is tied to an exact stored
  import. Each signal carries four pieces of evidence: caller, callee, the call
  edge, and the import.
- **Technical purpose:** a stateless, versioned rule (`AIRE-CWE-120-UNBOUNDED-COPY`
  1.0.0, `:90-96`) over an immutable fact snapshot. A direct external call gets
  MEDIUM strength; a call through an import-named thunk gets LOW and an explicit
  "binding not persisted" limitation (`:65-74`).
- **Why it matters:** no model, no guessing — import presence without a call is
  `INSUFFICIENT_EVIDENCE` (`:85-87`), no prerequisite is `NOT_APPLICABLE`
  (`:45-46`), and the maximum state is `SIGNAL`; `CONFIRMED` does not exist.
- **Architecture fit:** Diagram 3, "M7 RuleEngine (no model)".
- **Verify:** `python -m aire.security.rule_engine <db> <unsafe_copy id>` (FRESH:
  SIGNAL, LOW, `00401183`); `test_security_rules.py` (19 tests).

### 7.3 Agent orchestration and grounded retrieval — `aire-server/src/aire/agent/runner.py:459-476`

```python
target = session.current_function_id
# Overview questions must not accidentally inherit a prior function selection.
if overview or any(s in lower for s in ('this binary', 'the binary', 'important functions', 'all functions')):
    target = None
evidence = execute('retrieve_evidence', {'function': target, 'max_chars': self.limits.evidence_chars})
if not evidence['ok']:
    raise _Stopped('evidence_failure')
stream.emit('answer_started', 'Synthesizing grounded answer')
if required or deterministic:
    # Exact graph questions need exact stored results, not prose
    # that can reverse edge direction or invent relationships.
    answer = 'A.I.R.E. stored graph results'
else:
    response = AireChatService(self.store, model).ask(request=ChatRequest(session.binary_id, question, target,
        max_total_context_chars=self.limits.evidence_chars), evidence_bundle=tools.last_evidence,
        compact=compact,
        on_text=on_text,
        require_behavior_grounding=overview or any(s in lower for s in ('what does', 'why', 'explain')))
```

Paired validation, `aire-server/src/aire/ai/prompt_builder.py:311-318`:

```python
def ids(value, *, required=True):
    if not isinstance(value, list) or len(value) > 100 or any(not isinstance(v, str) for v in value):
        fail('evidence IDs must be a bounded list of strings')
    if required and not value:
        fail('Concrete claims need evidence IDs')
    if len(set(value)) != len(value) or any(v not in citations for v in value):
        fail('Duplicate or nonexistent evidence citation')
    return tuple(value)
```

- **Plain English:** every answer ends with one mandatory evidence retrieval.
  If the question is about the call graph, the stored results are printed as-is
  and the model is not allowed to paraphrase them. Otherwise the model must
  answer in JSON, and every claim must cite IDs that exist in that evidence.
- **Technical purpose:** a reserved final tool slot (`:388`), a
  graph-question bypass of prose synthesis, and citation-ID validation; behavior
  questions additionally require a code or call-edge citation (`chat.py:297-300`).
- **Why it matters:** it is the direct fix for observed failures — the 1.5B
  model once produced citation-valid prose with an invented caller and a reversed
  edge (`docs/M8_AGENT.md:290-293`).
- **Architecture fit:** Diagram 3, "retrieve_evidence" → decision → "Validation".
- **Verify:** `test_agent_runner.py` (24 tests), `test_chat.py:125`
  `test_nonexistent_citation`; deterministic GUI question in the demo.

**Honest caveat for Q&A:** citation existence is not semantic entailment — a
model can cite a real fact and still say something false about it
(`chat.py:311` appends exactly that caveat to every answer).

---

## 8. Results and validation slide

### 8.1 FRESH (2026-11-17, this session)

| Measurement | Value |
|---|---|
| Default suite | 649 run / 617 passed / 32 skipped / 0 failed, 24.2 s |
| M1 Ghidra integration | pass; 106 fn / 81 decompiled / 132 strings / 25 imports / 8 exports / 134 edges / 26 warnings on `tests/binaries/aire_test_stripped`; 14.08 s |
| M7 Ghidra integration | 3/3 pass; reproducible control builds |
| Indexer CLI, stripped simple ELF | 34 fn / 29 decompiled / 48 strings / 5 imports / 7 exports / 29 edges / 6 warnings; 8.48–8.60 s (3 runs, identical counts) |
| Ground truth | 12/12 application functions; 14/14 distinct application edges; 15/15 callsites |
| Debug vs stripped | identical function/edge/IR counts (34 / 29 / 395); names `validate_input` vs `FUN_004011bc`; same M10 trace and CONSISTENT verdict |
| SHA-256 | 4 fixtures and demo DB unchanged after all checks |
| Query latency (single sample each, warm) | 0.04–0.82 ms per tool call |
| Security controls | 2 SIGNAL (both LOW), 2 binaries NOT_APPLICABLE |
| Invalid-input rejection | unknown tool, out-of-bounds integer, unknown function all returned structured errors |
| GUI access control | 401 / 403 / 403 |

### 8.2 HISTORICAL (cite date and file)

| Measurement | Value | Source |
|---|---|---|
| Ghidra-enabled suite, Nov 17 Codex audit | 649 run / 645 pass / 4 live-model skips | `docs/HOST_ACCESS_SECURITY_REVIEW.md` |
| M10 vs objdump (5 binaries) | 100 % on 76,420 boundaries & mnemonics, 9,867 targets, 10,318 memory operands, 4,128 branch relations; 1,302 relations beyond the oracle not verified | `docs/M10_CHECKPOINT.md:52-63` |
| M2 round trip | exact equality; save 0.53 s, load 0.0016 s; 416 KiB | `docs/CURRENT_STATE.md:188-196` |
| M3 warm query means | callers 0.078 ms, callees 0.162 ms, depth-3 0.706 ms | `docs/CURRENT_STATE.md` M3 section |
| M9 extraction speed-up | sleigh.exe 77.7 → 33.4 s; professor PE 4.82 → 3.06 s (medians, n = 5) | `docs/M9_FINAL_REPORT.md:17-30` |
| GUI rehearsal (guest Firefox) | 37/37 actions × 2 launches; median 44–68 ms per view, 177.5 ms deterministic question | `docs/DEMO_READINESS_REPORT.md` |
| M5 live | 2 targeted requests accepted; binary summary timed out; one citation-valid but wrong interpretation not counted | `docs/CURRENT_STATE.md:314-336` |
| M6 live | output **rejected** (address-bearing names, invented citations); 0 accepted | `docs/CURRENT_STATE.md:356-367` |
| M8 live (5 questions) | 1 rejected `unsupported_grounding`, 1 deterministic success, 3 timeouts | `docs/M8_AGENT.md:270-283` |

### 8.3 Things you must NOT put on the slide

Naming accuracy %, AI answer accuracy %, vulnerability detection rate, false-
positive rate, analyst time saved, "10× faster", calibrated confidence. None
has been measured.

### 8.4 What a new controlled experiment could measure (proposed)

1. **Live grounding experiment:** run the 4 skipped live tests plus a fixed set of
   10 questions on the simple ELF via the Windows model; record accepted /
   rejected / timed-out, latency, and manual correctness against `GROUND_TRUTH.md`.
2. **Naming on stripped fixture:** for the 8 candidates, record suggestions
   accepted by validation and compare by address to `nm` names (exact /
   descriptive-match / wrong) with a pre-written rubric.
3. **Indexing scale:** indexer CLI on the 11 benchmark fixtures, 3 runs each,
   reporting median and range with VM-stall detection (`scripts/stall_monitor.py`).
4. **Rule controls:** add more positive/negative C controls (e.g. `strncpy`,
   `fgets`) to measure the rules' scope precisely.

---

## 9. Security boundaries and limitations slide

| Question | Answer | Evidence |
|---|---|---|
| How are originals protected? | Never executed; imported into a disposable unsaved project; SHA-256 before/after, mismatch rejects result | `indexer.py:117-133,237-250`; FRESH hashes |
| What is read-only? | All query/agent/rule/naming paths open SQLite with `mode=ro` + `query_only`; tools expose no mutation | `rule_engine.py:135-149`; `test_gui_server.py:133` |
| What writes? | Only the index worker subprocess (explicit upload/index job) and session files — separate from facts | `binary_library.py:341-346`; `index_worker.py` |
| Where is approval required? | Everywhere: Python backend never renames, comments or patches; Java plugin renames only on Apply, one function at a time, inside a rollback-safe transaction | `AireSuggestionsProvider.java:432-445` |
| How are AI responses validated? | Strict JSON, exact field set, bounded sizes, citation IDs must exist, cross-check observations cannot be "facts", behavior claims need code/edge citations, contradiction checks, one retry then withhold | `prompt_builder.py:295-335`, `chat.py:279-306` |
| Evidence attribution | Every fact carries source table + ID + address; findings carry evidence IDs; GUI addresses are links | `tools.py:190` `_provenance`; CLI scan output |
| Unsupported interpretations | Omitted with a reason in "uncertainties"; whole answer withheld if the summary fails | `chat.py:286-300` |
| Why a CWE signal isn't a vulnerability | Rule proves only "an import-tied call to strcpy exists here". Not proven: destination size, source length, attacker control, reachability, runtime binding | `api_calls.py:7-12` (printed with every finding) |
| Model trust boundary | Model on Windows receives bounded evidence text (binary content leaves the VM); remote host requires explicit opt-in; proxies/redirects off | `ollama_client.py:56-115` |
| Web boundary | per-launch token → HttpOnly SameSite=Strict cookie; exact Host/Origin; CSP; ≤ 4 concurrent chats | `server.py:55-59,798-841,1077`; FRESH probe |

**Not implemented:** vulnerability confirmation, CVE matching, taint or
argument-size analysis, dynamic execution/sandboxing, exploit generation,
autonomous actions, Python-side write-back, interactive graph view, completed
M10 evaluation, Windows-side network-exposure verification.

**Java rename vs Python advisory (say it in one breath):** "The original Java
plugin can change a name in your Ghidra project, but only after you click Apply
on one suggestion. The Python system can only recommend — it has no code path
that writes to the program."

**Known residual risks (from `docs/MS_DEFENSE_M10.md:101-104`):** plain HTTP
under local confinement; token visible in terminal; no dependency audit; live
prompt-injection resistance unmeasured.

---

## 10. Slide 12 — Lessons learned

| Challenge | Problem | Implemented solution | Evidence |
|---|---|---|---|
| PyGhidra/Ghidra integration | JVM is process-global; Ghidra writes settings/caches; a second JVM fails | One process-wide JVM behind a lock, headless, temp settings/cache dirs, disposable unsaved project, `program.release` | `indexer.py:1-6,47-82,137-147,237-239` |
| Whole-binary evidence | Large PEs: cold analysis > 10 min; decompile timeouts | Parallel decompile workers, timeout → one retry, explicit `decompilation_incomplete` list, cache, pre-warm | `docs/M9_FINAL_REPORT.md`; `indexer.py:183,224-228` |
| Deterministic relationships | Computed/indirect calls and thunks blur the graph | Store only resolved CALLs with callsites; warn on computed calls; separate thunk relations; no inferred edges | `graph_builder.py:21-23`; FRESH 14/15 ground truth |
| LLM context size | 32768 context OOM'd the VM | `AIRE_OLLAMA_NUM_CTX` (4096), character-bounded evidence with explicit truncation | `docs/CURRENT_STATE.md:314-322`; `ollama_client.py:63-73` |
| Unsupported AI claims | Citation-valid but wrong prose (invented caller, reversed edge) | Deterministic graph answers; behavior-grounding requirement; fixed caveats | `runner.py:467-470`; `docs/M8_AGENT.md:290-293` |
| Validating AI names | 1.5B model produced address-bearing names and invented citations | Strict name grammar, generic/address rejection, citation check, abstain allowed | `naming_prompt.py:87-95`; HISTORICAL rejection |
| Reliable agent tools | Model invents tool names/arguments | Typed registry, enum/bound checks, unknown-tool error, result-size cap, reserved final slot | `tools.py:37-100`; FRESH rejections |
| Model failures / timeouts | Local inference stalled the VM for minutes; agent timeouts | Deadlines, cancellation, partial results with facts; deterministic fast paths; narration opt-in; inference moved to Windows | `runner.py:277-284,490-507`; `server.py:626` |
| Read-only boundaries | GUI must index uploads yet keep queries read-only | Separate writer subprocess; read-only connections elsewhere; token/Host/Origin hardening | `index_worker.py`; `test_host_access_security.py` |
| Stripped binaries | No names to anchor questions or ground truth | Address-keyed IDs; stripped/debug pairs; ground truth mapped by address; prompts checked for name leakage | FRESH stripped/debug parity; `docs/M6_NAMING.md` |
| Testing integrity of the oracle itself | Evaluation harness had parser bugs | Five oracle bugs found and fixed (none in A.I.R.E.) before reporting 100 % agreement | `docs/M10_CHECKPOINT.md:64-66` |
| Native crash with deep JSON | A tampered store with 100,000-level nested IR JSON segfaulted CPython's C JSON decoder when the JVM shared the process (no `RecursionError`) | Nesting bound of 64 checked before `json.loads` → `PersistedDataError`; suites run with `ulimit -c 0` | `docs/M10_SECURITY_HARDENING.md:77` |

---

## 11. Slides 13–14 — Live demonstration (summary)

Full step-by-step, commands, expected output, timings, risks and fallbacks are
in the [runbook](DEFENSE_DEMO_RUNBOOK.md). Reliability ranking:

| Step | Interface | Model needed? | Reliability |
|---|---|---|---|
| 1 Launch | terminal + Chrome | no | High after one Windows rehearsal |
| 2 Select binary | GUI Library | no | High (guest rehearsal ×2) |
| 3 Metadata + functions | GUI | no | High |
| 4 Callers/callees | GUI Call Graph | no | High |
| 5 Relationships | GUI + slide figure from stored edges | no | High |
| 6 Decompiled / assembly / branch / trace / cross-validation | GUI Function explorer | no | High (exact trace syntax required) |
| 7 Evidence-grounded question | GUI "What does this function do?" (deterministic route) | no | High |
| 8 Naming | terminal `--candidates` | no | High; live suggestions **not** reliable |
| 9 CWE checks | GUI Findings or rule CLI | no | High |
| 10 Safety property | 401 in a second browser profile; `safe_copy` NOT_APPLICABLE; hash check | no | High |
| Optional: live model answer | GUI model card | **yes** | **Unvalidated** — only if rehearsed successfully on Windows |

### 11.6 Optional backup-only exhibit

`aes_gcm.exe FUN_004075e0` → POTENTIAL DISCREPANCY (writes XMM0 but decompiled
as `void`), HISTORICAL in `docs/DEMO_M10.md` §6. It lives in `m10.sqlite`, not
the compact demo store; show as a screenshot.

---

## 12. Final slide — technical references

Links were selected from known official locations; they were **not re-fetched
in this session** — click-check each before the final deck.

| Topic | Source |
|---|---|
| Ghidra | NSA, *Ghidra Software Reverse Engineering Framework* — <https://ghidra-sre.org/>; source and releases <https://github.com/NationalSecurityAgency/ghidra> |
| PyGhidra | *pyghidra* on PyPI — <https://pypi.org/project/pyghidra/> (source under `Ghidra/Features/PyGhidra` in the Ghidra repo) |
| JPype | *JPype documentation* — <https://jpype.readthedocs.io/> |
| Ollama | <https://ollama.com/>; REST API — <https://github.com/ollama/ollama/blob/main/docs/api.md> |
| Model | *qwen2.5-coder* — <https://ollama.com/library/qwen2.5-coder>; Hui et al., *Qwen2.5-Coder Technical Report*, arXiv:2409.12186 |
| Python | *Python 3.12 documentation* — <https://docs.python.org/3.12/>; `sqlite3` — <https://docs.python.org/3/library/sqlite3.html> |
| SQLite | <https://www.sqlite.org/>; URI `mode=ro` — <https://www.sqlite.org/uri.html>; `PRAGMA query_only` — <https://www.sqlite.org/pragma.html#pragma_query_only>; transactions — <https://www.sqlite.org/lang_transaction.html> |
| CWE-120 | MITRE, *Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')* — <https://cwe.mitre.org/data/definitions/120.html> |
| CWE-242 | MITRE, *Use of Inherently Dangerous Function* — <https://cwe.mitre.org/data/definitions/242.html> |
| x86 semantics | Intel, *64 and IA-32 Architectures Software Developer's Manuals* (Jcc condition table) — <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdms.html> |
| ABI | *System V AMD64 psABI* — <https://gitlab.com/x86-psABIs/x86-64-ABI> |
| Independent disassembler | GNU Binutils, *objdump* — <https://sourceware.org/binutils/docs/binutils/objdump.html> |
| PE format | Microsoft, *PE Format* — <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format> |
| ELF format | *Tool Interface Standard ELF Specification* — <https://refspecs.linuxfoundation.org/elf/elf.pdf> |
| JDK | OpenJDK 21 — <https://openjdk.org/projects/jdk/21/> |
| Gradle | <https://gradle.org/> |
| LLM risks | OWASP, *Top 10 for LLM Applications* (prompt injection) — <https://genai.owasp.org/llm-top-10/> |
| Background reading | Eagle & Nance, *The Ghidra Book*, No Starch Press, 2020; Lacomis et al., "DIRE: A Neural Approach to Decompiled Identifier Naming", ASE 2019 (related work on learned names) |

---

## 13. Phase 5 — defense readiness review (as a reviewing professor)

### 13.1 Strongest accomplishments

1. **Reproducibility.** The M1 index of the stripped fixture reproduced to the
   exact count on a new run months later; three indexer runs gave identical
   output; control binaries rebuild byte-identically.
2. **Independent ground truth.** Call graph checked against hand-written ground
   truth (12/14/15) and instruction facts against GNU objdump (76,420
   instructions) — the oracle is independent of Ghidra and the model.
3. **Explicit epistemic states.** `SIGNAL` / `NOT_APPLICABLE` /
   `INSUFFICIENT_EVIDENCE`, `CONSISTENT` / `POTENTIAL DISCREPANCY` /
   `INSUFFICIENT EVIDENCE`, fact vs interpretation — never "vulnerable" or
   "correct".
4. **Engineering response to measured AI failure.** The deterministic routes
   exist because the model's mistakes were observed and documented.
5. **Security engineering of the tool itself** — integrity checks, read-only
   connections, typed tool registry, web hardening with tests.

### 13.2 What differs from manual RE

Manual Ghidra use answers one question at a time inside one session; A.I.R.E.
persists the whole-program evidence, answers structural questions in
milliseconds with citations, compares the decompiler against the instructions,
and keeps an auditable record of which evidence supported each statement.
(Ghidra itself already offers references, call trees and decompilation; the
contribution is persistence, cross-checking, provenance and grounded
question-answering on top — say so if asked.)

### 13.3 Most convincing sequence

Stripped `FUN_004011bc` → callers/callees → branch at `004011e1` → trace
`[RBP-0x10]` to `strlen` → CONSISTENT → `objdump` agrees → switch to debug
build and reveal it is `validate_input` → CWE SIGNAL on `unsafe_copy` with
"not a vulnerability" limits → `safe_copy` NOT_APPLICABLE → 401 for an
unauthenticated browser.

### 13.4 Weaknesses a committee can challenge

- The "AI" part is the least validated: live chat/naming mostly timed out or
  was rejected; 4 live tests were skipped in every recent suite.
- Fixtures are small and self-built; results on real-world software are limited
  to the professor PE, crypto PEs and large Ghidra PEs.
- Only two security rules, both API-name based.
- No user study; no time-savings evidence.
- Single small model (1.5B) evaluated.
- Java plugin and Python backend are not integrated; Java plugin has no tests.
- Windows-side network exposure not yet verified.
- M10 Phase 6 evaluation incomplete.

### 13.5 Ten challenging questions with evidence-based answers

1. **"If the model fails most live tests, where is the AI in A.I.R.E.?"** —
   The AI is a bounded explainer, not the source of facts. Observed failures
   (`docs/M8_AGENT.md:276-283`) drove the design: graph answers are
   deterministic, and model output is admitted only through validation. The
   honest result is that the safety mechanisms worked (bad outputs were
   rejected), while useful-answer rate is unmeasured.
2. **"Does a valid citation mean the explanation is true?"** — No. Validation
   proves the cited IDs exist and that behavior claims cite code or edges;
   it does not prove entailment. That caveat is appended to every answer
   (`chat.py:311`). One historical citation-valid answer was wrong and was not
   counted as success.
3. **"How do you know Ghidra's facts are right?"** — For instruction decoding,
   objdump agreed on all 76,420 instructions across 5 binaries; for calls, the
   fixture ground truth matched 14/14 edges and 15/15 callsites. Beyond those
   scopes (e.g., 1,302 cross-block relations) correctness is not verified.
4. **"Your CWE rule is just grep for strcpy."** — It is stricter than text
   search: it needs an exact stored import, an external function at that
   address, and a resolved CALL from non-thunk code; import-only yields
   `INSUFFICIENT_EVIDENCE`. But it is still API-level: no size, taint or
   reachability analysis, which is why the maximum state is SIGNAL.
5. **"What about false negatives — inlined copies, `memcpy` misuse, indirect calls?"** —
   Not detected. Computed calls are omitted with a warning
   (`graph_builder.py:21-23`); `NOT_APPLICABLE` explicitly says "not a safety
   assessment". The rules' recall has not been measured.
6. **"Could a malicious binary attack the analyst through A.I.R.E.?"** —
   It is never executed; Ghidra parses it (Ghidra's parser is the attack
   surface). Strings from it reach the model as data labelled untrusted
   (`runner.py:414`) and reach the browser escaped under a strict CSP; deep
   JSON nesting is bounded. Live prompt-injection resistance is unmeasured.
7. **"Why should we believe the stripped results generalize?"** — The stripped
   fixture shows facts are address-identical to the debug build; that is
   expected because stripping removes symbols, not code. Generalization to
   optimized, obfuscated or packed code is not claimed; the `-O2` build is
   indexed but not separately evaluated.
8. **"What are the confidence values?"** — Labels (`low/medium/high`) or, in the
   Java plugin, a heuristic score = model value × evidence weights clamped to
   [0, 1] (`docs/CURRENT_STATE.md:116-121`). Neither is calibrated.
9. **"Why a split Windows/VM deployment, and does evidence leave the VM?"** —
   Local inference inside the VM stalled the guest for minutes; inference moved
   to the Windows host on the same laptop. Yes, bounded evidence text crosses
   to Windows Ollama; that requires an explicit opt-in. No cloud service is used.
10. **"What would you do with three more months?"** — Measure (live grounding
    and naming experiments in §8.4), add argument/size facts so rules can reach
    CANDIDATE, finish M10 Phase 6, verify Windows exposure, and integrate the
    Java plugin as a client of the backend rather than a separate tool.

### 13.6 Claims that cannot currently be supported

Accuracy of AI names or explanations; any detection or false-positive rate;
analyst speed-up; robustness to prompt injection; safety for LAN/internet
exposure; Windows Chrome/NAT confinement; Java extension working on Ghidra
12.1.3; completed M10 evaluation; behavior on packed/obfuscated binaries.

---

## 14. Presentation timing plan

Assumes a ~45-minute slot; scale proportionally if told otherwise.

| Block | Slides | Target | Narration focus |
|---|---|---|---|
| Opening | 1 | 1:00 | name, tagline, one-sentence description |
| Problem/solution | 2 | 2:30 | stripped names, relationships, unverified AI |
| Requirements | 3–4 | 2:00 | two components, versions, "observed, not minimum" |
| Functional matrix | 5 | 2:00 | colour-coded status column |
| Architecture | 6–8 | 5:00 | 1:40 per diagram |
| Code | 9–11 | 5:30 | ~1:50 each: what / why / verify |
| Results | + | 2:30 | fresh vs historical columns |
| Security & limits | + | 2:00 | signal ≠ vulnerability; Java vs Python |
| Lessons | 12 | 2:00 | 4–5 rows |
| **Narration subtotal** | | **24:30** | |
| Live demo | 13–14 | 9:00 | runbook sequence |
| References / close | final | 0:30 | |
| Questions | — | 10:00+ | §13.5 |

**Measuring rehearsal time:** run a stopwatch per block and log it with:

```bash
# type each block name as it STARTS; type `end` when you finish, then Ctrl-D
S=docs/defense_assets/rehearsal_$(date +%Y%m%d_%H%M).log
while read -r -p "block name> " b; do echo "$(date +%s) $b" >> "$S"; done
awk 'NR>1{printf "%-20s %4ds\n", prev, $1-t} {t=$1; prev=$2}' "$S"
```

Rehearse three times; record each block's actual time; cut content from any
block that runs > 20 % over target. Time the demo separately from narration and
note any step exceeding its budget in the runbook.
