# A.I.R.E. local analysis workspace

The A.I.R.E. GUI is a loopback-only web workspace layered directly over the
existing M8 agent. It does not implement a second analysis engine. Chat requests
use `AgentRunner`, tool-panel requests use the same `AgentTools` registry, and
conversation state uses `AgentSession` plus a separate UI transcript. The
analysis SQLite database is always opened through the existing read-only store.

## Launch

From the repository root, use the existing A.I.R.E. virtual environment and
Ollama configuration:

```bash
aire-server/.venv/bin/aire gui tests/fixtures/simple_elf/aire_test_binary \
  --database analysis.sqlite
```

The selected binary must already exist in the persisted analysis database. As
with `aire chat`, a file argument is resolved by SHA-256, while a stored binary
ID or unique stored name also works. If the binary argument is omitted, the GUI
starts with the first persisted analysis and the analyst can switch among stored
analyses from the top bar.

The default URL is `http://127.0.0.1:8765/`. Use `--port` to change the port and
`--no-browser` to prevent automatic browser launch. Remote binding is rejected;
the GUI accepts loopback hosts only.

## Preparing the small development fixture

The GUI never implicitly runs Ghidra or writes an index. To create a development
database from the preferred unstripped fixture, run:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python - <<'PY'
from pathlib import Path
from aire.knowledge.database import BinaryKnowledgeStore
from aire.pyghidra.indexer import index_binary

path = Path("tests/fixtures/simple_elf/aire_test_binary")
index = index_binary(path)
with BinaryKnowledgeStore("analysis.sqlite") as store:
    store.save_program_index(index)
print(index.binary.binary_id)
PY
```

Then launch the workspace with the `aire gui` command above. Use
`aire_test_binary_stripped` only when intentionally validating stripped-symbol
behavior.

## Interface

The welcome screen presents six binary-analysis prompt starters and the active
binary's stored format, architecture, function count and SHA-256. The active
chat view renders concise analyst explanations and public operational events emitted
by the agent. Hidden model reasoning is never requested or shown.

The right-side Analysis Tools panel maps directly to existing read-only tools:

| GUI view | Existing backend tool(s) |
| --- | --- |
| Functions | `list_functions`, `get_function` |
| Strings | `get_artifacts(kind="STRING")` |
| Imports | `get_artifacts(kind="IMPORT")` |
| Call Graph | `get_callers`, `get_callees` |
| Findings | `security_findings` |
| Decompiled View | `get_decompiled_text` |

Selecting a function updates the existing `AgentSession.current_function_id`, so
follow-ups such as "What calls it?" and the code views share the same binary-scoped
selection.

## Session storage

Agent state and GUI transcripts are separate from analysis facts. By default they
are stored under `~/.aire/gui-sessions/`; `--session-dir` can select another
directory. Each GUI conversation has an `.agent.json` file produced through
`AgentSession.save()` and a bounded `.transcript.json` used to reconstruct the
visible chat history. The SQLite analysis database is not modified by GUI chat,
function selection, or tool views.

## Local service boundary

`aire.api.server` now implements a small standard-library HTTP service. It adds no
runtime dependency. Requests are limited to loopback, JSON bodies are bounded,
static assets use a restrictive content-security policy, tool names/arguments are
validated by the existing registry, and the server never accepts model-supplied
code for execution.

Chat uses newline-delimited JSON for the existing `AgentEvent` activity stream,
immediate verified overview facts, and progressive model summary text. Summary
text is marked as provisional until structured output and citations pass the
existing parser. Private reasoning is never streamed. The validated `AgentResult`
replaces the preview as the last packet.

Answers place interpretation and relevant stored observations first, followed by
a compact static-analysis footer. Evidence, Call Relationships, Security Checks,
and Raw Analysis Details are collapsed by default. Full source IDs, provenance,
model configuration, tool results, bounded code and context diagnostics remain
available there and are restored with recent chats.

Selecting a binary prepares a `BinaryWorkspace` backed by existing `AgentTools`.
It caches metadata, up to 100 function identifiers, connectivity ranking, bounded
imports/strings/exports, deterministic findings, seed call relationships and a
bounded overview evidence bundle. Function code and assembly remain lazy except
for the small overview sample. Deterministic tool results are cached by binary,
tool and validated arguments, including defaults. Up to four binary workspaces
are retained; each has an LRU tool cache with 128 entries and a 4 MB serialized
payload budget. Database and WAL changes invalidate all loaded workspaces.

Common prompt cards use deterministic retrieval recipes in the existing runner.
Exact graph queries and the suspicious-behavior card return stored results
without a model planning pass. Other questions retain the existing bounded agent
loop. Successful binary overview answers are reused for repeated identical
questions, independently of the selected function; cache entries also include
model and context settings. Other answers are not cached as conversation prose.

The GUI reuses one Ollama client. Generation requests send `keep_alive="10m"`;
the model can still be unloaded by Ollama under resource pressure. There is no
automatic background generation at startup. `OllamaClient.warm()` is available
for an explicit evidence-free model warm-up.

Enable development timing logs with `AIRE_GUI_PERFORMANCE=1`. The
`aire.performance` logger records session/workspace resolution, retrieval,
evidence construction, prompt construction, all model requests (including
planning), Ollama startup/first output/generation, formatting, and first useful
visible output. Timings are not shown in normal answer text. Transport startup
includes provider work before its response headers arrive; Ollama's own load,
prompt-evaluation and generation durations provide the more precise breakdown.

For measurements and limitations, see [GUI_CHAT_PERFORMANCE.md](GUI_CHAT_PERFORMANCE.md).

## Limits

The GUI operates only on analyses already persisted in the selected SQLite
database. It does not currently index a newly chosen file from the browser,
visualize the call graph as an interactive node diagram, or provide dynamic
execution. Progressive text covers the public summary; further structured
interpretations appear after validation. The Call Graph panel displays exact stored
caller/callee relationships. Existing M8 model/tool/evidence limits still apply.
