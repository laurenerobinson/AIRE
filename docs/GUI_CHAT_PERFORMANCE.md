# GUI chat workspace implementation and measurements

The later application relevance policy and new warm-model benchmark are recorded
in [APPLICATION_RELEVANCE.md](APPLICATION_RELEVANCE.md). The measurements below
are historical GUI implementation measurements. Current whole-binary selection
uses the shared deterministic relevance layer, retains requested assembly and
includes its policy version in evidence/answer cache keys. Workspace, streaming,
session persistence and HTTP behavior remain in place.

The GUI now loads reusable binary analysis context, reuses deterministic tool
results and presents concise analyst answers with expandable audit records.
The standard-library HTTP server, AgentRunner, AgentTools registry, AgentSession,
knowledge store, graph queries and security rules remain the underlying system.
No target execution, analysis-database writes, indexing changes or new runtime
dependencies were introduced.

## Safety checkpoint and baseline

The working tree was clean before edits. The Git safety branch is
`aire-safety-before-workspace-20261005`, at commit
`4bbc112ff60c1342947b680bc6ceba0d7834d136`.

Before modification, `python -m unittest discover -s aire-server/tests -v`
ran 284 tests in 8.496 seconds: 268 passed and 16 opt-in integration tests were
skipped. Measurements used the existing `analysis.sqlite` index of
`tests/fixtures/simple_elf/aire_test_binary`, not the stripped fixture. Its SHA-256
is `be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e`.
Ollama 0.35.0 used `qwen2.5-coder:1.5b`, Q4_K_M, with `num_ctx=4096`.
The local residency endpoint reported `size_vram=0` (CPU execution).

## What caused the original delay

Database retrieval was not the bottleneck. Baseline tool execution took
5–110 milliseconds per request; evidence construction took 2–4 milliseconds,
and prompt construction took about 1 millisecond. Almost all elapsed time was
inside Ollama.

The suspicious-behavior question spent 108.07 of its 108.45 seconds in three
model requests. Ollama reported 85.95 seconds evaluating prompts and 20.46 seconds
generating output. Two model planning requests consumed approximately 59.3 seconds
before the 48.9-second final synthesis. The function explanation made a planning
request costing about 25 seconds before its 37.3-second synthesis. Repeatedly
sending the registry, retrieval records and verbose context was expensive on
this machine. Long evidence identifiers also appeared in generated JSON.

The first baseline overview timed out after 283.78 seconds and provided no Ollama
duration record. Its time was measured in the model call, but the failed
non-streaming request cannot tell us precisely how that time split between cold
loading, prompt evaluation and generation. Subsequent successful requests
reported only millisecond model-load durations: recreating the Python client did
not itself reload the model every time. Keeping a shared client is useful but
does not explain or eliminate the dominant inference cost.

## Timing comparison

Final measurements and request-level breakdowns are recorded in
[GUI_CHAT_BENCHMARK.json](GUI_CHAT_BENCHMARK.json). The benchmark explicitly
unloads the selected Ollama model first, creates a fresh application and session,
loads the workspace, and makes five sequential questions. Workspace loading is
reported separately because binary selection prepares it before chat.

| Request | Before total | After total | Before tools | After tools | Before model | After model | After first useful output |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| First overview after startup | 283.784 s, timed out | 75.983 s | 10.15 ms | 0.54 ms | 283.653 s, failed | 75.947 s | 1.04 ms, stored facts |
| Second question: suspicious behavior | 108.447 s | 0.02137 s | 110.03 ms | 0.59 ms | 108.073 s | 0 s | 21.37 ms, final answer |
| Function follow-up: `process_input` | 62.457 s | 17.766 s | 5.54 ms | 0.12 ms | 62.412 s | 17.744 s | 10.561 s, provisional summary |
| Repeated overview | 14.210 s | 0.01901 s | 15.23 ms | 0 ms | 14.168 s | 0 s | 7.82 ms, cached summary |
| Caller follow-up | Not measured in baseline | 0.01701 s | — | 2.14 ms | — | 0 s | 17.01 ms, final answer |

Workspace preload took **29.78 ms** in the final run. All five final requests
completed, and database bytes remained unchanged. The cold overview used two
generation attempts after a grounding rejection; 26.03 seconds were reported in
prompt evaluation, 1.93 seconds in model loading and 47.62 seconds in generation
across those attempts. Its first provisional model summary appeared at 27.99
seconds, independently of the 1.04 ms verified-fact preview. The function prompt
evaluated 1,209 tokens, compared with the baseline's 2,050 synthesis tokens plus
1,443 planning tokens. Its prompt evaluation took 10.25 seconds and generation
7.05 seconds. Model time is directly measured around every provider call,
including retries; transport counters may differ slightly from wall time.

The recorded answer text reflects the measurement capture. A subsequent
formatting/grounding refinement omits interpretations claiming `main` is the
binary entry point when the store has no matching entry-point record, and keeps
the omission reason in technical uncertainties. It does not change the model
prompt or transport. The first-output duration counter also now retains the
first attempt rather than summing first-output intervals across a retry; the
table uses independently recorded first-visible/summary timestamps.

First visible output means useful stored facts or answer text, not the first
activity spinner. Binary overview facts appear immediately while model prose is
pending. Model summary streaming starts separately, after prompt evaluation.
Security and exact call queries return final deterministic answers without
calling Ollama. A repeated identical overview uses a successfully validated
cached response and performs no model request.

Results are measurements of this local machine, not latency guarantees. Earlier
development runs showed substantial variation: overview prompt evaluation ranged
from about 24 to 113 seconds, and generation occasionally slowed considerably.
Uncached model synthesis remains the main bottleneck. The cache and deterministic
routes reliably remove model work; streaming improves visibility but does not
make provider computation faster.

## What loads, what caches, and what remains lazy

Selecting a binary loads one `BinaryWorkspace` containing:

- Existing stored binary metadata: ID, name/path, SHA-256, format, architecture,
  entry point if present, and coverage/function counts.
- Up to 100 function metadata records, without bulk decompilation or assembly.
- Ten functions ranked by distinct stored callees.
- Ten functions ranked separately by deterministic application relevance.
- Up to 20 imports, 20 strings and 10 exports, retaining existing bounds.
- All current deterministic rule evaluations and findings.
- Exact application entries or runtime-bridge/application-relevance seeds; up to 12
  seed call relationships, and a bounded overview evidence bundle.

The overview profile uses at most two relevance-selected seed hints and a bounded
six-function application-focused bundle. The first three selected functions share
code admission priority. It delegates selection to the common M5 selector; M3
connectivity remains a separate query. Audit code samples are bounded; overview prompts reserve
separate space for code, relationships and artifacts. Function prompts send the
target's code plus neighbor metadata and calls. Assembly is included only when
requested. Full bounded source records remain in the audit bundle.

Registered deterministic tool results are memoized by binary ID, tool name and
validated arguments with defaults filled in. Evidence keys also include seed
functions, assembly selection and relevance policy version. Functions, graph queries, imports, strings,
findings and previously requested code all benefit. Detailed function code,
assembly and further list pages are lazy. Failed tool results are not cached.
Returned records are copies, so UI/session mutation cannot corrupt the cache.

Each application retains up to four binary workspaces. Each has an LRU cache of
at most 128 entries and a 4 MB serialized result-payload budget. Evidence snapshots
and Python object overhead are additional bounded memory. Up to four successful
overview answers are retained per workspace, keyed by normalized exact question,
model name, context size, evidence budget and relevance policy version. No unrelated prose answer is cached.
Agent-session state has a bounded 128-session memory cache backed by the existing
separate session files; selection, recent references and conversation state
survive reopening. Transcript history remains bounded by count and size.

Workspaces are separated by binary identity and retain the stored SHA-256.
Database replacement identity, size, nanosecond modification/change times, and
the WAL file are checked. Changes clear all workspaces and their generated
overview answers. Requests reject a database revision change during retrieval or
synthesis rather than returning a mixed/stale result. SQLite connections remain
read-only and owned by the current request thread.

## Model reuse and streaming

The GUI keeps one configured Ollama client and opener. Each request still uses
an individual HTTP operation; there is no new connection-pool dependency.
Generation sends `keep_alive="10m"`, supported by the inspected local service and
the [Ollama generate API](https://docs.ollama.com/api/generate). The recorded
post-benchmark `/api/ps` response verifies model residency and expiration.
Ollama may evict the model under resource pressure. `warm()` performs an explicit
empty-prompt load without binary evidence; automatic background warm-up or model
overview generation is not enabled.

The transport now supports bounded NDJSON token streaming through the same
proxy-free, redirect-disabled, loopback-validated opener. It validates record
types, completion, model identity, byte bounds, transport errors and generation
deadlines. The browser progressively displays only the public summary string,
labelled as interpretation with validation pending. Other fields and hidden
reasoning are not streamed. Strict JSON and citation validation still gate the
final response; invalid or incomplete generation never becomes a cached answer.

Compact claims additionally reject explicit unsupported linkage/absence
assertions and named calls that contradict the supplied graph. These targeted
checks are not complete semantic verification of model prose. The existing
technical caveats remain available in Raw Analysis Details.

## Analyst presentation and prompt cards

Default answers show the behavioral interpretation, a short explanation,
important stored functions, relevant observations and an evidence-backed next
inspection suggestion. The footer reports static analysis, evidence count,
no target execution and bounded evidence when applicable. AI interpretation is
labelled once; the normal answer does not contain SHA identifiers, every rule
status, provenance dumps or generic diagnostic paragraphs.

Evidence, Call Relationships, Security Checks and Raw Analysis Details are
collapsed by default. Expanded views retain citation/source IDs, callsites,
provenance, exact deterministic rules/findings, model identity, complete retrieved
tool records, bounded code and context diagnostics. Recent Chats restores these
details with the answer. Historical transcripts from before this change still
render in their original plain-text form.

The six prompt cards use existing backend tools. Overview uses the loaded
workspace; summaries and assembly use the selected function; suspicious behavior
uses exact deterministic checks with static context; call relationships use exact
stored graph results; crypto/hash retrieval uses bounded imports/strings and
function-name matches only as retrieval hints, then requires code/call grounding.
No crypto finding is manufactured from a name. Missing function selection produces
a clear selection request instead of silently explaining a whole binary.

## Verification

- Final default suite: **305 tests in 6.138 seconds**, 289 passed and 16 optional
  integration tests skipped.
- Final Ghidra-enabled suite: **305 tests in 69.549 seconds**, 301 passed and four
  separate live-model opt-in tests skipped. Actual local Ollama performance was
  exercised through the benchmark rather than those optional tests.
- JavaScript syntax (`node --check`) and patch whitespace (`git diff --check`)
  passed.

Focused coverage includes workspace construction, binary isolation, normalized
cache arguments, copy isolation, eviction, database/WAL invalidation, session and
selection reuse, concise formatting, retained evidence/security details,
binary-level evidence, targeted prompt code admission, named-call checks,
read-only SQLite, no process execution, incremental summary decoding and streaming
protocol failures. Cached tools are compared with uncached AgentTools for normal
results and errors. Existing tests exercise legacy CLI behavior separately.

A headless Chromium check used the real unstripped fixture's stored database and
a deterministic streamed test provider. It verified all six cards, immediate
stored overview facts, provisional text, four collapsed detail sections,
expanded full IDs/security data, function follow-ups, restored audit details and
responsive layout at 1440 and 820 pixels. No browser errors occurred. The analysis
database hash remained unchanged. The separate performance benchmark used real
local Ollama and also verified unchanged database bytes. Existing stripped tests
were used only for their stripped-specific integration coverage.

## Files changed

Added:

| File | Purpose |
| --- | --- |
| `aire-server/src/aire/api/workspace.py` | Bounded workspace, cached validated tools and overview selection profile. |
| `aire-server/src/aire/api/chat_presentation.py` | Concise answers with separate complete audit presentation. |
| `aire-server/tests/test_gui_workspace.py` | Focused correctness, reuse, grounding and safety checks. |
| `scripts/benchmark_gui_chat.py` | Reproducible sequential local performance benchmark. |
| `docs/GUI_CHAT_PERFORMANCE.md` | Implementation, measurements, limits and full file inventory. |
| `docs/GUI_CHAT_BENCHMARK.json` | Recorded baseline and final measured results. |

Modified:

| File | Reason |
| --- | --- |
| `aire-server/src/aire/api/server.py` | Reuse workspace/client/session values, route common questions, stream previews, persist audit sections, invalidate caches and log timings. |
| `aire-server/src/aire/agent/runner.py` | Small optional hooks for injected cached tools, prepared actions, compact synthesis, public text streaming, deterministic results and model timing; legacy defaults retained. |
| `aire-server/src/aire/ai/chat.py` | Compact prompt option, public summary extraction, provider timings and targeted grounding checks; existing strict parsing retained. |
| `aire-server/src/aire/ai/prompt_builder.py` | Compact citation aliases/records, category budgets and accurate code-admission tracking; original prompt mode retained. |
| `aire-server/src/aire/ai/ollama_client.py` | Optional streaming, keep-alive, explicit warm-up and provider duration metrics through the existing security boundary. |
| `aire-server/src/aire/api/static/app.js` | Provisional text, useful fact preview, expandable audit sections and restored details. |
| `aire-server/src/aire/api/static/app.css` | Small typography/overflow rules for previews and expandable details. |
| `aire-server/tests/test_ollama_client.py` | Streaming success/failure, metrics, keep-alive and warm-up tests. |
| `docs/GUI.md` | Updated interface, workspace, streaming and performance-log usage. |

## Reproduce measurements and next optimizations

From the repository root:

```bash
aire-server/.venv/bin/python scripts/benchmark_gui_chat.py \
  --database analysis.sqlite \
  --binary tests/fixtures/simple_elf/aire_test_binary \
  --function process_input --output /tmp/aire-chat-timings.json --cold-model
```

`--cold-model` deliberately unloads only the configured Ollama model before the
run. Omit it for a warm-model comparison. Run benchmarks without simultaneous
indexing/tests to avoid distorting CPU timings. Set `AIRE_GUI_PERFORMANCE=1` on
the normal GUI command to log development timings without adding them to answers.

The next priority is measuring Ollama throughput with GPU acceleration or CPU
thread/batch tuning on the demo machine. Further safe options are bounded caches
for repeated identical function explanations, optional asynchronous model warm-up
or overview preparation on selection, and better question-specific evidence
selection. Background preparation shifts work earlier; it does not eliminate
inference cost. Broader semantic model verification and persisted cross-references
would need separate work beyond this GUI/cache change.
