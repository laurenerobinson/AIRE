# M5 local grounded chat

Status: **M5 targeted live validation passed at `num_ctx=4096`** with local
`qwen2.5-coder:1.5b`. Both simple-ELF variants returned validated structured
responses with supported call relationships. Binary-summary validation remains
pending after runtime/resource timeouts. The final full regression passed 155
tests with two live timeout errors and zero skips; overall live validation is
still pending. One earlier stripped interpretation was
incorrect despite valid citations; it was not counted as a grounded success.

`AIRE_OLLAMA_NUM_CTX` now explicitly controls allocation; the compatible default
remains 32768, which previously OOMed on this 1.9 GiB RAM / 1 GiB swap VM.
The successful low-memory requests used 4096 and bounded evidence. No models
were installed, targets executed/modified, or M1–M4 behavior changed.
See [the validation report](M5_VALIDATION.md) for measurements, regression results,
failed attempts, fixture hashes and limitations. M6 has not started.

## Trust boundary and implemented pipeline

```text
Binary -> read-only PyGhidra -> ProgramIndex -> SQLite Knowledge Store
       -> M3 relationships -> M4 EvidenceBundle -> deterministic M5 prompt
       -> configured local Ollama -> validated ChatResponse -> analyst
```

Only the first indexing step needs the binary or Ghidra. Chat reads the already
stored analysis. Ghidra produces extracted program facts; SQLite preserves them;
M3 computes relationships; M4 selects evidence. M5 interprets those facts without
writing interpretations into the store. There is no model retrieval loop, tool
interface, target execution, Ghidra modification, shell execution, or web API.

M5 deliberately narrows the model's `facts` channel to **fact selection**:
`fact_ids` selects deterministic catalog statements. The application reconstructs
those exact statements from evidence. A model cannot submit arbitrary prose as a
verified fact. For example, an EDGE statement names the stored caller, callee,
addresses, and callsite. A FUNC statement states the stored name and entry;
a meaningful name alone is not behavioral proof. Artifact facts describe stored
kind/address/scope; their values remain untrusted data.

Summary and interpretation prose are always labeled model interpretation.
Their citations are checked for existence, **not semantic entailment**. A model
can still misinterpret cited code; citation validation does not prove its claim.
Confidence is the model's low/medium/high assessment, not a calibrated probability.
Static evidence never establishes execution or a confirmed vulnerability.

## API and development CLI

```python
from aire.ai.chat import AireChatService, ChatRequest, render_response
from aire.ai.ollama_client import OllamaClient
from aire.knowledge.database import BinaryKnowledgeStore

client = OllamaClient()  # AIRE_OLLAMA_HOST / AIRE_OLLAMA_MODEL
print(client.health())  # host plus installed model names; no generation
# Select a model explicitly if AIRE_OLLAMA_MODEL is not set:
# client = OllamaClient(model="an-already-installed-model")
with BinaryKnowledgeStore("analysis.sqlite") as store:
    service = AireChatService(store, client)
    response = service.ask(binary_id=binary_id,
        question="What functions does process_input interact with?",
        target="process_input")
    print(render_response(response))
    structured = response.to_dict()
```

`service.ask(request=ChatRequest(...))` is also supported. Pass either a request
or individual fields. A target uses exact M4 ID/address/name selection; use
`target_by='id'/'address'/'name'` to distinguish selector kinds. Ambiguous, unknown,
and foreign targets retain M3 errors and cause **zero model calls**. There is no
implicit name/address extraction from question prose: omit the target for a
binary overview. No semantic relevance is implied.

```bash
# Existing database and binary_id from M1/M2; model must already be installed.
export AIRE_OLLAMA_HOST=http://127.0.0.1:11434
export AIRE_OLLAMA_MODEL=your-installed-model
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.chat \
  analysis.sqlite '<binary_id>' 'What functions does process_input interact with?' \
  --target process_input --depth 1
```

Options: `--target`, `--model`, `--host`, `--allow-remote-host`, `--depth`,
`--no-assembly`, `--no-decompile`, `--json`. No listener or GUI is started.
The CLI requires an existing database; it does not index or create a new analysis.
API store construction retains M2's normal schema-initialization behavior, while
chat queries perform no row writes. Errors produce JSON and exit status 1.

## Configuration and privacy

`OllamaClient(host=None, model=None, timeout_seconds=240, temperature=0.1,
allow_remote_host=False, *, num_ctx=None)` uses Python standard-library urllib/json only.
Explicit arguments override `AIRE_OLLAMA_HOST`, `AIRE_OLLAMA_MODEL`, and
`AIRE_OLLAMA_NUM_CTX`. Python
uses HOST, whereas the preserved Java v1 implementation uses AIRE_OLLAMA_URL.
Default host is `http://127.0.0.1:11434`. There is **no default model** and no
silent generation-time model selection. `list_models()` returns sorted installed
names via `/api/tags`; `health()` includes them and the configured host. Calling
`generate` without a selected model raises OllamaModelError with setup guidance.
No models are pulled or services started.

`AIRE_OLLAMA_NUM_CTX` sets Ollama's context allocation. Its default remains
**32768** for compatibility. Environment values must contain only ASCII decimal
digits and represent a positive integer; empty/malformed values, zero, and
negative values raise a clear ValueError. There is no fallback for malformed
configuration. An explicit `num_ctx=` positive Python integer takes precedence;
booleans, floats and strings are rejected for that constructor argument.

Context allocation is independent of the EvidenceBundle character cap. Reducing
`max_total_context_chars` shortens evidence but does not itself shrink Ollama's
KV cache. Low-memory validation explicitly uses `AIRE_OLLAMA_NUM_CTX=4096` and
6,000/5,000-character caps for the accepted unstripped/stripped requests.
The stripped request retained decompilation and two call edges, with assembly
explicitly omitted. Full prompts also include system/schema overhead;
characters are not tokens, and token retention is not independently guaranteed.
No tokenizer dependency or automatic model/context selection is introduced.

Loopback IP literals and `localhost` are accepted by default. `localhost` is
pinned to `127.0.0.1`; other hostnames are rejected without DNS lookup, even if
an alias might resolve locally. IPv6 `::1` is accepted. Remote origins require
explicit `allow_remote_host=True` / `--allow-remote-host`; there is no environment
variable that silently grants this permission. URLs with credentials, paths,
queries or fragments are rejected. Environment proxies and HTTP redirects are
always disabled so evidence cannot be silently forwarded to another host.

Binary evidence is sent only to the configured Ollama endpoint. Users enabling
a nonlocal endpoint are responsible for that configuration and its privacy.
A.I.R.E. requires no internet access for local inference. A localhost service
itself must also be configured for local inference; A.I.R.E. cannot inspect or
control what an independently administered service does with received data.
There is no cloud provider adapter or fallback.

Generation POSTs non-streaming JSON to `/api/generate`, with a separate `system`
field and a JSON response schema. Options use temperature 0.1, seed 0,
`num_predict=2048`, and the configured `num_ctx` (default 32768). Temperature is configurable in [0,1].
Model output is not guaranteed repeatable even with a fixed seed. A tags request
has at most a 3-second socket timeout; generation defaults to 240 seconds,
configurable from 0.1–600. These are socket-operation timeouts, not total
wall-clock deadlines. HTTP response bodies are capped at 1 MB; truncated or
incomplete generation, missing fields, malformed transport JSON, HTTP errors,
connection failures and timeouts raise typed Ollama errors. A generation 404
reports the selected model and endpoint as unavailable. No transport retries occur.

## Request bounds and evidence policy

| ChatRequest field | Default | Accepted bounds |
| --- | --- | --- |
| binary_id | required | Nonempty string |
| question | required | 1–2000 characters; nonblank |
| target | None | Exact selector, at most 500 characters |
| target_by | auto | auto/id/address/name |
| max_depth | 1 | 0–4 |
| max_functions | 8 | 1–32 |
| max_artifacts | 12 | 0–100 |
| max_edges | 20 | 0–100 |
| max_total_context_chars | 24000 | 1000–60000 |
| include_decompiled_text | True | bool |
| include_assembly | True | bool |

Targeted evidence uses ContextBuilder unchanged: direct callers/callees at depth
1, and forward traversal when depth >1. M5 caps each decompiled body at 4000
characters and assembly at 2000 before M4 applies its combined budget. Exports
are enabled. M4's warning policy and provenance remain intact.

Untargeted evidence uses OverviewContextBuilder, a separate M5 subclass using
M4's single read snapshot, bounds, provenance and renderer. Candidate functions
exclude externals and thunks. Up to two stored CALL roots are prioritized, then
functions are ordered by distinct callers+callees, with numeric address/ID ties.
Roots have no resolved incoming CALLs; they are not necessarily executable entry
points. At most half the function budget (minimum one) supplies seed functions;
M4 gathers their bounded neighborhoods. Shared identities/callsites are deduplicated.
STRING, IMPORT and EXPORT artifacts each receive one-third of the artifact cap,
with remainder slots in that order; unused quotas are not redistributed.
This can omit useful evidence and always discloses observed omissions. The policy
is connectivity-based, not semantic. Lightweight candidate ordering and M3 walks
can inspect more rows than the final output; no separate scan-time budget exists.

The prompt re-budgets M4's structured data because M4 retains identity/metadata
even when its own text blocks do not fit. Complete JSON evidence blocks are
admitted in binary, target, edges, other functions, artifacts, warnings order.
A block that does not fit is omitted and recorded as a prompt truncation. Only
admitted blocks receive citations. If the target cannot fit, generation fails
before calling the model. Evidence blocks including JSON escaping fit the request
character budget. System instructions, question, selection policy, schema and
compact truncation notice are extra prompt overhead, separately measured.

## Prompt, citations, parsing, and response

System instructions are constant and separate from user/evidence text. The prompt
contains a quoted question, declared selection policy, JSON-escaped untrusted
binary/function/relationship/artifact/warning data, truncation summary, and schema.
Binary strings, names, code and comments (including embedded instructions such
as “ignore previous instructions”) cannot become system instructions. Retry does
not echo prior model output. These measures reduce injection exposure; language
models can still ignore instructions. The absence of tools/actions and strict
fact reconstruction enforce the application boundary even if prose is malicious.
The terminal renderer escapes control characters in model and binary text.

Citation aliases are `BINARY:`, `FUNC:`, `EDGE:`, `ARTIFACT:`, or `WARNING:` plus
16 hex characters from SHA-256 of the binary ID and existing source identity.
The full identity is preserved in a provenance mapping, including table, binary,
source ID, address, related functions and selection reason. Edge identity is the
existing caller/callee/callsite/type tuple, preserving repeated callsites.
Alias collisions fail closed. Aliases are stable for identical evidence and do
not depend on ordering or timings; stripped/debug binaries have distinct IDs.

The model returns:

```json
{
  "summary": {"claim": "Advisory summary", "evidence_ids": ["FUNC:..."]},
  "fact_ids": ["EDGE:..."],
  "interpretations": [
    {"claim": "Possible purpose", "confidence": "low", "evidence_ids": ["FUNC:..."]}
  ],
  "uncertainties": ["Evidence is insufficient to establish runtime behavior."]
}
```

Whitespace is allowed. Markdown fences, unknown/missing fields, duplicate JSON
keys, nonfinite JSON numbers, malformed nested values, oversized lists/text,
invalid confidence, duplicate IDs and nonexistent citations are rejected.
Summary and interpretation claims require nonempty citations. An insufficient
evidence answer can cite binary metadata while declining behavioral inference,
leave facts/interpretations empty, and explain uncertainty. Uncertainty prose is
unverified model text. A format/structure/citation failure permits one correction
request with the original evidence and schema. A second failure raises ChatError
with `code='invalid_model_response'`. Other failures propagate without retry.
Raw replies are retained only with `debug=True`; they are not logged automatically.

ChatResponse exposes question, binary_id, target, cited summary, reconstructed
facts, cited interpretations/confidence, uncertainties, all admitted citations,
EvidenceBundle, selection policy, context_truncations, context_truncated, model,
attempt count, timing, sizes and optional raw_response. `to_dict()` is JSON-safe.
The renderer shows summary as interpretation, verified *stored* facts, model
interpretations, uncertainty, a context note, references/provenance and model.
Full structured provenance can be verbose; normal output lists referenced sources.

M4 truncations and M5 prompt omissions are both retained. Model instructions and
response rendering disclose bounded context, and deterministic uncertainty notes
cannot be removed by the model. Disabled code types are also disclosed. Character
limits are not token counts: Ollama's reported prompt/evaluation counts are exposed
when available, but M5 cannot independently prove that the model retained every
input token. It states this limitation rather than claiming complete coverage.

Timings separate context build, prompt build, inference (both attempts combined),
response parsing (both attempts), and total chat time. Sizes include M4 rendered
characters, admitted context characters, full initial and final prompt characters,
final/all response characters, and available Ollama token counts.

## Validation and development fixtures

Primary: `tests/fixtures/simple_elf/aire_test_binary`. Stripped comparison:
`tests/fixtures/simple_elf/aire_test_binary_stripped`. Ground truth remains
`tests/fixtures/simple_elf/GROUND_TRUTH.md`; it is test input, never model context.
The M5 tests do not rebuild or execute either binary.

```bash
# All pure tests; Ghidra/model integration cases skip by default.
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
# All static integrations and optional live Ollama checks.
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=1 \
 AIRE_CHAT_REPORT=/tmp/aire-m5-report.json PYTHONPATH=aire-server/src \
 aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v

# Resource settings; this direct command retains the 240-second client timeout.
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=1 \
 AIRE_OLLAMA_HOST=http://127.0.0.1:11434 \
 AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b AIRE_OLLAMA_NUM_CTX=4096 \
 AIRE_CHAT_TEST_CONTEXT_CHARS=5600 PYTHONPATH=aire-server/src \
 aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

On this VM, running Ghidra and the model in one process lifetime exhausted
most available RAM/swap and caused a live timeout. The recorded full rerun uses
a temporary measurement wrapper to index M5 fixtures in child processes, unload
the model between live calls, and explicitly select the supported 600-second
timeout. It retains every original test assertion; the direct command above
does not perform that orchestration. See the validation report for exact results.

`test_ollama_client.py` mocks HTTP without network listeners. `test_chat.py` uses
real SQLite and a fake model, with no Ghidra or Ollama requirement. The real
`test_chat_integration.py` indexes and persists both small binaries, checks M3
relationships and M4 context, then exercises M5 with a fake provider. Two separate
live cases discover existing models, prefer the configured model (otherwise the
first sorted installed name), and call local Ollama only when explicitly enabled.
Unavailable Ollama or missing models are reported as skips, never live successes.
Malformed or ungrounded responses from an available model fail the test.
`AIRE_CHAT_TEST_CONTEXT_CHARS` is an explicit test-only evidence cap for live
cases; absent it, those tests retain their original 24,000-character default.
All existing grounding/citation/relationship assertions remain in effect, and
static/fake-provider cases retain their original budgets. Normal application
requests use `ChatRequest.max_total_context_chars` instead of this test variable.

Ground-truth evaluation checks both process_input callee addresses corresponding
to validate_input/transform_input, selected edge facts, valid source identities,
confidence enum, target inclusion, truncation propagation and unchanged SHA-256.
Stripped selection uses the debug partner's address and checks that its name is
not process_input. Model statements are not graded by exact natural-language
wording; arbitrary interpretation entailment still requires analyst review.

Not implemented: semantic/vector retrieval, embeddings, CWE engine, vulnerability
detection or confirmation, CVE matching, taint analysis, dynamic validation,
exploit generation, autonomous actions, automatic naming/comments/signatures,
HTTP API, GUI, chat history, token estimation or cancellation.

M6 recommendation: analyst-controlled naming suggestions across the whole binary
using this evidence/prompt/validation pipeline, with function-ID provenance,
uncertainty and explicit review. **M6 must not automatically rename functions.**
M6 has not started. Binary-summary live validation remains pending.
