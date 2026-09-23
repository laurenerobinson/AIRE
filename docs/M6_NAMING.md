# M6 advisory function naming

M6 implements transient function naming suggestions for analyst review. The
current function name is a stored fact; a suggested name and its rationale are
model interpretations. **No rename is applied.** No apply API, persistence of
suggestions, schema migration, Ghidra modification, comments, binary patching,
target execution, security scanner or autonomous action is included.

M5 was committed at `7aa5e22`, tag `aire-m5`, before M6. Its source and validators
remain unchanged. Targeted M5 live inference passed with local
`qwen2.5-coder:1.5b` / context 4096; summary/full live regression remains limited
by VM resources. M6 does not redesign M5 or require those slow tests to pass.

## Public API

```python
from aire.ai.chat import AireChatService
from aire.ai.naming import NamingService, NamingOptions, render_naming_result
from aire.ai.ollama_client import OllamaClient
from aire.knowledge.database import BinaryKnowledgeStore

with BinaryKnowledgeStore("analysis.sqlite") as store:
    chat = AireChatService(store, OllamaClient())
    service = NamingService(store=store, chat_service=chat)
    candidates = service.find_naming_candidates(binary_id, NamingOptions(max_candidates=5))
    result = service.suggest_names(binary_id, "004012f8")
    print(render_naming_result(result))
    review_data = result.to_dict()
    # Explicit bounded serial inference, potentially slow:
    results = service.suggest_for_binary(binary_id, NamingOptions(max_candidates=2))
```

`find_naming_candidates(binary_id, options=None) -> list[FunctionRecord]` makes
no model calls. `suggest_names(binary_id, function, options=None) -> NamingResult`
accepts an exact ID, stored address, name, or FunctionRecord using M3 resolution.
Ambiguous/foreign/unknown selectors preserve M3 errors and do not call the model.
An explicitly selected meaningful function is still skipped unless the analyst
sets `skip_meaningful_names=False`. External/thunk/library overrides are separate.
The chat service must use the same store. All results are in memory only.

`NamingResult` contains binary/function IDs, current name, address, suggestions,
evidence summary, admitted citations with provenance, context truncations and
flag, model, timings, sizes, attempts, warnings, status and optional error.
Status is `ok`, `abstained`, `skipped` or `error` (batch failure). Each frozen
`NameSuggestion` has `suggested_name`, confidence, rationale and evidence IDs.
`to_dict()` is JSON-safe. Raw model responses are not retained in results.
Timings separate context construction, prompt construction, inference, parsing
and total time. Sizes distinguish evidence, full prompt, raw response and token
counts when the provider reports them.

## Options and candidate policy

| Option | Default | Accepted values |
| --- | --- | --- |
| max_candidates | 20 | integer 1–100 |
| max_suggestions_per_function | 3 | integer 1–5 |
| min_confidence | None | None / low / medium / high |
| include_decompiled_text | True | bool |
| include_assembly | True | bool |
| max_depth | 1 | integer 0–2 |
| max_context_chars | 5000 | integer 2000–12000 |
| skip_external | True | bool |
| skip_thunks | True | bool |
| skip_meaningful_names | True | bool |
| skip_library | True | bool |

Booleans are not accepted as integers. No options are silently coerced.
Generic detection recognizes empty/whitespace names, the small denylist below,
and case-insensitive `FUN_`, `LAB_`, `SUB_`, `UNK_` followed by hex digits, with
optional `thunk_` prefixes. It does not treat every name containing "function"
or starting with "fun" as generic. Symbols whose names look generic may still
have been assigned by an analyst; M1 does not persist symbol-source authority.

External functions and exact stored import names are excluded by default, as
are flagged/prefix thunks, known-library flags, and a documented small runtime/
libc symbol set in `naming.py` (`_start`, `_init`, `_fini`, clone registration,
libc startup, printf/puts/strlen/socket/memory/allocation primitives, etc.).
These heuristics cannot recognize all stripped runtime code.

High-connectivity naming candidates sort by descending distinct caller IDs,
then descending distinct outgoing `(callee ID, callsite)` CALL facts, then M3's
numeric address order and function ID. Duplicate edges do not inflate counts;
non-CALL relationships are excluded. This is an analyst navigation policy, not
an absolute measure of importance. Metadata/edges are scanned for the binary;
only the bounded selected records have their code bodies loaded. There is no
separate candidate-scan time or memory bound.

## Evidence, prompt and response

The service uses the existing chat service's M4 builder and M5 local transport.
It does not first ask a chat question and then parse chat prose. M5 `build_prompt`
continues to own stable citation aliases, complete-block evidence budgeting and
truncation. M6 replaces only the generated response-schema suffix and supplies
its dedicated naming system instructions; binary evidence is never searched or
rewritten to insert that schema. M5 chat's schema/parser remain untouched.

Per-function evidence requests include the target, bounded direct callers and
callees with exact callsites, up to four function records and eight edges,
1200 decompilation characters and 400 assembly characters per function. Depth
above one enables bounded forward traversal. Imports are visible only through
proven stored graph endpoints/code; no thunk-to-import links are synthesized.
Unassociated binary strings/import/export artifacts are disabled. M2 has no
function-string xrefs, so M6 does not invent such associations. Global diagnostics
retain M4 bounds and provenance. Smaller budgets can omit neighbor bodies and
edges; both prompt and result explicitly disclose those omissions. Disabled code
types are disclosed independently. Required target evidence must fit or the
request fails before inference.

Fixed system instructions mark binary text and all embedded instructions as
untrusted data. They request behavior-oriented snake_case names, citations,
uncertainty and no invented product/protocol/business semantics. Autogenerated
names are explicitly nonsemantic. Insufficient evidence should produce an empty
list with an explanation, not an invented name. Suggested response:

```json
{"suggestions":[{"name":"validate_then_transform","confidence":"medium",
"rationale":"A check gates the next call.","evidence_ids":["FUNC:..."]}],
"uncertainties":["Callee behavior needs review."]}
```

Strict parsing rejects malformed JSON, duplicate object keys, nonfinite values,
unknown/missing fields, wrong types, oversized output/lists, invalid confidence,
empty/duplicate/unknown citation IDs and foreign binary citations. Every
suggestion must cite the admitted target function or a relationship touching it;
binary metadata alone cannot ground a name. Only evidence actually shown to the
model is citable. Citation existence is not semantic entailment.

Names must be 2–64 ASCII characters matching
`[a-z][a-z0-9]*(?:_[a-z0-9]+)*`. Spaces, punctuation, shell/path syntax, newlines,
camelCase, uppercase, generated names, repeated current names, `0x` addresses,
long hex-only name segments and the target address are rejected. No sanitization
or case normalization occurs. The address heuristic can reject legitimate
hex-looking terminology; an analyst should review that limitation.

The small exact denylist is: `function`, `func`, `helper`, `routine`, `subroutine`,
`unknown`, `unnamed`, `generic_handler`, `process_data`, `handle_data`, `do_work`,
`operation`, `generic_function`. V1's broader filtering and numeric confidence
multipliers were intentionally not copied. In particular, `process_input` is
not categorically rejected.

Validate the requested maximum before deduplication. Exact duplicate names keep
the highest-confidence occurrence (first on ties), then sort by confidence and
name. No semantic/edit-distance similarity is implemented. Confidence thresholds
filter only after complete validation and disclose omissions. Existing-name
collisions are flagged for analyst review, never resolved by renaming anything.

Like M5, invalid content permits one format correction without echoing the bad
response. Two invalid responses raise ChatError with `invalid_naming_response`.
Transport errors are not retried. In a batch, completed results survive; invalid
content/context failures become per-function errors and processing continues.
A provider error records the failing function and stops before remaining
candidates. There are at most two generation calls per attempted function, no
parallel/background inference, and no automatic resumption.

## CLI and local configuration

```bash
# List candidates without inference; database must already contain analysis.
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.naming \
  analysis.sqlite '<binary_id>' --candidates --limit 5

# One exact function, conservative context and an already installed local model.
AIRE_OLLAMA_HOST=http://127.0.0.1:11434 \
 AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b AIRE_OLLAMA_NUM_CTX=4096 \
 PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.ai.naming \
  analysis.sqlite '<stripped_binary_id>' --function 004012f8 --no-assembly --json
```

Modes `--function`, `--candidates`, and explicit `--batch` are mutually exclusive.
CLI batch/candidate limit defaults to five; the API defaults to twenty.
Additional flags: `--model`, `--context-chars`, `--no-assembly`,
`--include-meaningful`, `--json`. There are no apply/rename/write flags. The CLI
uses an existing SQLite database in `mode=ro`, checks the schema version and
never invokes schema initialization. API callers supply their existing store;
generating suggestions only reads it. Model host/context/temperature/output limits
come from M5. M6 adds no remote opt-in or model-controlled tool interface.

## Validation and stripped evaluation

Ground truth does not list fixed entry addresses: it explicitly directs mapping
from the unstripped partner because compiler builds can change addresses. Tests
freshly index both binaries and map unstripped `process_input` to the stripped
record by its actual indexed address, **004012f8** for this build. Evaluation
uses the stripped binary only. Prompts are checked for absence of `process_input`,
`validate_input`, `transform_input` and `GROUND_TRUTH.md`. Meaningful unstripped
names are used only after inference for evaluation.

The static fake-provider integration returned `validate_then_transform`, with
medium confidence and a real target citation. Relative to the documented
validation gate followed by transformation, this is a **close semantic match**
as a supplied test example. The fake provider does not infer semantics; this
proves pipeline contracts, not model naming ability. No exact-name assertion
is used to grade model reasoning.

Run pure tests without Ghidra/Ollama:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

Run all static M1–M6 integrations (live tests explicitly disabled):

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=0 AIRE_RUN_NAMING_LIVE_TESTS=0 \
 AIRE_NAMING_REPORT=/tmp/aire-m6-report.json PYTHONPATH=aire-server/src \
 aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -v
```

Opt into just one live stripped naming function:

```bash
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_NAMING_LIVE_TESTS=1 \
 AIRE_OLLAMA_HOST=http://127.0.0.1:11434 AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b \
 AIRE_OLLAMA_NUM_CTX=4096 AIRE_NAMING_REPORT=/tmp/aire-m6-live.json \
 PYTHONPATH=aire-server/src:aire-server/tests aire-server/.venv/bin/python \
 -m unittest test_naming_integration.NamingIntegrationTests.test_stripped_live_naming -v
```

Indexing occurs in a child process that exits before naming, releasing its JVM.
The live test accepts explicit abstention but reports it separately; enabled
transport/model errors fail instead of silently skipping. No whole-binary live
inference is part of regression. Hashes and complete ProgramIndex snapshots are
compared, database reads run with query_only, and no Ghidra object enters naming.
Pure tests block file/network/process/write calls during fake-provider naming.

### Recorded validation — 2026-09-23

Syntax compilation passed. Final pure discovery: **193 tests, 182 passed, 11
opt-in integration skips**, including 33 new pure naming tests. Final full static
M1–M6 discovery: **193 tests, 190 passed, three opt-in live skips**, zero failures
or errors. This includes all four existing M1–M4 static integrations, both M5
fake-provider integrations and both M6 success/rejection static integrations.
The three skips are the two M5 live cases and the M6 live case (run separately
below). Pure run time was 7.563 s; full static wall time was 2114.332 s on this
resource-limited VM, not a general performance benchmark. Syntax compilation
and `git diff --check` passed. No Ruff/mypy installation or new runtime dependency
was needed.

The optional live test ran **one stripped function**, with the standard one
format-correction retry. Both real Ollama calls completed, but **no live naming
suggestion was accepted**. The test ended with one `invalid_naming_response`
error, zero skips. This is a model output-quality failure, not an OOM or timeout.
The model was the already installed local `qwen2.5-coder:1.5b`, digest prefix
`d7372fd82851`; endpoint `http://127.0.0.1:11434`, context 4096, temperature 0.1,
seed 0, output limit 2048, unchanged 240-second socket timeout.

Attempt 1 proposed `validate_004012f8` and `handle_004012f8`; both were rejected
for embedding the address. Its rationale invented cleanup/error-handling behavior
and contradicted its own uncertainty note. Attempt 2 proposed
`analyze_004012f8` and `evaluate_004012f8`, again invalid, and also invented IDs
`EDGE:00401316` and `EDGE:00401334` instead of using only the admitted aliases.
The parser failed on the names first; review of the saved transport confirmed
these additional citation defects. Semantic assessment: **generic/unhelpful names
and incorrect/unsupported rationale**, not successful name recovery. Validation
was not relaxed, names were not sanitized, and no third call or live batch ran.

| Live measure | First call | Correction call |
| --- | ---: | ---: |
| Evidence characters | 4841 | 4841 |
| Full prompt characters | 7371 | 7549 |
| Raw response characters | 529 | 665 |
| Reported prompt tokens | 3342 | 3375 |
| Reported generated tokens | 195 | 255 |
| Generation call seconds | 170.809 | 56.646 |
| Model load seconds (included) | 4.371 | 0.032 |
| Available RAM before / minimum / after, MiB | 1320.1 / 177.9 / 182.7 | 182.2 / 166.8 / 179.3 |
| Swap before / peak / after, MiB | 524.5 / 605.6 / 593.9 | 593.9 / 595.9 / 592.4 |

The runner survived and was explicitly unloaded after the test. No new kernel
OOM was observed; no VM/swap configuration changed. Sampling can miss brief
peaks. The two calls are part of one naming-service invocation, not a live
whole-binary batch. The measurement wrapper changed no client options or test
assertions. Application network calls were local only; this is not a claim of
network isolation for every background task of the separately managed daemon.

The fake-provider integration also checks rejected output through a `finally`
integrity check: no changed ProgramIndex, database-file SHA-256, database mutation
count or fixture hashes on success or rejection. The live request used SQLite
query_only and fixture hashes were checked after it; no Ghidra object was present
in naming. The additional rejection-integrity test was added after live rejection
and rerun statically, without making another live request.

Both fixture hashes were identical before and after:

```text
unstripped:
be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e
stripped:
08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188
```

Local validation artifacts: `/tmp/aire-m6-pure-final.log`,
`/tmp/aire-m6-full-static.log`, `/tmp/aire-m6-full-static-report.json`,
`/tmp/aire-m6-live.log`, `/tmp/aire-m6-live-transport.json` and
`/tmp/aire-m6-live-totals.json`. Raw live responses exist only in the opt-in
measurement artifact, not NamingResult. These files are not dependencies.

Final git state: HEAD `7aa5e22`, tag `aire-m5`, seven modified documentation files
and six new M6 files (three source, two tests, this document). Three unrelated
untracked files (`FunctionOverloading.exe`, `FunctionOverloading.zip`,
`demo_readonly.py`) remain untouched. Nothing staged or committed. A SHA-256
comparison of every previously tracked file confirmed that only the seven
requested existing documents changed; all M1–M5 source/tests and fixtures match
the task-start baseline.

M6 implementation/static acceptance is complete and distinct from live model quality. The
small model did not produce acceptable names in this evaluation. M5 source,
validators and networking were not changed to accommodate it. No suggestions
were persisted or applied, no commits were created, and M7 was not started.

## Limitations and next milestone

Suggestions and confidence remain fallible interpretations, even with valid
citations. Small contexts may omit meaningful callee/caller code, and names can
be generic despite passing the deliberately small denylist. No calibrated score,
semantic proof, global name-uniqueness enforcement, similarity engine, symbol
source tracking, cancellation, persistence or application workflow is provided.
Binary/whole-store indexing and persistence are separate analyst actions.

M7 should begin a deterministic CWE/security rule framework: explicit versioned
rule contracts, applicability/insufficient-evidence states, evidence provenance,
CWE references and synthetic positive/negative tests over stored static facts.
Rule candidates must be separate from verified vulnerabilities and model naming
interpretations. Do not introduce execution, cloud transport or automatic changes.
M7 has not started.
