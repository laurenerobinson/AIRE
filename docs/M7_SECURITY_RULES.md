# M7 deterministic CWE/security rule framework

M7 adds a small offline rule framework over stored program facts. Its output is
an evidence-backed **security signal requiring analyst review**, never a
confirmed vulnerability. No LLM is required to create, validate or render a
finding. M6 is committed at `ed8881e` / `aire-m6`; this milestone leaves M1–M6
implementation and SQLite schema v1 unchanged. M8 has not started.

## Public API and rule contract

```python
from aire.security.rule_engine import RuleEngine, render_scan
from aire.security.contracts import RuleRegistry
from aire.security.rules import UnboundedCopyRule, DangerousApiRule

registry = RuleRegistry()
registry.register(UnboundedCopyRule())
registry.register(DangerousApiRule())
metadata = registry.list_rules()
result = RuleEngine(store, registry).scan_binary(binary_id)
selected = RuleEngine(store).scan_binary(
    binary_id, rule_ids=["AIRE-CWE-120-UNBOUNDED-COPY"])
print(render_scan(result))
wire = result.to_dict()
stable_content = result.to_dict(include_timings=False)
```

`RuleMetadata` contains rule ID, semantic version, title, description, CWE ID and
title, required facts, tags and optional severity hint. Both built-ins are
version `1.0.0` and have no severity hint. IDs/versions and metadata shape are
validated. Metadata is static project content; there is no CWE/NVD download.

`SecurityRule.evaluate(facts: RuleFacts) -> RuleEvaluation` is the stateless
contract. `RuleRegistry` uses explicit registration, rejects duplicate IDs even
for another version, and executes/lists by sorted exact rule ID. One active
version per ID is supported. Selection rejects unknown or duplicate IDs; an
empty list selects no rules. No plugin discovery is provided.

`RuleEngine(store, registry=None).scan_binary(binary_id, rule_ids=None)` loads
one binary-scoped M3 read snapshot and projects frozen function/import/CALL
records plus extraction coverage into `RuleFacts`. Rules receive no database
handle, target file path, Ghidra program, decompiler text, strings, M5 answer or
M6 naming interpretation. Current function names are stored labels, not semantic
claims. Ordinary internal functions named like APIs are not accepted as imports.

Rules must return exact catalog evidence. The engine rejects foreign/forged
evidence, altered descriptions, identity/version/CWE mismatch, unsupported
primary locations and invalid result states. This validates provenance, not the
logical correctness of arbitrary registered Python code. Rule implementations
are trusted application code; the registry is not an untrusted plugin sandbox.

Each rule exception or invalid result becomes a `RuleFailure` with ID/version,
exception type and message. Completed results survive and subsequent rules run.
Failures have their own error channel and never masquerade as NOT_APPLICABLE or
INSUFFICIENT_EVIDENCE. Unknown binary/invalid selection/snapshot failures fail
the request before rule execution. Timing covers fact loading, each evaluation
including result validation, and total scan time.

## States and findings

| State | Meaning |
| --- | --- |
| NOT_APPLICABLE | Required API prerequisite is absent from the stored analyzed facts. Not a safety verdict. |
| INSUFFICIENT_EVIDENCE | Required extraction coverage is missing/disabled, or an API prerequisite exists without a corroborated resolved internal CALL. |
| SIGNAL | A documented deterministic API-call condition is present; analyst review is needed. |
| CANDIDATE | Contract reserved for a rule with multiple supporting conditions. Neither initial rule emits it. |

There is no CONFIRMED state. Evidence strength LOW/MEDIUM/HIGH describes support
for the rule's observation, not exploit probability, impact or severity.

`SecurityFinding` fields: deterministic finding ID; binary ID; rule ID/version;
CWE ID; title; status; evidence strength; primary function ID and address
(callsite for these rules); deterministic discriminator; message; supporting and
contradicting evidence; assumptions; limitations; optional `created_at`. Default
`created_at=None` avoids injecting a wall clock into deterministic results.
Independent lists prevent evidence leaking between findings. These records are
transient and never saved to function rows or a new table.

`RuleEvaluation` contains binary/rule/version, state, message, findings and
evaluation-level supporting/contradicting evidence, assumptions and limitations.
`SecurityScanResult` contains evaluations, flattened findings, per-rule errors,
rule counts, timing and warnings. Serialization is JSON-safe; renderer content
is deterministic and escapes terminal control characters from stored text.

`SecurityEvidence` contains ID, binary ID, type, exact source table/source ID,
description, optional function ID, address, callsite and artifact ID. Initial
types are FUNCTION, IMPORT, CALL_EDGE and ANALYSIS_METADATA. Descriptions report
stored observations. No STRING/CONTROL_FLOW evidence is fabricated for this
milestone. Contradicting evidence is supported but empty for the two initial
rules: no bounds/source analysis exists to justify inventing it.

IDs are `PREFIX:sha256(canonical JSON identity)`:

- Finding identity: binary ID, rule ID/version, primary function ID, primary
  address and discriminator (`[api, actual_callee_function_id]`).
- Evidence identity: binary ID, type, source table and source ID. CALL source
  identity is `[caller_id, callee_id, callsite, "CALL"]`, matching persisted facts.

Repeated scans preserve IDs and content excluding explicit timings. Duplicate
stored CALL rows are coalesced. Different callsites, binaries or rule versions
produce distinct finding IDs. Reanalysis/toolchain changes may change source
facts and therefore IDs; these are not cross-version semantic identities.

## Initial rules and prerequisites

| Rule | CWE | API set | Maximum emitted state |
| --- | --- | --- | --- |
| AIRE-CWE-120-UNBOUNDED-COPY | CWE-120: Buffer Copy without Checking Size of Input | `strcpy` only | SIGNAL |
| AIRE-CWE-242-DANGEROUS-API | CWE-242: Use of Inherently Dangerous Function | `gets` only | SIGNAL |

There is deliberately no memcpy rule or broad blacklist. No alias, substring,
versioned-name, decompiler-text or suggested-name inference is used.

Both rules require stored `analysis_completed=True`,
`options.include_imports=True`, and `options.include_call_edges=True`. Missing or
disabled coverage yields INSUFFICIENT_EVIDENCE even if an API is not observed.
These flags are extraction coverage, not proof that all possible runtime calls
are known. Loader diagnostics remain visible as a warning count; unresolved
calls never become edges or findings.

External API identity requires an exact external function name and an IMPORT
artifact at that same address, with exact API or `namespace::api` value. A
resolved internal, non-thunk caller's CALL directly to this external record
yields SIGNAL with MEDIUM evidence strength.

ELF typically stores an application CALL to a PLT thunk instead. The second,
weaker condition requires the actual resolved callee to be a thunk whose exact
API name and nonempty, non-Global namespace match the corroborated external
function/import pair. It yields LOW strength and says **CALL to import-named
thunk**, not a proven direct external call. The actual callee/callsite is retained;
no thunk-to-external edge is synthesized. Findings explicitly disclose that
thunk binding is not persisted and that API association needs analyst review.

Import/external/thunk presence without either qualifying CALL condition yields
INSUFFICIENT_EVIDENCE. No exact prerequisite yields NOT_APPLICABLE within stored
facts. Ordinary internal names, strings mentioning APIs, computed/unresolved
calls, external callers and thunk callers do not create application signals.

Even for a qualifying call, destination capacity, source length, external input
control, reachability, runtime binding and surrounding checks are not proven.
No argument, taint, source/sink flow or exploitability analysis is performed.
The strcpy message states that the API does not enforce destination bounds and
requests further analysis; the gets message states its lack of a destination-size
argument. Neither message claims a buffer overflow has occurred.

## Read-only CLI and trust boundary

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.security.rule_engine \
  analysis.sqlite '<binary_id>'
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.security.rule_engine \
  analysis.sqlite '<binary_id>' --rule AIRE-CWE-120-UNBOUNDED-COPY --json
```

Optional `--list-rules` uses the same positional arguments. CLI exit status is
1 for scan errors/invalid requests and 0 for a completed scan, including signals.
There are no fix, patch, exploit or execute flags. The CLI opens an existing
SQLite file with `mode=ro` and `query_only`, checks schema v1 and never initializes
or migrates it. Programmatic scans only read the caller's existing store.

M7 has no AI transport, sockets, subprocesses, target-file reads/writes or Ghidra
write APIs. Binary labels are data: JSON escaping and terminal escaping prevent
rendering them as commands/control sequences. Model output cannot enter a rule
or trigger a rename, patch or execution. No schema migration or persistence of
findings was necessary. Existing PyGhidra indexing still builds facts in its
temporary unsaved program and M2 persists analysis in a temporary test database;
the rule scan itself performs no writes.

## Controls and validation

Dedicated sources and ground truth live in
[`tests/fixtures/security_rules`](../tests/fixtures/security_rules/GROUND_TRUTH.md).
The existing simple-ELF fixtures are not rebuilt or changed. GCC compiles only;
the three generated targets are never launched. Debug paths/toolchain settings
can change hashes. Compilation output is ignored or temporary.

- `unsafe_copy.c`: copy_input calls strcpy into a local 16-byte buffer. Expected
  CWE-120 SIGNAL. Source ground truth is used for evaluation, never rule input.
- `safe_copy.c`: same shape with a length check and memcpy. Expected absence of
  both API signals, not a broad proof of safety.
- `dangerous_gets.c`: read_input calls the explicitly declared legacy gets
  symbol. Expected CWE-242 SIGNAL. Its compiler/linker warning is expected.
- Pure synthetic indexes test direct external calls, missing imports/calls,
  unresolved calls, wrong identity, isolation and disabled coverage.

`test_security_rules.py` covers the two deterministic contracts;
`test_rule_engine.py` covers registration, states, stable IDs, provenance
rejection, failure isolation, immutable facts, JSON/rendering and read-only CLI.
`test_security_integration.py` freshly compiles/indexes/persists each control
without decompilation/assembly, then verifies exact callsite/import provenance,
unchanged analysis/database/fixture hashes, repeat determinism and bounded states.
It requires `AIRE_RUN_GHIDRA_TESTS=1`; missing local GCC explicitly skips it.
Opted-in compilation/indexing failures are errors, not silent skips.

The pure dependency test starts a separate Python interpreter that rejects any
`aire.ai`, `aire.pyghidra`, `pyghidra`, `ghidra`, `jpype` or `ollama` import, then
scans an existing database successfully. Additional scans block socket/process/
shell creation and Python file opens, enable SQLite query_only, check zero row
writes and compare full ProgramIndex and database bytes. Real integrations block
scan-time sockets/processes and perform the same integrity checks. No Ollama
service or model configuration is required. Registered Python rule code remains
trusted; these tests are regression guards, not an OS sandbox claim.

## Validation run — 2026-09-23

Git baseline: branch `main`, HEAD `ed8881e`, tag `aire-m6`. No commit, staging,
history rewrite, dependency installation, model request or VM configuration change
was performed. M1–M6 implementation, schema, Java plugin and existing fixtures
are unchanged. The old unused security finding scaffold was refined; its single
container-isolation unit test was adapted to the typed M7 constructor.

| Check | Result |
| --- | --- |
| Pure M1–M7 suite | 221 passed; 14 opt-in integration/live tests skipped; 0 errors/failures |
| New pure M7 tests | 39 passed (19 rule controls + 20 framework tests) |
| Standalone real M7 integrations | 3 passed, 0 skipped (30.898 seconds) |
| Full M1–M7 static regression | 232 passed; 3 live tests skipped; 0 errors/failures (235 discovered, 85.919 seconds) |
| Static integrations within full run | All 11 passed, including 8 existing M1–M6 cases and 3 M7 cases |
| Syntax compilation / git diff --check | Passed |

The three full-run skips are M5 unstripped live chat, M5 stripped live chat and
M6 stripped live naming. M7 needs no live test or model. These skips do not make
any new claim about the pre-existing M5/M6 live-resource limitations.

Both positive calls are from entry `00401126` to the actual import-named thunk
`00401030`. strcpy callsite: `00401140`; gets callsite: `00401135`. Each produces
exactly one LOW-strength SIGNAL with matching external/import corroboration and
an explicit unpersisted-binding limitation. The other rule is NOT_APPLICABLE.
The bounded-copy control yields NOT_APPLICABLE for both rules and no findings.

| Fixture | Total scan ms | Fact load ms | CWE-120 rule ms | CWE-242 rule ms |
| --- | ---: | ---: | ---: | ---: |
| unsafe_copy | 3.906 | 3.809 | 0.080 | 0.014 |
| safe_copy | 1.633 | 1.560 | 0.054 | 0.016 |
| dangerous_gets | 0.628 | 0.542 | 0.022 | 0.063 |

These are one local development run, excluding fixture compilation, static
indexing and persistence. They are not production benchmarks. Total includes
fact loading and rule validation. Index/persist times and full machine-readable
results were recorded in `/tmp/aire-m7-full-security-report.json`.

Stable finding IDs (same across standalone and full runs):

- unsafe_copy: `FINDING:324a582515f03915f9e81acaa1693d7a546461ab6e342e6a7e61f732d9a843b9`
  CALL evidence: `EVIDENCE:d08d51b3bcd7b48a39dab251e5c18efc4832b2bc10af5a6ecf1eb63735d84e7d`; source `["ebbd189dc423c5e32d702b9e9d19676d5ddcd27b972f0cefb3b8faf8f72ad4a2:00401126","ebbd189dc423c5e32d702b9e9d19676d5ddcd27b972f0cefb3b8faf8f72ad4a2:00401030","00401140","CALL"]`.
- dangerous_gets: `FINDING:d8427f6fab798c74eea7961c21074897ef6fc29ea70d4cf8a9053d4b96c72480`
  CALL evidence: `EVIDENCE:2f29158d8ba7aba27fcd731eeaa5758db66bba8b40b84e8b71cd1547be14aa3d`; source `["dce554a1342bcaf88a62935772554605f62c49b5540726ef582e134bb0535a87:00401126","dce554a1342bcaf88a62935772554605f62c49b5540726ef582e134bb0535a87:00401030","00401135","CALL"]`.

SHA-256 before/after (each pair identical):

| Fixture | Before | After |
| --- | --- | --- |
| unsafe_copy (new temporary compile) | `ebbd189dc423c5e32d702b9e9d19676d5ddcd27b972f0cefb3b8faf8f72ad4a2` | `ebbd189dc423c5e32d702b9e9d19676d5ddcd27b972f0cefb3b8faf8f72ad4a2` |
| safe_copy (new temporary compile) | `18626f3f632206b44f43b6eaa9da8dfadaf480a7bdb91e63d37a86390b68c852` | `18626f3f632206b44f43b6eaa9da8dfadaf480a7bdb91e63d37a86390b68c852` |
| dangerous_gets (new temporary compile) | `dce554a1342bcaf88a62935772554605f62c49b5540726ef582e134bb0535a87` | `dce554a1342bcaf88a62935772554605f62c49b5540726ef582e134bb0535a87` |
| simple_elf/aire_test_binary | `be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e` | `be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e` |
| simple_elf/aire_test_binary_stripped | `08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188` | `08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188` |

No target was executed. M7 scanning changed no database rows/bytes or stored
ProgramIndex fields. It invokes no Ghidra API and has no binary access/write
path. Only compile outputs, temporary analysis databases and validation reports
were created during testing. `FunctionOverloading.exe`, `FunctionOverloading.zip`
and `demo_readonly.py` remain untouched and unstaged.

M7 meets its framework acceptance criteria. The positive and negative controls
establish the documented API-signal behavior, not a general vulnerability scanner.


## Change inventory and git status

Created:

- `aire-server/src/aire/security/contracts.py`
- `aire-server/src/aire/security/facts.py`
- `aire-server/src/aire/security/rules/__init__.py`
- `aire-server/src/aire/security/rules/api_calls.py`
- `aire-server/tests/test_rule_engine.py`
- `aire-server/tests/test_security_rules.py`
- `aire-server/tests/test_security_integration.py`
- `tests/fixtures/security_rules/unsafe_copy.c`
- `tests/fixtures/security_rules/safe_copy.c`
- `tests/fixtures/security_rules/dangerous_gets.c`
- `tests/fixtures/security_rules/build.sh`
- `tests/fixtures/security_rules/GROUND_TRUTH.md`
- `docs/M7_SECURITY_RULES.md`

Modified:

- `aire-server/src/aire/security/findings.py`
- `aire-server/src/aire/security/rule_engine.py`
- `aire-server/src/aire/security/rules/README.md`
- `aire-server/tests/test_models.py` (typed finding constructor in the existing
  evidence-container isolation test; no M1–M6 implementation change)
- `README.md`, `aire-server/README.md`
- `docs/ARCHITECTURE.md`, `docs/CURRENT_STATE.md`, `docs/ROADMAP.md`, `docs/DEVELOPMENT.md`
- `tests/integration/README.md`

Final git state: `main` at unchanged `ed8881e` / `aire-m6`; 11 tracked files
modified and 13 new M7 files, all unstaged. The three pre-existing untracked
`FunctionOverloading.exe`, `FunctionOverloading.zip`, and `demo_readonly.py` are
unchanged and unstaged. No commit or tag was created. A SHA-256 comparison of
all tracked files against the initial snapshot agrees exactly with this modified
file list; no M1–M6 implementation, existing binary or Java file changed.

## Remaining limits and M8 recommendation

Only exact strcpy/gets import-call conditions are covered. Static linking,
inlining, aliases/wrappers, indirect calls, hidden imports and other APIs can be
missed. Flags do not prove exhaustive analysis. Import-named thunk association is
weaker than an explicit persisted binding. No size/argument/source/sink or
reachability proof, automatic CANDIDATE escalation, vulnerability confirmation,
finding persistence or large-binary scan budget is implemented. The engine
copies lightweight facts for one binary, not all decompiled text; registered
rules run serially without a timeout mechanism.

M8 should expand the small deterministic checks and begin richer source/sink/
context facts with explicit provenance. Prioritize persisted thunk binding and
bounded argument/source/destination evidence, add positive and negative controls,
and retain INSUFFICIENT_EVIDENCE when facts cannot support a conclusion. Signals
and candidates must remain separate from confirmed vulnerabilities. M8 is not
started by this change.
