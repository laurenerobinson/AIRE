# M10 pre-hardening Git checkpoint — 2026-11-17

Branch: `checkpoint/m10-pre-hardening`.
Commit message: `checkpoint(m10): preserve assembly intelligence implementation before hardening`.
This record describes preservation checks, not completion of M1–M10 hardening.

## Preserved scope

Instruction IR extraction and persistence, instruction semantics, control/data flow,
decompiler cross-validation, assembly intelligence, deterministic factual chat,
structural-condition reporting, agent tools, GUI integration, associated regression
tests, evaluation/benchmark/browser-verification scripts, buildable M10 fixtures,
and existing M10/chat-performance evaluation documentation and metrics.

## Validation

- Existing `aire-server/.venv` and `PYTHONPATH=aire-server/src`; no packages installed.
- Focused M10 and chat suite: **78 passed, 0 failed, 0 skipped**, plus 107 passing pytest subtests.
- Documented default `unittest discover -s aire-server/tests -v`: **597 discovered,
  568 passed, 0 failed, 29 skipped**, in 13.065 seconds. Skips are explicitly opt-in
  Ghidra/static integration tests. Live inference was not enabled.
- Python syntax checked for the changed Python files and preserved profiling helpers.
- `node --check aire-server/src/aire/api/static/app.js` passed.
- Initial staged and unstaged `git diff --check` passed. Final staging exposed five
  trailing spaces in the historical `phase1_ghidra_tests.txt` log; those spaces were
  removed without changing results, then both checks passed on the final index.
- M10 optimized ELF hash matches `tests/fixtures/m10/SHA256SUMS`.
- Credential-pattern inspection covered changed text and SQLite text/decompressed IR;
  no credentials or private session tables were found in the selected files.

The focused test command was:

```bash
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m pytest -q \
  aire-server/tests/test_m10_agent.py aire-server/tests/test_m10_crossval.py \
  aire-server/tests/test_m10_flow.py aire-server/tests/test_m10_semantics.py \
  aire-server/tests/test_chat_fact_answers.py aire-server/tests/test_chat_structure.py
```

## Intentional SQLite fixture

`tests/fixtures/chatperf/crypto_pe_index.sqlite` is a 4,317,184-byte regression
fixture required by the deterministic chat tests. Its SHA-256 matches its manifest:
`3723208dde564df7771bead6ba8d37858c2f4f59f3ad7282d0c0aac05e83a689`.
SQLite integrity and foreign-key checks passed. Its three binary identities match
the checked-in M9 crypto fixtures and their ground truth. It contains only index
tables, including 17 retained instruction-IR documents, with no session tables,
triggers, or views. Exporting from the existing M10 store to a temporary directory
using `scripts/export_chat_crypto_fixture.py` reproduced the file byte-for-byte.

Non-secret original source paths under the repository author's home directory
remain in binary metadata, Ghidra import warnings, and program provenance. These
refer only to checked-in test executables; they contain no credentials. Historic
profiling helpers and test records also retain local paths. A fresh Ghidra index
can vary in timestamps, timing, and tool-version metadata; exact byte reproduction
was verified against the existing source snapshot, not across different installations.

## Deliberately excluded; retained on disk

- All of `demo_artifacts/m10/`: analysis stores, runtime output, uploads, browser profiles,
  and sessions. Existing generated databases and prior demo session/profile directories
  remain ignored as well.
- Temporary Firefox profiles, browser caches/session state, and SQLite sidecars.
- `docs/m10/browser_*.png`, `docs/chatperf/**/*.png`: browser captures.
- `docs/m10/phase4_gui_transcript.txt`, baseline `run1.jsonl` and `stall.jsonl`:
  session/transcript-style outputs.
- M10 and chat-performance `*.log` files: transient runtime/benchmark logs.
- Existing virtual environment, Python caches, pytest cache, and packaging metadata.

Benchmark `http_fastpath.jsonl` files were reviewed as evaluation metrics: predefined
fixture questions, timings, correctness, counts, and no session IDs or answer bodies.
They are preserved alongside JSON evaluation reports and historical test records.
No existing files or directories were deleted, and implementation behavior was not changed.

## Outstanding work and next steps

1. Run the documented Ghidra-enabled M1–M10 integration suite with the existing
   configured runtime, recording all skips and failures separately from pure tests.
2. Complete the interrupted M10 evaluation: the saved AES report is partial, several
   evaluation units and the merged `eval_full.json` are absent, and the linked
   `M10_EVALUATION.md` has not been produced. Existing checkpoint notes are historical.
3. Audit upload/path handling, API/session isolation, untrusted binary/SQLite/IR input,
   decompression/resource bounds, GUI rendering, and model narration/citation claims.
4. Re-run browser, cancellation/responsiveness, cold/warm cache, malformed-input,
   and performance regressions; test fixture portability from a fresh checkout.
5. Validate optional local-model behavior separately, accounting for the previously
   documented VM stalls. Keep all new profiles, transcripts, and runtime stores ignored.

No push is part of this checkpoint workflow.
