# GUI & chatbot reliability / UX — checkpoint

Authoritative progress record for the GUI/UX work (Phases 0–6). Read this first when resuming.
Nothing in this work has been committed. Commit, push, reset, clean and branch switches need explicit approval.

## Phase 0 — protect state (2026-11-12) ✅
- Checkpoint: `~/aire_backups/guiux-phase0-20261112-142624`, restore verified (`RESTORE.md`). It includes
  `ignored-files.tar.gz` with the gitignored Step 1 fixture and `docs/m9/benchmarks` data.
- Disk was at 100% (205 MB free). With user approval, deleted `/tmp/aire_ghidra_runtime_*` (stale, unused)
  and `~/aire-backup-pre-agents-2026-11-10`. Free space is now 1.3 GB (95%).
- `.gitignore`: added an exception for `tests/fixtures/chatperf/crypto_pe_index.sqlite` (approved).
- The GUI on port 8767 was not running at the start (no listener, no process).

## Phase 1 — correctness fixes ✅
- **Issue A (combined intents):** `fact_answers.signature_operations()` handles coordinated sign/verify phrasing
  under signature context. A bare "signature" is treated as a C prototype, and signed/sign-extend/sign flag are
  integer semantics. Operations are ordered by `DISPLAY_ORDER`.
- **Issue B (damaged files):** `aire/analysis/file_structure.py` re-validates the original file (M9
  `validate_pe`, or `inspect_binary` for ELF) only when its SHA-256 matches. Each issue code maps to the evidence
  it makes unreliable. New `file_identity` intent ("What is this file?", "Is this binary corrupted?").
  - Whole-program overviews of `partial`/`none` files are answered deterministically, with no model call.
  - Model and M10 answers about damaged or unverified files get a structural banner.
  - Deterministic answers state the condition.
  - The compact model prompt no longer contains the file name.
- Tests: `tests/test_chat_structure.py` (all 18 `EXPECTED.json` fixtures, valid/partial/invalid/missing,
  misleading-name), plus combined-intent tests in `test_chat_fact_answers.py`.
- Full default suite: 567 passed, 29 skipped, 0 failed.

## Phase 2 — concise presentation ✅
- Deterministic answers lead with `**Answer:**`, then a role table (role · function+address · API @ call site ·
  callers), then one context line and a one-line "verified" note.
- The visible answer has no long IDs and no "Retrieved tool facts" dump. Presentation fields: `verified`,
  `limitations` (full list), `tool_facts` (full identifiers), structured `facts` (roles / apis / edges /
  api_calls / call_sites / structure). All are stored in the transcript.
- Frontend (`app.js`, `app.css`):
  - verified vs AI badge;
  - markdown tables, bold in list items, italics;
  - expandable sections only when non-empty: Evidence (short ID, full ID on hover, provenance JSON on expand),
    Call relationships, Limitations, Tool output, Security, Raw record.
- Verification:
  - full suite: 568 passed, 29 skipped;
  - HTTP benchmark (`docs/chatperf/guiux_phase2_2026-11-12/http_fastpath.jsonl`): 108/108 correct, 0 model
    calls, result median 6 ms, p95 21 ms, max 53 ms;
  - real Firefox (`scripts/verify_chat_ui_browser.py`): PASSED; answer rendered 38–88 ms after submit;
    screenshots saved.

## Next (awaiting user go-ahead after the Phase 1–2 report)
Phase 3 narration (non-blocking, opt-in, contradiction checks), Phase 4 cancel/responsiveness, Phase 5 planner,
Phase 6 verification.
