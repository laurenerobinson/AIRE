# Screenshot capture checklist (manual)

Prepared 2026-11-17. Capture these from a **genuine** run and label each with
date, browser/terminal, binary and store. Never capture the tokenized launch
URL, the server terminal line that prints it, browser developer tools, cookies
or session files. Close unrelated windows and notifications first.

Existing sanitized guest-Firefox captures (Nov 17, ignored, not in Git) are in
`demo_artifacts/m10/defense_20261117/01-…13-*.png`. They cover the GUI path but
were taken in **Ubuntu headless Firefox**, not Windows Chrome. Re-capture in
Windows Chrome during rehearsal if you want slides to match the live setup.

## A. GUI (Windows Chrome, store `demo_artifacts/m10/defense_20261117/demo.sqlite`)

| # | Screen | Exact state to capture | Slide use | Existing backup |
|---|---|---|---|---|
| G1 | Library | Binary list showing 7 stored binaries; `aire_test_binary` highlighted; URL bar shows `http://127.0.0.1:8770/` with **no** `?token=` | Demo step 1–2 | `01-library.png` |
| G2 | Binary overview | Metadata for `aire_test_binary` (ELF, x86:LE:64:default, SHA-256 prefix `be852ca8…`) | Demo step 3 | `06-overview.png` |
| G3 | Functions list | `validate_input` selected at `004011bc` | Demo step 3 | `06-overview.png` |
| G4 | Imports | `strlen`, `puts`, `printf` | Functional matrix | `02-imports.png` |
| G5 | Strings | "Input must contain 1 to 31 printable ASCII characters." | Demo step 3 | `03-strings.png` |
| G6 | Call Graph (caller/callee lists) | Callers: `process_input` @ `00401316`; callees `strlen`, `puts`×2, `calculate_checksum` | Demo step 4–5 | `04-calls.png` |
| G7 | Decompiled View | `validate_input` C text | Demo step 6 | `05-decompiled.png` |
| G8 | Function explorer → Assembly | Rows `004011dc CMP` and `004011e1 JZ` with explanations visible | Code/Demo step 6 | `07-assembly.png` |
| G9 | Branch paths | Output of **paths** on `004011e1` (true → `puts` error path; false → `CMP …,0x1f`) | Demo step 6 | (none — capture) |
| G10 | Value trace | **trace** on `[RBP-0x10]` at `004011dc` → `MOV` at `004011d8` ← `CALL strlen` at `004011d3` | Demo step 6 | `08-dataflow.png` (data-flow tab) |
| G11 | CFG | Blocks, loop header `00401238` | Diagram slide | `08-cfg.png` |
| G12 | Decompiled vs assembly | Verdict **CONSISTENT** with per-check list | Validation slide | `08-decompiler.png` |
| G13 | Deterministic question | "What does this function do?" answer with citation links | Demo step 7 | `09-question.png` |
| G14 | Evidence / activity expanded | Tool activity + provenance panel | Agent slide | `10-evidence.png` |
| G15 | Findings (unsafe_copy) | CWE-120 **SIGNAL**, LOW strength, callsite `00401183` | Demo step 9 | `11-cwe.png`, `12-cwe-callsite.png` |
| G16 | Findings (safe_copy) | Both rules `NOT_APPLICABLE` | Limitations slide | (none — capture) |
| G17 | Session restore | Recent Chats restored after switching binaries | Demo step 10 | `13-restored.png` |
| G18 | Unauthenticated browser | Second, clean profile opening `http://127.0.0.1:8770/api/health` → 401 | Security slide | (none — capture) |

## B. Terminal (model-free CLI; verified Nov 17 — see `fresh_outputs_20261117/`)

| # | Command | What must be visible | Saved text backup |
|---|---|---|---|
| T1 | `sha256sum tests/fixtures/simple_elf/aire_test_binary_stripped` before and after T2 | identical `08bbd1f4…fb188` | `sha256_after_checks.txt` |
| T2 | `python -m aire.pyghidra.indexer tests/fixtures/simple_elf/aire_test_binary_stripped` | Functions 34 · Decompiled 29 · Strings 48 · Imports 5 · Exports 7 · Call edges 29 · Warnings 6 · ~8.5 s | `indexer_stripped_stdout.txt` |
| T3 | `python -m aire.security.rule_engine <db> <unsafe_copy id>` | CWE-120 SIGNAL, LOW, `00401183`, the four limitations | `cwe_scan_unsafe_copy.txt` |
| T4 | same for `safe_copy` | both NOT_APPLICABLE + "not a safety assessment" | `cwe_scan_safe_copy.txt` |
| T5 | `python -m aire.ai.naming <db> <stripped id> --candidates --limit 8` | 8 `FUN_…` candidates | `naming_candidates_stripped.txt` |
| T6 | `nm tests/fixtures/simple_elf/aire_test_binary \| grep ' T '` | ground-truth addresses (`004011bc validate_input`, …) | (capture) |
| T7 | `objdump -d -M intel tests/fixtures/simple_elf/aire_test_binary \| grep -A1 4011dc` | `cmp QWORD PTR [rbp-0x10],0x0` / `je 4011ea` | (capture) |
| T8 | default test suite summary | `Ran 649 tests … OK (skipped=32)` | `default_suite_summary.txt` |

## C. Java v1 extension (only if rebuilt and rehearsed — see runbook §8)

| # | Screen | State |
|---|---|---|
| J1 | Ghidra CodeBrowser with AIRE dock panel | Function list after **Refresh** |
| J2 | Candidate cards | After **Suggest** on one function |
| J3 | Applied rename | After analyst **Apply** — show this is a manual, per-function action |

No current-environment capture of the Java extension exists; the extension was
not rebuilt in this environment (Gradle is not installed).

## Labeling rule

Every slide image caption: *"Captured <date> from <live run | rehearsal>, store
<name>, fixture <name>. Not a benchmark."* A screenshot from the Nov 17 guest
rehearsal must say "Ubuntu Firefox rehearsal" — not "Windows Chrome".
