# M9 Phase 2 — Corrupted Windows executables

A.I.R.E. now validates PE structure before any analysis and reports, for every
upload or library fixture:

- file type and architecture/bitness whenever the headers that carry them parse;
- whether the PE structure is valid;
- each specific corruption or parsing issue (severity, code, message, file offset);
- whether **full**, **partial** or **no** static analysis is possible.

Validation is pure Python over bytes already read (`aire/validation/pe_structure.py`).
Nothing is executed, mapped or modified. Malformed input never raises from the
validator (fuzzed with 600 deterministic mutations in the tests).

## Policy

| Level | Meaning | Intake / GUI behaviour |
|---|---|---|
| `none` | Not a PE, or DOS/PE/COFF/optional headers or section table unusable | Upload rejected (HTTP 400) with the structured report; library row shows *Invalid: rejected*; analysis button disabled |
| `partial` | Headers parse; section data, entry point or import table damaged | Upload accepted; issues shown before and after analysis with *Evidence may be incomplete*; Ghidra loads what is present |
| `full` | No structural errors (informational notes such as overlays allowed) | Normal analysis |

Severity mapping: `fatal` → none; `error`/`warning` → partial; `info` → no effect.
ELF validation is unchanged (header checks; malformed ELF is rejected as before).

Robustness: the analysis worker runs in a separate process. A worker crash
fails only that job; a hang is stopped by a watchdog after
`AIRE_ANALYSIS_TIMEOUT` seconds (default 3600) and the next job starts a fresh
worker. A malformed optional demo binary no longer prevents GUI startup
(Codex review finding; it is listed as unavailable instead).

## Fixtures and documented expected outcomes

Generated deterministically by `scripts/make_corrupt_pe_fixtures.py` from
disposable in-memory copies of two source-backed imported benchmarks
(`TLS.exe` PE32/x86, SHA-256 `5a9327f8…489d`; `GetProcAddress.exe` PE32+/x86-64,
SHA-256 `fac8a1f6…246c`). Originals are hash-verified before and after
generation and are never written. Outputs are read-only (`0444`) in
`tests/fixtures/m9/corrupt_pe/`; hashes and expectations are in
`EXPECTED.json` and the GUI library manifest `tests/fixtures/m9/manifest.json`.
`--check` re-derives every fixture and confirms byte equality.

| Fixture | Derived from | Mutation | Expected analysis | Required issue codes |
|---|---|---|---|---|
| `corrupt_pe/dos_signature_invalid.exe` | `TLS.exe` | DOS magic MZ replaced by ZM | **none** | `dos_signature` |
| `corrupt_pe/pe_signature_invalid.exe` | `GetProcAddress.exe` | PE\0\0 signature replaced by PX\0\0 | **none** | `pe_signature` |
| `corrupt_pe/e_lfanew_out_of_range.exe` | `TLS.exe` | e_lfanew points past end of file | **none** | `pe_header_offset` |
| `corrupt_pe/optional_magic_invalid.exe` | `GetProcAddress.exe` | Optional header magic is neither PE32 nor PE32+ | **none** | `optional_magic` |
| `corrupt_pe/zero_sections.exe` | `TLS.exe` | COFF NumberOfSections set to 0 | **none** | `no_sections` |
| `corrupt_pe/truncated_in_optional_header.exe` | `GetProcAddress.exe` | File cut inside the optional header | **none** | `truncated_optional_header` |
| `corrupt_pe/truncated_section_table.exe` | `TLS.exe` | File cut after the first section header | **none** | `truncated_section_table` |
| `corrupt_pe/truncated_tiny.exe` | `GetProcAddress.exe` | Only 40 bytes remain | **none** | `truncated_dos_header` |
| `corrupt_pe/truncated_half.exe` | `TLS.exe` | Last half of the file removed | **partial** | `section_truncated` |
| `corrupt_pe/section_offset_beyond_eof.exe` | `GetProcAddress.exe` | Code section PointerToRawData past end of file | **partial** | `section_beyond_eof` |
| `corrupt_pe/section_size_oversized.exe` | `TLS.exe` | Code section SizeOfRawData set to 0x7FFF0000 | **partial** | `section_truncated` |
| `corrupt_pe/section_offset_into_headers.exe` | `GetProcAddress.exe` | Code section raw data offset points into the headers | **partial** | `section_raw_offset` |
| `corrupt_pe/section_overlap.exe` | `TLS.exe` | Second section VirtualAddress equals the first | **partial** | `section_overlap` |
| `corrupt_pe/import_directory_invalid.exe` | `GetProcAddress.exe` | Import directory RVA maps to no file data | **partial** | `import_directory` |
| `corrupt_pe/import_dll_name_invalid.exe` | `TLS.exe` | First import descriptor DLL-name RVA invalid | **partial** | `import_dll_name` |
| `corrupt_pe/import_thunks_invalid.exe` | `GetProcAddress.exe` | First import descriptor thunk arrays point nowhere | **partial** | `import_thunks` |
| `corrupt_pe/valid_overlay_appended.exe` | `GetProcAddress.exe` | 4 KiB overlay appended after the last section (common for installers) | **full** | — (must report none) |
| `corrupt_pe/valid_renamed_sections.exe` | `TLS.exe` | All section names replaced with nonstandard names | **full** | — (must report none) |
