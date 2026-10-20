# ELF and Windows PE static-analysis verification

Validated 2026-10-06 with the existing Python venv, PyGhidra 3.1.0,
Ghidra 12.1.3, and installed Java 21.

ELF SUPPORT: **PASS**  
PE SUPPORT: **PASS**  
PROFESSOR PE BINARY: **PASS**  
PROFESSOR ELF BINARY: **PASS**

**YES:** Actual tests demonstrate that “A.I.R.E. supports static analysis of
both Linux ELF and Windows PE executables through Ghidra/PyGhidra.”
This verifies the supplied x86-64 ELF and x86 PE32 targets; it does not promise
complete recovery for every executable, architecture, or packed binary.

## Targets and recovered facts

| Target | Path |
| --- | --- |
| Simple ELF | `tests/fixtures/simple_elf/aire_test_binary` |
| Professor ELF | `professor_samples/function_overloading_elf/original/FunctionOverloading` |
| Professor PE | `professor_samples/function_overloading/original/FunctionOverloading.exe` |

| Property | Simple ELF | Professor ELF | Professor PE |
| --- | --- | --- | --- |
| Ghidra executable format | Executable and Linking Format (ELF) | Executable and Linking Format (ELF) | Portable Executable (PE) |
| Ghidra language/architecture | `x86:LE:64:default` | `x86:LE:64:default` | `x86:LE:32:default` |
| Bitness (pointer size × 8) | 64 | 64 | 32 |
| Endianness | little | little | little |
| Compiler spec | gcc | gcc | windows |
| Image base | `0x00400000` | `0x00100000` | `0x00400000` |
| Functions, total | 34 | 46 | 385 |
| Internal / external functions | 29 / 5 | 33 / 13 | 302 / 83 |
| Functions marked thunk | 9 | 21 | 169 |
| Functions with decompiled text | 29 | 33 | 302 |
| Functions with nonempty assembly | 24 | 20 | 302 |
| String artifacts | 100 | 103 | 138 |
| Import artifacts | 5 | 13 | 86 |
| EXPORT artifacts | 30 | 23 | 1 |
| Entry symbol and address | `_start` at `00401060` | `_start` at `001010a0` | `entry` at `004113ca` |
| Direct CALL edges | 29 | 19 | 287 |
| Warning records | 6 | 12 | 127 |
| JSON serialization | PASS | PASS | PASS |
| SHA-256 preserved | PASS | PASS | PASS |

Every recovered function has an address and signature. External functions retain
their namespaces and external flags; thunks retain their thunk flags. Import
artifacts can include labels as well as functions, explaining the PE import
count of 86 versus 83 external functions. Bodyless functions/thunks can have empty
assembly; all internal functions in these runs have decompiled text.

`EXPORT` means symbols at Ghidra external entry points, including executable
entry symbols and sometimes data symbols. These counts are **not** counts of
literal PE export-table or ELF dynamic-export entries. The existing optional
`BinaryRecord.entry_point` remains `None`; the entry symbols above are recovered
as EXPORT artifacts. No new entry-point inference was introduced.

## Warnings and limits

- Simple ELF: one import-log record reports a GNU hash-table markup failure,
  missing `libc.so.6` in the disposable project, and four unresolved external
  symbols; five indirect calls are omitted from the direct-call graph.
- Professor ELF: one import-log record reports unsupported `R_X86_64_COPY`
  runtime relocation for `_ZSt4cout` (272 bytes), missing `libstdc++.so.6` and
  `libc.so.6`, and ten unresolved external symbols; eleven indirect calls are
  omitted from the direct-call graph.
- Professor PE: one import-log record reports missing `KERNEL32.DLL`,
  `MSVCP140D.DLL`, `UCRTBASED.DLL`, and `VCRUNTIME140D.DLL`; one analysis-log record
  reports a missing appropriate PDB; 125 indirect calls are omitted from the
  direct-call graph.

These diagnostics are preserved in each index's `warnings` list. Import symbols
are still recovered without loading their implementation libraries. Recovery is
static and does not resolve runtime indirect calls. Assembly uses the existing
default limits of 200 instructions / 20,000 characters per function.

## Implementation and safety

Inspection of `aire.pyghidra.indexer`, `extractor`, and `graph_builder` found no
ELF-specific loader, section-name, architecture, or image-base assumptions.
`pyghidra.program_loader().source(...).load()` selects the Ghidra loader.
Executable format, language, image base, endianness, and pointer size come from
the loaded Ghidra program. Functions, external symbols, entry symbols, assembly,
decompilation, and call references use Ghidra APIs shared across both formats.

The existing normalized model is named `ProgramIndex` in this codebase.
**No production code changed and no custom executable parser was added.**
The only added files are this report and
`aire-server/tests/test_binary_formats_integration.py`.

Neither professor binary was executed or modified. All target access was for
static loading, extraction, file identification, or hashing. The existing
indexer uses disposable Ghidra projects and closes them without saving.
SHA-256 was recorded before the first analysis, verified before/after every
index call, and checked again after the sequence:

```text
Simple ELF:
be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e
Professor ELF:
be3d58ba6ba922f2e8499025dc28a65d9cc97fe5ca6332310ced1622b7e115e3
Professor PE:
cfc8c5f031587c721d680d3dd9bd94bbc690667acf8651403fb8c7e70f2fab07
```

## Automated tests and reproduction

Four new opt-in integration tests passed in 58.095 seconds:

1. `test_01_simple_elf`
2. `test_02_professor_pe`
3. `test_03_professor_elf`
4. `test_04_shared_runtime_format_isolation`

They check the actual `index_binary()` result, metadata, format, architecture,
bitness, endianness, image base, signatures/addresses, decompiled text, assembly,
strings, imports, entry artifacts, thunk/external flags, valid graph endpoints,
warning serialization, `.to_dict()`, and input integrity. The isolation test
compares complete binary/function/artifact/edge facts across repeated ELF and PE
loads in the same JVM, excluding timestamps, timings, and log text. Both formats
retain identical facts after the other format has been analyzed.
The existing eleven `test_indexer.py` unit tests also passed.

Run from the repository root. `~/tools/jdk-21` is absent on this machine, so the
commands use the existing system Java 21 installation; nothing was installed.

```bash
cd ~/aire
export GHIDRA_INSTALL_DIR="$HOME/tools/ghidra"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PYTHONPATH="$PWD/aire-server/src"

AIRE_RUN_GHIDRA_TESTS=1 \
AIRE_FORMAT_REPORT_DIR=/tmp/aire-format-validation \
aire-server/.venv/bin/python -m unittest discover \
  -s aire-server/tests -p test_binary_formats_integration.py -v

aire-server/.venv/bin/python -m unittest discover \
  -s aire-server/tests -p test_indexer.py -v
```

The integration command writes full indexes and before/after integrity records
under `/tmp/aire-format-validation/`, including repeat-run indexes. For individual
CLI summaries, with the same environment:

```bash
aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/fixtures/simple_elf/aire_test_binary
aire-server/.venv/bin/python -m aire.pyghidra.indexer professor_samples/function_overloading_elf/original/FunctionOverloading
aire-server/.venv/bin/python -m aire.pyghidra.indexer professor_samples/function_overloading/original/FunctionOverloading.exe

sha256sum \
  tests/fixtures/simple_elf/aire_test_binary \
  professor_samples/function_overloading_elf/original/FunctionOverloading \
  professor_samples/function_overloading/original/FunctionOverloading.exe
```
