# External binary benchmarks

Imported on October 20, 2026: **11 precompiled binaries, 11 original C/C++ source
files (10 C, 1 C++), five upstream build/provenance support files, and two license
notices**. There are eight small dynamically linked x86-64 ELF executables,
two genuine Windows PE executables (x86 and x86-64), and one PE32+ DLL with an
intentional malformed export forwarder. Ten fixtures support ordinary application
behavior evaluation; the negative DLL supports only its local C export and raw
export metadata. No binaries were executed, rebuilt, locally stripped, patched,
emulated, or made executable.

## Repository audit and preserved implementation

The working tree was clean on `main` at
`3a2b5c35ee4855a769226ee905ffb4746b5a3d95` (Speed Update).
`origin` was `git@github.com:laurenerobinson/AIRE.git`; read-only `git ls-remote
origin refs/heads/main` matched HEAD and the local origin/main reference.
No pull, fetch-to-local-ref, merge, reset, commit or push was performed.
Local source was the authority; the unauthenticated GitHub web rendering was
not used to infer synchronization.

Reviewed existing `tests/README.md`, `tests/fixtures/simple_elf/GROUND_TRUTH.md`,
`docs/M9_IMPLEMENTATION_2026-10-13.md`, `docs/BINARY_FORMAT_SUPPORT.md`, the current
indexer/options/models/store/investigation code, and format/indexing/reference
integration tests. No AGENTS.md instructions were found in the workspace or its
ancestor locations. No requested external candidates were already present.

The existing corpus uses tests/source, tests/binaries and fixture-local ground
truth; professor samples live separately. There was no external fixture library.
The new subtree is `tests/fixtures/external/angr/<fixture>/`. All **46 existing
files under tests/ and professor_samples/** (excluding generated __pycache__)
remain byte-identical. This includes original small ELF fixtures, controlled
corpus, maps and professor Windows/ELF examples. See
[before/after integrity evidence](external_benchmarks/existing-fixture-integrity.json).
All project changes are additions; no agent, analysis algorithm, schema, UI or
existing fixture/build script was edited.

M9 provenance distinctions are preserved: direct CALL edges, typed computed
references, separate thunk bindings, exact function-owned string references,
binary-global strings, and unknown runtime targets are not conflated.

## Pinned inventory

Every imported binary and source comes from [angr/binaries](https://github.com/angr/binaries) at
**`7c257a842592b885be27acf5c836bcbb8ec84e08`** (master as observed during retrieval). Original upstream paths,
all source/support hashes and Git blob identities are in the
[machine-readable manifest](../tests/fixtures/external/manifest.json).
The table links each fixture's complete ground truth. Hashes below are SHA-256.

| Format | Fixture and ground truth | Bytes | What it tests | SHA-256 |
| --- | --- | ---: | --- | --- |
| ELF64 | [brancher](../tests/fixtures/external/angr/brancher/GROUND_TRUTH.md) | 8430 | Unsigned ranges, parity, short-string coverage | `2ecad01a776415f64653de5ca89514d79a2bae68f7ffb4b1ef606f6f4e799541` |
| ELF64 | [argc_decide](../tests/fixtures/external/angr/argc_decide/GROUND_TRUTH.md) | 6618 | Argument counts, early returns, leaf function | `e8617de193c86ae4375ef1f08d7a678e906d61e4b53ca62b1055f12983386eca` |
| ELF64 | [cpp_classes](../tests/fixtures/external/angr/cpp_classes/GROUND_TRUTH.md) | 18416 | Multiple inheritance, vtables, indirect calls, adjusting thunk | `820b9c10aa8d8a422d464bcf920e15aef0315a865902c6798e64673f8225a985` |
| ELF64 | [basic_buffer_overflows](../tests/fixtures/external/angr/basic_buffer_overflows/GROUND_TRUTH.md) | 8651 | Actual source-level out-of-bounds writes, loop bounds, canaries | `68f759392c97968d906faf1a34cf1c50f5e86c8926926b5009d6e767429d7715` |
| ELF64 | [bindiff_a](../tests/fixtures/external/angr/bindiff_a/GROUND_TRUTH.md) | 7456 | Simple half of similarity pair, input conversion | `f7eef0a7d8d2e0f866551c10145a2b0e9c40229ea3c85cd753a3ba0545d49616` |
| ELF64 | [bindiff_b](../tests/fixtures/external/angr/bindiff_b/GROUND_TRUTH.md) | 7576 | Modified similarity pair, short-circuit arithmetic predicate | `b3308d8e7a68fa217d561dbfac55597e176941fb0545f7721476440b0cc09d1e` |
| ELF64 | [datadep_test](../tests/fixtures/external/angr/datadep_test/GROUND_TRUTH.md) | 8826 | Scalar vs buffer dependencies, two copy callsites, global writes | `3ea90813e09d1ef110505cb2030dbe3d50172540c389229cdf7261f1db3fe980` |
| ELF64 | [langdetect_gcc_stripped_dyn](../tests/fixtures/external/angr/langdetect_gcc_stripped_dyn/GROUND_TRUTH.md) | 14376 | Stripped PIE, argv loop and conversion | `c90c1f272ce9a72bffd3234cccab2f5b61ae861ed16e5778cacb80ac9ab9ca6a` |
| PE32+ | [windows_getprocaddress](../tests/fixtures/external/angr/windows_getprocaddress/GROUND_TRUTH.md) | 14848 | Dynamic resolution, global pointer, guarded indirect calls | `fac8a1f6e2351b870ebb426a2339ff817b195a437be0f7f6fc91f739579d246c` |
| PE32 | [windows_tls_x86](../tests/fixtures/external/angr/windows_tls_x86/GROUND_TRUTH.md) | 36864 | TLS metadata, callbacks, thread-entry pointer, PE32 runtime code | `5a9327f87f994a76c84c986a498e105be183a558b520fe6004ceb6e498a7489d` |
| DLL / PE32+ | [windows_invalid_export_forwarder](../tests/fixtures/external/angr/windows_invalid_export_forwarder/GROUND_TRUTH.md) | 6276 | Negative DLL parser/encoding case; local export returns 42 | `8b2ca323c14b2f3a46142a027713fd50f56b1baf0d4ab83c38c01cc56f4cbb3a` |

## Authenticity, source confidence and licenses

Selective GitHub tree metadata pinned the commit before raw-file retrieval.
Every original file was compared with the Git blob SHA-1 at that commit and
recorded with SHA-256 and size. Bounded static validation checks ELF/PE signatures,
architecture, executable/DLL flags, header/table ranges, section file bounds,
symbol-table status and debug markers. It rejects HTML, LFS pointers, missing or
oversized files and truncated/out-of-range structures. The per-file limit is
2 MiB; the largest imported binary is only 36,864 bytes. This is structural
validation, not a promise that every possible malformed executable is detected.

Source confidence is **high/corroborated**, not “reproducibly exact build”. For the
seven original ELF candidates, STT_FILE records, application function symbols,
literal references, callsites, branches and constants match the source. C++ RTTI,
vtable symbols and adjustment instructions support the class layout. The stripped
fixture has an explicit source-to-output build recipe plus independently matched
instructions and literals. GetProcAddress and TLS have co-changing upstream source
and binary history plus matching application bodies. The DLL has a co-added C,
.def, compiler-version/build recipe and documented one-byte post-link mutation.
Full compiler flags/build logs are missing for most samples; no exact source-byte
or toolchain attestation is invented. Unknowns and undefined C behavior are stated
per fixture. No unverified source relationship is admitted to accuracy scoring.

Compiler clues: older ELF .comment markers report GCC 4.6.3, 4.7.3, 4.9.1 or mixed
4.8.4/4.9.2 objects; C++ reports GCC 9.3.0. These are object-level clues, not complete
commands. GetProcAddress has GCC 13-win32 markers; TLS's v140 project and external
PDB path indicate a VS2015-era debug configuration. The stripped fixture removes
.comment. The DLL's upstream recipe identifies GCC 15.3.0/binutils 2.46/
mingw-w64 14.0.0 and a no-CRT link. Supplied recipes were never run.

Root LICENSE.md licenses angr-authored samples under MIT, Copyright 2018 The angr
Team, unless otherwise specified. Reviewed file headers and all ancestor license
locations in the pinned tree. The retained tests/x86_64/LICENSE.md overrides only
unrelated named valgrind/coreutils files. LICENSE.libc concerns copied system
shared objects; none was imported. No more-specific exception applies to these
selected files. Source notices remain unchanged, shared upstream notices are
retained once, and each provenance record points to them. Dynamically imported
system DLLs and libc/libstdc++ implementations are not redistributed.

## Compatibility and validation

The normal command sandbox failed before executing commands (`bwrap` network
and UID-map setup errors). Executable inspection therefore used the retained
Linux Landlock/seccomp launcher, which installs restrictions before starting any
static tool: read-only/no-execute fixtures, no network sockets, no ptrace/mount,
no private repository metadata, and writes only inside a disposable directory.
Self-tests confirmed denied network, private .git reads and outside writes.
No target analysis used unrestricted host permissions. Git/network retrieval and
copying were separate from restricted executable analysis.

Ghidra 12.1.3 PUBLIC, JDK 21 and the existing PyGhidra environment were used.
All 11 imported files were indexed with the existing index_binary implementation
in disposable, unsaved projects. Six representatives additionally received full
assembly/decompilation, temporary SQLite save/load checks, M9 local-string queries,
and cached AgentTools get_function_strings calls without a model. The other five
received lightweight facts without decompilation. Source-defined direct call
relationships, repeated copy callsites, graph endpoints and unresolved computed
targets were checked where applicable. The DLL has zero direct calls as expected.
The smoke utility succeeds only after all selected checks complete; it is a
compatibility test, not an AI explanation-accuracy score.

| Validation group | Passed | Failed/errors | Skipped |
| --- | ---: | ---: | ---: |
| All pre-existing unittest modules | 418 | 0 | 23 |
| New offline fixture integrity/corruption tests | 8 | 0 | 0 |
| Static fixture indexing checks | 11 | 0 | 0 |
| Full representative M9/store/tool checks (subset of preceding row) | 6 | 0 | 0 |

The pre-existing suite ran 441 tests; 23 opt-in integration/model tests were
skipped. New tests were run separately within the static sandbox because the
normal existing GUI regressions use a local HTTP server. Combined unittest total:
449 tests, 426 passed, 0 failed/errors, 23 skipped. No skip is counted as a pass.
See [validation counts](external_benchmarks/validation.json) and
[full compatibility summary/warnings](external_benchmarks/compatibility.json).
No live Ollama/model-quality evaluation was run.

| Fixture | Functions | STRING artifacts | Direct CALL edges | Typed references |
| --- | ---: | ---: | ---: | ---: |
| brancher | 22 | 74 | 13 | 158 |
| argc_decide | 17 | 72 | 6 | 131 |
| cpp_classes | 56 | 127 | 28 | 338 |
| basic_buffer_overflows | 23 | 77 | 12 | 193 |
| bindiff_a | 31 | 87 | 13 | 165 |
| bindiff_b | 32 | 88 | 14 | 174 |
| datadep_test | 32 | 86 | 14 | 220 |
| langdetect_gcc_stripped_dyn | 26 | 39 | 5 | 139 |
| windows_getprocaddress | 96 | 87 | 70 | 917 |
| windows_tls_x86 | 319 | 115 | 208 | 1813 |
| windows_invalid_export_forwarder | 3 | 5 | 0 | 22 |

Counts include runtime/library artifacts; they are observations, not universal
version-independent golden totals. Not every STRING artifact is application text.
Ghidra external-entry EXPORT artifacts are not necessarily literal PE exports.

Observed limitations:

- **brancher:** none of its six short application output literals became STRING
  artifacts in this run. The M9 main-local-string query is correctly empty. Raw
  address references and pseudocode retain the uses; independent bytes/assembly
  establish the messages. An early smoke assertion expecting a local string
  failed; the final check records all omissions and verifies a raw reference.
  No extraction code was changed to conceal the gap.
- **C++:** R_X86_64_COPY for std::cout is unsupported in this static import;
  external library implementations are absent. Three virtual main calls remain
  unresolved computed references. The adjusting thunk has instructions before its
  JMP, beyond M9's entry-only direct-JMP verification. No fictitious direct edges
  to virtual implementations are introduced.
- **Windows executables:** application symbols/PDBs are missing. Ground truth
  maps application bodies by static addresses and behavior. DLL imports remain
  unresolved without imported library bodies. TLS startup callback/thread roots
  are not represented as direct main-to-worker calls. CRT/debug routines and
  strings substantially inflate counts.
- **Negative DLL:** the PE is structurally valid and byte-identical to upstream,
  but a non-UTF-8 forwarder is intentionally malformed. Ghidra replaces 0x9f in
  displayed names and reports an unavailable U�ER32.DLL. It still extracts
  local_export returning 42. This does not establish Windows loader success and
  does not substitute for a normal multi-function source-backed DLL benchmark.
- **General:** indirect calls are omitted from the direct-call graph by design;
  missing libraries, PDB warnings, and an older ELF GNU-hash markup warning are
  retained in the report. No general def-use slice or dynamic behavior was tested.

## Investigated exclusions and remaining gaps

- [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp), default dev
  `cf8b12db27eb139b28b90eaa3488306da910d759`, and main
  `0c9573efc174bbb1ea8f3c2336ec4bb3ebfe9f10`: current
  tests/fixtures/benchmark/Benchmark.dll and BenchmarkDebug.exe are generated by
  Python x86/PE emitters. They are not binaries compiled from the historical C.
  The old fun-doc/benchmark tree at
  `279c0b7394f696439b1945501f1159433851bcd7` contains C and build instructions,
  but its compiled outputs were gitignored, then the directory was moved out.
  Sources from that history were not falsely paired with today's generated PEs.
  No secondary files were added to the benchmark library.
- [RevEngAI/plugin-ghidra](https://github.com/RevEngAI/plugin-ghidra), main
  `fd4add4f465ea7a1bc08e185c3efe4d076dbd15a`: fdupes and fdupes.stripped share
  build ID 039170547dfe490e7361825097853872a6aef539. DWARF identifies fdupes 1.6.1,
  fdupes.c, md5/md5.c and GCC 6.3.0. That supports a variant relationship but
  does not establish an exact original source revision. The nearby Debian archive
  fdupes_1.6.1-1+b1_amd64.deb was checked statically and its executable hash differs
  from the sample. No exact-source claim or redistribution under the plugin's
  general license was made; both samples remain excluded. Downloaded investigation
  copies/archives remain temporary, outside this library.
- angr's larger static langdetect variant was deferred in favor of the small
  dynamically linked stripped sample. Existing langdetect_gcc_dyn uses a different
  C source; it is not mislabeled as the stripped sample's unstripped partner.
- Windows x64 TLS was inspected as a candidate but not imported; its source match
  was not investigated to the same level as the corroborated x86 sample. Large,
  packed, system-library and unrelated candidates were not selected.
- A normal Windows DLL and an exact upstream stripped/unstripped pair remain
  desirable additions. The current library provides symbol-status diversity;
  existing AIRE strip pairs were preserved for exact-pair experiments.

## Reproduction

From the repository root, use the existing Python environment. These commands do
not download, install, rebuild or execute targets. The helper requires Linux
x86-64 with Landlock ABI >=3 and the already installed libseccomp.so.2; it fails
closed when unavailable. On other platforms use an appropriately restricted
container/VM for static inspection. Give Python/script paths as absolute paths
because the helper changes to the disposable directory.

```bash
python3 scripts/external_fixture_sandbox.py /tmp/aire-external-check --self-test

python3 scripts/external_fixture_sandbox.py /tmp/aire-external-check \
  /usr/bin/python3 "$PWD/scripts/validate_external_fixtures.py"

python3 scripts/external_fixture_sandbox.py /tmp/aire-external-check \
  "$PWD/aire-server/.venv/bin/python" -m unittest test_external_fixtures -v

python3 scripts/external_fixture_sandbox.py /tmp/aire-external-check \
  "$PWD/aire-server/.venv/bin/python" "$PWD/scripts/smoke_external_fixtures.py" \
  --all --output /tmp/aire-external-check/indexes
```

Omit --all for the six representatives. GHIDRA_INSTALL_DIR and JAVA_HOME may point
to existing installations; no new dependencies were added. Original upstream
download URLs are reproducible as
`https://raw.githubusercontent.com/angr/binaries/<upstream_commit>/<upstream_path>`
for each upstream file record. Retrieve selectively and verify before admission.
Do not execute copied upstream support scripts. The manifest validator is
offline and standard-library-only; it checks every listed file, detects extra
files, and does not start Ghidra or any target.

To run the ordinary full default unittest discovery in a normal permitted test
environment, use the existing documented command:
`PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m unittest discover -s
aire-server/tests -v`. In this environment the pre-existing 441 tests were run
separately from the sandboxed new fixture tests to keep downloaded-target
inspection restricted while allowing the GUI regression's local test server.

## Added files

- tests/fixtures/external/: 75 files — 11 binaries, 11 original sources, five inert
  upstream support files, two shared license notices, 11 GROUND_TRUTH.md,
  11 STATIC_EVIDENCE.md, 11 PROVENANCE.json, 11 SHA256SUMS, README.md and manifest.json.
- scripts/validate_external_fixtures.py: dependency-free offline integrity and
  ELF/PE structure validation.
- scripts/smoke_external_fixtures.py: optional static index/store/M9 checks.
- scripts/external_fixture_sandbox.py: fail-closed Linux static-tool restrictions
  and self-tests, needed because the session's default sandbox could not start.
- aire-server/tests/test_external_fixtures.py: eight targeted corruption/integrity
  tests; no target execution and no new production behavior.
- docs/EXTERNAL_BINARY_BENCHMARKS.md: this report.
- docs/external_benchmarks/compatibility.json: observed per-fixture extraction
  counts, checks, limitations and warnings.
- docs/external_benchmarks/validation.json: actual validation counts and safety facts.
- docs/external_benchmarks/existing-fixture-integrity.json: 46 preserved original
  paths, byte sizes and hashes checked again after import.

Total: **83 new files; zero existing tracked files modified**. All work is
uncommitted and unpushed.
