# Controlled test corpus

All six original C sources, eight intentional binaries, and two original maps
were preserved byte-for-byte. No binary was executed during reconstruction.
Binaries are Linux x86-64 ELF, dynamically linked. Except `analysis_target`
(non-PIE), they are PIE. Original compilation flags are known only where noted;
source-to-binary reproducibility has not been established by rebuilding.

| Source in source/ | Binaries in binaries/ | Purpose and ground truth |
| --- | --- | --- |
| analysis_target.c | analysis_target (unstripped) | Simple password comparison, authenticate/show_secret/deny_access; names in source and binary symbols. Exact original build command unknown. |
| crackme.c | crackme (stripped) | XOR-encoded input comparison and decoy credential paths; source names are semantic ground truth. No address map or debug partner supplied; original build command unknown. |
| crackmedemo.c | crackmedemo (stripped) | Length, rolling XOR, DJB2 and rotation checks plus decoys; source names are ground truth. Source mentions -s, but complete original flags unknown. Header password/length claims are historical comments, not verified behavior. |
| raptor7.c | raptor7 (stripped) | Drone-themed authentication demonstration with decoy checks and terminal presentation. Source names only; header mentions strip, full original build command unknown. |
| aire_test.c | aire_test_debug (DWARF, unstripped), aire_test_stripped | Eight manual AIRE scenarios: crypto evidence, stub/insufficient evidence, large TLV parser, dispatcher, TCP setup, similar TLS functions, bad-model failure, session orchestration. FUNCTION_MAP.txt matches all 12 listed global text symbols. |
| raptor7_aire.c | raptor7_aire_debug (DWARF, unstripped), raptor7_aire (stripped) | Expanded RAPTOR demo combining the evidence scenarios with telemetry, crypto, authentication and a simulated command UI. Historical RAPTOR7_FUNCTION_MAP.txt mismatches all 12 listed addresses; use the separately derived RAPTOR7_PRESERVED_BINARY_FUNCTION_MAP.txt. |

## Debug/stripped relationships

Each supplied debug/stripped pair has an identical ELF build ID:

- aire_test: `3dc2d10c96f661a9cd2b0ae5b8e609d0271a15bd`
- raptor7_aire: `d9295d95ce13db2ae7fc6e91b3bd50f7c1f47bed`

The maps contain ELF symbol values. For PIE loaded at a different base, apply
Ghidra's load bias; a map address is not automatically a runtime address.
Historical maps list global `T` symbols, not all static/local functions.
FUNCTION_MAP.txt's original header incorrectly mentions SIZE, but rows contain
only address and name; preserved unchanged. The rebuild script corrects the header.
The new RAPTOR map records its source binary SHA-256 and is derived with `nm`,
not inferred from source. Original maps and demo are retained for provenance.

## Rebuild

Known archived build recipes are retained and made location-independent:

```bash
./scripts/build_aire_test.sh
./scripts/build_raptor7_aire.sh
```

These use GCC `-O0 -fno-inline -g`, create a map with `nm -n --defined-only`,
and copy/strip the debug result with `strip --strip-all`. OpenSSL is optional
at compile time; when detected they define HAVE_OPENSSL and link crypto/ssl.
Both link libm. Sources come from tests/source regardless of current directory.
Outputs and regenerated maps go to `build/test-corpus/` by default. Set
AIRE_TEST_OUTPUT_DIR to an alternate output directory; do not point it at the
preserved corpus. Rebuilt addresses can change with compiler/library versions.
No automatic download, package installation, or target execution occurs.

For the four simpler fixtures, a new non-historical local build can be made with:

```bash
mkdir -p build/test-corpus
# Substitute analysis_target, crackme, crackmedemo, or raptor7:
gcc -O0 -g tests/source/analysis_target.c -o build/test-corpus/analysis_target
```

That example is not a reconstruction of unknown original flags. Safe syntax checks:

```bash
for source in tests/source/*.c; do gcc -fsyntax-only -Wall -Wextra "$source"; done
```

Some fixtures contain actual socket/connect calls, despite simulation-themed
names and comments. Compilation and static inspection do not require running them.
Optional manual execution is only for authorized isolated testing.

## Evaluation status

The demo in [docs/AIRE_DEMO_SCRIPT.md](../docs/AIRE_DEMO_SCRIPT.md) is historical
presentation material, not an automated evaluation. Model outputs are variable;
expected suggestions, confidence and insufficient-evidence responses are not
asserted test results. No integration suite existed in the archive.
The Python tests now cover M1 identities, options, bounds, JSON serialization,
failure recovery, and evidence isolation. The opt-in real Ghidra integration
test verifies the controlled stripped fixture without executing it. See
[integration instructions](integration/README.md).
