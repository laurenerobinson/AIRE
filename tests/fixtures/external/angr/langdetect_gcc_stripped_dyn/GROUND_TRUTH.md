# langdetect_gcc_stripped_dyn — ground truth

Recover an argv summation loop from a small stripped dynamically linked C PIE.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/langdetect_gcc_stripped_dyn`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/langdetect_gcc_stripped_dyn)

Source: [`tests_src/language_detector/langdetect_gcc_stripped.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/language_detector/langdetect_gcc_stripped.c)

Binary SHA-256: `c90c1f272ce9a72bffd3234cccab2f5b61ae861ed16e5778cacb80ac9ab9ca6a`; 14376 bytes.

Observed: ELF, x86_64, 64 bits,
elf-stripped; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
Upstream build.sh explicitly maps langdetect_gcc_stripped.c to this dynamic output using gcc, then strip --strip-all --remove-section=.comment. No .symtab or .debug_info remains. Main body is ELF VA 0x1149 (Ghidra 0x101149); loop calls atoi at 0x1182, compares i against argc at 0x1191, and calls printf at 0x11aa. Literal at ELF VA 0x2004 agrees.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: not retained; consult supplied project/recipe where present.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

The source main initializes signed int sum=0, loops i from 1 to argc-1, adds atoi(argv[i]), prints sum = %d followed by newline, and returns 0.

## Calls and control flow

Recovered application entry body -> atoi@plt repeatedly, then printf@plt. No application helper is declared.

Loop excludes argv[0], skips entirely for argc<=1, and advances pointers by 8 bytes on x86-64.

## Strings and references

`sum = %d\n`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Which argument is skipped?** argv[0]. Cite initialization i=1 and indexed load by 8 in the recovered body.
- **Can the name main be claimed from symbols?** No original main symbol survives. Identify the startup-passed body by address, calls and exact string reference; attribute the semantic name to source.

## Limits and security interpretation

No matching unstripped build of this same source is supplied: langdetect_gcc_dyn uses a different source. This is stripped-versus-unstripped corpus diversity, not an exact strip pair. Compiler version was removed with .comment and is unknown. atoi conversion range and signed sum overflow limit source-defined behavior.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
