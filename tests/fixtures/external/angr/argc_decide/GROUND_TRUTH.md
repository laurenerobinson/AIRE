# argc_decide — ground truth

Distinguish argument counts with two equal early return values.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/argc_decide`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/argc_decide)

Source: [`tests_src/argc_decide.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/argc_decide.c)

Binary SHA-256: `e8617de193c86ae4375ef1f08d7a678e906d61e4b53ca62b1055f12983386eca`; 6618 bytes.

Observed: ELF, x86_64, 64 bits,
elf-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
STT_FILE is argc_decide.c. main is 0x4004b6. Comparisons at 0x4004c1 and 0x4004ce test 1 and 2; MOV EAX,0xa at 0x4004c7/0x4004d4 and MOV EAX,0 at 0x4004db establish returns.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (GNU) 4.9.1 20140903 (prerelease).
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

`main(argc, argv)` returns 10 when argc is 1 or 2, and 0 otherwise. argv contents are not inspected.

## Calls and control flow

main is a leaf: no calls from the application function. Runtime startup calls are outside this application ground truth.

Two separate equality tests, argc == 1 then argc == 2. Both early exits return 10; the fallback returns 0.

## Strings and references

No application message literals are present in the original source.

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **What depends on argv contents?** Nothing in main. Cite the saved but unused argv pointer and comparisons against argc.
- **What does argc=3 return?** 0. Cite both failed equality paths and 0x4004db.

## Limits and security interpretation

No application strings are expected. Generic loader/library-name artifacts must not be presented as strings referenced by main. Calling the function outside ordinary process startup could supply other argc values.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
