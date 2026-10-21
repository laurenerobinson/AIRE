# brancher — ground truth

Read a four-byte unsigned number and report nested range and parity branches.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/brancher`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/brancher)

Source: [`tests_src/brancher.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/brancher.c)

Binary SHA-256: `2ecad01a776415f64653de5ca89514d79a2bae68f7ffb4b1ef606f6f4e799541`; 8430 bytes.

Observed: ELF, x86_64, 64 bits,
elf-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
STT_FILE names brancher.c. main at 0x400544 calls read at 0x400569 with length 4. Comparisons at 0x400571/0x400583 use 0xa/0x13; 0x4005a1 masks by 1. The unsigned jumps and all six literals agree with the source.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

`main` reads four bytes from fd 0 into a zero-initialized unsigned integer. It prints `<=10` for values at most 10; otherwise `>10`, then `<20` or `>=20`, followed by `odd` or `even`.

## Calls and control flow

`main -> read@plt` and `main -> puts@plt`. Six output callsites exist across mutually exclusive branches; no application helpers.

Unsigned comparison with 10 gates all later checks. The inner upper bound is 20 and parity is the low bit. Input is raw little-endian bytes, not ASCII decimal.

## Strings and references

`>10`; `<20`; `>=20`; `odd`; `even`; `<=10`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Does it parse decimal text?** No. Cite read(fd=0, buffer, 4) at 0x400569 and the absence of numeric conversion in main.
- **Which cases produce a parity message?** Only num > 10. Cite the unsigned gate at 0x400574 and the AND/test at 0x4005a1–0x4005a6.

## Limits and security interpretation

In the Ghidra 12.1.3 smoke run none of the six short output literals became STRING artifacts, and the M9 local-string query for main was empty. Raw data references (including target 0x4006bc) and decompiler literals were retained. Use the independent byte/disassembly evidence for those literals; do not relabel decompiler text as an exact stored string artifact. The return value of read is unchecked; short reads leave some initialized bytes unchanged. main has no explicit return in the original source, and this historical build does not force a zero return. Do not assert a deterministic process exit code.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
