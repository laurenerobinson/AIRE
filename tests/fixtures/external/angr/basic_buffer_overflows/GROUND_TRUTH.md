# basic_buffer_overflows — ground truth

Expose three source-level out-of-bounds write patterns and compiler stack-canary instrumentation.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/basic_buffer_overflows`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/basic_buffer_overflows)

Source: [`tests_src/basic_buffer_overflows.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/basic_buffer_overflows.c)

Binary SHA-256: `68f759392c97968d906faf1a34cf1c50f5e86c8926926b5009d6e767429d7715`; 8651 bytes.

Observed: ELF, x86_64, 64 bits,
elf-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
STT_FILE and all three named functions agree. Entry addresses: overflow_1=0x40055c, overflow_2=0x4005b6, overflow_3=0x40063e, main=0x40068f. Bounds 0x27,0x77,0x4f,0x64 and initialization 0xc8 appear in assembly; overflow_3 increments at 0x40066f. main callsites are 0x400698/0x4006a2/0x4006ac.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (Ubuntu/Linaro 4.7.3-1ubuntu1) 4.7.3.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

`overflow_1` declares 20 bytes and writes indices 0..39. `overflow_2` declares arrays of 100 and 80 bytes; the first loop writes buf_1[i+2] for i=0..119, and the second writes even indices 0..78 in buf_2. `overflow_3` starts i at 200 and increments while i>100, writing outside buf[100] from its first iteration. main lists calls to all three.

## Calls and control flow

main -> overflow_1, overflow_2, overflow_3 as three direct callsites. Each helper has an inserted conditional __stack_chk_fail path.

overflow_1 compares i<=39; overflow_2 compares i<=119 then i<=79 with step 2; overflow_3 compares i>100 with step +1, not a terminating countdown.

## Strings and references

No application message literals are present in the original source.

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Is the second loop in overflow_2 itself out of bounds?** No: it writes even indices below 80. Cite the 0x4f bound and increment by 2, together with the 80-byte declaration.
- **Does overflow_3 count down?** No. Cite i=200, ADD 1 at 0x40066f and JG at 0x400677; distinguish undefined source behavior from a promised infinite execution.

## Limits and security interpretation

Out-of-bounds writes and eventual signed overflow are undefined behavior in C. Sequential source calls do not prove all three execute successfully: an earlier canary failure can terminate the process. No exploit, crash, or execution result is claimed. There are no application message literals.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
