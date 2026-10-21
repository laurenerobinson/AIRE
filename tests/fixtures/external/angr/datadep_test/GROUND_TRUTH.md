# datadep_test — ground truth

Separate computed scalar data from local and global buffer-copy dependencies.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/datadep_test`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/datadep_test)

Source: [`tests_src/datadep_test.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/datadep_test.c)

Binary SHA-256: `3ea90813e09d1ef110505cb2030dbe3d50172540c389229cdf7261f1db3fe980`; 8826 bytes.

Observed: ELF, x86_64, 64 bits,
elf-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
STT_FILE datadep_test.c and calc_sum=0x40064c, gen_random=0x400684, buf_cpy=0x4006db, main=0x400720. calc_sum call at 0x400774 writes a scalar; lengths 0x400 are passed at 0x400780/0x40079b/0x4007b2. Copy callsites 0x4007a6/0x4007bf target the same helper; global destination is 0x601080.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (Ubuntu/Linaro 4.7.3-1ubuntu1) 4.7.3.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

calc_sum stores sum(0..upper-1) through int* n. gen_random fills n bytes with rand()%256. buf_cpy copies n bytes from src to dst. main scans upper, computes n, fills a 1024-byte source, then copies 1024 bytes to a local buffer and to g_buf[1024]. The computed n is not used as either copy length.

## Calls and control flow

main -> printf, scanf (binary __isoc99_scanf), calc_sum, gen_random, and buf_cpy at two distinct callsites. gen_random -> rand. calc_sum and buf_cpy are application leaves.

Each helper has an index loop. calc_sum stops at i>=upper; nonpositive upper yields zero when called with a defined integer. Copies use fixed sizeof values, independent of the scanned bound.

## Strings and references

`Please input sum: `; `%d`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Does user input determine the buffer-copy size?** No. Cite immediate 0x400 lengths at both copy callsites and the separate stack slot receiving calc_sum output.
- **Is buf_cpy necessarily an overflow here?** No: both destinations and the source have 1024 bytes and both calls use 1024. Cite source dimensions and binary argument setup.

## Limits and security interpretation

scanf return is unchecked, so failed conversion can leave upper indeterminate. Large upper can overflow signed sum. rand is not cryptographic randomness. M9 currently does not provide general def-use slicing; source dependency expectations are for evaluation, not a claim that such a feature was added.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
