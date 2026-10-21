# bindiff_a — ground truth

Provide the simpler half of a function-similarity pair with repeated numeric input.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/bindiff_a`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/bindiff_a)

Source: [`tests_src/bindiff_a.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/bindiff_a.c)

Binary SHA-256: `f7eef0a7d8d2e0f866551c10145a2b0e9c40229ea3c85cd753a3ba0545d49616`; 7456 bytes.

Observed: ELF, x86_64, 64 bits,
elf-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
STT_FILE bindiff_a.c; main=0x400616, get_num=0x40064c, print_bad=0x400689. Compare at 0x40062b uses 0x539. get_num passes 0x10 to fgets. main loops at 0x40064a. All three literals are present.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (Debian 4.9.2-10) 4.9.2, GCC: (Debian 4.8.4-1) 4.8.4.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

main loops indefinitely in source, calls get_num, compares with 1337, prints Accepted! on equality and otherwise calls print_bad. get_num prompts, calls fgets(buf,16,stdin), and passes the buffer to atoi. print_bad prints Nope!.

## Calls and control flow

main -> get_num; main -> puts@plt on accepted branch; main -> print_bad -> puts@plt. get_num -> printf@plt, fgets@plt, atoi@plt. Source printf with a fixed trailing newline is lowered to puts for the status messages.

Equality with 1337 (0x539) and an unconditional loop back. No success exit is present.

## Strings and references

`Accepted!`; `Enter secret number : `; `Nope!`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **What input is accepted?** The value returned by atoi must equal 1337. Cite main compare, get_num conversion and accepted string reference.
- **Which helpers should resemble bindiff_b?** get_num and print_bad share source purpose, calls and literals. Compare these rather than asserting byte-identical whole binaries.

## Limits and security interpretation

fgets return is unchecked. EOF and conversion overflow are not defined by an idealized numeric-input model. fgets is bounded by the 16-byte buffer here; its mere presence is not evidence of a buffer overflow. No cryptographic authentication is implemented.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
