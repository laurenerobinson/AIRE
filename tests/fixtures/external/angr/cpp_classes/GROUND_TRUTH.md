# cpp_classes — ground truth

Exercise C++ multiple inheritance, virtual dispatch, construction, and an adjusting thunk.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/cpp_classes`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/cpp_classes)

Source: [`tests_src/cpp_classes.cpp`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/cpp_classes.cpp)

Binary SHA-256: `820b9c10aa8d8a422d464bcf920e15aef0315a865902c6798e64673f8225a985`; 18416 bytes.

Observed: ELF, x86_64, 64 bits,
elf-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
STT_FILE cpp_classes.cpp, demangled A/B/C methods, RTTI and vtable symbols agree with the source. ELF main is 0x129d (Ghidra default 0x10129d). Direct C::bar call is 0x134b; computed calls are 0x1361, 0x1378 and 0x138f. Thunk at 0x14cb subtracts 8 from RDI then jumps to C::tool at 0x1490. C::C sets k at offset 0x10 to zero.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

`B::bar` and `B::qux` print B messages. `A::lam` and `A::tool` print A messages. C derives from B and A, overrides bar/tool, and initializes k=0. `main` allocates two C objects through B*/A* and creates a local C. C::C initializes both base subobjects and vptrs.

## Calls and control flow

main directly calls C::bar for the local object and C constructors for allocations; b->bar, b->qux, a->tool compile as three indirect calls. Their source-defined targets are C::bar, B::qux, and C::tool, respectively. The A-subobject path uses a non-virtual adjusting thunk. Source semantic targets are not additional observed direct CALL edges.

Compiler-inserted null adjustment for the A base pointer and stack-canary check are visible in main. Virtual dispatch uses vtable loads. This source has overrides, not an overload test.

## Strings and references

`This is B's implementation of bar`; `This is B's implementation of qux`; `This is A's imp of lam`; `This is A's imp of tool`; `This is C's imp of tool`; `This is C's implementation of bar`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Are all virtual targets direct callees of main?** No. Cite the three computed CALL instructions and their unresolved reference status; explain vtable targets using source separately.
- **Why is this adjusted by eight bytes?** The A base is at offset 8 in C in this build. Cite constructor vptr writes at +8 and thunk SUB RDI,8 before JMP.

## Limits and security interpretation

PIE addresses require the Ghidra load bias (0x100000 in this run). Runtime library methods are not application functions. Allocated objects are not deleted; do not extrapolate exploitability. M9 entry-instruction-only thunk verification may not verify this multi-instruction adjusting thunk. No exact build flags are known.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
