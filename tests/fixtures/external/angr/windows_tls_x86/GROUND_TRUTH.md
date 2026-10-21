# windows_tls_x86 — ground truth

Exercise PE32 thread-local storage, loader callbacks, and a thread-entry pointer.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86/windows/TLS.exe`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86/windows/TLS.exe)

Source: [`tests_src/windows/AngrTests/TLS/tls.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/windows/AngrTests/TLS/tls.c)

Binary SHA-256: `5a9327f87f994a76c84c986a498e105be183a558b520fe6004ceb6e498a7489d`; 36864 bytes.

Observed: PE, x86, 32 bits,
pe-no-coff-symbol-table; debug status external-pdb-reference.

Source relationship: **high-confidence corroborated application behavior**.
Commit 822c070f87d1104283ffbd4ce0bdac0f1dde9c4f updates binary, tls.c and TLS.vcxproj together. Project uses v140; PE CodeView points to AngrTests\Debug\TLS.pdb. Ghidra bodies 0x4116c0 (increment), 0x411730 (main), 0x411800 (decrement) agree. FS:[0x2c] and _tls_index select storage; application TLS offset is +0x104. CreateThread gets 0x41135c, a jump thunk to the worker.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: not retained; consult supplied project/recipe where present.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

tls_i is initialized to 0xaa per thread. tls_callback increments it without checking reason. thread_func decrements its own TLS value and returns 0. main passes thread_func to CreateThread, then WaitForSingleObject(INFINITE), and returns 0.

## Calls and control flow

main -> CreateThread and WaitForSingleObject through import pointers. main passes a thread-entry thunk address; it does not directly call thread_func. Windows loader invocation of tls_callback is represented by TLS metadata, not an application direct CALL.

The application callback and worker body have no source conditionals. Debug initialization loops, runtime checks, thunks and startup branches are compiler/runtime artifacts. Callback does not restrict itself to attach reasons; detach may increment too.

## Strings and references

No application message literals are present in the original source.

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Is the main thread TLS value decremented by the worker?** No, source declares __declspec(thread). Cite separate TLS lookup in worker and callback plus the PE TLS directory.
- **Is thread_func a direct callee of main?** No. Cite address 0x41135c passed to CreateThread and distinguish callback/thread-entry references from direct CALL edges.

## Limits and security interpretation

No original PDB is included; semantic function names are source-derived and mapped by instructions, not symbols. Source comments narrate attach/thread activity but callback increments on every loader reason. Failed CreateThread/WaitForSingleObject are unchecked. This is static evidence only; no threads were started and no callback was executed. CRT/debug strings are not application message strings.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
