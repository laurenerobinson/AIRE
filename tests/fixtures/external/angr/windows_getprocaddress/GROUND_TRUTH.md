# windows_getprocaddress — ground truth

Recover guarded dynamic API resolution through a global function pointer.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/windows/GetProcAddress.exe`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/windows/GetProcAddress.exe)

Source: [`tests_src/windows/GetProcAddress.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/windows/GetProcAddress.c)

Binary SHA-256: `fac8a1f6e2351b870ebb426a2339ff817b195a437be0f7f6fc91f739579d246c`; 14848 bytes.

Observed: PE, x86_64, 64 bits,
pe-no-coff-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
Commit 768614954298b248f7fe8965641685499daa7686 adds the binary and GetProcAddress.c together. Application body at 0x140001480 matches both guards, exact strings and API sequence. Global pointer storage is 0x140007030; computed calls are at 0x14000149e/0x1400014c0/0x1400014f5/0x140001505. GCC 13-win32 strings corroborate MinGW provenance.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (GNU) 13-win32.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

main loads user32.dll, resolves MessageBoxA only if loading succeeds, stores the result in pMessageBox, calls it only if non-null, and frees the successfully loaded module. The call displays Hello, world! with title Dynamic MessageBox in source-defined successful execution.

## Calls and control flow

Source main -> LoadLibraryA, GetProcAddress, optional indirect pMessageBox call, FreeLibrary. These calls are compiled as CALL RAX; resolved runtime behavior must not be fabricated as direct CALL graph edges.

Two null guards: hModule then pMessageBox. FreeLibrary occurs inside the module-success branch even if symbol resolution fails.

## Strings and references

`user32.dll`; `MessageBoxA`; `Hello, world!`; `Dynamic MessageBox`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **How is MessageBoxA reached?** Through GetProcAddress and the global pointer, not a static imported MessageBoxA implementation. Cite string reference, pointer store and indirect call 0x1400014f5.
- **Is a null pointer called if lookup fails?** The function has a null guard at 0x1400014d0–0x1400014d3. Cite it and distinguish an intended guard from an execution result.

## Limits and security interpretation

No application COFF symbols or PDB are supplied. Ghidra names this body FUN_140001480. Imported DLL implementations are unavailable; API import names and source suffice for the declared purpose, not runtime success. Dynamic library loading is not itself evidence of malicious behavior.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
