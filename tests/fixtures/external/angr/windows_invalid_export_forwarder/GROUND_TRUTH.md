# windows_invalid_export_forwarder — ground truth

Test a genuine PE32+ DLL with a simple C export and a deliberately non-UTF-8 forwarded-export string.

## Provenance and build

Original repository: https://github.com/angr/binaries

Pinned commit: `7c257a842592b885be27acf5c836bcbb8ec84e08`

Binary: [`tests/x86_64/windows/invalid_export_forwarder.dll`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests/x86_64/windows/invalid_export_forwarder.dll)

Source: [`tests_src/windows/invalid_export_forwarder.c`](https://github.com/angr/binaries/blob/7c257a842592b885be27acf5c836bcbb8ec84e08/tests_src/windows/invalid_export_forwarder.c)

Binary SHA-256: `8b2ca323c14b2f3a46142a027713fd50f56b1baf0d4ab83c38c01cc56f4cbb3a`; 6276 bytes.

Observed: PE, x86_64, 64 bits,
pe-coff-symbol-table; debug status none.

Source relationship: **high-confidence corroborated application behavior**.
Commit 9bea8f2777201c50b96a568d7a7ecab8e0fe6cab adds binary, C, .def and build script together. Builder states gcc 15.3.0/binutils 2.46/mingw-w64 14.0.0, -shared -nostdlib, image base 0x180000000, timestamp disabled. PE DLL bit is set; two exports have RVAs 0x5059 (forwarder) and 0x1000 (local). Bytes at forwarder are 75 9f 65 72 33 32 2e 4d 65 73 73 61 67 65 42 6f 78 41 00. local_export at 0x180001000 returns 0x2a.
An exact source/build match has not been reproduced or cryptographically attested.
Full original compilation flags are unknown except the recipes retained with the
stripped C fixture and DLL; the TLS project supplies configurations, not a build log.
Compiler markers: GCC: (GNU) 15.3.0.
See [static evidence](STATIC_EVIDENCE.md), [provenance](PROVENANCE.json), and
the shared [upstream MIT notice](../LICENSE.md). The x86-64 directory notice
only overrides licensing for unrelated named files; no such file is included.
No external runtime libraries are bundled.

## Functions and actual purposes

local_export returns 42. The .def declares a second export forwarded_export=user32.MessageBoxA; the upstream builder changes its second forwarder-string byte to 0x9f after linking. The compiled C body is preserved.

## Calls and control flow

local_export is a leaf, with no imports or direct calls. A PE forwarded export is loader metadata, not a CALL instruction or a C wrapper.

local_export has no conditional branches. AddressOfEntryPoint is zero; do not invent a DllMain or initialization path.

## Strings and references

`invalid_export_forwarder.dll`; `forwarded_export`; `local_export`

Require an actual function-owned instruction reference before attributing a
string to a function. Import names, PDB paths, runtime strings and all-binary
strings do not automatically belong to the application body.

## Suggested A.I.R.E. questions and expected evidence

- **Does forwarded_export call MessageBoxA?** There is no such CALL body. Cite export-directory forwarder RVA and the absence of a local code function for that name.
- **What is safe to claim about local_export?** It returns 42. Cite MOV EAX,0x2a at 0x180001004, RET and the source. Do not claim the malformed forwarded export loads or resolves.

## Limits and security interpretation

Negative parser fixture: malformed export bytes are intentional upstream, not a corrupt download. Ordinary loader behavior is not an accuracy assertion. Ghidra decodes the byte with a replacement character and reports an unresolved U�ER32.DLL; exact original bytes must come from the binary evidence. Eligible ground truth is local_export and raw export structure only. This does not fill the gap for a normal multi-function Windows DLL.

All observations are static. No target, upstream build script, installer,
emulator, or fuzzer was run. Ghidra source names, inferred signatures and
pseudocode types are not independent proof of original types. Source-defined
semantics and independently observed instructions are separated above.
