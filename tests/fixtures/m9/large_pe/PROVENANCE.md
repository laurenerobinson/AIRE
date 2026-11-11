# Large PE fixtures — provenance

| File | SHA-256 | Origin |
|---|---|---|
| `decompile.exe` | `5ae40d01bf03e09ee89b65d1ca465537a1b5d2626cdcfae6e6a9f98ee2d8f536` | Ghidra 12.1.3 PUBLIC, `Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe` |
| `sleigh.exe` | `83926858607571056109df50ae75b3304e0f075a51e20e8ccfeee6a4ec7b6cec` | Ghidra 12.1.3 PUBLIC, `Ghidra/Features/Decompiler/os/win_x86_64/sleigh.exe` |

Byte-identical copies of the official Ghidra 12.1.3 release binaries (NSA, Apache License 2.0;
source: https://github.com/NationalSecurityAgency/ghidra, `Ghidra/Features/Decompiler/src/decompile/cpp`).
Used only as read-only static-analysis benchmark inputs (x86-64 PE32+, 2,384 and 6,337 functions);
never executed by A.I.R.E. Verify with `sha256sum -c SHA256SUMS`.
