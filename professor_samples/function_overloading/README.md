# Function overloading professor demo

This is demo preparation before M8. The original executable was copied, not
moved. No M1–M7 production code was edited, no target code was executed, no
database was accessed, no LLM was invoked, and no commit or staging was performed.

## Run the live demo

From `~/aire`:

```sh
aire-server/.venv/bin/python scripts/demo_function_overloading.py
```

For complete decompiler bodies and bounded assembly as well:

```sh
aire-server/.venv/bin/python scripts/demo_function_overloading.py --full
```

The helper uses the existing PyGhidra environment, defaulting to
`~/tools/ghidra` and, if JAVA_HOME is unset, `~/tools/jdk-21`. Existing environment
overrides remain effective. It analyzes the preserved copy with the unchanged
M1 indexer, then obtains real string xrefs and verifies thunk jumps in a second
disposable PyGhidra session. Allow approximately 45 seconds, depending on host
load. `--full` changes presentation only. The helper writes no reports itself;
stdout can be redirected if desired. All temporary projects are disposed without
saving their analyzed programs. Automatic analysis changes temporary in-memory
programs; there is no manual Ghidra editing or persistent project modification.

## Preservation and integrity

Original: `../../FunctionOverloading.exe` relative to this directory.
Preserved copy: `original/FunctionOverloading.exe` (49,664 bytes).

Known original, before-analysis and after-analysis SHA-256, for both files:

```text
cfc8c5f031587c721d680d3dd9bd94bbc690667acf8651403fb8c7e70f2fab07
```

The checksum baseline is [original/SHA256SUMS](original/SHA256SUMS).
The final run and separate integrity record are in
[analysis/demo-transcript.txt](analysis/demo-transcript.txt) and
[analysis/integrity.json](analysis/integrity.json). The helper requires both
files to match the known hash before analysis and rechecks both afterward,
including on an analysis error. Matching hashes establish byte preservation;
they do not establish the executable's provenance or safety to run.

## Target and successful indexing

- PE32 console executable, Intel 80386 machine type; little-endian 32-bit x86.
- Language: `x86:LE:32:default`; pointer size 4; compiler spec: `windows`.
- Ghidra compiler identification: `visualstudio:unknown`.
- Preferred image base `00400000`; PE entry point `004113ca` (RVA `000113ca`).
- PE linker version 14.16 and Ghidra's Visual Studio Debug library matches
  support an MSVC debug build; they do not prove the exact compiler version.
- Fresh M1 result: 385 function records, 302 decompiled, 138 strings,
  86 imports, 1 EXPORT artifact, 287 resolved direct CALL records, 127 warnings.
- 83 functions are external; totals include runtime functions and thunks.
  Decompilations of thunks can repeat their target bodies.
- Initial indexing took 27.13 seconds using Ghidra 12.1.3. Timing is host dependent.
- The single A.I.R.E. EXPORT artifact is Ghidra's external entry point `entry`.
  The PE export directory is empty: do not describe this as one exported API.

All addresses below are virtual addresses at the preferred image base.
The PE enables DYNAMIC_BASE/ASLR, so an actual Windows load may relocate them.

## String xrefs identify the implementation bodies

These are actual Ghidra DATA references, not substring matches in decompilation:

| String | String address | Referencing instruction | Containing function |
|---|---|---|---|
| `"square of integer "` | `00419b38` | `00412653: PUSH 0x419b38` | `FUN_00412620` @ `00412620` |
| `"square of double "` | `00419b50` | `004126fc: PUSH 0x419b50` | `FUN_004126c0` @ `004126c0` |
| `"PAUSE"` | `00419b68` | `00412857: PUSH 0x419b68` | `FUN_00412790` @ `00412790` |

Each distinctive square string has one reference owner in this analysis.
The names remain Ghidra's current names; `square(int)` and `square(double)`
are interpretations corroborated by the arithmetic and supplied source.

### Integer overload

Current signature: `int __cdecl FUN_00412620(int param_1)`.
Decompiler excerpts, verbatim (separate lines from the full body):

```c
                            "square of integer ");
  return param_1 * param_1;
```

```asm
0041267f: MOV EAX,dword ptr [EBP + 0x8]
00412682: IMUL EAX,dword ptr [EBP + 0x8]
```

A 32-bit stack argument is loaded into EAX and multiplied by itself using
integer multiplication. The integer result remains in EAX. This supports
`int square(int)` together with the caller's `PUSH 0x7` and recovered signature.
Do not infer source-level overflow behavior merely from the instruction.

### Double overload

Current signature:
`float10 __cdecl FUN_004126c0(undefined4 param_1, undefined4 param_2)`.
Decompiler excerpts, verbatim (separate lines from the full body):

```c
                            "square of double ");
  return (float10)((double)CONCAT44(param_2,param_1) * (double)CONCAT44(param_2,param_1));
```

```asm
00412727: MOVSD XMM0,qword ptr [EBP + 0x8]
0041272c: MULSD XMM0,qword ptr [EBP + 0x8]
00412731: MOVSD qword ptr [EBP + 0xffffff38],XMM0
00412739: FLD double ptr [EBP + 0xffffff38]
```

This loads an eight-byte double, multiplies it by itself using scalar
double-precision SSE2 arithmetic, stores it, then loads the result onto the x87
stack for return. The caller uses `0041280f: FSTP double ptr [ESP]` to pass that
return value to the double ostream overload. `float10` reflects Ghidra's x87
representation, and `CONCAT44` combines two four-byte pieces of one double;
these do not establish two source arguments or a source `long double` return.
MOVSD here is the XMM scalar-double form, not a string-copy instruction.

Full unedited decompiler bodies, signatures, and assembly are in
[analysis/evidence.md](analysis/evidence.md). The integer body has 39
instructions (`00412620`–`00412699`); the double body has 42
(`004126c0`–`00412752`). Neither listing is truncated. Independent GNU objdump
disassembly is in [analysis/objdump-overloads-and-caller.txt](analysis/objdump-overloads-and-caller.txt).

## Exact caller and thunk relationships

Common caller: `FUN_00412790` @ `00412790`.
Current Ghidra signature: `undefined4 __stdcall FUN_00412790(void)`.

```text
FUN_00412790 @ 00412790
  004127ba: CALL 00411028  (thunk_FUN_00412620)
    00411028: JMP 00412620 (FUN_00412620, integer body)
  00412802: CALL 004110cd  (thunk_FUN_004126c0)
    004110cd: JMP 004126c0 (FUN_004126c0, double body)
```

There are **no direct CALL edges to either implementation body** in the index.
The common function directly calls their thunks. Each overload thunk has exactly
one indexed direct caller: `FUN_00412790`, at the respective callsite above.
The body receives a JMP from its thunk. Reporting a direct CALL to `00412620`
or `004126c0` would misstate the encoded instructions.

The caller passes integer 7 (`004127b8: PUSH 0x7`). Its double is loaded at
`004127f5` from `00419b70`, whose bytes are `00 00 00 00 00 00 1e 40`:
IEEE-754 little-endian double 7.5. It prints through imported ostream functions,
uses stream manipulators consistent with the supplied newlines, pushes `PAUSE`
at `00412857`, calls through the `system` IAT slot `0041d1d4` at `0041285c`,
and zeroes EAX at `0041286c` before returning. The latter system call is indirect;
it is visible in assembly/decompilation but intentionally absent from the CALL graph.

### Is it main?

**Strongly supported semantic identification as the supplied source's main;
not a recovered original symbol.** Keep its existing `FUN_00412790` name.
The behavior matches the source, and the actual startup path is:

```text
entry @ 004113ca
  JMP @ 004113ca -> FUN_004130d0 @ 004130d0
  CALL @ 004130d3 -> __scrt_common_main @ 00412d50
  CALL @ 00412d58 -> __scrt_common_main_seh @ 00412d70
  CALL @ 00412ec2 -> invoke_main @ 00413040
  CALL @ 00413059 -> thunk_FUN_00412790 @ 00411325
  JMP @ 00411325 -> FUN_00412790 @ 00412790
```

The CRT routine names are Ghidra library-function matches. `invoke_main` obtains
the environment, argv and argc and pushes them before calling the thunk. The
callee does not use those arguments. Ghidra's `__stdcall`/`void` prototype is
inferred; it is not proof of the original C++ declaration or calling convention.

## Constraint audit and execution readiness

### Execution constraints

- This is a Windows PE, not a native Kali/Linux executable. For a controlled
  execution demo, prepare an isolated Windows VM supporting x86 programs
  (for example, x64 Windows with its x86 compatibility subsystem), a snapshot,
  a normal non-administrator account, and a console. Keep host shares/network
  disabled when not needed. No execution has been performed or authorized here.
- The import descriptors name `KERNEL32.dll`, `MSVCP140D.dll`,
  `VCRUNTIME140D.dll`, and `ucrtbased.dll`. All three `D` runtimes are direct
  dependencies, not merely speculative debug-build clues.
- Provide compatible **x86** Visual C++ debug libraries from an official Visual
  Studio C++/Windows SDK installation, preferably matching the producer's toolset.
  A normal release Visual C++ Redistributable alone does not satisfy these debug
  DLL names. Do not substitute x64 or release DLLs or download random DLL files.
- Microsoft documents restricted testing/debugging deployment for debug libraries;
  see [preparing a test machine](https://learn.microsoft.com/en-us/cpp/windows/preparing-a-test-machine-to-run-a-debug-executable?view=msvc-170)
  and [CRT/debug-library mappings](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170).
- `KERNEL32.dll` is provided by Windows. PDB files are not needed for execution.
  The exact runtime version and transitive DLL dependencies cannot be validated
  here because those DLLs and a Windows execution environment were not supplied.
- Recheck SHA-256 after transferring a copy to the VM. `system("PAUSE")` invokes
  a command processor and waits for keyboard input. Arithmetic predicts 49 and
  56.25; these are expected results, not captured execution output.

**Environment requirements determined: PASS. Actual Windows launch: PENDING
(intentionally not performed).** A future release rebuild could simplify runtime
deployment but would be a different binary and would not validate this exact EXE.

### Analysis constraints

- Ghidra searched for all four DLLs and reported them unavailable. It still
  recovered import names from the PE table and some library signatures from
  installed analysis data. The external DLL implementations were not analyzed.
  Missing DLLs do not prevent static analysis of the EXE's internal code.
- Ghidra reported: `Could not find an appropriate PDB file`. Embedded CodeView
  metadata names `FunctionOverloading.pdb`, GUID
  `1f455851-c5cb-47d1-a766-70db77143190`, age 1. The original Windows PDB path
  is recorded in [analysis/pe-headers.txt](analysis/pe-headers.txt). It is a
  reference to a PDB, not embedded source symbols. The supplied ZIP contains only
  the EXE, and no PDB/DLL was found in this project.
- Names/types/local variables and some calling conventions remain inferred.
  The actual decompilations contain `unaff_EDI`, suspicious ostream arguments,
  and `__RTC_CheckEsp` injection warnings. Debug instrumentation and incomplete
  type/call modeling make that output imperfect. Do not present it as exact
  source recovery. The core arithmetic and call instructions corroborate the
  interpretations independently.
- The four-byte parameter fragments and x87 return representation in the double
  decompilation are particularly important caveats for this demonstration.

### A.I.R.E. limitations

- The 287 records represent resolved direct callsites, not a complete dynamic
  call graph. 125 indirect callsites are intentionally omitted. Together with
  one import-warning record and one PDB-warning record, these make 127 warnings.
- Thunk JMPs are not CALL edges and are not automatically collapsed. This demo
  supplements the graph with independently inspected thunk instructions.
- M1 does not persist string-to-function xrefs. The helper reads them using
  PyGhidra and changes neither the schema nor production extraction behavior.
- Assembly is bounded by the existing 200-instruction/20,000-character defaults.
  The three demo bodies fit entirely. Decompiler success does not guarantee
  correct types, source recovery, or function coverage beyond Ghidra's discovery.
- This demonstration establishes static analysis and byte integrity, not runtime
  correctness, a complete library analysis, or executable safety.

## Files and reproducibility

- `original/`: preserved EXE and baseline checksum.
- `analysis/index.json`: complete in-memory M1 index serialized as a report,
  not a database or saved Ghidra program.
- `analysis/xrefs.json`: actual string references, inspected control transfers,
  thunk targets and program metadata from the disposable supplementary session.
- `analysis/evidence.md`: complete selected bodies, bounded assembly and callers.
- `analysis/pe-headers.txt`: `objdump -p` output, including import names and RSDS.
- `analysis/objdump-overloads-and-caller.txt`: independent static disassembly.
- `analysis/demo-transcript.txt`: actual concise demo run; stderr is separate.
- `analysis/demo-full-transcript.txt`: actual `--full` run.
- `analysis/integrity.json`: final hash checks and preexisting-file preservation.

The old root `demo_readonly.py` is unchanged. Its `process_input -> validate_input`
control belongs to another fixture and is unsuitable for this executable. Use the
new helper above for the professor demo.

## PASS / PENDING checklist

| Check | Status |
|---|---|
| Original preserved | PASS |
| Integrity baseline recorded | PASS |
| PE indexing works | PASS |
| Integer overload found through actual xref | PASS |
| Double overload found through actual xref | PASS |
| Integer disassembly verified | PASS |
| Double disassembly verified | PASS |
| Common caller found | PASS — calls both overload thunks |
| Exact callsites found | PASS — `004127ba`, `00412802` |
| Constraints documented | PASS |
| Execution environment determined | PASS — Windows x86 + debug runtimes |
| Final hash unchanged | PASS |
| Windows execution tested | PENDING — deliberately not executed |

## 60-second explanation

“I preserved the professor's original executable and checked its SHA-256 before
and after analysis. A.I.R.E. statically analyzes this 32-bit Windows PE on Kali;
it does not run it. I followed actual references from the two distinctive output
strings to these implementation bodies. The integer version uses IMUL and returns
its result in EAX. The double version uses MULSD for double-precision arithmetic
and returns through the x87 stack. The common caller supplies 7 and 7.5 and reaches
the overloads through these two jump thunks, at callsites 004127ba and 00412802.
Its behavior and the CRT invoke_main path strongly identify it as main, although
the original symbol is unavailable. Missing PDB information and debug DLLs limit
names, types and external-library analysis; indirect calls are omitted from the
stored graph. Execution would need Windows and matching x86 debug runtimes.
Both copies still match the original hash.”
