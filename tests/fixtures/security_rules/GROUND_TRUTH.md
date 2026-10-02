# M7 controlled rule fixtures — static analysis only

Never execute these programs. `bash tests/fixtures/security_rules/build.sh`
uses the existing local GCC/libc to compile into ignored `build/security-rules/`.
It does not launch targets, download libraries, strip/patch binaries or modify
the existing simple_elf fixtures. `AIRE_SECURITY_FIXTURE_OUTPUT_DIR` overrides
the output directory. Compiler/library versions can change hashes and addresses.
The gets compatibility symbol may be absent on other toolchains; pure synthetic
rule tests remain available there. No alternative model or tool is installed.

- `unsafe_copy.c`: `copy_input` directly calls `strcpy` into a 16-byte local
  buffer, with a command-line string passed as its source. The source contains
  no size check. Expected M7 result: CWE-120 SIGNAL at that stored direct call;
  the framework does not itself establish destination size, input control or
  an overflow. Its rule cannot infer those source semantics from mere API use.
- `safe_copy.c`: same main/copy_input shape; measures source length, rejects
  lengths >=16, then copies length+1 bytes with `memcpy`. Expected M7 result:
  no strcpy/gets signals. This tests absence of the particular API condition,
  not a general proof of safety or an M7 verification of the size check.
- `dangerous_gets.c`: `read_input` calls the explicitly declared legacy libc
  `gets` symbol on a local buffer. Expected M7 result: CWE-242 SIGNAL. The
  declaration exists solely to compile the static fixture on local libc that
  retains the symbol; linker warnings are expected. Never run it.

All application calls are direct at -O0 with builtins/inlining disabled. ELF
imports usually appear as named PLT thunks plus external function/import records.
M1 records the application CALL to the thunk, not a thunk-to-external binding.
M7 must disclose that boundary, retain the actual callee ID and callsite, and
use LOW evidence strength for this named-thunk association. A pure synthetic
control tests a CALL directly to a corroborated external function (MEDIUM).
Neither path establishes exploitability or a confirmed vulnerability.

Pure ProgramIndex controls cover imports without resolved calls, wrong names/
addresses/namespaces, ordinary same-named internal functions, absent extraction
metadata and unresolved-call warnings. Missing evidence remains explicit.
Ground-truth source is not itself used as rule input: rules read only SQLite
facts produced by normal indexing. No semantic assertions depend on decompiler
wording, and no fixture is altered to force a signal.
