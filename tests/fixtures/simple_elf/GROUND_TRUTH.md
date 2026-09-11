# Simple ELF ground truth

This isolated fixture complements the preserved corpus in `tests/binaries/`.
It contains **12 application functions, 14 distinct application call edges,
and 15 application-to-application callsites**. It uses only the C standard
library. There is no input from stdin, networking, allocation, randomness,
recursion, or application-level indirect calling.

## Build and run

From the repository root:

```bash
./tests/fixtures/simple_elf/build.sh
./tests/fixtures/simple_elf/aire_test_binary hello 2
./tests/fixtures/simple_elf/aire_test_binary_stripped test 3
```

The script works from any working directory and writes both binaries beside
the source. It requires Bash, GCC with Linux x86-64 libc development support,
`strip`, and ordinary Linux `dirname`/`cp` utilities. It compiles with:

```bash
gcc -m64 -std=c11 -O0 -g -fno-inline -fno-pie -no-pie \
    -Wall -Wextra -Werror -o aire_test_binary aire_test_binary.c
cp aire_test_binary aire_test_binary_stripped
strip --strip-all aire_test_binary_stripped
```

The output is ELF64, little-endian, x86-64, dynamically linked, and non-PIE
(`ET_EXEC`). Non-PIE simplifies address comparisons at the default import base.
The script runs all three operations on **both** binaries and checks complete
stdout (apart from trailing newlines removed by Bash command substitution) and
successful exit status. Compilation, stripping, execution, or output mismatch
causes a nonzero script exit. It rebuilds only this fixture.

## Deterministic behavior and data

Every invocation first resets `global_bias` to 7 and prints the banner.
Exactly two arguments are required. The operation must be a single ASCII digit
`0` through `9`. Text must contain 1–31 printable ASCII bytes (32–126 inclusive).
Invalid arguments print a diagnostic to stdout and return status 1 without
printing a result. Valid inputs, including fallback operations, return status 0.

Checksum is the sum of unsigned input bytes modulo 256. Transformation converts
ASCII `a`–`z` to `A`–`Z` and copies all other accepted characters unchanged.
There is no locale dependence. Operation 1 adds transformed checksum and length;
operation 2 multiplies them. Operation 3 recomputes the transformed checksum and
adds `global_bias`. Digits 0 and 4–9 print the fallback message and use addition.
"Secret" is only a branch label; this operation does no authentication or crypto.
Checksum is at most 255, length at most 31, and result at most 7905, so these
computations cannot overflow the unsigned integers used by this fixture.

`global_bias` is a writable, initialized `unsigned int` in `.data`, reset by
`initialize_app` and read by `secret_operation`. `main` owns one zero-initialized
local `struct InputData`, passed by pointer. On the target ABI it is 44 bytes:

| Member | Offset | Meaning |
| --- | ---: | --- |
| `char transformed[32]` | 0 | Uppercase output, including a terminating NUL |
| `unsigned int length` | 32 | Validated original length |
| `unsigned int checksum` | 36 | Original checksum |
| `unsigned int transformed_checksum` | 40 | Transformed checksum |

## Functions

“Called by” lists application callers; “Calls” also names explicit libc calls.
All application calls are direct. Constants listed here are source semantics:
machine instructions may express an equivalent comparison or mask.

### main

- Function: `main`
- Purpose: Own local data, validate CLI shape, coordinate processing and output.
- Called by: C runtime startup; no application caller.
- Calls: `initialize_app`, `process_input`, `choose_operation`, `print_result`;
  libc `strlen`, `puts` (two diagnostic callsites).
- Important branches: Wrong argc; operation length/range rejection; processing
  failure; otherwise print result and return 0. All failures return 1.
- Expected strings/constants: `Usage: aire_test_binary TEXT OPERATION (1=add, 2=multiply, 3=secret)`,
  `Operation must be one digit (0-9).`; argc 3, length 1, ASCII `0`/`9`, status 0/1.

### initialize_app

- Function: `initialize_app`
- Purpose: Reset global state and display the banner.
- Called by: `main`.
- Calls: `print_banner`.
- Important branches: None.
- Expected strings/constants: 7 assigned to `global_bias`; no direct string.

### print_banner

- Function: `print_banner`
- Purpose: Print a fixed banner with a newline.
- Called by: `initialize_app`.
- Calls: libc `puts`.
- Important branches: None.
- Expected strings/constants: `A.I.R.E. simple ELF fixture`.

### process_input

- Function: `process_input`
- Purpose: Gate transformation on successful validation.
- Called by: `main`.
- Calls: `validate_input`, `transform_input`.
- Important branches: Validation failure returns 0 and skips transformation;
  success transforms and returns 1.
- Expected strings/constants: Return values 0/1; no direct strings.

### validate_input

- Function: `validate_input`
- Purpose: Enforce length/ASCII constraints and store original metadata.
- Called by: `process_input`.
- Calls: `calculate_checksum`; libc `strlen`, `puts` (two diagnostic callsites).
- Important branches: Reject zero or >=32 bytes; loop rejects bytes outside
  32–126; only valid input reaches checksum calculation.
- Expected strings/constants: `Input must contain 1 to 31 printable ASCII characters.`,
  `Input must be printable ASCII.`; 0, 1, 32, 126.

### calculate_checksum

- Function: `calculate_checksum`
- Purpose: Sum unsigned bytes modulo 256 until the terminating NUL.
- Called by: `validate_input`, `transform_input`, `secret_operation`.
- Calls: None.
- Important branches: Loop continues for non-NUL bytes, stops at NUL.
- Expected strings/constants: Initial sum/index 0, increment 1, modulus 256;
  compiled modulus is a mask `0xff` in the inspected build. No direct strings.

### transform_input

- Function: `transform_input`
- Purpose: Uppercase ASCII letters into the local structure and store checksum.
- Called by: `process_input`.
- Calls: `calculate_checksum`.
- Important branches: Length-bounded loop; lowercase letters subtract 32,
  else copy unchanged; terminate output before calculating checksum.
- Expected strings/constants: `a` (97), `z` (122), case delta 32, NUL 0;
  no direct strings.

### choose_operation

- Function: `choose_operation`
- Purpose: Dispatch an operation using transformed checksum and length.
- Called by: `main`.
- Calls: `add_values` (two distinct callsites), `multiply_values`,
  `secret_operation`; libc `puts` on default.
- Important branches: Switch 1 -> add, 2 -> multiply, 3 -> secret;
  default -> diagnostic and add. The inspected build uses compare/jump branches.
- Expected strings/constants: `Unknown operation; using addition.`; cases 1/2/3.

### add_values

- Function: `add_values`
- Purpose: Return the unsigned sum of two arguments.
- Called by: `choose_operation`, `secret_operation`.
- Calls: None.
- Important branches: None.
- Expected strings/constants: None; both operands are parameters.

### multiply_values

- Function: `multiply_values`
- Purpose: Return the unsigned product of two arguments.
- Called by: `choose_operation`.
- Calls: None.
- Important branches: None; reached only through case 2.
- Expected strings/constants: None; both operands are parameters.

### secret_operation

- Function: `secret_operation`
- Purpose: Announce case 3, recompute checksum, and add the global bias.
- Called by: `choose_operation`, only through case 3.
- Calls: `calculate_checksum`, `add_values`; libc `puts`.
- Important branches: None inside the function; entry is conditional on case 3.
- Expected strings/constants: `Secret operation selected.`; reads `global_bias`
  (7 during normal execution), rather than embedding 7 as a literal operand.

### print_result

- Function: `print_result`
- Purpose: Print transformed text, metadata, and final result.
- Called by: `main`.
- Calls: libc `printf` (three distinct callsites).
- Important branches: None.
- Expected strings/constants: `Processed: %s\n`,
  `Length: %u; checksum: %u; transformed checksum: %u\n`, `Result: %u\n`.

## Expected call graph

This graph includes only application functions. Repeated names are the same
function, not duplicate functions. It describes possible calls across inputs,
not a single execution trace.

```text
main
├── initialize_app
│   └── print_banner
├── process_input
│   ├── validate_input
│   │   └── calculate_checksum
│   └── transform_input
│       └── calculate_checksum
├── choose_operation
│   ├── add_values          [case 1 and default: two callsites]
│   ├── multiply_values     [case 2]
│   └── secret_operation    [case 3 only]
│       ├── calculate_checksum
│       └── add_values
└── print_result
```

## Expected important-function ranking

This is a rough ranking by **distinct application callers + callees**, with
ties ordered for manual review. A.I.R.E. may use a different scoring policy;
numeric scores and tie order are not ground-truth assertions. Including libc
and runtime functions changes the ranking (especially `puts`).

| Rank | Function | Callers | Callees | Why it matters |
| ---: | --- | ---: | ---: | --- |
| 1 | `main` | 0 | 4 | Root reaches all 11 other application functions. |
| 2 | `choose_operation` | 1 | 3 | Dispatch hub controls three operation paths. |
| 3 | `calculate_checksum` | 3 | 0 | Highest fan-in; shared by validation, transformation, and secret paths. |
| 4 | `process_input` | 1 | 2 | Gates both validation and transformation paths. |
| 5 | `secret_operation` | 1 | 2 | Connects a conditional path to two shared helpers. |
| 6 | `validate_input` | 1 | 1 | Rejects invalid data before transformation or arithmetic. |
| 7 | `transform_input` | 1 | 1 | Reaches the checksum helper through a second processing path. |
| 8 | `add_values` | 2 | 0 | Shared by dispatcher and secret operation; three incoming callsites. |
| 9 | `initialize_app` | 1 | 1 | Connects the root to banner output. |
| 10 | `multiply_values` | 1 | 0 | Leaf reached only through case 2. |
| 11 | `print_result` | 1 | 0 | Output leaf. |
| 12 | `print_banner` | 1 | 0 | Initialization leaf. |

## Expected paths and reachability

These are call paths: each arrow is a direct call edge, not a return or a
sequential call to a sibling function.

```text
main -> initialize_app -> print_banner
main -> process_input -> validate_input -> calculate_checksum
main -> process_input -> transform_input -> calculate_checksum
main -> choose_operation -> add_values
main -> choose_operation -> multiply_values
main -> choose_operation -> secret_operation
main -> choose_operation -> secret_operation -> calculate_checksum
main -> choose_operation -> secret_operation -> add_values
main -> print_result
```

- All three shortest paths from `main` to `calculate_checksum` have 3 edges.
  A shortest-path query returning just one may choose any of these.
- Strict reverse reachability of `calculate_checksum` is exactly
  `{validate_input, transform_input, secret_operation, process_input,
  choose_operation, main}`. A query including its seed also includes checksum.
- Strict forward reachability of `process_input` is exactly
  `{validate_input, transform_input, calculate_checksum}`.
- Strict forward reachability of `choose_operation` is exactly
  `{add_values, multiply_values, secret_operation, calculate_checksum}`.
- No application path leads from `process_input` to `secret_operation`, or
  from `calculate_checksum` to `main`. The graph has no cycles.
- Successful operations 1/2/default call checksum twice; case 3 calls it three
  times. Bad operation syntax never reaches `process_input`. Invalid text
  reaches validation but skips checksum, transformation, dispatch, and result.

## Known executions

All output is stdout. Each line ends with a newline. These three exact outputs
are asserted by `build.sh` for both binaries (all exit with status 0):

```text
$ ./aire_test_binary hello 1
A.I.R.E. simple ELF fixture
Processed: HELLO
Length: 5; checksum: 20; transformed checksum: 116
Result: 121

$ ./aire_test_binary hello 2
A.I.R.E. simple ELF fixture
Processed: HELLO
Length: 5; checksum: 20; transformed checksum: 116
Result: 580

$ ./aire_test_binary test 3
A.I.R.E. simple ELF fixture
Secret operation selected.
Processed: TEST
Length: 4; checksum: 192; transformed checksum: 64
Result: 71
```

Additional manual branch cases (each also prints the banner first):

| Arguments | Expected behavior after banner | Exit |
| --- | --- | ---: |
| `hello 0` or `hello 9` | Fallback message, then same output as `hello 1` | 0 |
| `'aZ!' 1` | `Processed: AZ!`; length 3, checksums 220/188, result 191 | 0 |
| 31 copies of `a`, operation 2 | 31 copies of `A`; length 31, checksums 191/223, result 6913 | 0 |
| `'' 1` or 32-character text with operation 1 | Length diagnostic only | 1 |
| `$'a\tb' 1` or `$'\x80' 1` | Printable-ASCII diagnostic only | 1 |
| No arguments or extra arguments | Usage diagnostic only | 1 |
| `hello ''`, `hello 12`, or `hello x` | Operation diagnostic only | 1 |

## ELF interpretation and next development work

1. Import the unstripped binary through PyGhidra and index it using A.I.R.E.'s
   existing ingestion workflow. Compare the 12 application functions, metadata,
   string references, structure access, and direct relationships above. Verify
   all 14 edges and preserve both `choose_operation -> add_values` callsites.
2. Persist and query the index using existing callers/callees, forward/reverse
   reachability, path, and ranking interfaces. Use the sets above as exact
   application-only expectations; treat the ranking order as advisory.
3. Review function summaries against each purpose and branch. For future AI
   analysis, check that summaries describe ASCII uppercasing and a byte sum,
   and that the secret operation is described as checksum plus a global value.
4. Import the stripped copy separately. Map its function entries to the debug
   partner by address and compare edges, callsites, strings, and behavior even
   when application names are unavailable. The pair comes from one link, so
   stripping preserves code addresses and code bytes. Apply any importer load
   bias consistently if the import base is changed.
5. For future assembly/decompiler checks, compare loop bounds, struct offsets,
   global read/write, arithmetic, and switch branch targets. `-O0` still permits
   ordinary compiler lowering: `% 256` can become an AND, and a C switch need
   not appear as a switch in the decompiler. Do not require exact pseudocode.

The total discovered-function count will exceed 12. GCC/libc add startup and
teardown functions (such as `_start`, `_init`, `_fini`, `frame_dummy`,
`register_tm_clones`, `deregister_tm_clones`, `__do_global_dtors_aux`, and on this
build `_dl_relocate_static_pie`), PLT stubs, and external imports. The runtime
passes `main` to `__libc_start_main`; do not demand a direct `_start -> main`
call instruction. Imported application functions are `puts`, `strlen`, and
`printf`. Runtime startup also imports `__libc_start_main` and weak
`__gmon_start__`. Separate these runtime/library nodes when applying the counts
and ranking above. The presence of normal runtime indirect calls is expected.

`strip --strip-all` removes `.symtab`, `.strtab`, and DWARF debug sections;
it retains `.dynsym`/`.dynstr` needed by the dynamic linker. Thus imported libc
names and ordinary constant strings survive; application function names and
the `global_bias` symbol are unavailable in the stripped copy. `.eh_frame` is
normal C unwind metadata, not application exception handling.

Useful read-only sanity checks from this directory:

```bash
file aire_test_binary aire_test_binary_stripped
nm -n --defined-only aire_test_binary
nm aire_test_binary_stripped                 # reports no symbols
readelf -h aire_test_binary                  # ELF64 / EXEC / X86-64
readelf -SW aire_test_binary                 # .symtab and .debug_* present
readelf -SW aire_test_binary_stripped        # .symtab and .debug_* absent
readelf --dyn-syms --wide aire_test_binary_stripped
objdump -d aire_test_binary                  # labeled calls and branches
```

Absolute addresses, binary hashes, sizes, and runtime scaffolding can change
with compiler/linker versions or source paths. Behavioral and application graph
expectations remain the contract; use the debug partner from the same build
for address mapping. This fixture does not change or automatically join the
existing M1–M4 tests, and does not assert that A.I.R.E. already passes these
future checks.
