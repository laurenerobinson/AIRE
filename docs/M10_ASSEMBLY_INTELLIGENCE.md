# M10 — Evidence-Grounded Assembly Intelligence

M10 makes A.I.R.E. explain how executable code works at the instruction, function and
call-graph level, cross-check Ghidra's decompiled C against lower-level evidence, and
answer analyst questions with verifiable citations. **Deterministic evidence is the source
of truth; a local language model may only narrate it, and its narration is validated.**
Evaluation: **incomplete**; the planned `docs/M10_EVALUATION.md` and merged
`docs/m10/eval_full.json` are absent. Existing phase/per-unit results and the
scoped November 17 evidence are distinguished in
[M10_INTEGRATION_HARDENING.md](M10_INTEGRATION_HARDENING.md).
Demo: [DEMO_M10.md](DEMO_M10.md).
Progress log: [M10_CHECKPOINT.md](M10_CHECKPOINT.md).

## Architecture

The [deployment diagram](ARCHITECTURE.md) places this entire static pipeline
inside Ubuntu. Isolated Chrome and Ollama (`qwen2.5-coder:1.5b`) run on Windows 11;
the API reaches the model through NAT at `http://10.0.2.2:11434` with explicit
opt-in. Model inference is local to the laptop, outside the VM. All addresses
and host confinement must be verified for the current machine.

```
Ghidra analysed Program (indexing, once)
  └─ aire/pyghidra/instruction_ir.py      structured facts per function (same pass as M9 extraction)
       instructions: address, mnemonic, text, typed operands (+ parsed memory structure),
                     flow type/targets/fall-through, raw P-code (normalised)
       blocks:       BasicBlockModel blocks + successor edges/flow types
       signature:    calling convention, parameter/return storage, signature source
     → SQLite table function_ir (zlib JSON per function; created lazily; loaded per function)

Read-only analysis (no JVM, no model)
  aire/analysis/instruction_semantics.py  per-instruction semantics + plain-English explanation
  aire/analysis/decompiler_crossval.py    decompiled C vs assembly/P-code checks
  aire/analysis/flow_analysis.py          CFG, loops, branch paths, reaching definitions,
                                          value origins, parameter use, return-value use
  aire/analysis/assembly_intelligence.py  service: resolves functions, builds context, caches
  aire/evaluation/objdump_truth.py        independent ground truth (GNU objdump) for evaluation

Interfaces
  aire/agent/tools.py            8 agent tools (explain_instructions, function_evidence, function_cfg,
                                 branch_paths, trace_value, parameter_use, return_usage,
                                 crossvalidate_function)
  aire/agent/assembly_answers.py deterministic routing + grounded answers + narration validator
  aire/api/server.py             GUI chat fast path (_assembly_answer); /api/tool for the explorer
  aire/api/static/*              Function explorer (Overview / Assembly / Control flow /
                                 Data flow / Decompiled vs assembly)
```

## How evidence is collected

Collection happens once, during indexing, in the extractor's existing single instruction
pass (assembly text and counts are byte-identical to M9) while decompilation runs in
parallel. JPype calls are minimised: P-code is fetched as one string per instruction and
parsed in Python; flow-type booleans are cached per flow type; fall-through addresses and
memory-operand structure (`base`, `index`, `scale`, `disp`, `segment`, `absolute`) are
derived from Ghidra's own operand text. Facts are bounded at 4,096 instructions per
function (truncation is recorded and shown). Older snapshots without facts are marked
"refresh required" by the cache (`EXTRACTION_VERSION` 2 + `instruction_ir.version`); until
refreshed, A.I.R.E. falls back to parsing stored assembly text at **low** confidence and says so.

## Instruction semantics

Classification is decided from P-code, not mnemonics: `LOAD`/`STORE` or direct RAM varnodes
→ memory read/write; a memory operand with neither → address calculation (LEA); flag-only
outputs from `INT_SUB`/`INT_AND`/`FLOAT_*` → compare/test; `CBRANCH` in a Ghidra jump →
conditional branch, inside a non-jump (CMOVcc, BSR) → internal skip; `CALL`/`CALLIND`,
`RETURN`. Only P-code operations that feed non-flag results (a backward slice inside the
instruction) name an operation, so flag bookkeeping and address arithmetic never produce a
wrong verb. Multi-step operations are listed as P-code steps (`compound`) and SIMD lane
writes as `vector`, at medium confidence, rather than paraphrased.

Conditional branches: the flag predicate is rebuilt from the instruction's P-code as an
expression tree, normalised (double negation, De Morgan) and rendered canonically (`CF|ZF`,
`!ZF&(OF==SF)`). The flag setter is found earlier in the same basic block, or in the block's
unique predecessor. For x86 the relation is named from tables for `CMP`/`SUB`
(signed/unsigned), `TEST`/`AND`/`OR`/`XOR` (OF/CF cleared) and `UCOMIS*`/`FUCOMI`
(unordered = NaN). When no table applies, only the flags are reported.

Example (aire_test_binary, `validate_input`, verified against source and objdump):

| Instruction | Explanation |
|---|---|
| `0x004011cc MOV RAX,qword ptr [RBP + -0x28]` | Reads a qword (8 bytes) value from memory at RBP - 0x28 (frame-pointer-relative stack slot) and writes it to RAX. |
| `0x004011dc CMP qword ptr [RBP + -0x10],0x0` | Compares qword ptr [RBP + -0x10] with 0x0 by subtraction without storing the result, setting flags (CF, OF, SF, ZF, PF). |
| `0x004011e1 JZ 0x004011ea` | Jumps to 0x004011ea when the flag condition ZF holds, i.e. when qword ptr [RBP + -0x10] == 0x0 (flags set by CMP … at 0x004011dc); otherwise continues at 0x004011e3. |
| `0x004011e8 JBE 0x004011fb` | … when qword ptr [RBP + -0x10] <= 0x1f (unsigned) … |
| `0x004011ea MOV EDI,0x402028` | Copies 0x402028 into EDI — 0x00402028 is the address of the string "Input must contain 1 to 31 printable ASCII characters.". |

No source-level meaning (variable names, types, intent) is asserted.

## Control flow and data flow

* **CFG**: blocks, typed edges (fall-through, conditional, unconditional, computed), dominators,
  natural loops from back-edges (header, body, exits), unreachable blocks.
* **Branch paths**: for a conditional jump, the straight-line contents of the taken and
  fall-through paths (≤ 24 instructions) up to the next branch or return, with calls.
* **Reaching definitions** over x86 register families (`EAX`→`RAX`, XMM lanes→`XMMn`) and
  frame-pointer stack slots; calls clobber caller-saved registers; zeroing idioms are not reads.
* **Value origin**: constant / parameter (Ghidra-recovered storage) / call result / stack slot /
  global / pointer dereference / computed — data registers separated from address registers;
  path-local loop detection; depth 6; 160-node budget. Asking about a location an instruction
  does not read returns the value it holds there (labelled).
* **Return-value use** at every stored caller (including through thunks): tested, compared,
  stored, copied, passed to another call, dereferenced, returned — with the branch it controls.

Verified example: the value `validate_input` compares with 0 at `0x004011dc` comes from
`[RBP-0x10]`, written at `0x004011d8` from RAX, which is the return value of `strlen`
(`0x004011d3`); `validate_input`'s own result is tested by `process_input` and controls the
branch `EAX != 0`.

## Decompiler cross-validation

Checks with evidence (instruction addresses, decompiled line numbers): call targets (direct,
import, tail; Ghidra call-fixup injection explained; indirect calls matched to indirect C
expressions; calls in C to known functions the assembly never makes are flagged), string
references, control flow (presence of conditionals including boolean expressions; loop
back-edges), return value, plus supporting constants, global data and M9 arithmetic.
Thunks are not compared (Ghidra decompiles them as their target). Decompiler warnings about
unreachable blocks, bad data or jump tables downgrade discrepancies to INSUFFICIENT EVIDENCE.

* **CONSISTENT** — all core checks (calls, strings, control flow, return value) agree.
* **POTENTIAL DISCREPANCY** — an observable fact present on one side is unaccounted for on the
  other and no known transformation explains it; analyst review is warranted.
* **INSUFFICIENT EVIDENCE** — equivalence cannot be decided (e.g. constants rewritten).

Real findings (confirmed by manual review): compiler-runtime helpers in the CNG PEs that
return a value in XMM0 were decompiled as `void` with their branches and computation
discarded (e.g. `FUN_004075e0`), and a math helper stores the `"__powil"` string address into
an error structure the C never shows.

## Agent and GUI

Deterministic routing answers: *What does this function do? · Explain these instructions ·
What happens when the branch at 0x… is true? · Where does the value of REG/[RBP-0x…] at 0x…
come from? · How is the return value used? · Does the assembly support the decompiled code? ·
Where is input validation performed?* (crypto and importance questions use the M9
`crypto_evidence` and relevance tools). Every answer gives binary identity, function name and
address, instruction addresses, assembly/P-code-derived explanations, confidence and
limitations. The existing function cards ("Summarize this function", "Explain this assembly")
keep the M8 model pipeline.

Narration: if `AIRE_M10_NARRATION=1` (default off) and Ollama answers within `AIRE_M10_NARRATION_SECONDS`
(default 60), the local model's summary is appended only when every cited `0x…` address
appears in the deterministic answer/function and every mnemonic it ties to an address
matches; otherwise it is rejected with the reason. Ollama unavailable → deterministic answer only.

The **Function explorer** tool card shows all of this for the selected function with
clickable addresses, inline branch paths and value traces.

## Supported architectures and limitations

* Facts and generic P-code explanations: any Ghidra language. Named branch relations,
  register families, stack-slot data flow and ABI return defaults: **x86 / x86-64** only.
* Raw P-code (not high P-code): no type recovery beyond Ghidra's signature storage.
* Data flow is intra-procedural (plus call-site return use), register/frame-slot only;
  memory through other pointers, aliasing and RSP-relative slots across pushes are not tracked.
* Relation search: same block or unique predecessor; flags from SBB/ADC and other setters
  without a template are reported as flags only.
* Purpose statements are rule-derived and hedged; application-level intent is not proven.
* Snapshots indexed before M10 need re-analysis for P-code evidence.
* Earlier VM-hosted inference coincided with long scheduling stalls. Windows
  inference and Chrome reduce guest resource contention, but deterministic
  answers also depend on guest scheduling. No measured split-host speedup or
  elimination of stalls has been established.
* Cross-validation checks selected observable properties, not semantic equivalence;
  citations establish traceability, not truth of every interpretation. Phase 6
  completion and live-model robustness remain future validation work.
