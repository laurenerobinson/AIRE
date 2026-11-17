# DEMO — M10 Evidence-Grounded Assembly Intelligence

Shows an analyst selecting a function, reading its assembly in plain English, exploring branches and
value origins, and checking every claim against cited instruction addresses. All answers below are
deterministic (no language model); they were produced by the code in this working tree on the store
`demo_artifacts/m10/m10.sqlite`. Background: [M10_ASSEMBLY_INTELLIGENCE.md](M10_ASSEMBLY_INTELLIGENCE.md);
measured accuracy: [M10_EVALUATION.md](M10_EVALUATION.md).

Nothing in this demo executes an analysed binary.

## 1. Start the GUI (≈ 5 s with the existing store)

```bash
cd ~/aire
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PYTHONPATH=aire-server/src
export AIRE_M10_NARRATION=0          # recommended on this VM: deterministic answers only (see "Narration")
aire-server/.venv/bin/aire gui \
  --database demo_artifacts/m10/m10.sqlite \
  --session-dir demo_artifacts/m10/sessions \
  --upload-dir demo_artifacts/m10/uploads \
  --port 8768 --no-browser --no-prewarm
# open http://127.0.0.1:8768/
```

The store already contains the indexed demo binaries (`aire_test_binary`, its stripped and `-O2` builds,
the three CNG PEs and `sleigh.exe`). To rebuild it from scratch (Ghidra analysis, several minutes per PE):
`PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/m10_index.py` (see the script header).

## 2. Select a function

1. In the binary list choose **aire_test_binary**.
2. In the function list choose **validate_input** (`0x004011bc`).
3. Open the **Function explorer** tool card.

**Overview** tab: calls (`strlen`, `puts` ×2), conditional branches with their conditions
(e.g. `qword ptr [RBP + -0x10] == 0x0`), the loop (header and back-edge), referenced strings
("Input must contain 1 to 31 printable ASCII characters.", …), parameter use (RDI read before written) and the
cross-validation verdict **CONSISTENT**.

## 3. Read the assembly in plain English

**Assembly** tab — one row per instruction with category and confidence badges, block separators and
clickable addresses:

| Address | Instruction | Explanation (as shown) |
|---|---|---|
| `0x004011cc` | `MOV RAX,qword ptr [RBP + -0x28]` | Reads a qword (8 bytes) value from memory at RBP - 0x28 (frame-pointer-relative stack slot) and writes it to RAX. |
| `0x004011dc` | `CMP qword ptr [RBP + -0x10],0x0` | Compares qword ptr [RBP + -0x10] with 0x0 by subtraction without storing the result, setting flags (CF, OF, SF, ZF, PF). |
| `0x004011e1` | `JZ 0x004011ea` | Jumps to 0x004011ea when the flag condition ZF holds, i.e. when qword ptr [RBP + -0x10] == 0x0 (flags set by CMP … at 0x004011dc); otherwise continues at 0x004011e3. |
| `0x004011ea` | `MOV EDI,0x402028` | Copies 0x402028 into EDI — 0x00402028 is the address of the string "Input must contain 1 to 31 printable ASCII characters.". |

How to verify a row yourself: `objdump -d -M intel tests/fixtures/simple_elf/aire_test_binary | grep -A1 4011dc`
shows the same instruction; the condition `ZF` for `JZ` after `CMP x,0` means `x == 0` (Intel SDM Jcc table).

## 4. Explore a branch

Click **paths** on the `JZ` row (or ask in chat: *What happens when the branch at 0x004011e1 is true?*):

```
Condition true (branch taken) → starts at 0x004011ea; reaches another branch at 0x004011f9 (JMP 0x00401267).
- 0x004011ea MOV EDI,0x402028 — … address of the string "Input must contain 1 to 31 printable ASCII characters.".
- 0x004011ef CALL 0x00401030 — Calls 0x00401030 (puts); … return value, if any, is in EAX:4 (Ghidra-recovered int; signature source IMPORTED).
- 0x004011f4 MOV EAX,0x0 — Copies 0x0 into EAX.
- 0x004011f9 JMP 0x00401267 — Jumps unconditionally to 0x00401267.
  Calls on this path: puts at 0x004011ef
Condition false (falls through) → starts at 0x004011e3; reaches another branch at 0x004011e8 (JBE 0x004011fb).
- 0x004011e3 CMP qword ptr [RBP + -0x10],0x1f — …
- 0x004011e8 JBE 0x004011fb — … when qword ptr [RBP + -0x10] <= 0x1f (unsigned) …
Confidence: high for the condition and the straight-line path contents; later merges are not followed beyond the next branch.
```

Reading: when the stored length is 0, the function prints the error string and returns 0. (The source
`length == 0 || length >= 32` is the ground truth; A.I.R.E. states only what the instructions do.)

## 5. Where does a value come from?

Click **trace** on `[RBP-0x10]` in the `CMP` row (chat: *Where does the value of [RBP-0x10] at 0x004011dc come from?*):

```
- [RBP-0x10] at 0x004011dc ← 0x004011d8 MOV qword ptr [RBP + -0x10],RAX: stored value
  - RAX at 0x004011d8 ← 0x004011d3 CALL 0x00401040: return value of the call to strlen
Limits: Intra-procedural reaching definitions over register families and frame-pointer stack slots; depth <= 6; …
```

**Data flow** tab → return-value use: `validate_input`'s result is tested by `process_input` and controls the
branch `EAX != 0`.

## 6. Does the decompiled C match the assembly?

**Decompiled vs assembly** tab (chat: *Does the assembly support the decompiled code?*):

```
Verdict: CONSISTENT
- call_targets — CONSISTENT: All 3 assembly call target(s) appear in the decompiled text.
- string_references — CONSISTENT: All 2 referenced string(s) appear in the decompiled text.
- control_flow — CONSISTENT: 5 conditional branch(es), 1 back-edge(s); decompiled text has 10 conditional construct(s) and 1 loop(s).
- return_value — CONSISTENT: 2 value return(s) in the decompiled text; return register written before RET on 1/1 RET path(s).
- constants — CONSISTENT …   global_data — CONSISTENT …   arithmetic — INSUFFICIENT EVIDENCE …
```

A real discrepancy for contrast: select **aes_gcm.exe** → `FUN_004075e0`. The verdict is **POTENTIAL
DISCREPANCY**: the function writes its result to XMM0 and has conditional branches, but Ghidra decompiled it
as `void` with the computation discarded (confirmed by manual review; see M10_EVALUATION.md §Cross-validation).

## 7. Review cited evidence

Every chat answer starts with the binary (name, SHA-256 prefix, language), the function name and entry address,
and the evidence source (`Ghidra P-code and instruction facts`, or a **low-confidence** assembly-text fallback for
snapshots indexed before M10). Every `0x…` in an answer is a link in the GUI that jumps to that instruction in
the Assembly tab; the evaluation checks that each cited address is a real instruction, function entry, string or
referenced address in that binary (validity 1.0 on the ELF builds — see M10_EVALUATION.md).

Other questions answered deterministically: *What does this function do?*, *Explain these instructions*,
*How is the return value used?*, *Where is input validation performed?*. The function cards
"Summarize this function" / "Explain this assembly" keep the existing M8 model pipeline.

## Narration (optional)

With `AIRE_M10_NARRATION=1` and Ollama running (`qwen2.5-coder:1.5b`), a short model summary may be appended
after the deterministic answer, within `AIRE_M10_NARRATION_SECONDS` (default 60). It is shown only if every
address it cites appears in the deterministic evidence and every instruction it names matches; otherwise it is
rejected with the reason. On this VirtualBox VM Ollama load has coincided with host CPU stalls, so leave it off
for demos.

## Reproduce the automated checks

```bash
cd ~/aire
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m pytest -q aire-server/tests/test_m10_*.py   # 47 tests
scripts/run_m10_eval_resumable.sh        # Phase 6 evaluation, one binary per process, resumable
python3 -m json.tool docs/m10/eval_full.json | less
PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/verify_m10_browser.py   # Firefox GUI check (port 8768)
```
