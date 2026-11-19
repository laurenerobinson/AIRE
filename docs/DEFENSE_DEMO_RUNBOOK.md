# A.I.R.E. defense live-demonstration runbook

Prepared 2026-11-17. Builds on the Nov 17 guest rehearsal
([readiness report](DEMO_READINESS_REPORT.md), [earlier runbook](DEMO_READY_RUNBOOK.md))
and adds the model-free terminal steps freshly verified today. Every expected
output below comes from a genuine run; the source is named in each step.

**Principles**

- Two interfaces, shown as two interfaces: the **browser GUI** (Windows Chrome →
  Ubuntu API) and a **terminal** in the Ubuntu VM. They share one SQLite store;
  they are not one fused application. The Java Ghidra extension is not part of
  the live demo (§8).
- **No model is on the critical path.** Every step works with Ollama down.
- Never execute a fixture. Never show the token URL.

---

## 1. Preparation (day before and 30 min before)

### 1.1 Things that are different from the Nov 17 notes

1. **Disk is no longer a blocker** — 53 GB free (was ~123 MiB).
2. **A GUI is already running on `127.0.0.1:8770`** (pid 9388, demo store,
   loopback bind). Windows Chrome cannot reach a loopback-bound guest server
   through the NAT rule. Stop it from **its own terminal with Ctrl-C** before
   starting the split-host instance (§2), or start the new one on a spare port.
3. **Your shell exports `AIRE_OLLAMA_HOST=http://127.0.0.1:11434` — the guest
   Ollama.** If you launch the GUI from that shell without overriding it, a
   model card would run inference *inside the VM*, which historically froze the
   guest for minutes. Always export the Windows endpoint (§2) — or, for a
   strictly model-free demo, point it at Windows anyway and simply never click a
   model card.

### 1.2 Ubuntu pre-flight (read-only; ~1 min)

```bash
cd ~/aire
git status --short                       # expect only the known docs/tests changes
df -h / ; free -h                         # >5 GB free, >8 GB RAM available
ip -br addr                               # enp0s3 10.0.2.15 (Adapter 1); enp0s8 10.0.3.15 (Adapter 2 — review)
ss -ltnp | grep -E ':8770|:11434'         # know what is already listening
sha256sum demo_artifacts/m10/defense_20261117/demo.sqlite
#   expect f88fa14e2e1098fd0459e16aad23a855583ad2966b80911b7c46a8fa22b1d379
sha256sum tests/fixtures/simple_elf/aire_test_binary tests/fixtures/simple_elf/aire_test_binary_stripped
#   be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e
#   08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188
curl --noproxy '*' -s --max-time 5 http://10.0.2.2:11434/api/tags | head -c 200   # Windows Ollama metadata only
```

### 1.3 Windows pre-flight (manual — still never verified)

```powershell
ollama list                                            # qwen2.5-coder:1.5b present
Get-NetTCPConnection -State Listen | ? { $_.LocalPort -in 8770,11434 } |
  Select LocalAddress,LocalPort,OwningProcess          # expect 127.0.0.1 only
```

VirtualBox → VM → Network → Adapter 1 (NAT) → Port Forwarding: TCP, Host IP
**127.0.0.1**, Host Port 8770, Guest IP 10.0.2.15, Guest Port 8770. Inspect
Adapter 2. From a phone/other device on the same Wi-Fi, the laptop's LAN IP on
8770 and 11434 must **not** connect. Record results in the readiness report.

### 1.4 Windows offline backup (must be done before the defense)

Copy to a Windows folder (and a USB stick) and open each once offline:

- `demo_artifacts/m10/defense_20261117/01-…13-*.png` (15 sanitized screenshots)
- `docs/defense_assets/fresh_outputs_20261117/*.txt`
- rendered PNGs of the three Mermaid diagrams

Do **not** copy `firefox-profile-defense/`, `sessions/`, `live-sessions/`, or
anything containing a token or cookie.

---

## 2. Launch (Ubuntu terminal 1 — keep private, off the projector)

```bash
cd ~/aire
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export AIRE_OLLAMA_HOST=http://10.0.2.2:11434      # Windows, NOT the guest
export AIRE_OLLAMA_ALLOW_REMOTE=1
export AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b
export AIRE_OLLAMA_NUM_CTX=4096
export AIRE_M10_NARRATION=0
aire-server/.venv/bin/aire gui \
  --database demo_artifacts/m10/defense_20261117/demo.sqlite \
  --session-dir demo_artifacts/m10/defense_20261117/live-sessions \
  --upload-dir demo_artifacts/m10/defense_20261117/live-uploads \
  --bind 10.0.2.15 --allow-non-loopback-bind \
  --port 8770 --public-port 8770 \
  --no-browser --no-prewarm
```

`--no-prewarm` keeps Ghidra/JVM off (nothing is indexed in the GUI). Startup
was 0.37–0.45 s in the Nov 17 rehearsal. On Windows, open isolated Chrome:

```powershell
$Chrome = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
& $Chrome "--user-data-dir=$env:LOCALAPPDATA\AIRE\DefenseChrome" --no-first-run
```

Paste the **printed** `http://127.0.0.1:8770/?token=…` URL privately, then
confirm the address bar shows no `token=`. Do this before the audience sees
the screen.

**Ubuntu terminal 2 (projected)**: a clean terminal at `~/aire` with large font,
`export PYTHONPATH=aire-server/src`, `GHIDRA_INSTALL_DIR` and `JAVA_HOME` set,
and `DB=demo_artifacts/m10/defense_20261117/demo.sqlite`.

---

## 3. Live sequence (~9 min)

**Rehearsal scope note.** In the Nov 17 GUI rehearsal, Steps 3–7 ran on the
*debug* build (`validate_input`); the stripped build was only switched to. Today
the same deterministic answers were verified for stripped `FUN_004011bc` at the
service level (function summary with 18 citations, trace, CONSISTENT), but not
clicked through in a browser. Either rehearse Steps 3–6 on the stripped build
once in Chrome, or run them on the debug build and use the stripped build for
Steps 1, 4 and 8 only.

Binary IDs used below:

| Binary | ID (SHA-256) |
|---|---|
| `aire_test_binary` (debug) | `be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e` |
| `aire_test_binary_stripped` | `08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188` |
| `unsafe_copy` | `23d1152ddce4f04449f515a64e1482e9a877dd35d71e7f17fccfc8ec9805fe4a` |
| `safe_copy` | `b0af2881fbc03871a8d353545f29aff5590878d1499078e6c538d78d8ea6847c` |
| `dangerous_gets` | `58e3a13496fa765a7650930ea3dbff5bf645809941fbb4844d85dc1b2859135c` |

### Step 1 — Show the system is up and the target is protected (0:45) · terminal

```bash
sha256sum tests/fixtures/simple_elf/aire_test_binary_stripped
aire-server/.venv/bin/python -m aire.pyghidra.indexer tests/fixtures/simple_elf/aire_test_binary_stripped 2>/dev/null
sha256sum tests/fixtures/simple_elf/aire_test_binary_stripped
```

(Use the venv interpreter; system `python3` has no PyGhidra. `2>/dev/null`
hides Ghidra's loader log, which is kept as warnings in the result.)

- **Expected** (FRESH ×3): `Functions: 34`, `Decompiled: 29`, `Strings: 48`,
  `Imports: 5`, `Exports: 7`, `Call edges: 29`, `Warnings: 6`,
  `Indexing seconds: ~8.5`; both hashes `08bbd1f4…fb188`.
- **Say:** "This analyzed the stripped binary in a throw-away Ghidra project —
  it was never run — and the hash is identical afterwards."
- **Risk:** VM stall makes it slow (> 30 s). **Fallback:** `cat
  docs/defense_assets/fresh_outputs_20261117/indexer_stripped_stdout.txt`.
- This does not write the demo store (indexer CLI only prints).

### Step 2 — Select a controlled binary (0:30) · GUI

Library → **aire_test_binary_stripped**.
- **Expected:** ELF, `x86:LE:64:default`, SHA-256 prefix `08bbd1f4…`.
- **Evidence:** walkthrough step B/J passed ×2 (guest Firefox).
- **Fallback:** `01-library.png`.

### Step 3 — Metadata, functions, strings, imports (0:45) · GUI

Investigate binary → Functions shows `FUN_004011bc`, `FUN_004012f8`, … ;
Imports: `puts`, `strlen`, `printf`; Strings tab.
- **Say:** "No names — this is what a stripped binary gives you."
- **Fallback:** `02-imports.png`, `03-strings.png`, `06-overview.png`.

### Step 4 — Callers and callees (0:45) · GUI

Select `FUN_004011bc` → Call Graph.
- **Expected:** caller `FUN_004012f8` at callsite `00401316`; callees `strlen`
  (`004011d3`), `puts` (`004011ef`, `00401227`), `FUN_0040116d` (`00401256`).
  (Same edges as the debug build — verified in the store.)
- **Fallback:** `04-calls.png` (debug-build capture).

### Step 5 — Relationships on a slide (0:30)

Flip to a slide figure of the 14 application edges (from §6 of the evidence
packet / `GROUND_TRUTH.md`). The GUI shows lists, not an interactive graph —
say so.

### Step 6 — Decompiled, assembly, branch, value trace, cross-check (2:00) · GUI

Function explorer on `FUN_004011bc`:
1. **Decompiled View** — C text.
2. **Assembly** tab — row `0x004011dc CMP qword ptr [RBP + -0x10],0x0`; row
   `0x004011e1 JZ 0x004011ea` with "…when qword ptr [RBP + -0x10] == 0x0".
3. **paths** on `004011e1` — true path: `MOV EDI,0x402028` (error string
   "Input must contain 1 to 31 printable ASCII characters."), `CALL puts`,
   `MOV EAX,0x0`, `JMP 0x00401267`; false path: `CMP …,0x1f`, `JBE`.
4. **trace** on `[RBP-0x10]` at `004011dc` — `← 0x004011d8 MOV … ,RAX ←
   0x004011d3 CALL 0x00401040: return value of the call to strlen`.
   In chat, type it **with brackets**:
   `Where does the value of [RBP-0x10] at 0x004011dc come from?`
   (FRESH pitfall: `RBP-0x10` without brackets is parsed as a different
   location and answers "from function entry".)
5. **Decompiled vs assembly** — Verdict **CONSISTENT**; arithmetic
   INSUFFICIENT EVIDENCE. Say "consistent on the checked properties — not
   proof of equivalence."
- **Evidence:** FRESH probe (`deterministic_tool_probe.txt`) on debug and
  stripped; objdump agrees.
- **Optional (terminal, 15 s):**
  `objdump -d -M intel tests/fixtures/simple_elf/aire_test_binary | grep -A2 '4011dc:'`
  → `cmp QWORD PTR [rbp-0x10],0x0` / `je 4011ea`.
- **Fallback:** `05-decompiled.png`, `07-assembly.png`, `08-*.png`.

### Step 7 — Evidence-grounded question (1:00) · GUI

With `FUN_004011bc` selected, ask **"What does this function do?"**
- **Expected:** "Function analysis (deterministic evidence)", evidence source
  "Ghidra P-code and instruction facts", hedged purpose ("Appears to check
  values against constants…"), loop at `0x00401238`, calls strlen/puts/checksum,
  ~20 clickable addresses. **No model call** (deterministic route).
- Expand evidence/activity; click one address → jumps to Assembly row.
- **Reveal:** switch to `aire_test_binary` → `validate_input` at the same
  `004011bc`. The ground truth confirms it validates length and printable ASCII.
- **Fallback:** `09-question.png`, `10-evidence.png`.

### Step 8 — Naming candidates (0:45) · terminal

```bash
aire-server/.venv/bin/python -m aire.ai.naming $DB 08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188 --candidates --limit 8
```

- **Expected** (FRESH): 8 candidates `FUN_0040116d, FUN_00401340, FUN_0040139f,
  FUN_004011bc, FUN_00401367, FUN_0040142b, FUN_004012f8, FUN_00401146` — all
  application functions; runtime stubs excluded. No model call.
- **Say:** "Suggestions for these require the model. In our live runs the
  small model's names were **rejected** by validation — address-bearing names
  and invented citations — so A.I.R.E. showed nothing rather than something
  wrong. Nothing is ever renamed by the backend."
- **Fallback:** `naming_candidates_stripped.txt`.
- **Do not** run `--function …` (live suggestion) unless it passed rehearsal.

### Step 9 — Deterministic security checks (1:00) · terminal (or GUI Findings)

```bash
aire-server/.venv/bin/python -m aire.security.rule_engine $DB 23d1152ddce4f04449f515a64e1482e9a877dd35d71e7f17fccfc8ec9805fe4a
aire-server/.venv/bin/python -m aire.security.rule_engine $DB b0af2881fbc03871a8d353545f29aff5590878d1499078e6c538d78d8ea6847c | grep -E 'Status|No exact|safety'
```

- **Expected** (FRESH): `unsafe_copy` — `[AIRE-CWE-120-UNBOUNDED-COPY v1.0.0]
  Status: SIGNAL`, `Evidence strength: LOW`, `Location: 00401183`, five evidence
  lines, limitations incl. "not a confirmed vulnerability". `safe_copy` — both
  rules `NOT_APPLICABLE`, "Absence … is not a safety assessment."
- GUI alternative: Library → `unsafe_copy` → Findings (`11-cwe.png`,
  `12-cwe-callsite.png`).
- **Fallback:** `cwe_scan_unsafe_copy.txt`, `cwe_scan_safe_copy.txt`.

### Step 10 — Explicit safety property (0:45)

Pick two:
- **Auth:** in a second, clean Chrome profile open
  `http://127.0.0.1:8770/api/health` → **401**. (FRESH against the guest
  server; Windows path to be rehearsed.)
- **Integrity:** re-run `sha256sum $DB` → still `f88fa14e…d379` after the whole
  demo (database unchanged by every read in the GUI walkthrough, Nov 17).
- **Insufficient evidence:** the arithmetic check above, or `safe_copy`.

### Step 11 — Close (0:15)

Restore via Recent Chats (`13-restored.png` fallback), then say what was not
shown: live model answers, vulnerability confirmation, dynamic analysis.

---

## 4. Optional model step — only if rehearsed successfully

Run **once during rehearsal, not during the demo first**, from Ubuntu with no
other heavy load:

```bash
cd ~/aire; ulimit -c 0
AIRE_RUN_GHIDRA_TESTS=1 AIRE_RUN_OLLAMA_TESTS=1 AIRE_RUN_NAMING_LIVE_TESTS=1 AIRE_RUN_AGENT_LIVE_TESTS=1 \
AIRE_OLLAMA_HOST=http://10.0.2.2:11434 AIRE_OLLAMA_ALLOW_REMOTE=1 \
AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b AIRE_OLLAMA_NUM_CTX=4096 \
GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
PYTHONPATH=aire-server/src bash -c 'for t in test_chat_integration.py test_naming_integration.py test_agent_integration.py; do
  aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -p "$t" -v; done' 2>&1 | tee ~/aire-live-$(date +%Y%m%d-%H%M).log
```

These use the uncommitted remote-opt-in test changes. Record per-test status,
latency, and whether answers were accepted, rejected or timed out. A "passed"
report test means outcomes were recorded, not that inference succeeded
(`docs/M8_AGENT.md:248-251`).

If a model answer is accepted twice in rehearsal, you may add one GUI model
card ("Summarize this function") after Step 7, introduced as: "this is the
model's interpretation; its citations were checked, its meaning was not."
Budget 60 s; if nothing returns in 30 s, say so and move on — that is itself a
real result.

---

## 5. Troubleshooting

| Symptom | Action |
|---|---|
| Chrome refuses connection | Guest server bound to 127.0.0.1? Re-launch with `--bind 10.0.2.15 --allow-non-loopback-bind`; check NAT rule |
| 401 | Use this launch's printed URL in the dedicated profile |
| 403 | Use `127.0.0.1:8770` (matching `--public-port`); never the guest IP |
| "Address already in use" | Another `aire gui` is on 8770 (see §1.1); stop it from its terminal |
| Model card spins | Stop; stay deterministic; mention timeout handling |
| Trace answer says "from function entry" | Retype with brackets `[RBP-0x10]` |
| Function not found in chat | Select it in Functions first, or give the address |
| Indexer > 30 s | VM scheduling stall; show saved output |
| GUI request fails | Reload once, select the cached binary, restore Recent Chats; never re-index on stage |
| VM unresponsive | Switch to Windows backup bundle (screenshots + text outputs) |

Never: disable auth, bind 0.0.0.0, widen Ollama's bind, delete files, or run
a fixture binary.

---

## 6. Shutdown

Ctrl-C in terminal 1 (exit 130), then `ss -ltn 'sport = :8770'` shows nothing;
close the dedicated Chrome window; leave Windows Ollama as it was.

---

## 7. Reliability verdict

| Activity | Verdict |
|---|---|
| Steps 1–3, 6–10 (deterministic GUI + CLI) | **Ready** — verified fresh today and/or in two guest rehearsals |
| Windows Chrome path | **Ready after one rehearsal** — never run end-to-end on Windows |
| Model chat / naming / narration | **Not ready** — no accepted live result in recent runs; keep optional |
| Fresh indexing of a large PE | **Not for live** — minutes, VM-stall sensitive |
| Java Ghidra extension | **Not ready** — not built in this environment |

---

## 8. Java v1 extension (only if you choose to show it)

Requires installing Gradle ≥ 8.5 (not done — needs your approval) and pulling a
model or overriding the default (`-Daire.ollama.model=qwen2.5-coder:1.5b`,
`AirePlugin.java:21-22`, priority described in `docs/CURRENT_STATE.md`).
Build with `./ghidra-plugin/scripts/build_extension.sh`, install the zip in
Ghidra, enable AIRE, open a fixture → Refresh → Suggest → Apply. Rehearse at
least twice; otherwise present it with source excerpts and say it is the v1
prototype, separate from the backend.
