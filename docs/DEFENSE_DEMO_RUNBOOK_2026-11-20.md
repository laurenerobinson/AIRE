# Defense demonstration runbook — Friday, November 20, 2026

This runbook was written on **2026-11-19** from the repository audit. Every
command and expected output below was checked against the current entry
points. A step marked **VERIFIED 11-19** was executed today in the Ubuntu
guest. A step marked **UNVERIFIED** could not be checked from the guest.
[DEFENSE_DEMO_RUNBOOK.md](DEFENSE_DEMO_RUNBOOK.md), the Nov 17 runbook that
is not committed yet, remains valid. This file supersedes it only where they
differ, and the differences are listed in §0.

> **Golden rules.** Never execute a target binary. Never run
> `tests/fixtures/simple_elf/build.sh`, because it runs the binaries it
> builds. Never type the live token URL on a projected screen. Keep model
> inference off the critical path.

## 0. What changed since the Nov 17 notes

1. **No GUI is running.** The VM rebooted, so there is nothing on 8770.
   Start fresh.
2. **Guest Ollama *is* running** (`ollama serve`, listening on
   `127.0.0.1:11434`), and the login shell exports
   `AIRE_OLLAMA_HOST=http://127.0.0.1:11434` and
   `AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b`. Launching from this shell
   without overrides would run inference **inside the VM**, which has
   frozen this VM before. You have two choices:
   - override with the Windows endpoint (§2A); or
   - point at a closed port for a guaranteed model-free demo (§2C).

   Stopping guest Ollama is your call. If you stop it, use the same method
   that started it.
3. **Fresh regression results:**
   - default suite: 649 run / 617 passed / 32 opt-in skips;
   - Ghidra suite: 649 / 644 passed / 5 skips (4 live-model, 1 browser);
   - no failures in either.

   See [TEST_VALIDATION_2026-11-19.md](TEST_VALIDATION_2026-11-19.md).
4. **Tool count is 27**, not 18. Say "27 read-only tools".

## 1. Preflight (Ubuntu, read-only, about 2 minutes)

```bash
cd ~/aire
git status --short            # expect only known docs/tests changes
df -h / ; free -h             # VERIFIED 11-19: 53 GB free, ~15 GiB available
sha256sum demo_artifacts/m10/defense_20261117/demo.sqlite
#  f88fa14e2e1098fd0459e16aad23a855583ad2966b80911b7c46a8fa22b1d379   (VERIFIED 11-19)
sha256sum tests/fixtures/simple_elf/aire_test_binary tests/fixtures/simple_elf/aire_test_binary_stripped
#  be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e   (VERIFIED 11-19)
#  08bbd1f43aecd39b3020290b75e66b4a748109d46c6c8b5c47b27c72f19fb188   (VERIFIED 11-19)
env | grep '^AIRE_'           # know what the shell will pass to the GUI
ss -ltnp | grep -E ':8770|:11434'   # 11434 = guest Ollama; 8770 should be free
ip -br addr                   # Adapter 1 NAT address, expected 10.0.2.15 (UNVERIFIED today)
cp -p demo_artifacts/m10/defense_20261117/demo.sqlite ~/aire_backups/demo-20261120.sqlite   # private backup copy
```

The demo store `demo_artifacts/m10/defense_20261117/demo.sqlite` (6.6 MB,
schema v2, with `function_ir`) contains seven binaries:

| Binary | Use |
|---|---|
| `aire_test_binary` | Main walkthrough (unstripped, with symbols) |
| `aire_test_binary_stripped` | Same code without symbols (`FUN_…` names) |
| `aire_test_binary_O2` | Optional: optimized build |
| `FunctionOverloading.exe` | Optional: PE32 example |
| `unsafe_copy` / `dangerous_gets` / `safe_copy` | CWE-120 / CWE-242 positive controls and the negative control |

Both simple-ELF fixtures are x86-64 ELF, non-PIE, built with `-O0 -g`, and
the stripped copy has symbols removed. Their ground truth is in
`tests/fixtures/simple_elf/GROUND_TRUTH.md`: 12 application functions,
14 edges and 15 call sites. Both are already indexed in the store, so
**nothing needs to be analyzed live.**

## 2. Launch

### 2A. Split-host: Windows Chrome + Windows Ollama (UNVERIFIED Windows side)

Ubuntu terminal 1 (private, off the projector):

```bash
cd ~/aire
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra      # exists (VERIFIED 11-19)
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64       # exists (VERIFIED 11-19)
export AIRE_OLLAMA_HOST=http://10.0.2.2:11434             # Windows, NOT the guest
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

All of these flags exist in `agent/cli.py` (VERIFIED 11-19). On Windows,
complete the checks in [README → Windows Host
Inference](../README.md#running-aire-with-windows-host-inference) steps
1–3, 6–8:

- NAT rule Host IP `127.0.0.1`;
- listeners on 8770/11434 bound to `127.0.0.1`;
- `ollama list` shows `qwen2.5-coder:1.5b`;
- an isolated Chrome profile.

Then open the **Host-side URL** printed by the server.

### 2B. Guest-only fallback: Firefox in the VM (VERIFIED 11-19 on a spare port)

```bash
cd ~/aire
export AIRE_OLLAMA_HOST=http://127.0.0.1:9 AIRE_OLLAMA_MODEL=none AIRE_M10_NARRATION=0
aire-server/.venv/bin/aire gui \
  --database demo_artifacts/m10/defense_20261117/demo.sqlite \
  --session-dir demo_artifacts/m10/defense_20261117/live-sessions \
  --upload-dir demo_artifacts/m10/defense_20261117/live-uploads \
  --port 8770 --no-prewarm
```

This binds loopback, opens the browser itself, and prints
`Local URL: http://127.0.0.1:8770/?token=…`. If Snap Firefox misbehaves,
add `--no-browser` and paste the URL into guest Firefox yourself.

### 2C. Guaranteed model-free

Use 2A or 2B with `AIRE_OLLAMA_HOST=http://127.0.0.1:9`.

- Health then shows `ok:false`, "Connection refused". This is harmless
  (VERIFIED 11-19).
- Every step in §4 except step 10 still works.

### Connectivity checks after launch

| Check | How | Expected |
|---|---|---|
| Server up | terminal prints `A.I.R.E. GUI` and a URL | VERIFIED 11-19 |
| Auth works | open the tokenized URL; the address bar ends at `/` | 303 → cookie (VERIFIED 11-19) |
| Bare API refused | `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8770/api/bootstrap` | `401` (VERIFIED 11-19) |
| Model reachable (2A only) | About view → health card, or `curl --noproxy '*' -s --max-time 5 http://10.0.2.2:11434/api/tags` | Lists `qwen2.5-coder:1.5b`. UNVERIFIED. Metadata only; it does not prove generation works |

## 3. Timing plan (about 10 minutes; planning targets, not measurements)

| Segment | Target |
|---|---|
| Problem + architecture slide | 1:30 |
| Library + binary selection | 0:45 |
| Deterministic facts and call graph | 2:00 |
| Function explorer (assembly, CFG, branch, trace, decompiler check) | 2:30 |
| Stripped binary | 1:00 |
| Security signals (positive and negative controls) | 1:15 |
| Optional model answer, or fallback explanation | 1:00 |

## 4. Step-by-step demonstration

Every question below was answered on 11-19 against a copy of this exact
store with **no model call** (path `deterministic_facts` or `m10_assembly`).
Response times were 4–74 ms, single runs.

1. **Library.** Open Binary Library and show the fixtures with their
   SHA-256, *indexed* and *cached* status.
   - *Point out:* format detection reads headers, not extensions; uploads
     are capped at 32 MiB; targets are never executed.
   - *Optional:* press Analyze on "aire_test_binary (Local demo)". On 11-19
     a copy of this store finished as a **cache hit in 0.21 s** with no
     Ghidra start. Skip this if you are short on time.
2. **Select `aire_test_binary`** from the top bar. The header shows ELF,
   `x86:LE:64:default`, and the counts.
3. **Ask:** `What is this file?`
   - *Expected:* "ELF — structure valid. Full static analysis is possible."
   - *Badge:* **Verified stored facts · deterministic · no AI model**.
4. **Ask:** `Who calls validate_input?`
   - *Expected:* `validate_input` (`0x004011bc`) has 1 stored caller
     (1 call site): `process_input`, with a table of caller → callee and
     the call site.
   - *Point out:* the direction comes from stored CALL edges. Model prose
     is never used for graph answers.
5. **Ask:** `What does process_input call?`
   - *Expected:* 2 callees: `validate_input` and `transform_input`.
6. **Select `validate_input`** (Functions → click it) and open the
   **Function explorer**.
   - **Assembly tab.** `Explain the instructions in validate_input` gives
     explanations citing instruction addresses, with
     *Evidence source: Ghidra P-code and instruction facts*.
   - **CFG tab.** 11 basic blocks, 1 loop found by a dominator back-edge.
   - **Branch.** Ask `What happens when the branch at 0x004011e1 is true?`
     The condition at `0x004011e1` is `qword ptr [RBP + -0x10] == 0x0`.
   - **Trace.** Ask `Where does the value of [RBP-0x10] at 0x004011e1 come from?`
     Use the bracketed form.
   - **Decompiler tab.** Ask `Cross-check the decompiler for validate_input`.
     The verdict is **CONSISTENT** for call targets, strings, control flow,
     return value, constants and globals. Arithmetic is INSUFFICIENT
     EVIDENCE.
   - *Point out:* this is three-valued, and "insufficient" is reported
     honestly.
7. **Ask:** `What does this function do?` (with `validate_input` selected).
   This gives a deterministic function analysis. Purpose hints are
   rule-derived and hedged, and each one cites addresses.
8. **Stripped binary.** Switch to `aire_test_binary_stripped` and ask
   `Who calls FUN_004011bc?`
   - *Expected:* 1 caller, `FUN_004012f8`.
   - *Point out:* these are the same addresses as `validate_input` and
     `process_input` in the unstripped build. The fixture is non-PIE, so
     the stripped analysis recovers the same relationships without
     symbols.
   - Optional: `What does FUN_004011bc call?` gives 3 callees over 4 call
     sites: `puts`, `strlen`, `FUN_0040116d`.
9. **Security.** Select `unsafe_copy` and open Findings, then repeat for
   `dangerous_gets` and `safe_copy`.

   | Binary | Expected (VERIFIED 11-19) |
   |---|---|
   | `unsafe_copy` | CWE-120 **SIGNAL** at `0x00401183`, strength LOW |
   | `dangerous_gets` | CWE-242 **SIGNAL** at `0x00401178`, strength LOW |
   | `safe_copy` | No signal (negative control) |

   - *Point out:* this is a SIGNAL, not a confirmed vulnerability. There is
     no CONFIRMED state in the code. Limitations are listed with every
     finding.
10. **Optional model step (2A only, and only if the Windows model was
    checked earlier).** Select `aire_test_binary` and ask
    `What does this binary do?`
    - The answer carries the badge "AI interpretation · grounded in stored
      evidence, not verified fact" and citations.
    - **Live generation was not verified on 11-19.** If it is slow or
      fails, the result is `partial` with the deterministic tool facts.
      That is the designed fallback (VERIFIED 11-19 with the model
      disabled).

Also verified, but not in the main path:

- `How is the return value used?`;
- `Where is input validated?` (74 ms on the small ELF; **do not** ask it on
  large binaries);
- `Is this file corrupted?`;
- `Show the evidence for validate_input`.

The crypto questions (`Which functions perform encryption?`,
`Which functions call BCryptEncrypt?`) were verified against `aes_gcm.exe` in
`demo_artifacts/m10/m10.sqlite`, not in the defense store. To show them,
launch a second instance with `--database demo_artifacts/m10/m10.sqlite` on
another port.

## 5. Known demo risks

| Risk | Mitigation |
|---|---|
| Guest inference freezes the VM (BR-01) | Use the 2A overrides or the 2C closed port; never ask model questions on 2B |
| Windows NAT, Chrome or listener not as documented (BR-03) | Fall back to 2B in guest Firefox |
| Live model slow, wrong or unavailable (BR-02) | Skip step 10; explain the `partial` fallback |
| VirtualBox descheduling stalls (HISTORICAL up to minutes) | Nothing heavy running; `--no-prewarm`; pre-indexed store; no live indexing |
| Long binary-wide query (BR-06) | Ask "Where is input validated?" only on the small ELF |
| Token leakage | Paste the URL privately; restart the server to rotate the token |
| Store corruption or accidental writes | GUI connections are read-only. Check the SHA-256 before and after. If it differs, restore the backup copy made in §1 |

## 6. Recovery procedures

| Failure | Action |
|---|---|
| GUI 401 | Open this launch's full tokenized URL again (tokens change every launch) |
| GUI 403 | Use `127.0.0.1:<port>` exactly, matching `--public-port`. Do not use the guest IP or `localhost.` variants |
| Port already in use | `ss -ltnp \| grep :8770`. Stop that server from its own terminal (Ctrl-C) or use another port |
| Browser shows nothing / JS error | Reload; try the other browser; check the terminal for errors |
| Chat returns 429 | Wait. At most 4 chats run concurrently |
| Model errors or timeouts | Continue with deterministic questions, which need no model |
| Analysis job hangs | Don't analyze live. The watchdog kills it after `AIRE_ANALYSIS_TIMEOUT`. Restart the GUI |
| VM freeze | Wait. If it lasts more than 2 minutes, switch to the offline screenshots in `demo_artifacts/m10/defense_20261117/*.png` (sanitized, Nov 17) |
| Wrong store | The header shows the database name. Restart with the correct `--database` |

**Deterministic read-only terminal fallback** (no GUI, no model; same code
paths, VERIFIED 11-19 by the audit probe):

```bash
cd ~/aire
env -u AIRE_OLLAMA_HOST -u AIRE_OLLAMA_MODEL PYTHONPATH=aire-server/src aire-server/.venv/bin/python - <<'EOF'
from aire.security.rule_engine import _ReadOnlyRuleStore
from aire.agent.tools import AgentTools
DB = 'demo_artifacts/m10/defense_20261117/demo.sqlite'
BID = 'be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e'
with _ReadOnlyRuleStore(DB) as store:
    t = AgentTools(store, BID)
    print(len(t.registry.catalog()), 'read-only tools')
    for e in t.registry.run('get_callers', {'function': 'validate_input'})['data']['items']:
        print('caller:', e['caller']['function']['current_name'], '@', e['callsite_address'])
    x = t.registry.run('crossvalidate_function', {'function': 'validate_input'})['data']['crossvalidation']
    print('cross-validation:', x['verdict'])
EOF
PYTHONPATH=aire-server/src aire-server/.venv/bin/python -m aire.security.rule_engine \
  demo_artifacts/m10/defense_20261117/demo.sqlite 23d1152ddce4f04449f515a64e1482e9a877dd35d71e7f17fccfc8ec9805fe4a
```

## 7. Shutdown

1. Ctrl-C in terminal 1. It prints "A.I.R.E. GUI stopped." (VERIFIED 11-19).
2. Confirm `ss -ltn | grep 8770` is empty.
3. Close the dedicated browser profile.
4. Optionally re-check the store SHA-256.

## 8. Final readiness checklist

- [ ] Store SHA-256 is `f88fa14e…` and the fixture hashes match (§1)
- [ ] `env | grep AIRE_` checked; the launch uses 2A overrides or the 2C closed port
- [ ] Decided whether guest `ollama serve` stays running
- [ ] Windows: NAT rule Host IP 127.0.0.1:8770 → 10.0.2.15:8770; listeners loopback-only; Adapter 2 reviewed *(UNVERIFIED)*
- [ ] Windows: `ollama list` shows `qwen2.5-coder:1.5b`; one test generation done *(UNVERIFIED)*, or step 10 dropped
- [ ] Token URL opened privately; the address bar shows no `token=`
- [ ] Steps 3–9 rehearsed once end to end in the chosen browser
- [ ] Offline screenshots copied to Windows/USB and opened once offline *(pending per Nov 17 checklist)*
- [ ] Uncommitted defense docs and test edits backed up or committed (BR-11)
- [ ] Claims to avoid are understood (see [DEFENSE_TECHNICAL_BRIEF.md](DEFENSE_TECHNICAL_BRIEF.md) §12 and [REPOSITORY_AUDIT_2026-11-19.md](REPOSITORY_AUDIT_2026-11-19.md#11-defense-readiness))
