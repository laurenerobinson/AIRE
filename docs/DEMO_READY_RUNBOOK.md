# MS defense demonstration runbook

November 17 checkpoint for the November 20, 2026 defense. **Final sign-off is
pending.** Read the [readiness report](DEMO_READINESS_REPORT.md) before presenting.
The path below passed in guest Firefox twice; Windows Chrome and host security
checks remain manual. Keep model inference outside the critical demonstration.

## Prerequisites and safe checks

Use pre-indexed `demo_artifacts/m10/defense_20261117/demo.sqlite`. The original
`demo_artifacts/m10/m10.sqlite` was preserved. Seven selected binaries are cached:
debug/stripped/O2 ELF, the established PE32, and three trusted CWE controls.
Do not rebuild or analyze the whole library during the defense. The current
guest has only about 123 MiB free; recover approved disk space before further
indexing or long tests. Never execute the fixture binaries.

Ubuntu checks (these do not start or stop the existing server):

```bash
cd ~/aire
git status --short
df -h /
free -h
ip -br addr
ip route
ss -ltn 'sport = :8770'
curl --fail --max-time 5 http://10.0.2.2:11434/api/tags
```

The verified NAT guest is `10.0.2.15`; Windows is reached from it at `10.0.2.2`.
Adapter 2 currently also has `10.0.3.15`. These are deployment-specific addresses,
not universal defaults. Confirm Adapter 2's attachment in VirtualBox. An existing
API on 8770 must be accounted for before starting another; use its controlling
terminal for a normal shutdown when a restart is needed.

## Windows launch and exposure verification — still pending

In PowerShell, check model availability and listeners:

```powershell
ollama list
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -in 8770,11434 } |
  Select-Object LocalAddress,LocalPort,OwningProcess
```

Start the existing Windows Ollama application, or `ollama serve` if no server is
already running. Do not start a second listener. Confirm `qwen2.5-coder:1.5b`
is installed. Avoid changing Ollama to a wildcard/LAN bind to resolve connectivity;
first verify the approved Windows/VirtualBox configuration from
[README.md](../README.md#running-aire-with-windows-host-inference).

In VirtualBox settings, verify Adapter 1 NAT and TCP forwarding: host IP
`127.0.0.1`, host port `8770`, guest IP `10.0.2.15`, guest port `8770`.
Inspect saved settings with the actual VM name if VBoxManage is available:

```powershell
$VmName = Read-Host 'VirtualBox VM name'
VBoxManage showvminfo $VmName --machinereadable
```

Verify 8770 is loopback-only on Windows. Verify the actual 11434 binding and
firewall scope allows only the intended local/VM path, with no LAN or public
access. Review Adapter 2 before approving deployment. From a separate device,
confirm the Windows LAN address rejects connections to both ports. An Ubuntu
success response alone cannot prove those restrictions.

## Ubuntu API launch

Use this only after resolving the existing listener and confirming the addresses:

```bash
cd ~/aire
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export AIRE_OLLAMA_HOST=http://10.0.2.2:11434
export AIRE_OLLAMA_ALLOW_REMOTE=1
export AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b
export AIRE_OLLAMA_NUM_CTX=4096
export AIRE_M10_NARRATION=0
aire-server/.venv/bin/aire gui \
  --database demo_artifacts/m10/defense_20261117/demo.sqlite \
  --session-dir demo_artifacts/m10/defense_20261117/live-sessions \
  --upload-dir demo_artifacts/m10/defense_20261117/live-uploads \
  --bind 10.0.2.15 \
  --allow-non-loopback-bind \
  --port 8770 \
  --public-port 8770 \
  --no-browser \
  --no-prewarm
```

Keep the terminal private. Open its newly printed Host-side token URL in the
isolated Windows Chrome profile; never paste it into notes, screenshots or logs.
After authentication, verify the URL has no token query, the library loads and
a separate unauthenticated browser profile receives an authentication error.
Close developer tools before sharing the display. Do not reuse yesterday's URL.

Example isolated Chrome launch in PowerShell (adjust executable if needed):

```powershell
$Chrome = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
$DemoProfile = Join-Path $env:LOCALAPPDATA 'AIRE\DefenseChrome'
& $Chrome "--user-data-dir=$DemoProfile" --no-first-run 'http://127.0.0.1:8770'
```

Navigate privately to the fresh token URL in that window. Authentication is
per launch; bare origin navigation alone is not a login. `AIRE_M10_NARRATION=0`
disables M10 narration; some other model cards may still infer. Use only the
validated deterministic question below until live-model tests are completed.

## Nine-minute presentation path

| Time | Action | Expected output and speaking cue |
|---|---|---|
| 0:00–0:45 | Explain split-host diagram; show already authenticated Library | Windows runs Chrome and local Ollama; Python/Ghidra/store/analysis execute in Ubuntu. Inference is laptop-local, not necessarily VM-local. |
| 0:45–1:30 | Select cached `aire_test_binary`; Investigate binary; look up `validate_input` | Function at `004011bc`; state that this is a trusted, pre-indexed fixture. |
| 1:30–2:30 | Open Imports, Strings, Call Graph | Show `strlen`, `puts`, ASCII-validation string and caller/callee evidence. |
| 2:30–4:15 | Open Decompiled View; Function explorer and Assembly | Compare stored source to exact instructions; show branch `004011e1`, paths and stack-value trace at `004011dc`. |
| 4:15–5:00 | Open CFG, Data flow and decompiler check | Explain `CONSISTENT` as a scoped comparison, not proof of equivalence. |
| 5:00–6:15 | Switch to `unsafe_copy`; Investigate; Findings; inspect `copy_input` calls | CWE-120 SIGNAL and `strcpy` at `00401183`; explain LOW strength and need for analyst review. Optional `safe_copy` is a negative control, not a safety guarantee. |
| 6:15–7:30 | Return to original ELF and `validate_input`; ask “What does this function do?” | Deterministic evidence answer. Expand citations, provenance and tool activity; point to inspectable instruction references. |
| 7:30–8:30 | Switch stripped/O2/PE, then return via Recent Chats | Different binary/architecture metadata; original function and answer restored. Avoid re-analysis. |
| 8:30–9:00 | Explain limitations and future validation | Static evidence, fixture scope, remaining live-model/evaluation work and host verification. Do not claim complete security validation. |

Detailed expected instruction/branch outputs are in [DEMO_M10.md](DEMO_M10.md).
All Windows GUI actions still need a manual rehearsal; guest-browser results
are recorded in the [report](DEMO_READINESS_REPORT.md).

## Recovery, shutdown and reproducibility

If a request fails, wait briefly, reload once, select the same cached binary,
open Recent Chats and restore the session. Reload/restore passed in the guest
rehearsal; explicit failed-request injection was not tested. Do not re-index
to repair a UI request. A 401 requires the current launch's private token URL;
a 403 requires checking Host/origin/forwarding, not disabling access controls.
If Ollama is unavailable, keep narration off and stay on the deterministic path.
If the VM stalls, switch to the sanitized backup images already copied to
Windows; that transfer and offline check are still pending.

Stop a demonstration server with Ctrl+C in its controlling terminal, then
confirm its listener is gone with `ss -ltn 'sport = :8770'`. Do not stop an
unrelated user's process or remove active Ghidra/session directories. Close the
isolated Chrome window. A fresh launch creates a new token.

To reproduce the completed guest-only rehearsal later, after checking resources:

```bash
cd ~/aire
PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/verify_defense_demo.py \
  --database demo_artifacts/m10/defense_20261117/demo.sqlite \
  --output demo_artifacts/m10/defense_20261117
```

This uses spare port 18770 and its own sessions/profile. It requires the prepared
ignored store and existing Firefox; it does not validate Windows NAT or Chrome.
Do not start long regression or model runs until resuming the readiness work.
