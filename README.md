# A.I.R.E. — AI-Assisted Reverse Engineering

A.I.R.E. helps analysts understand binary programs using Ghidra evidence and
local language models. This repository restores the working Java v1 extension
and implements **A.I.R.E. 2.0 M1–M10: read-only whole-binary indexing, SQLite
persistence, relationship queries, bounded evidence, local grounded chat and
advisory function naming, deterministic security rules, a bounded conversational agent,
browser GUI/API, richer ELF/PE evidence, and assembly intelligence**.
M10 evaluation remains incomplete. M6 adds bounded naming
suggestions for analyst review, with no automatic rename or write-back.

## Current capabilities

The Python backend statically analyzes a binary into ProgramIndex: binary metadata,
functions, decompilation, bounded assembly, strings/imports/exports, and direct
call edges. M2 saves and reloads complete ProgramIndex snapshots in SQLite.
M3 queries callers/callees, callsites, bounded reachability/paths, and connectivity
rankings over persisted facts without an LLM. M4 selects, bounds, orders and
labels evidence with provenance and explicit truncations. M5 sends bounded evidence
to configured local Ollama, validates citations, and separates stored facts from
model interpretation. M6 discovers high-connectivity generic-name candidates and
returns validated, cited naming interpretations separately from current names.
M7 evaluates versioned, deterministic CWE rules over stored facts, without a model.
Its `strcpy` and `gets` signals preserve callsite/import provenance and require
analyst review; they do not establish a vulnerability.
See [M7 security rules](docs/M7_SECURITY_RULES.md), [M6 naming](docs/M6_NAMING.md) and [M5 chat](docs/M5_CHAT.md).
M8 adds 18 read-only tools, immediate operational activity, bounded model actions,
binary-scoped follow-up sessions and `aire chat <binary>` over an existing database.
See [agent architecture, CLI and validation](docs/M8_AGENT.md).
Exact function/string and data references and separate thunk bindings are persisted
in schema v2. Agent tools and evidence citations now expose these relationships;
see [M9 implementation and validation](docs/M9_IMPLEMENTATION_2026-10-13.md).
The optional `aire gui` browser workspace uses the same agent and read-only tools.
See [GUI launch and usage](docs/GUI.md).
M9 adds format-aware ELF/PE intake, references/thunks, crypto evidence, caching,
parallel decompilation and timeout recovery. M10 stores instruction IR and provides
instruction explanations, CFG/loop and bounded value-flow analysis, decompiler
cross-validation, and a Function explorer. See [M10](docs/M10_ASSEMBLY_INTELLIGENCE.md).
Named branch relations and register/frame-slot flow are x86/x86-64 specific;
Ghidra selects each binary's language and ABI. Partial/corrupt PE analysis and
older snapshots have explicit coverage limits.
It does not execute or modify the target. See the
[backend README](aire-server/README.md) for API, CLI, and test commands.

The Ghidra extension extracts per-function decompiled code, assembly, callers,
named callees, strings, import-related evidence, structural metrics and behavior
flags. It asks local Ollama for naming candidates, filters confidence and near
duplicates, and presents evidence in a dockable panel. The analyst selects and
applies each rename. The UI currently lists up to 250 functions; confidence is
heuristic, not a measured probability of correctness.

The original Java implementation, six C fixtures, eight intentional test binaries,
ground-truth maps and demo are preserved. See [current state](docs/CURRENT_STATE.md)
for exact behavior and limitations, and [audit](docs/AUDIT.md) for provenance.

## Implemented and planned 2.0 architecture

Implemented: Binary → PyGhidra → ProgramIndex → SQLite Knowledge Store →
Relationship Queries → Evidence Context Builder → Local Grounded Model →
Naming Suggestion Service (M6) → Analyst Review. **No write-back.**

A separate M7 branch runs Relationship Queries → Deterministic CWE Rule Engine
→ Evidence-backed security signals → Analyst Review. It needs no Ollama.

Not implemented: semantic/vector retrieval, vulnerability confirmation,
CVE matching, dynamic validation, exploit generation, and autonomous actions.

Ghidra supplies facts, rules identify deterministic findings where possible,
and local models explain evidence. Analysts approve changes and execution.
See [architecture](docs/ARCHITECTURE.md) for the trust boundaries.

## Repository layout

```text
AIRE/
├── ghidra-plugin/   Canonical v1 Ghidra extension and bundled Gson
├── aire-server/     Read-only indexer, SQLite store, deterministic graph queries
├── tests/           Sources, preserved binaries, ground truth, integration instructions
├── docs/            Current state, architecture, roadmap, setup, demo and recovery archive
├── scripts/         Repository-relative fixture rebuild scripts
├── .gitignore
├── README.md
└── LICENSE-TODO.md
```

## Setup overview

For the separate Java v1 extension, the archived build target is Ghidra 12.0.1
PUBLIC and JDK 21. Select the Gradle
version required by that Ghidra installation, set GHIDRA_INSTALL_DIR and JAVA_HOME,
and run `./ghidra-plugin/scripts/build_extension.sh`. Install the generated
extension zip in Ghidra and enable AIRE. Configure a local Ollama service and model
(default `gemma3:4b` at `http://localhost:11434`), then Refresh → select function →
Suggest → select candidate → Apply. Keep endpoint overrides local.

The November 17 audit used Python 3.12.3, PyGhidra 3.1.0, Ghidra 12.1.3 and
OpenJDK 21.0.13.0.3 on Ubuntu 24.04.5. Earlier M1 reports used Python 3.11.
Use the existing aire-server/.venv; pure Python checks need no Ghidra runtime.
The optional local GUI/API server is launched with `aire gui`; see [GUI.md](docs/GUI.md).
See [development](docs/DEVELOPMENT.md) and [test corpus](tests/README.md) for commands.
No packages or models are installed automatically.

## Running A.I.R.E. with Windows Host Inference

The current deployment uses **Windows 11 Chrome and Ollama on the laptop**;
the Ubuntu VirtualBox VM runs the Python API, Ghidra/PyGhidra, SQLite and all
static analysis. Local inference on Windows is outside the VM, without a cloud
model service. Binary evidence crosses the VM boundary to the Windows model and
browser. See the [deployment and trust-boundary diagram](docs/ARCHITECTURE.md).

The addresses below are specific to the current VirtualBox NAT configuration.
Verify the VM address (`ip -br addr`), Adapter 1 NAT settings and host gateway
before reuse. Local-only forwarding is a required configuration, **pending final
Windows verification**. This setup is not intended for LAN or internet exposure.

1. **Start Windows Ollama.** If the desktop app is already serving, use that
   instance. Otherwise, in PowerShell, start a loopback listener and keep its
   terminal open:

   ```powershell
   $env:OLLAMA_HOST = '127.0.0.1:11434'
   ollama serve
   ```

   If changing an existing app's environment, exit it first and restart it with
   the intended binding. Do not start a second competing listener.

2. **Confirm the Windows model**, in another PowerShell terminal:

   ```powershell
   ollama list
   Invoke-RestMethod http://127.0.0.1:11434/api/tags
   ```

   Both should identify `qwen2.5-coder:1.5b`. If absent, install it separately
   with `ollama pull qwen2.5-coder:1.5b` before rehearsal. No installation was
   performed by this documentation update. The earlier audit saw only
   `llama3.2:latest` on the Windows endpoint; that observation did not verify
   the current model's installation or generation.

3. **Configure VirtualBox forwarding.** Adapter 1 → NAT → Advanced → Port
   Forwarding: TCP, Host IP **127.0.0.1**, Host Port **8770**, Guest IP
   **10.0.2.15**, Guest Port **8770**. Never leave Host IP blank. Inspect
   Adapter 2 as well; its enabled state and any bridged/host-only network must
   be verified on Windows. `--public-port` controls the API's Host allowlist;
   it does not create a forwarding rule.

   For guest access to host-loopback Ollama, inspect VirtualBox's
   `nat-localhostreachable1` setting. If required and deliberately enabled
   while the VM is powered off, the existing review's command is:

   ```powershell
   VBoxManage modifyvm '<VM name>' --nat-localhostreachable1 on
   ```

   Replace the VM name and verify the option against the installed VirtualBox
   CLI. This permits guest access to other host loopback services too; it is
   not an Ollama-only exception. Keep Ollama bound to loopback.

4. **Start the Ubuntu API** with the existing environment and pre-indexed store:

   ```bash
   cd ~/aire

   export AIRE_OLLAMA_HOST=http://10.0.2.2:11434
   export AIRE_OLLAMA_ALLOW_REMOTE=1
   export AIRE_OLLAMA_MODEL=qwen2.5-coder:1.5b
   export AIRE_OLLAMA_NUM_CTX=4096
   export AIRE_M10_NARRATION=0

   aire-server/.venv/bin/aire gui \
     --database demo_artifacts/m10/m10.sqlite \
     --bind 10.0.2.15 \
     --allow-non-loopback-bind \
     --port 8770 \
     --public-port 8770 \
     --no-browser
   ```

   Ghidra intake also requires the existing configured `GHIDRA_INSTALL_DIR`
   and Java 21 runtime. Check that the demo store exists: the CLI creates an
   empty store if the path is missing. Prewarming starts the analyzer by
   default; `--no-prewarm` is available for an existing-store-only rehearsal.

5. **Check guest-to-host connectivity.** In Ubuntu:

   ```bash
   curl --noproxy '*' --fail --max-time 5 http://10.0.2.2:11434/api/tags
   ```

   The GUI's authenticated health check also lists the selected model and
   available models. Tags/health prove metadata connectivity, not generation
   quality or latency. `AIRE_OLLAMA_ALLOW_REMOTE=1` (or
   `--allow-remote-ollama`) is the GUI's explicit opt-in for the Windows
   origin; it cannot be enabled through an HTTP request. Narration is off;
   ordinary M8 chat and function prompt cards can still invoke Ollama.

6. **Launch isolated Chrome on Windows**, adjusting its installation path if
   needed:

   ```powershell
   & 'C:\Program Files\Google\Chrome\Application\chrome.exe' --user-data-dir="$env:LOCALAPPDATA\AIRE-Chrome" --no-first-run --no-default-browser-check
   ```

   Keep this profile dedicated to A.I.R.E., without extensions, Sync or unrelated
   browsing. It is separate from the browser profile used for daily work.

7. **Open the printed per-launch Host-side URL** in that Chrome window. Its
   origin is `http://127.0.0.1:8770`; copy the complete tokenized URL from the
   VM terminal. Never paste it into documentation, screenshots or shared logs.
   Login exchanges the token for an `HttpOnly; SameSite=Strict` cookie and
   redirects to `/`. Bare `/api/*` requests without a valid cookie or
   `X-AIRE-Token` header return 401. A restart requires the new launch URL.

8. **Verify interface restrictions** before the demonstration. In Ubuntu:

   ```bash
   ip -br addr
   ss -ltn 'sport = :8770'
   ```

   Expect `10.0.2.15:8770` only for this instance. In Windows PowerShell:

   ```powershell
   Get-NetTCPConnection -State Listen -LocalPort 8770,11434 | Select-Object LocalAddress,LocalPort,OwningProcess
   VBoxManage showvminfo '<VM name>' --machinereadable
   ```

   Require `127.0.0.1:8770` for the forward and `127.0.0.1:11434` for Ollama;
   investigate wildcard, LAN or IPv6 listeners. Check owning processes and
   firewall rules, the explicit NAT Host IP, and Adapter 2. From another
   device on the same network, attempts to reach the Windows LAN address on
   both ports must fail; repeat for any reachable host IPv6 address. In a
   fresh isolated Chrome profile, verify bare API denial, token login and
   rejection of the old token after restart. These Windows/external-device
   checks remain **pending**, not established by the VM test suite.

9. **Stop safely** with Ctrl-C in the Ubuntu server terminal. The server
   closes its listener and analyzer worker; the CLI normally returns 130 on
   interruption. Confirm the guest listener is gone, close dedicated Chrome,
   and stop a foreground `ollama serve` with Ctrl-C if it was started just
   for the demo. The VirtualBox host listener may remain until its NAT rule
   or VM is stopped; it no longer has a guest API to forward to.

10. **Troubleshoot connections** using the following checks:

    | Symptom | Check |
    | --- | --- |
    | Chrome connection refused | API process, current guest IP, matching 8770 NAT rule and Windows listener |
    | Cannot assign requested address | `ip -br addr`; replace the guest bind and NAT guest destination together |
    | Address already in use | Identify the existing listener; stop its owning server normally |
    | API 401 | Open this launch's full printed URL in the dedicated profile |
    | API 403 | Use `127.0.0.1:8770`, matching `--public-port`; direct guest-IP URLs are rejected by Host checks |
    | Remote Ollama rejected | Set the GUI launch opt-in and restart; the endpoint is immutable during the session |
    | Ollama connection refused/timeout | Windows loopback listener, NAT host-loopback reachability and firewall; do not widen the bind |
    | Selected model missing | Check Windows `/api/tags`, not the guest's historical model installation |
    | Empty Binary Library | Confirm the database path and required persisted analyses |
    | Long pauses despite reachable services | Check disk headroom and VM scheduling; use the small pre-indexed deterministic demo |

The [host-access review](docs/HOST_ACCESS_SECURITY_REVIEW.md) reports the
November 17 Codex run: **649 tests executed, 645 passed, 0 failed/errors,
4 live-model tests skipped**, Python 3.12.3, Ghidra enabled, browser enabled
(Firefox 155.0.1 headless in Ubuntu with synthetic payloads and a fake model).
This is attributed evidence, not a fresh run or Windows Chrome certification.
The earlier Phase 2 result remains **621 passed / 4 skipped** separately.
See [defense notes and evidence ledger](docs/MS_DEFENSE_M10.md) and the
[documentation audit](docs/M10_DOCUMENTATION_UPDATE_2026-11-17.md).

## Roadmap

M0 cleanup and architecture → M1 read-only indexing → M2 SQLite → M3 relationships
→ M4 retrieval → M5 chat → M6 analyst-controlled naming suggestions → M7 CWE framework →
M8 read-only agent and GUI/API → M9 format-aware evidence/performance/recovery → M10 assembly intelligence →
M11 evaluation → M12 reporting/integration. See [roadmap](docs/ROADMAP.md).

**Next: finish M10 evaluation and Windows deployment verification, rehearse the
split-host defense, and retain explicit incomplete-evidence states.** Dynamic
validation, broader source/sink/alias analysis and automatic write-back remain future work.

## Safety and licensing

This project is intended only for authorized reverse engineering, vulnerability research, education, and defensive security testing. Dynamic execution must only be performed against binaries the analyst is authorized to test and in an isolated environment.

No exploitation or dynamic execution functionality is implemented in the 2.0
scaffold. The project-wide license remains undecided; see [LICENSE-TODO.md](LICENSE-TODO.md).
Original author metadata credits Laurene Robinson.
