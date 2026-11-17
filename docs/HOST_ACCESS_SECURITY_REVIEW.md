# A.I.R.E. — Host-Access Security Review (GUI opened from the Windows host)

Date: 2026-11-17 · Branch `checkpoint/m10-pre-hardening` (working tree, includes uncommitted M10 Phase 2 work) ·
Python 3.12.3 · Firefox 155.0.1 (VM, headless test) · **Nothing committed or pushed.**

**Threat model.** The GUI is served from the Ubuntu VM and opened in Firefox on the Windows host through a
VirtualBox NAT port forward bound to host `127.0.0.1`. Any website in another tab, and any local Windows process,
can send requests to `localhost`. Binary-derived strings and model output reach a browser outside the VM.
Optional: Ollama on Windows reached from the VM at `http://10.0.2.2:11434`.

## Verdict

**SAFE WITH CONDITIONS.** The conditions are listed at the end of this document.

## Results

Status is the state **before** this review. "Fixed" means the item failed and was changed here.

| # | Item | Before | Evidence (file:line, current tree) | Fix | Test |
|---|------|--------|------------------------------------|-----|------|
| A1 | Default bind | PASS | `cli.py:47` `--bind 127.0.0.1`, `--port 8765`; `server.py` `_validate_bind_host` rejects non-loopback | — | `BindPolicyTests.test_wildcard_and_public_binds_refused_even_with_opt_in` |
| A2 | Reach NAT forward without `0.0.0.0` | **FAIL** (loopback only, so a NAT forward to `10.0.2.15` could not connect; the only way to make it work would have been weakening the check) | `server.py` `_validate_bind_host(host, allow_non_loopback)` | New explicit opt-in `--allow-non-loopback-bind`. It accepts one **private IPv4** interface address (e.g. `10.0.2.15`) and refuses `0.0.0.0`, `::`, public, link-local, multicast, broadcast and IPv6. It requires the token and logs and prints a startup WARNING. It never opens the VM browser. | `test_nat_address_requires_opt_in_and_token`, `test_nat_address_binds_only_that_interface_when_present`, `test_serve_warns_and_prints_tokenized_urls` |
| A3 | Guest interfaces | PASS | `ip -br addr`: `lo 127.0.0.1/8 ::1/128`; `enp0s3 UP 10.0.2.15/24` + ULA/link-local IPv6. **No bridged or host-only interface.** Binding `10.0.2.15` exposes the port only to the VirtualBox NAT engine (i.e. the forward). | — | — |
| B4 | Host allowlist | **FAIL** (accepted any loopback spelling `127.x`, `[::1]` on **any** port) | `server.py` `_AUTHORITY_RE`, `AireRequestHandler._authority` | Exactly `localhost` / `127.0.0.1` (case-insensitive) on an allowed port: the guest port plus `--public-port` / `AIRE_GUI_PUBLIC_PORT` (the host-side forwarded port). Everything else gets 403, static files included. | `HostAccessHttpTests.test_host_header_allowlist_is_exact` |
| B5 | Origin on state-changing requests | **FAIL** (a missing `Origin` was accepted) | `_trusted_request` | POST requires a same-origin `http://` Origin matching the Host. A missing Origin is allowed only with a valid `X-AIRE-Token` **header** (a non-browser client; a cross-site page cannot send that header without a preflight, which fails). GETs with `Sec-Fetch-Site` other than `same-origin`/`none` are refused. | `test_foreign_or_missing_origin_rejected_on_state_changing_endpoints`, `test_cross_site_fetch_metadata_rejected_for_reads`, updated `test_m10_security.test_origin_must_match_host` |
| B6 | CORS | PASS | No `Access-Control-*` header anywhere; `OPTIONS` → 501 | — | `test_cross_origin_preflight_refused_and_no_cors_headers` |
| B7 | JSON content type | PASS | `_body()` requires `application/json`; upload requires `application/octet-stream` (not CORS-safelisted) | — | `test_simple_form_content_types_rejected` |
| B8 | Authentication | **FAIL** (none) | `serve()`, `_authorized`, `_token_login` | Per-launch `secrets.token_urlsafe(32)` printed in the terminal as `http://127.0.0.1:<port>/?token=…`. `GET /?token=` → 303 + `HttpOnly; SameSite=Strict` cookie `aire_token_<guestport>`. Every `/api/*` request needs the cookie or the `X-AIRE-Token` header (constant-time compare); otherwise 401. The token is redacted from the request log. **No `app.js` change was needed.** | `test_per_launch_token_required_for_api`, `test_token_never_written_to_request_log`, `test_loopback_serve_generates_a_fresh_token`, browser test (real login flow) |
| C9 | Untrusted data in `app.js` | PASS | All `innerHTML` sinks (`app.js:121,131,193,207,231,369,387,394,445,452,582,615,644,654,660,681,692,705,957`) interpolate through `escapeHtml` or constants. `renderMarkdown` (`:22`) escapes **first**, then adds only fixed tags (its one attribute is escaped). Model text, decompiled code, assembly, transcripts, errors, findings and paths use `escapeHtml`/`textContent`. No `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or third-party markdown. Unescaped values are server-computed integers only (`:539` counts, `:607` coverage counts, `:622`/`:693` `parameter.ordinal`, `:681` lengths). | — (not changed; see risk R5) | `BrowserXssTests.test_payloads_render_as_literal_text` (headless Firefox). A mutation check that disabled `escapeHtml` made it fail. |
| C10 | Response headers | PASS | `end_headers()`: CSP `default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, `nosniff`, `no-referrer`, `Cache-Control: no-store` on every response | — | `test_security_headers_on_static_and_api` |
| D11 | Static confinement | PASS | `SimpleHTTPRequestHandler(directory=static)`; `translate_path` drops `..` after unquoting | Gap fixed: `HEAD` bypassed the Host check (`do_HEAD` inherited). It is now gated, and `/api/*` HEAD returns 405. | `test_static_route_path_traversal_rejected`, `test_head_requests_use_the_same_gate` |
| D12 | No raw binary/DB download | PASS | No route streams files except `static/`; uploads are write-only; the database is opened read-only | — | covered by D11 tests + existing `test_m10_security` |
| D13 | Path inputs canonicalized | PASS | Binary selectors are IDs/names only (`resolve_binary(..., allow_paths=False)`); fixtures are resolved under the repo (`binary_library.py:153`); upload names are basenamed and sanitized (`:214`); session IDs match `^[0-9a-f]{32}$` | — | existing `test_http_binary_selector_never_reads_filesystem_paths` |
| D14 | No stack traces/paths in errors | **FAIL (partial)** | `_public_error` hid tracebacks, but `ValueError`, job `error` and fixture `error` strings could carry absolute paths (e.g. `[Errno 2] … '/home/…'`) | `redact_paths()` maps repo → `<repo>` and home → `~`. It is applied in `_public_error`, analysis job errors and fixture errors (OSError → `strerror` only). | `test_client_errors_redact_absolute_paths` |
| E15 | Remote Ollama opt-in only by env/CLI | **FAIL** (the GUI had **no** opt-in at all, so `10.0.2.2` was impossible without code edits) | `GuiModelConfig.allow_remote_host` (frozen), `cli.py` `--allow-remote-ollama` / `AIRE_OLLAMA_ALLOW_REMOTE=1` | Added. No HTTP route reads it, and the config is immutable. | `test_virtualbox_host_requires_explicit_opt_in`, `test_gui_client_gets_opt_in_only_from_launch_config`, `test_cli_flag_and_environment_set_the_opt_in` |
| E16 | `test_remote_hosts_rejected_without_dns` (`[::ffff:127.0.0.1]`) | PASS (already fixed by the M10 Phase 2 mapped-address rule, `ollama_client.py:97-103`) | `tests.test_ollama_client`: 33/33 OK before any change in this review | — (no loosening) | existing test + `test_ipv4_mapped_loopback_rejected_without_opt_in` |
| E17 | Model output untrusted | PASS | Rendered via escaped markdown/`textContent`. Agent tools are a fixed read-only registry (no shell/path tool). M10 narration is validated against cited addresses and off by default. | — | browser test (model payload); existing `test_m10_security` injection tests |
| E18 | No world-readable prompts/responses | PASS in effect (`/home/laurene` is `0750`) but files were `0664` under umask `0002` | `_atomic_json`, `AgentSession.save` | Session/transcript files are created `0600` regardless of umask. Prompts are never logged; the request log has no bodies. | `test_session_files_are_owner_only_regardless_of_umask` |
| F19 | Read-only actions | PASS | No endpoint runs shell commands or executes targets. The only subprocess is the fixed Ghidra index worker (`binary_library.py:336`, argv list). Writes go only to the session/upload dirs. | — | existing `test_tools_preserve_binary_scope_and_reject_mutations`, `test_m10_security` |
| F20 | Limits | **FAIL (partial)** | Body 1 MB, upload 32 MiB, socket timeout 60 s, analysis queue 8 / 1 worker, but **unbounded concurrent chats** | `/api/chat` limited to 4 concurrent (non-blocking semaphore → 429) | `test_chat_concurrency_is_bounded`, `test_body_size_limit` |
| G21 | Dependencies | MANUAL REVIEW | Runtime: stdlib only (`dependencies = []`). Optional `pyghidra==3.1.0` → `jpype1==1.5.2`, `packaging==26.3`; dev: `pytest==9.2.0`, `pluggy==1.7.0`, `iniconfig==2.3.1`, `Pygments==2.21.0`, `pip==26.2.1`. Ghidra 12.1.3 (Java). **No JavaScript dependencies** (vanilla `app.js`, no CDN). `pip-audit` is not installed and the VM is offline for this review, so **NOT AUDITED**. | — | — |

## Code changes (this review)

| File | Change |
|------|--------|
| `aire-server/src/aire/api/server.py` | Exact Host/port allowlist; required same-origin Origin on POST; Sec-Fetch-Site check; per-launch token (cookie/header) and `/?token=` exchange; token log redaction; gated `HEAD`; `_reject` closes the connection after early refusal; chat concurrency 429; opt-in NAT bind validation and startup warning; tokenized URLs; `GuiModelConfig.allow_remote_host`; `0600` transcripts; path-redacted errors |
| `aire-server/src/aire/agent/cli.py` | `--allow-non-loopback-bind`, `--public-port` / `AIRE_GUI_PUBLIC_PORT`, `--allow-remote-ollama` / `AIRE_OLLAMA_ALLOW_REMOTE=1` |
| `aire-server/src/aire/agent/session.py` | Agent session file created `0600` |
| `aire-server/src/aire/api/binary_library.py` | `redact_paths()`; applied to job and fixture errors |
| `aire-server/tests/test_host_access_security.py` | **New**, 24 tests (one real-Firefox test, opt-in `AIRE_RUN_BROWSER_TESTS=1`) |
| `aire-server/tests/test_gui_server.py`, `test_binary_library.py`, `test_m10_security.py` | POSTs now send the same-origin `Origin` a browser sends. `test_origin_must_match_host` now expects **403** for a missing Origin (it previously asserted 201). |
| `scripts/verify_oct22_demo.py`, `scripts/measure_gui_responsiveness.py` | Send `Origin` on POST so they keep working |

Behavior changes for you:

- You must open the **tokenized URL** printed at launch. Opening the bare URL shows "A.I.R.E. could not start: Missing or invalid A.I.R.E. access token".
- Non-browser clients must send `X-AIRE-Token`.
- `Host: [::1]` and `127.0.0.2` are no longer accepted.

Analysis results, evidence references and citations are unchanged; the full suite confirms this.
`app.js`, `binary_scope.py` and `instruction_ir.py` diffs in `git status` are earlier Phase 2 work. This review did not change them. `app.js` was mutated temporarily for the mutation check and restored byte-identical (sha256 `d70fe080…bf277f`).

## Test results

| Run | Ran | Passed | Failed | Errors | Skipped | Time |
|-----|----:|------:|------:|------:|------:|-----:|
| Before (M10 Phase 2 final, from `docs/M10_SECURITY_HARDENING.md`; **not re-run**, since the pre-review tree was not separately preserved) | 625 | 621 | 0 | 0 | 4 | 369 s |
| Before, targeted: `test_ollama_client` on this tree prior to edits | 33 | 33 | 0 | 0 | 0 | 1.5 s |
| **After, full suite** (`AIRE_RUN_GHIDRA_TESTS=1`, `AIRE_RUN_BROWSER_TESTS=1`, Python 3.12.3) | **649** | **645** | **0** | **0** | **4** | 604 s |

The 4 skips are the live-model opt-ins (`test_live_demo`, `test_debug_live_ollama`, `test_stripped_live_ollama`, `test_stripped_live_naming`). They are **NOT TESTED**, not passed. The run also used the documented command (core dumps off, `nice -n 10`). Log: `demo_artifacts/host_access/full_suite.log` (not git-ignored; delete it if you don't want it).

## Manual checks (live server, `curl`)

The server was launched exactly as the host setup would launch it, but on spare ports. **Port 8767 was not touched.**

```
AIRE_OLLAMA_HOST=http://10.0.2.2:11434 AIRE_OLLAMA_ALLOW_REMOTE=1 aire-server/.venv/bin/python -m aire.agent.cli gui \
  --database demo_artifacts/m10/m10.sqlite --bind 10.0.2.15 --allow-non-loopback-bind --port 18767 \
  --public-port 28767 --no-browser --no-prewarm
```

Startup output (token redacted here):

```
A.I.R.E. GUI
WARNING: listening on non-loopback address 10.0.2.15:18767 (explicit opt-in). Only Host localhost/127.0.0.1 on ports 18767, 28767 and the access token are accepted. Keep the VirtualBox port forward bound to host IP 127.0.0.1.
WARNING: listening on non-loopback address 10.0.2.15:18767 (explicit opt-in). ...   (second copy = logging handler)
Host-side URL (VirtualBox forward 127.0.0.1:28767): http://127.0.0.1:28767/?token=<REDACTED>
Treat the token like a password. It changes every launch.
```

`ss -ltn`: `10.0.2.15:18767` only (loopback instance: `127.0.0.1:18768`). No `0.0.0.0` listener.

The token is shown as `<TOKEN>`. `N=http://10.0.2.15:18767`. The `Host: 127.0.0.1:28767` header is what the Windows browser sends through the forward.

```
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' $N/api/bootstrap
401
$ curl -s -w '\n%{http_code}\n' -H 'Host: 127.0.0.1:28767' -H 'X-AIRE-Token: <TOKEN>' $N/api/binaries | tail -c 120
": "little", "pointer_size": 8, "entry_point": null, "executable_size": 152064, "program_name": "ecdsa_sign.exe"}]}
200
$ curl -s -w '\n%{http_code}\n' -H 'Host: evil.example' -H 'X-AIRE-Token: <TOKEN>' $N/api/binaries
{"error": "Forbidden", "message": "A.I.R.E. GUI accepts same-origin requests to localhost only"}
403
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: 10.0.2.15:18767' -H 'X-AIRE-Token: <TOKEN>' $N/api/binaries
403
$ curl -s -w '\n%{http_code}\n' -H 'Host: 127.0.0.1:28767' -H 'X-AIRE-Token: <TOKEN>' -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{"binary_id":"x"}' $N/api/sessions
{"error": "Forbidden", "message": "A.I.R.E. GUI accepts same-origin requests to localhost only"}
403
$ curl -s -w '\n%{http_code}\n' -H 'Host: 127.0.0.1:28767' -H 'Cookie: aire_token_18767=<TOKEN>' -H 'Content-Type: application/json' -d '{"binary_id":"x"}' $N/api/sessions      # cookie but no Origin
{"error": "Forbidden", "message": "A.I.R.E. GUI accepts same-origin requests to localhost only"}
403
$ curl -s -i -X OPTIONS -H 'Host: 127.0.0.1:28767' -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: POST' $N/api/chat | grep -iE '^HTTP|^access-control'
HTTP/1.1 501 Unsupported method ('OPTIONS')
$ curl -s -w '\n%{http_code}\n' -H 'Host: 127.0.0.1:28767' -H 'X-AIRE-Token: <TOKEN>' -H 'Origin: http://127.0.0.1:28767' -H 'Content-Type: text/plain' -d '{}' $N/api/sessions
{"error": "GuiError", "message": "Expected application/json"}
400
$ curl -s -i -H 'Host: 127.0.0.1:28767' "$N/?token=<TOKEN>" | grep -iE '^HTTP|^location|^set-cookie'
HTTP/1.1 303 See Other
Location: /
Set-Cookie: aire_token_18767=<TOKEN>; Path=/; HttpOnly; SameSite=Strict
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' "$N/?token=wrongwrongwrongwrongwrongwrongwrongwrong"
401
$ curl -s -i -H 'Host: 127.0.0.1:28767' $N/ | grep -iE '^HTTP|^content-security|^x-content|^referrer|^cache-control'
HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
$ curl -s --path-as-is -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' "$N/../server.py"                 → 404
$ curl -s --path-as-is -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' "$N/%2e%2e/server.py"             → 404
$ curl -s --path-as-is -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' "$N/..%2f..%2fapi%2fserver.py"    → 404
$ curl -s --path-as-is -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' "$N//etc/passwd"                  → 404
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: 127.0.0.1:28767' -H 'X-AIRE-Token: <TOKEN>' -H 'Sec-Fetch-Site: cross-site' $N/api/bootstrap
403
$ curl -s -H 'Host: 127.0.0.1:28767' -H 'X-AIRE-Token: <TOKEN>' $N/api/health
{"ok": true, "host": "http://10.0.2.2:11434", "models": ["llama3.2:latest"], "selected_model": "qwen2.5-coder:1.5b"}
$ curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 http://127.0.0.1:18767/        # NAT-only bind: not on guest loopback
000
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'X-AIRE-Token: <NAT-server token>' http://127.0.0.1:18768/api/binaries   # other launch's token
401
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'X-AIRE-Token: <NAT-server token>' -H 'Host: [::1]:18768' http://127.0.0.1:18768/api/binaries
403
```

Request log lines: `"GET /?token=<redacted> HTTP/1.1" 303 -`. The token appears only in the printed launch URL.

Two observations from the health check:

- `/api/health` made one metadata request (`/api/tags`) to `10.0.2.2:11434`, and **a Windows-side Ollama answered**. No prompt was sent.
- The configured model `qwen2.5-coder:1.5b` is **not** in that Ollama's model list (`llama3.2:latest` only). Pull it on Windows or set `AIRE_OLLAMA_MODEL=llama3.2:latest`.

## Remaining risks and unverified items

| ID | Risk | Severity | Note |
|----|------|----------|------|
| R1 | **The Windows side was not verified** (port-forward Host IP, firewall, Ollama bind). Ollama answering on `10.0.2.2` means either VirtualBox "localhost reachable" is on or Ollama listens beyond loopback. The VM cannot tell which. | HIGH until you run the checklist | See the checklist below |
| R2 | Cookies are not port-scoped. The `aire_token_<port>` cookie is also sent to *other* `127.0.0.1` ports you visit in the same Firefox profile. A malicious local Windows server could collect it if you browse to it. | LOW–MEDIUM | Use the dedicated profile; the token changes every launch |
| R3 | The token sits in the terminal and in Firefox history (the `/?token=` URL, before the redirect). | LOW | Same model as Jupyter; use the dedicated profile and close the terminal when done |
| R4 | Plain HTTP over the forward. Traffic stays on host loopback and in the VirtualBox NAT engine. | LOW | Do not forward on a non-loopback host IP |
| R5 | A few `app.js` `innerHTML` interpolations of server-computed integers are not escaped (`:539,:607,:622,:681,:693`). They are not exploitable unless the analysis database is tampered with. CSP blocks inline script anyway. | LOW | Left unchanged (the brief asks to fix confirmed issues only). One-line hardening if wanted. |
| R6 | `ThreadingHTTPServer` has no global connection cap. Slow clients are bounded by the 60 s socket timeout, and a hostile *web page* cannot reach the API without the token. A local Windows process that can connect can still occupy threads. | LOW | — |
| R7 | Prompt injection against a live model is unmeasured (also Phase 2 R2). Model text is display-only and the tools are read-only. | MEDIUM | Keep `AIRE_M10_NARRATION=0` |
| R8 | `pip-audit` was not run (offline, not installed). | UNKNOWN | Run `pip install pip-audit && pip-audit` from a networked machine against the versions above |
| R9 | Binary metadata (`/api/bootstrap`) still includes the binary's absolute VM path as data (used for display names). Only token holders see it. | INFO | Not an error message, so not changed |
| R10 | `docs/M10_SECURITY_HARDENING.md` R3: free disk is still ~650 MB (98%). `/var/crash` holds a 133 MB `_usr_bin_python3.12.1000.crash`. | HIGH for VM stability | User action |

## Host-side checklist (Windows)

The examples use guest port **8767** and host port **8767**. If they differ, pass `--public-port <host port>`.

1. **VirtualBox port forward.** Settings → Network → Adapter 1 (NAT) → Advanced → Port Forwarding:

   | Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
   |------|----------|---------|-----------|----------|------------|
   | aire-gui | TCP | **127.0.0.1** | 8767 | 10.0.2.15 | 8767 |

   Never leave Host IP blank (blank means all host interfaces). Command-line equivalent, with the VM running:
   `VBoxManage controlvm "<VM name>" natpf1 "aire-gui,tcp,127.0.0.1,8767,10.0.2.15,8767"`
2. **Confirm the listener.** In `cmd`, run `netstat -ano | findstr :8767`.
   - Expected, exactly one line: `TCP    127.0.0.1:8767    0.0.0.0:0    LISTENING    <PID>`.
   - `tasklist /FI "PID eq <PID>"` should show `VirtualBoxVM.exe`.
   - **Any `0.0.0.0:8767` or `[::]:8767` line means the rule is wrong.** Stop and fix it.
3. **Windows Firewall.** Decline (Cancel, or untick both Private and Public) any "Allow access" prompt for:
   - `VirtualBoxVM.exe` / `VirtualBox Headless Frontend`
   - `ollama.exe` / `ollama app.exe`

   A loopback-only setup needs no inbound rule. Check that none exists: `wf.msc` → Inbound Rules → no *Allow* rule for those programs on Public/Private.
4. **Dedicated Firefox profile.**
   - Create it with `"C:\Program Files\Mozilla Firefox\firefox.exe" -P` → Create Profile… → `aire`.
   - Launch with `"C:\Program Files\Mozilla Firefox\firefox.exe" -P aire -no-remote "http://127.0.0.1:8767/?token=<token from VM terminal>"`.
   - In that profile: no extensions, no Sync sign-in, no other browsing.
5. **Windows Ollama on loopback only.**
   - Run `netstat -ano | findstr :11434`. Expected: `TCP 127.0.0.1:11434 … LISTENING` only. A `0.0.0.0:11434` line means fix it.
   - Run `echo %OLLAMA_HOST%` and PowerShell `[Environment]::GetEnvironmentVariable('OLLAMA_HOST','User')`. Both must be empty or `127.0.0.1`, **not** `0.0.0.0`. Restart Ollama after changing it.
   - The VM reaches it as `10.0.2.2`, which VirtualBox NAT maps to host loopback when "localhost reachable" is enabled.
   - If Ollama is on `127.0.0.1` and the VM gets "connection refused", enable it: `VBoxManage modifyvm "<VM name>" --nat-localhostreachable1 on` (VM powered off). Do not bind Ollama to `0.0.0.0` instead. Trade-off: this lets the guest reach **all** host loopback services.
6. **VM side launch** (in the VM terminal; port 8767 must be free, so stop any old GUI first):

   ```bash
   cd ~/aire
   export AIRE_OLLAMA_HOST=http://10.0.2.2:11434   # only if using Windows Ollama
   export AIRE_OLLAMA_ALLOW_REMOTE=1               # explicit opt-in; omit to stay loopback-only
   export AIRE_OLLAMA_MODEL=llama3.2:latest        # a model that exists on that Ollama
   export AIRE_M10_NARRATION=0
   aire-server/.venv/bin/aire gui --database demo_artifacts/m10/m10.sqlite \
     --bind 10.0.2.15 --allow-non-loopback-bind --port 8767 --public-port 8767 --no-browser
   ```

   - Copy the printed `Host-side URL … ?token=…` into the `aire` Firefox profile on Windows.
   - The bind is NAT-only, so the VM's own browser cannot use it. For in-VM use, launch without `--bind`/`--allow-non-loopback-bind`.
   - Verify in the VM that `ss -ltn | grep 8767` shows `10.0.2.15:8767`, never `0.0.0.0:8767`.

## Conditions for "SAFE WITH CONDITIONS"

1. Windows checklist items 1–3 pass: forward on host `127.0.0.1` only, `netstat` shows no `0.0.0.0:8767`, firewall prompts declined.
2. You open the GUI only in the dedicated `aire` Firefox profile, through the tokenized URL.
3. If you use Windows Ollama: it listens on `127.0.0.1:11434` only (item 5), and you accept the localhost-reachable trade-off.
4. Keep `AIRE_M10_NARRATION=0`. Treat model text as interpretation.
5. Run `pip-audit` once on the listed versions from a networked machine.
