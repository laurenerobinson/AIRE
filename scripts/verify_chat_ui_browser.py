#!/usr/bin/env python3
"""Real-Firefox verification of verified chat answers (GUI/UX Phases 1-2).

Starts its own in-process A.I.R.E. server on a free loopback port (never the
user's GUI on 8767, no analyzer JVM) with a model client that fails if called,
drives headless Firefox over Marionette (stdlib only, as verify_m10_browser.py),
types questions into the real composer, and checks the rendered answer: the
verified badge, the role table, no long identifiers or tool dumps in the visible
answer, and expandable evidence / limitations / tool-output sections. Times are
measured in the page, from form submit to the rendered answer. Screenshots and a
JSON report are written to --output-dir.

    scripts/verify_chat_ui_browser.py demo_artifacts/m9/m9.sqlite docs/chatperf/guiux_phase2_2026-11-12
"""
import argparse
import base64
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
from aire.api.server import GuiApplication, create_server  # noqa: E402

CASES = [
    ('aes_gcm.exe', 'Which functions perform encryption and decryption?',
     ['Encryption', 'FUN_0041d160', 'BCryptEncrypt', 'Decryption', 'FUN_0041d1e0', 'BCryptDecrypt']),
    ('ecdsa_sign.exe', 'Which functions sign and verify a digital signature?',
     ['Signature creation', 'FUN_0041d1b0', 'BCryptSignHash', 'Signature verification', 'FUN_0041d1f0']),
    ('import_dll_name_invalid.exe', 'What is this file?',
     ['structure damaged (partial analysis)', 'import_dll_name', 'No program purpose is stated']),
]


class NoModel:
    model, num_ctx, calls = 'none', 4096, 0

    def generate(self, *args, **kwargs):
        NoModel.calls += 1
        raise RuntimeError('model call on a verified path')


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('database')
    parser.add_argument('output_dir', type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='aire-ui-verify-'))
    app = GuiApplication(args.database, session_dir=work / 's', upload_dir=work / 'u', client_factory=NoModel)
    server = create_server(app, '127.0.0.1', 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = 'http://127.0.0.1:%d/' % server.server_address[1]
    binaries = {b['program_name']: b['binary_id'] for b in app.list_binaries()}
    marionette = free_port()
    # Snap Firefox has a private /tmp and cannot read hidden home dirs; its own data dir is always
    # readable and lies outside the repository. The throwaway profile is deleted afterwards.
    snap_common = Path.home() / 'snap/firefox/common'
    profile_root = Path(tempfile.mkdtemp(prefix='aire-ui-verify-', dir=snap_common if snap_common.is_dir() else None))
    profile = profile_root / 'firefox-profile'
    profile.mkdir()
    (profile / 'user.js').write_text(f'user_pref("marionette.port", {marionette});\n'
                                     'user_pref("browser.shell.checkDefaultBrowser", false);\n')
    log = (profile_root / 'firefox.log').open('w')
    process = subprocess.Popen(['firefox', '--headless', '--no-remote', '--marionette', '--profile', str(profile)],
                               stdout=log, stderr=log)
    report = {'url': url, 'cases': [], 'model_calls': 0}
    sock = None
    try:
        for _ in range(150):
            try:
                sock = socket.create_connection(('127.0.0.1', marionette), timeout=2)
                break
            except OSError:
                time.sleep(.3)
        if sock is None:
            log.flush()
            raise RuntimeError('Firefox Marionette did not start; log tail:\n' +
                               (profile_root / 'firefox.log').read_text(errors='replace')[-1500:])
        sock.settimeout(120)

        def receive():
            prefix = b''
            while not prefix.endswith(b':'):
                prefix += sock.recv(1)
            remaining, data = int(prefix[:-1]), b''
            while len(data) < remaining:
                data += sock.recv(remaining - len(data))
            return json.loads(data)

        receive()
        counter = [0]

        def command(name, parameters=None):
            counter[0] += 1
            data = json.dumps([0, counter[0], name, parameters or {}]).encode()
            sock.sendall(str(len(data)).encode() + b':' + data)
            result = receive()
            if result[2]:
                raise RuntimeError(result[2])
            return result[3]

        def script(code, *values):
            result = command('WebDriver:ExecuteScript', {'script': code, 'args': list(values),
                                                         'newSandbox': False, 'sandbox': None})
            return result.get('value') if isinstance(result, dict) and 'value' in result else result

        def wait(code, timeout=60):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = script(code)
                if value:
                    return value
                time.sleep(.05)
            raise AssertionError('Timed out: ' + code + ' BODY: ' + str(script('return document.body.innerText'))[:1200])

        command('WebDriver:NewSession', {'capabilities': {}})
        command('WebDriver:SetWindowRect', {'width': 1400, 'height': 1000})
        command('WebDriver:Navigate', {'url': url})
        wait('return document.querySelector("#binarySelect") && document.querySelector("#binarySelect").options.length > 0')
        for index, (program, question, needles) in enumerate(CASES):
            binary_id = binaries[program]
            script('''const s = document.querySelector("#binarySelect"); s.value = arguments[0];
                      s.dispatchEvent(new Event("change"));''', binary_id)
            wait('return !document.querySelector("#binarySelect").disabled && '
                 'document.querySelector("#binarySelect").value === arguments[0] && '
                 '!document.body.classList.contains("loading")'.replace('arguments[0]', json.dumps(binary_id)))
            time.sleep(0.5)  # let the switch's bootstrap request settle
            before = script('return document.querySelectorAll(".message-row.assistant").length')
            on_home = script('return !!document.querySelector("#homeComposer") && '
                             'document.querySelector("#homeComposer").offsetParent !== null')
            form, field = ('#homeComposer', '#homeInput') if on_home else ('#chatComposer', '#chatInput')
            script('''window.__aireT0 = performance.now(); window.__aireFirst = null; window.__aireDone = null;
                const before = arguments[2];
                const observer = new MutationObserver(() => {
                  const rows = document.querySelectorAll(".message-row.assistant");
                  if (rows.length <= before) return;
                  const shell = rows[rows.length - 1];
                  if (window.__aireFirst === null && shell.querySelector(".activity-text, .answer-body *"))
                    window.__aireFirst = performance.now() - window.__aireT0;
                  if (window.__aireDone === null && shell.querySelector(".answer-badge"))
                    { window.__aireDone = performance.now() - window.__aireT0; observer.disconnect(); }
                });
                observer.observe(document.body, {subtree: true, childList: true, characterData: true});
                document.querySelector(arguments[1]).value = arguments[3];
                document.querySelector(arguments[0]).requestSubmit();''', form, field, before, question)
            done = wait('return window.__aireDone')
            first = script('return window.__aireFirst')
            checks = script('''const rows = document.querySelectorAll(".message-row.assistant");
                const shell = rows[rows.length - 1]; const body = shell.querySelector(".answer-body");
                const visible = [...body.children].filter(e => e.tagName !== "DETAILS").map(e => e.innerText).join("\\n");
                return {badge: (body.querySelector(".answer-badge") || {}).textContent || "",
                        table_rows: body.querySelectorAll("table.fact-table tbody tr").length,
                        sections: [...body.querySelectorAll("details.analysis-details > summary")].map(s => s.textContent),
                        visible_text: visible, visible_chars: visible.length,
                        long_ids_visible: /[0-9a-f]{40,}/.test(visible), tool_dump_visible: visible.includes("Retrieved tool facts"),
                        raw_asterisks: /\\*\\*/.test(visible)};''')
            missing = [n for n in needles if n not in checks['visible_text']]
            problems = missing and [f'missing: {missing}'] or []
            if 'Verified stored facts' not in checks['badge']:
                problems.append('verified badge missing')
            if checks['long_ids_visible'] or checks['tool_dump_visible'] or checks['raw_asterisks']:
                problems.append('noise in visible answer')
            if not any(s.startswith('Evidence') for s in checks['sections']) and program != 'import_dll_name_invalid.exe':
                problems.append('evidence section missing')
            shot = command('WebDriver:TakeScreenshot', {'full': False})
            shot = shot.get('value', shot)
            image = args.output_dir / f'browser_answer_{index + 1}.png'
            image.write_bytes(base64.b64decode(shot))
            case = {'program': program, 'question': question, 'first_visible_ms': round(first or 0, 1),
                    'answer_rendered_ms': round(done, 1), 'table_rows': checks['table_rows'],
                    'sections': checks['sections'], 'visible_chars': checks['visible_chars'],
                    'badge': checks['badge'], 'problems': problems, 'screenshot': image.name}
            report['cases'].append(case)
            print(json.dumps(case), flush=True)
        report['model_calls'] = NoModel.calls
        report['passed'] = all(not c['problems'] for c in report['cases']) and NoModel.calls == 0
    finally:
        try:
            if sock:
                command('WebDriver:DeleteSession')
        except Exception:
            pass
        process.terminate()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
        server.shutdown()
        server.server_close()
        app.library.close()
        log.close()
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(profile_root, ignore_errors=True)
    (args.output_dir / 'browser_verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASSED' if report.get('passed') else 'FAILED')
    return 0 if report.get('passed') else 1


if __name__ == '__main__':
    sys.exit(main())
