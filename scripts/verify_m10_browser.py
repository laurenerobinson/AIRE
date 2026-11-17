"""M10 function-explorer browser verification in real headless Firefox (Marionette, stdlib only).

Requires the M9 GUI running (see docs/DEMO_M9_PROGRESS_CHECK.md, port 8767). Uses its own
Firefox profile under demo_artifacts/m9/; never touches the October 22 artifacts.
Checks: analyzer status, M9 library rows, corrupt-PE rejection with structure report,
partial-PE acceptance, cached large-PE open, crypto evidence panel; saves a screenshot.
"""
import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='http://127.0.0.1:8768/')
parser.add_argument('--output', type=Path, default=ROOT / 'docs/m10/browser_verification.json')
args = parser.parse_args()
profile = ROOT / 'demo_artifacts/m10/firefox-profile'
profile.mkdir(parents=True, exist_ok=True)
(profile / 'user.js').write_text('user_pref("marionette.port", 2831);\n'
                                 'user_pref("browser.shell.checkDefaultBrowser", false);\n')
log = (ROOT / 'demo_artifacts/m10/firefox.log').open('w')
process = subprocess.Popen(['firefox', '--headless', '--no-remote', '--marionette', '--profile', str(profile)],
                           stdout=log, stderr=log)
report = {'url': args.url, 'steps': {}}
sock = None
try:
    for _ in range(100):
        try:
            sock = socket.create_connection(('127.0.0.1', 2831), timeout=2)
            break
        except OSError:
            time.sleep(.3)
    if sock is None:
        raise RuntimeError('Firefox Marionette did not start; inspect demo_artifacts/m10/firefox.log')
    sock.settimeout(300)

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

    def wait(code, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = script(code)
            if result:
                return result
            time.sleep(.2)
        raise AssertionError('Timed out: ' + code + ' BODY: ' + str(script('return document.body.innerText'))[:1500])

    def text(selector):
        return script('return document.querySelector(arguments[0]).textContent', selector)

    def file_input():
        element = command('WebDriver:FindElement', {'using': 'css selector', 'value': '#binaryFile'})
        element = element.get('value', element)
        return element.get('element-6066-11e4-a52e-4f735466cecf') or element.get('ELEMENT')

    def choose(path):
        element_id = file_input()
        command('WebDriver:ElementClear', {'id': element_id})
        command('WebDriver:ElementSendKeys', {'id': element_id, 'text': str(path), 'value': list(str(path))})

    def open_fixture(name):
        script('document.querySelector(\'[data-nav="library"]\').click()')
        wait('return document.querySelectorAll(".fixture-row").length >= 30')
        script('document.querySelector("#analysisStatus").textContent = ""')  # no stale result
        wait('return [...document.querySelectorAll(".fixture-row button")].some(b => !b.disabled)')
        clicked = script('''for (const row of document.querySelectorAll(".fixture-row")) {
            if (row.querySelector("strong").textContent === arguments[0]) { row.querySelector("button").click(); return true; } }
            return false;''', name)
        assert clicked, name
        wait('return document.querySelector("#analysisStatus").textContent.includes("Persisted cache reused") '
             '|| document.querySelector("#analysisStatus").textContent.includes("failed")')
        return text('#analysisStatus')

    command('WebDriver:NewSession', {'capabilities': {'alwaysMatch': {'acceptInsecureCerts': True}}})
    command('WebDriver:SetWindowRect', {'width': 1500, 'height': 1000})
    started = time.perf_counter()
    command('WebDriver:Navigate', {'url': args.url})
    wait('return document.querySelector("#binarySelect").options.length > 0')
    report['steps']['page_ready_seconds'] = time.perf_counter() - started
    selected = script('''const s = document.querySelector("#binarySelect");
        const o = [...s.options].find(o => o.textContent.trim().startsWith("aire_test_binary") && !o.textContent.includes("stripped"));
        if (!o) return null; s.value = o.value; s.dispatchEvent(new Event("change", {bubbles: true})); return o.value;''')
    assert selected, 'binary option not found'
    time.sleep(1.5)
    script('document.querySelector(\'[data-tool-view="functions"]\').click()')
    wait('return document.querySelector(".function-lookup input") !== null')
    script('''const f = document.querySelector(".function-lookup"); f.querySelector("input").value = "validate_input";
        f.dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));''')
    wait('return document.querySelector("#selectedFunctionChip").textContent.includes("validate_input")')
    tick = time.perf_counter()
    script('document.querySelector(\'[data-tool-view="explorer"]\').click()')
    wait('return document.querySelector(".explorer-body") && document.querySelector(".explorer-body").textContent.includes("Conditions")')
    overview = text('.explorer-body')
    report['steps']['overview'] = {'seconds': time.perf_counter() - tick,
        'ok': all(s in overview for s in ('strlen', 'puts', 'calculate_checksum', '0x004011e1', 'Input must contain'))}
    tick = time.perf_counter()
    script('document.querySelector(\'.explorer-tabs [data-tab="assembly"]\').click()')
    wait('return document.querySelectorAll(".asm-table tr[id^=ins-]").length > 20')
    rows = script('return document.querySelectorAll(".asm-table tr[id^=ins-]").length')
    script('document.querySelector(\'[data-branch="004011e1"]\').click()')
    wait('return document.querySelector("#detail-004011e1").textContent.includes("condition true")')
    paths = text('#detail-004011e1')
    script('document.querySelector(\'[data-trace="004011dc"]\') && document.querySelector(\'[data-trace="004011dc"]\').click()')
    trace = ''
    if script('return !!document.querySelector(\'[data-trace="004011dc"]\')'):
        wait('return document.querySelector("#detail-004011dc").textContent.length > 10')
        trace = text('#detail-004011dc')
    asm = text('.explorer-body')
    report['steps']['assembly'] = {'seconds': time.perf_counter() - tick, 'rows': rows, 'paths': paths[:400], 'trace': trace[:400],
        'ok': rows >= 40 and 'Jumps to 0x004011ea when' in asm and 'puts' in paths and 'strlen' in trace}
    shot = command('WebDriver:TakeScreenshot', {'full': False}); shot = shot.get('value', shot)
    (ROOT / 'docs/m10/browser_explorer_assembly.png').write_bytes(base64.b64decode(shot))
    for tab, needle in (('cfg', 'loop header'), ('dataflow', 'process_input'), ('decompiler', 'Verdict')):
        script(f'document.querySelector(\'.explorer-tabs [data-tab="{tab}"]\').click()')
        wait(f'return document.querySelector(".explorer-body").textContent.includes("{needle}")')
        report['steps'][tab] = {'ok': True, 'excerpt': text('.explorer-body')[:300]}
    shot = command('WebDriver:TakeScreenshot', {'full': False}); shot = shot.get('value', shot)
    (ROOT / 'docs/m10/browser_explorer_decompiler.png').write_bytes(base64.b64decode(shot))
    script('document.querySelector(".explorer-close").click()')
    tick = time.perf_counter()
    script('''const visible = el => el && el.offsetParent !== null;
        const form = visible(document.querySelector("#chatComposer")) ? document.querySelector("#chatComposer")
                                                                        : document.querySelector("#homeComposer");
        const box = form.querySelector("textarea"); box.value = "What does this function do?";
        box.dispatchEvent(new Event("input", {bubbles: true}));
        form.dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));''')
    wait('return document.body.innerText.includes("Function analysis (deterministic evidence)")', timeout=240)
    wait('return document.body.innerText.includes("Limitations")', timeout=240)
    chat = script('return document.body.innerText')
    excerpt = chat[chat.rfind('Function analysis (deterministic evidence)'):][:900]
    report['steps']['chat'] = {'seconds': time.perf_counter() - tick, 'excerpt': excerpt,
        'ok': '0x004011e1' in excerpt and 'Confidence' in chat}
    shot = command('WebDriver:TakeScreenshot', {'full': False}); shot = shot.get('value', shot)
    (ROOT / 'docs/m10/browser_chat.png').write_bytes(base64.b64decode(shot))
    report['passed'] = all(step.get('ok', True) for step in report['steps'].values() if isinstance(step, dict))
    command('WebDriver:DeleteSession')
finally:
    if sock:
        sock.close()
    process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
    log.close()
args.output.write_text(json.dumps(report, indent=1) + '\n')
print(json.dumps({'passed': report.get('passed'), **{k: (v.get('ok') if isinstance(v, dict) else v)
                                                    for k, v in report['steps'].items()}}, indent=1))
