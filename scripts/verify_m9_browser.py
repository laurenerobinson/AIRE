"""M9 progress-check browser verification in real headless Firefox (Marionette, stdlib only).

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
parser.add_argument('--url', default='http://127.0.0.1:8767/')
parser.add_argument('--output', type=Path, default=ROOT / 'docs/m9/browser_verification.json')
args = parser.parse_args()
profile = ROOT / 'demo_artifacts/m9/firefox-profile'
profile.mkdir(parents=True, exist_ok=True)
(profile / 'user.js').write_text('user_pref("marionette.port", 2830);\n'
                                 'user_pref("browser.shell.checkDefaultBrowser", false);\n')
log = (ROOT / 'demo_artifacts/m9/firefox.log').open('w')
process = subprocess.Popen(['firefox', '--headless', '--no-remote', '--marionette', '--profile', str(profile)],
                           stdout=log, stderr=log)
report = {'url': args.url, 'steps': {}}
sock = None
try:
    for _ in range(100):
        try:
            sock = socket.create_connection(('127.0.0.1', 2830), timeout=2)
            break
        except OSError:
            time.sleep(.3)
    if sock is None:
        raise RuntimeError('Firefox Marionette did not start; inspect demo_artifacts/m9/firefox.log')
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
    command('WebDriver:SetWindowRect', {'width': 1440, 'height': 1000})
    started = time.perf_counter()
    command('WebDriver:Navigate', {'url': args.url})
    wait('return document.querySelector("#binarySelect").options.length > 0')
    report['steps']['page_ready_seconds'] = time.perf_counter() - started
    script('document.querySelector(\'[data-nav="library"]\').click()')
    wait('return document.querySelectorAll(".fixture-row").length >= 30')
    library = text('#fixtureList')
    report['steps']['library'] = {'rows': script('return document.querySelectorAll(".fixture-row").length'),
                                  'analyzer_note': next((l for l in library.splitlines() if 'Analyzer' in l), None),
                                  'has_m9_rows': all(s in library for s in ('large_pe_sleigh', 'crypto_aes_gcm',
                                                                             'corrupt_pe_signature_invalid'))}
    choose(ROOT / 'tests/fixtures/m9/corrupt_pe/pe_signature_invalid.exe')
    wait('return document.querySelector("#uploadDetails").textContent.includes("Validation failed")')
    rejected = text('#uploadDetails')
    report['steps']['corrupt_rejected'] = {'text': rejected,
                                           'ok': 'Invalid PE signature' in rejected and 'No analysis possible' in rejected}
    choose(ROOT / 'tests/fixtures/m9/corrupt_pe/import_dll_name_invalid.exe')
    wait('return document.querySelector("#uploadDetails").textContent.includes("SHA-256")')
    partial = text('#uploadDetails')
    report['steps']['partial_accepted'] = {'text': partial, 'ok': 'Partial analysis only' in partial
                                           and 'import_dll_name' in partial}
    tick = time.perf_counter()
    status = open_fixture('large_pe_sleigh')
    report['steps']['large_pe_cached'] = {'text': status, 'ok': 'Persisted cache reused' in status,
                                          'browser_seconds': time.perf_counter() - tick}
    status = open_fixture('crypto_aes_gcm')
    script('document.querySelector(\'[data-tool-view="crypto"]\').click()')
    wait('return document.body.innerText.includes("function(s) with crypto API calls")')
    body = script('return document.body.innerText')
    report['steps']['crypto_panel'] = {'ok': all(s in body for s in ('0041d160', 'BCryptEncrypt', 'encryption',
                                                                    '0041d1e0', 'BCryptDecrypt', 'ChainingModeGCM')),
                                       'excerpt': body[body.find('function(s) with crypto'):][:800]}
    shot = command('WebDriver:TakeScreenshot', {'full': False})
    shot = shot.get('value', shot)
    (ROOT / 'docs/m9/browser_m9.png').write_bytes(base64.b64decode(shot))
    report['passed'] = all(step.get('ok', True) for step in report['steps'].values() if isinstance(step, dict)) \
        and report['steps']['library']['has_m9_rows']
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
