#!/usr/bin/env python3
"""Rehearse the existing GUI twice in isolated headless Firefox; no target execution.

Uses two production CLI launches on a spare private guest port and a transparent
guest-loopback TCP relay. This exercises the NAT-style HTTP path, not Windows NAT
or Chrome. Tokens stay in memory; reports and screenshots never contain launch URLs.
Requires existing Firefox and a prepared store. Writes only under the ignored M10
artifact tree, with separate sessions/profile. Does not touch the user's port 8770.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import re
import select
import signal
import socket
import socketserver
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean(text):
    return re.sub(r'([?&]token=)[^\s"<>]+', r'\1<redacted>', str(text)).replace(str(ROOT), '<repo>').replace(str(Path.home()), '~')


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Forward(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(self.server.destination, timeout=10) as upstream:
            pair = [self.request, upstream]
            while True:
                ready, _, _ = select.select(pair, [], [], 30)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.request else self.request).sendall(data)


class Browser:
    def __init__(self, profile, log):
        profile.mkdir(mode=0o700, parents=True, exist_ok=True)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        (profile / 'user.js').write_text(
            f'user_pref("marionette.port", {port});\n'
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("browser.startup.homepage", "about:blank");\n'
            'user_pref("network.captive-portal-service.enabled", false);\n'
            'user_pref("network.connectivity-service.enabled", false);\n')
        self.log = log.open('w')
        self.process = subprocess.Popen(['firefox', '--headless', '--no-remote', '--marionette', '--profile', str(profile)],
                                        stdout=self.log, stderr=self.log)
        self.socket = None
        self.counter = 0
        for _ in range(160):
            try:
                self.socket = socket.create_connection(('127.0.0.1', port), timeout=2)
                break
            except OSError:
                if self.process.poll() is not None:
                    raise RuntimeError('Isolated Firefox exited before Marionette started')
                time.sleep(.25)
        if self.socket is None:
            raise RuntimeError('Firefox Marionette unavailable')
        self.socket.settimeout(65)
        self.receive()
        self.command('WebDriver:NewSession', {'capabilities': {}})
        self.command('WebDriver:SetWindowRect', {'width': 1500, 'height': 1050})
        self.command('WebDriver:SetTimeouts', {'script': 60000, 'pageLoad': 60000})

    def receive(self):
        prefix = b''
        while not prefix.endswith(b':'):
            chunk = self.socket.recv(1)
            if not chunk:
                raise RuntimeError('Browser connection closed')
            prefix += chunk
        remaining, raw = int(prefix[:-1]), b''
        while len(raw) < remaining:
            raw += self.socket.recv(remaining - len(raw))
        return json.loads(raw)

    def command(self, name, parameters=None):
        self.counter += 1
        raw = json.dumps([0, self.counter, name, parameters or {}]).encode()
        self.socket.sendall(str(len(raw)).encode() + b':' + raw)
        result = self.receive()
        if result[2]:
            raise RuntimeError(clean(result[2].get('message', 'Browser command failed')))
        return result[3]

    def script(self, code):
        result = self.command('WebDriver:ExecuteScript', {'script': code, 'args': [], 'newSandbox': False, 'sandbox': None})
        return result.get('value') if isinstance(result, dict) and 'value' in result else result

    def wait(self, condition, seconds=30):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            value = self.script('return !!(' + condition + ')')
            if value:
                return
            time.sleep(.05)
        raise AssertionError('UI did not reach expected state: ' + condition)

    def action(self, action, condition, expect_api=True):
        # Measure in the browser, ending two animation frames after the UI condition.
        code = '''const done = arguments[arguments.length - 1];
        const started = performance.now();
        const timer = setInterval(() => {
          try {
            if ((CONDITION) && (API_READY)) {
              clearInterval(timer);
              requestAnimationFrame(() => requestAnimationFrame(() => {
                const ended = performance.now();
                const requests = performance.getEntriesByType('resource').filter(e =>
                  e.startTime >= started && new URL(e.name).pathname.startsWith('/api/'));
                done({end_to_end_ms: ended-started, api: requests.map(e => ({
                  path: new URL(e.name).pathname.replace(/[0-9a-f]{32,}/g, '<id>'),
                  duration_ms:e.duration, response_end_ms:e.responseEnd-started})),
                  ui_after_last_response_ms: requests.length ? ended-Math.max(...requests.map(e=>e.responseEnd)) : null,
                  browser_render_ms:null});
              }));
            } else if (performance.now()-started > 45000) {
              clearInterval(timer); done({error:'UI condition timeout'});
            }
          } catch(e) {clearInterval(timer);done({error:String(e)});}
        }, 10);
        try { ACTION } catch(e) {clearInterval(timer);done({error:String(e)});}
        '''.replace('CONDITION', condition).replace('ACTION', action).replace('API_READY',
            "performance.getEntriesByType('resource').some(e=>e.startTime>=started && new URL(e.name).pathname.startsWith('/api/'))" if expect_api else 'true')
        result = self.command('WebDriver:ExecuteAsyncScript', {'script': code, 'args': [], 'newSandbox': False, 'sandbox': None})
        result = result.get('value', result)
        if result.get('error'):
            raise AssertionError(clean(result['error']))
        return result

    def screenshot(self, path):
        assert self.script('return location.search') == '', 'Refusing token-bearing screenshot'
        self.script(r'''window.__defenseRedacted=[];
          const walk=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
          let node;while(node=walk.nextNode()) {
            const value=node.nodeValue;
            const safe=value.replace(/\/home\/[^/\s"']+\/aire/g,'<repo>')
              .replace(/\/home\/[^/\s"']+/g,'~').replace(/\/tmp\/[^\s"']+/g,'<temporary>');
            if(safe!==value){window.__defenseRedacted.push([node,value]);node.nodeValue=safe;}
          }''')
        text = self.script('return document.body.innerText')
        if re.search(r'/home/|/tmp/|[?&]token=|X-AIRE-Token:', text):
            raise AssertionError('Refusing screenshot with private path or authentication material')
        image = self.command('WebDriver:TakeScreenshot', {'full': False})
        path.write_bytes(base64.b64decode(image.get('value', image)))
        self.script('window.__defenseRedacted.forEach(([node,value])=>node.nodeValue=value);window.__defenseRedacted=[];')

    def close(self):
        if self.socket:
            self.socket.close()
        self.process.terminate()
        try:
            self.process.wait(15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--guest', default='10.0.2.15')
    parser.add_argument('--port', type=int, default=18770)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT / 'demo_artifacts/m10'), 'Output must be ignored M10 artifacts'
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    prior_report = output / 'browser-report.json'
    if prior_report.exists():
        (output / f'browser-report-prior-{time.time_ns()}.json').write_bytes(prior_report.read_bytes())
    database = args.database.resolve()
    before = digest(database)
    report = {'browser': 'Firefox 155.0.1 headless, Ubuntu; not Windows Chrome',
              'path': 'Guest-loopback relay to private guest bind; not Windows NAT verification',
              'launches': [], 'screenshots': [], 'database_sha256_before': before}
    relay = Relay(('127.0.0.1', args.port), Forward)
    relay.destination = (args.guest, args.port)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    previous_token = None
    browser = None
    process = None
    samples = []
    step_name = 'startup'
    try:
        browser = Browser(output / 'firefox-profile-defense', output / 'firefox.log')
        for launch in (1, 2):
            current = {'launch': launch, 'steps': []}
            report['launches'].append(current)
            started = time.monotonic()
            env = dict(os.environ, AIRE_M10_NARRATION='0', AIRE_OLLAMA_HOST='http://10.0.2.2:11434',
                       AIRE_OLLAMA_ALLOW_REMOTE='1', AIRE_OLLAMA_MODEL='qwen2.5-coder:1.5b', AIRE_OLLAMA_NUM_CTX='4096')
            process = subprocess.Popen([str(ROOT / 'aire-server/.venv/bin/aire'), 'gui', '--database', str(database),
                '--session-dir', str(output / 'sessions'), '--upload-dir', str(output / 'uploads'),
                '--bind', args.guest, '--allow-non-loopback-bind', '--port', str(args.port),
                '--public-port', str(args.port), '--no-browser', '--no-prewarm'], cwd=ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            token = None
            lines = queue.Queue()
            def read_launch_output():
                for line in process.stdout:
                    lines.put(line)
            threading.Thread(target=read_launch_output, daemon=True).start()
            until = time.monotonic() + 30
            while time.monotonic() < until:
                try:
                    line = lines.get(timeout=.2)
                    match = re.search(r'\?token=([A-Za-z0-9_-]+)', line)
                    if match:
                        token = match.group(1)
                        break
                except queue.Empty:
                    pass
                if process.poll() is not None:
                    raise RuntimeError('API startup failed: ' + clean(process.stderr.read()))
            if not token:
                raise RuntimeError('API did not provide a launch URL within 30 seconds')
            current['startup_seconds'] = round(time.monotonic() - started, 3)

            def request(path, *, cookie=None, headers=None):
                conn = http.client.HTTPConnection('127.0.0.1', args.port, timeout=10)
                try:
                    conn.request('GET', path, headers={**(headers or {}), **({'Cookie':cookie} if cookie else {})})
                    response = conn.getresponse(); raw = response.read()
                    return response.status, raw
                finally:
                    conn.close()

            assert request('/api/bootstrap')[0] == 401
            assert request('/api/bootstrap', headers={'Host':'evil.example'})[0] == 403
            if previous_token:
                assert previous_token != token
                assert request('/api/bootstrap', cookie=f'aire_token_{args.port}={previous_token}')[0] == 401
                current['old_token_rejected'] = True
            previous_token = token
            step_name = 'A'
            started = time.monotonic()
            browser.command('WebDriver:Navigate', {'url':f'http://127.0.0.1:{args.port}/?token={token}'})
            browser.wait('document.querySelector("#binarySelect")?.options.length >= 7')
            assert browser.script('return document.cookie') == ''
            cookies=browser.command('WebDriver:GetCookies')
            cookies=cookies.get('value',cookies) if isinstance(cookies,dict) else cookies
            auth_cookie=next(c for c in cookies if c['name']==f'aire_token_{args.port}')
            assert auth_cookie['httpOnly'] and auth_cookie['sameSite'].lower()=='strict'
            current['cookie_policy']={'httpOnly':True,'sameSite':'Strict'}
            current['steps'].append({'step':'A','action':'Production CLI startup and token URL login',
                'expected':'Bare API 401; foreign Host 403; login cookie hidden from JavaScript; redirected URL',
                'actual':'All assertions passed','status':'PASS','end_to_end_ms':round((time.monotonic()-started)*1000,2)})

            def step(name, action, condition, expected, shot=None, repeats=1, expect_api=True):
                nonlocal step_name
                step_name = name
                measured = []
                for _ in range(repeats):
                    row = browser.action(action, condition, expect_api)
                    measured.append(row)
                    samples.append({'action':name,'launch':launch,**row})
                current['steps'].append({'step':name,'action':action,'expected':expected,
                    'actual':clean(browser.script('return document.body.innerText')).replace(token,'<redacted>')[-1800:],
                    'status':'PASS','samples':measured})
                if shot and launch == 1:
                    path = output / shot
                    browser.screenshot(path)
                    report['screenshots'].append(shot)

            def click(view):
                return f'''const control=document.querySelector('[data-tool-view="{view}"]');
                  if(!control || control.offsetParent===null) throw Error('Tool control is not visible');
                  control.click();'''

            def choose(name):
                return '''const s=document.querySelector('#binarySelect');
                  const o=[...s.options].find(o=>o.textContent.trim()===NAME);
                  if(!o) throw Error('Required indexed binary missing');
                  s.value=o.value;s.dispatchEvent(new Event('change',{bubbles:true}));'''.replace('NAME',json.dumps(name))

            def lookup(name):
                return '''const f=document.querySelector('.function-lookup');
                  f.querySelector('input').value=NAME;
                  f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));'''.replace('NAME',json.dumps(name))

            step('B-library', 'document.querySelector(\'[data-nav="library"]\').click();',
                 'document.querySelectorAll(".fixture-row").length >= 13', 'Repository library visible', '01-library.png')
            step('B-select', choose('aire_test_binary'),
                 'document.querySelector("#binarySelect").selectedOptions[0].textContent === "aire_test_binary"', 'Indexed unstripped ELF active')
            step('C-functions', 'document.querySelector("#investigateBtn").click();',
                 'document.querySelector(".function-lookup") && !document.querySelector("#chatView").classList.contains("hidden")',
                 'Investigate binary opens the visible function list and exact lookup')
            step('C-select', lookup('validate_input'),
                 'document.querySelector("#selectedFunctionChip").textContent.includes("validate_input")',
                 'validate_input selected at 004011bc')
            step('D-imports', click('imports'), 'document.querySelector(".tool-result-head").textContent.includes("Imports") && document.querySelector("#toolResult").textContent.includes("strlen")',
                 'Stored strlen/puts imports', '02-imports.png', 3)
            step('D-strings', click('strings'), 'document.querySelector(".tool-result-head").textContent.includes("Strings") && document.querySelector("#toolResult").textContent.includes("printable ASCII")',
                 'Known validation string', '03-strings.png', 3)
            step('D-calls', click('callgraph'), 'document.querySelector(".tool-result-head").textContent.includes("Call Graph") && document.querySelector("#toolResult").textContent.includes("process_input")',
                 'process_input caller and strlen/puts/checksum callees', '04-calls.png', 3)
            step('E-decompiled', click('decompiled'), 'document.querySelector(".tool-result-head").textContent.includes("Decompiled") && document.querySelector(".code-view").textContent.includes("strlen")',
                 'Stored validate_input decompilation', '05-decompiled.png', 3)
            step('E-assembly', click('assembly'), 'document.querySelector(".tool-result-head").textContent.toLowerCase().includes("assembly") && document.querySelector("#toolResult").textContent.includes("004011dc")',
                 'Stored addressed assembly', None, 3)
            step('F-overview', click('explorer'), 'document.querySelector(".explorer-body")?.textContent.includes("Conditions")',
                 'Structured function overview and conditions', '06-overview.png')
            step('F-semantics', 'document.querySelector(\'.explorer-tabs [data-tab="assembly"]\').click();',
                 'document.querySelectorAll(".asm-table tr[id^=ins-]").length >= 40', 'Instruction explanations and categories')
            step('F-branch', 'document.querySelector(\'[data-branch="004011e1"]\').click();',
                 'document.querySelector("#detail-004011e1")?.textContent.includes("puts")', 'Cited taken/fallthrough paths')
            step('F-trace', 'document.querySelector(\'[data-trace="004011dc"]\').click();',
                 'document.querySelector("#detail-004011dc")?.textContent.includes("strlen")', 'Frame-slot origin traced to strlen', '07-assembly.png')
            for tab,needle in [('cfg','loop header'),('dataflow','process_input'),('decompiler','CONSISTENT')]:
                step('F-'+tab, f'document.querySelector(\'.explorer-tabs [data-tab="{tab}"]\').click();',
                     f'document.querySelector(".explorer-body").textContent.includes({json.dumps(needle)})',
                     needle+' visible', '08-'+tab+'.png',3,expect_api=False)
            browser.script('document.querySelector(".explorer-close").click();')
            submit = '''window.__defenseExpectedAnswers=document.querySelectorAll('.message-row.assistant').length+1;
              const form=document.querySelector('#chatComposer').offsetParent!==null?
              document.querySelector('#chatComposer'):document.querySelector('#homeComposer');
              const box=form.querySelector('textarea');box.value='What does this function do?';
              box.dispatchEvent(new Event('input',{bubbles:true}));
              form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));'''
            step('H-question', submit, '!document.querySelector("#chatComposer .send-button").disabled && document.querySelector(".message-row.assistant:last-child .analysis-footer")?.textContent.includes("Deterministic evidence (M10)")',
                 'Completed deterministic assembly answer with citations', '09-question.png',3)
            selected_binary = browser.script('return document.querySelector("#binarySelect").value')
            sessions = json.loads(request('/api/sessions?binary_id='+selected_binary,headers={'X-AIRE-Token':token})[1])['sessions']
            original_session = sessions[0]['session_id']
            original_snapshot = json.loads(request('/api/sessions/'+original_session,headers={'X-AIRE-Token':token})[1])
            original_function = original_snapshot['current_function_id']
            step('I-evidence', 'document.querySelectorAll("#messages details").forEach(e=>e.open=true);',
                 'document.querySelector("#messages").textContent.includes("004011e1") && document.querySelector("#messages").textContent.includes("Confidence")',
                 'Inspectable instruction citations, confidence and activity', '10-evidence.png',expect_api=False)
            step('G-binary', choose('unsafe_copy'), 'document.querySelector("#binarySelect").selectedOptions[0].textContent === "unsafe_copy" && document.querySelector("#selectedFunctionChip").classList.contains("hidden")', 'Separate security fixture resets function selection')
            step('G-investigate','document.querySelector("#investigateBtn").click();',
                 '!document.querySelector("#chatView").classList.contains("hidden") && document.querySelector(".tool-result-head").textContent.includes("Functions") && document.querySelector(".function-lookup")', 'Security workspace and function list ready')
            step('G-findings', click('findings'), 'document.querySelector(".tool-result-head").textContent.includes("Findings") && document.querySelector("#toolResult").textContent.includes("SIGNAL") && document.querySelector("#toolResult").textContent.includes("CWE-120")',
                 'Verified strcpy/CWE-120 signal, not confirmed overflow', '11-cwe.png',3)
            step('G-functions', click('functions'), 'document.querySelector(".function-lookup")', 'Security function lookup')
            step('G-select', lookup('copy_input'), 'document.querySelector("#selectedFunctionChip").textContent.includes("copy_input")', 'copy_input selected')
            step('G-callsite', click('callgraph'), 'document.querySelector(".tool-result-head").textContent.includes("Call Graph") && document.querySelector("#toolResult").textContent.includes("strcpy")',
                 'Supporting strcpy callsite and caller', '12-cwe-callsite.png')
            for name in ['safe_copy','aire_test_binary_stripped','aire_test_binary_O2','FunctionOverloading.exe','aire_test_binary']:
                step('J-'+name,choose(name),f'document.querySelector("#binarySelect").selectedOptions[0].textContent === {json.dumps(name)} && document.querySelector("#selectedFunctionChip").classList.contains("hidden")',
                     'Correct binary metadata; selection isolated')
                if name=='safe_copy':
                    step('G-negative-investigate','document.querySelector("#investigateBtn").click();',
                         '!document.querySelector("#chatView").classList.contains("hidden") && document.querySelector(".tool-result-head").textContent.includes("Functions") && document.querySelector(".function-lookup")', 'Negative control workspace and function list ready')
                    step('G-negative',click('findings'),'document.querySelector("#toolResult").textContent.includes("NOT_APPLICABLE") && !document.querySelector("#toolResult").textContent.includes("SIGNAL")',
                         'Bounded-copy negative control does not emit the API signal')
            step('J-recent','document.querySelector(\'[data-nav="recent"]\').click();',
                 'document.querySelector("#recentList .recent-card")', 'Saved conversations visible')
            step('J-restore', 'document.querySelector("#recentList .recent-card").click();',
                 'document.querySelector("#selectedFunctionChip").textContent.includes("validate_input") && document.querySelector("#messages").textContent.includes("Function analysis (deterministic evidence)")',
                 'Original binary, function, transcript and session restored', '13-restored.png')
            assert json.loads(request('/api/sessions/'+original_session,headers={'X-AIRE-Token':token})[1])['current_function_id']==original_function
            browser.command('WebDriver:Refresh')
            browser.wait('document.querySelector("#binarySelect")?.options.length >= 7')
            step('J-reload-select',choose('aire_test_binary'),
                 'document.querySelector("#binarySelect").selectedOptions[0].textContent === "aire_test_binary"', 'Return to original binary after reload',expect_api=False)
            step('J-reload-recent','document.querySelector(\'[data-nav="recent"]\').click();',
                 'document.querySelector("#recentList .recent-card")', 'Saved conversation remains available')
            step('J-reload-recover','document.querySelector("#recentList .recent-card").click();',
                 'document.querySelector("#selectedFunctionChip").textContent.includes("validate_input") && document.querySelector("#messages").textContent.includes("Function analysis (deterministic evidence)")',
                 'Reload and saved-session recovery without reanalysis')
            process.send_signal(signal.SIGINT)
            process.wait(15)
            current['shutdown_exit_code'] = process.returncode
            process = None
            time.sleep(.3)
        report['passed'] = True
    except Exception as exc:
        report['passed'] = False
        report['error'] = {'step':step_name,'message':clean(exc)}
        if browser:
            try:
                report['error']['visible_text'] = clean(browser.script('return document.body.innerText'))[-5000:]
            except Exception:
                pass
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:process.wait(15)
            except subprocess.TimeoutExpired:process.terminate();process.wait(10)
        if browser:
            browser.close()
        relay.shutdown();relay.server_close()
        report['samples'] = samples
        report['database_sha256_after'] = digest(database)
        report['database_unchanged'] = report['database_sha256_after'] == before
        (output/'browser-report.json').write_text(clean(json.dumps(report,indent=2))+'\n')
    print(json.dumps({'passed':report.get('passed'),'launches':len(report['launches']),
                      'screenshots':len(report['screenshots']),'error':report.get('error'),
                      'database_unchanged':report['database_unchanged']}))
    return 0 if report.get('passed') and report['database_unchanged'] else 1


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
