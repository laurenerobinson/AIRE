"""Real Firefox smoke test via its built-in Marionette protocol, stdlib only."""
import base64
import argparse
import json
from pathlib import Path
import socket
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url',default='http://127.0.0.1:8765/')
args=parser.parse_args()
profile=ROOT/'demo_artifacts/oct22/firefox-profile'
profile.mkdir(parents=True,exist_ok=True)
(profile/'user.js').write_text('user_pref("marionette.port", 2829);\nuser_pref("browser.shell.checkDefaultBrowser", false);\n')
log=(ROOT/'demo_artifacts/oct22/firefox.log').open('w')
process=subprocess.Popen(['firefox','--headless','--no-remote','--marionette','--profile',str(profile)],stdout=log,stderr=log)
sock=None
try:
    for _ in range(100):
        try:
            sock=socket.create_connection(('127.0.0.1',2829),timeout=2)
            break
        except OSError:
            time.sleep(.3)
    if sock is None:
        raise RuntimeError('Firefox Marionette did not start; inspect firefox.log')
    sock.settimeout(240)
    def receive():
        prefix=b''
        while not prefix.endswith(b':'):
            prefix+=sock.recv(1)
        remaining=int(prefix[:-1])
        data=b''
        while len(data)<remaining:
            data+=sock.recv(remaining-len(data))
        return json.loads(data)
    print('GREETING',receive(),flush=True)
    counter=0
    def command(name,parameters=None):
        global counter
        counter+=1
        data=json.dumps([0,counter,name,parameters or {}]).encode()
        sock.sendall(str(len(data)).encode()+b':'+data)
        result=receive()
        if result[2]:
            raise RuntimeError(result[2])
        return result[3]
    def script(code,*args):
        result=command('WebDriver:ExecuteScript',{'script':code,'args':list(args),'newSandbox':False,'sandbox':None})
        return result.get('value') if isinstance(result,dict) and 'value' in result else result
    def wait(code,timeout=120):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            result=script(code)
            if result:
                return result
            time.sleep(.2)
        raise AssertionError('Timed out: '+code+' BODY: '+str(script('return document.body.innerText')))
    def click(selector):
        return script('document.querySelector(arguments[0]).click()',selector)
    print('SESSION',command('WebDriver:NewSession',{'capabilities':{'alwaysMatch':{'acceptInsecureCerts':True}}}),flush=True)
    command('WebDriver:SetWindowRect',{'width':1440,'height':1000})
    command('WebDriver:Navigate',{'url':args.url})
    wait('return document.querySelector("#binarySelect").options.length > 0')
    click('[data-nav="library"]')
    wait('return document.querySelectorAll(".fixture-row").length >= 13')
    print('LIBRARY',script('return document.querySelector("#fixtureList").innerText'),flush=True)
    element=command('WebDriver:FindElement',{'using':'css selector','value':'#binaryFile'})
    element=element.get('value',element)
    element_id=element.get('element-6066-11e4-a52e-4f735466cecf') or element.get('ELEMENT')
    # First demonstrate invalid-file rejection in the real frontend.
    invalid=ROOT/'demo_artifacts/oct22/invalid.exe'
    invalid.write_text('This is intentionally not an executable.\n')
    command('WebDriver:ElementSendKeys',{'id':element_id,'text':str(invalid),'value':list(str(invalid))})
    wait('return document.querySelector("#uploadDetails").textContent.includes("Validation failed")')
    print('INVALID',script('return document.querySelector("#uploadDetails").textContent'),flush=True)
    command('WebDriver:ElementClear',{'id':element_id})
    binary=ROOT/'tests/fixtures/external/angr/brancher/brancher'
    command('WebDriver:ElementSendKeys',{'id':element_id,'text':str(binary),'value':list(str(binary))})
    wait('return !document.querySelector("#analyzeUpload").disabled')
    print('VALIDATED',script('return document.querySelector("#uploadDetails").textContent'),flush=True)
    click('#analyzeUpload')
    wait('return !document.querySelector("#chatView").classList.contains("hidden") && !document.querySelector("#toolResult").classList.contains("hidden")',240)
    print('FIRST',script('return document.querySelector("#analysisStatus").textContent'),flush=True)
    click('[data-nav="library"]')
    click('#analyzeUpload')
    wait('return !document.querySelector("#chatView").classList.contains("hidden") && document.querySelector("#analysisStatus").textContent.includes("Persisted cache reused")')
    print('CACHE',script('return document.querySelector("#analysisStatus").textContent'),flush=True)
    click('[data-nav="library"]')
    wait('return !document.querySelector(".fixture-row button").disabled')
    script('const row=[...document.querySelectorAll(".fixture-row")].find(r=>r.innerText.includes("FunctionOverloading.exe")); row.querySelector("button").click()')
    wait('return !document.querySelector("#chatView").classList.contains("hidden") && document.querySelector("#binaryStats").textContent.includes("Portable")')
    wait('return !!document.querySelector(".function-lookup input")')
    script('document.querySelector(".function-lookup input").value="00412620"; document.querySelector(".function-lookup").requestSubmit()')
    wait('return document.querySelector("#selectedFunctionChip").textContent.includes("00412620")')
    click('[data-tool-view="assembly"]')
    wait('return document.querySelector("#toolResult").innerText.includes("IMUL")')
    print('ASSEMBLY',script('return document.querySelector("#toolResult").innerText'),flush=True)
    click('[data-tool-view="crosscheck"]')
    wait('return document.querySelector("#toolResult").innerText.includes("Integer multiplication")')
    print('INTEGER CHECK',script('return document.querySelector("#toolResult").innerText'),flush=True)
    click('[data-tool-view="functions"]')
    wait('return !!document.querySelector(".function-lookup input")')
    script('document.querySelector(".function-lookup input").value="004126c0"; document.querySelector(".function-lookup").requestSubmit()')
    wait('return document.querySelector("#selectedFunctionChip").textContent.includes("004126c0")')
    click('[data-tool-view="crosscheck"]')
    wait('return document.querySelector("#toolResult").innerText.includes("double-precision")')
    print('DOUBLE CHECK',script('return document.querySelector("#toolResult").innerText'),flush=True)
    screenshot=command('WebDriver:TakeScreenshot',{'id':None,'full':True,'scroll':False})
    if isinstance(screenshot,dict): screenshot=screenshot['value']
    (ROOT/'docs/DEMO_2026-10-22_browser.png').write_bytes(base64.b64decode(screenshot))
    print('BROWSER PASS',flush=True)
    command('Marionette:Quit',{'flags':['eForceQuit']})
finally:
    if sock: sock.close()
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill()
    log.close()
