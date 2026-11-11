#!/usr/bin/env python3
"""Static-only HTTP acceptance and timing capture. Never executes target files.

Use a new Python process and a new --database for genuine cold measurements.
Existing databases are preserved; without --database we seed a dedicated demo
store from analysis.sqlite using SQLite backup only on its first creation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aire.api.server import GuiApplication, create_server
from aire.knowledge.database import BinaryKnowledgeStore

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=ROOT/'demo_artifacts/oct22/demo.sqlite')
    parser.add_argument('--output', type=Path, default=ROOT/'docs/DEMO_2026-10-22_verification.json')
    args = parser.parse_args()
    args.database = args.database.resolve()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    if not args.database.exists():
        with sqlite3.connect(f'file:{ROOT / "analysis.sqlite"}?mode=ro', uri=True) as original:
            with sqlite3.connect(args.database) as destination:
                original.backup(destination)
    report = {'database':str(args.database), 'recorded_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
              'jobs':[], 'bootstrap':[], 'evidence':{}, 'errors':[]}
    app = GuiApplication(args.database, session_dir=args.database.parent/'sessions',
                         upload_dir=args.database.parent/'uploads')
    server = create_server(app, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_address[1]}'
    def request(endpoint, payload=None, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        headers = headers or ({'Content-Type':'application/json'} if data is not None else {})
        with urlopen(Request(base+endpoint, data=data, headers=headers), timeout=30) as response:
            return json.load(response)
    def wait(job):
        deadline = time.monotonic()+240
        last = None
        while time.monotonic() < deadline:
            job = request('/api/analysis/'+job['job_id'])
            if job['phase'] != last:
                print(job['filename'], job['phase'], round(job['elapsed_seconds'],3), flush=True)
                last = job['phase']
            if job['status'] in ('failed','completed') and 'total_seconds' in job:
                if job['status'] == 'failed':
                    raise AssertionError(job)
                report['jobs'].append(job)
                return job
            time.sleep(.1)
        raise AssertionError('Analysis exceeded verification time budget')
    def tool(sid, name, **arguments):
        result = request('/api/tool', {'session_id':sid,'tool':name,'arguments':arguments})
        assert result['ok'], result
        return result['data']
    try:
        for binary in app.list_binaries():
            for kind in ('first','repeat'):
                tick=time.perf_counter()
                data=request('/api/bootstrap?binary_id='+binary['binary_id'])
                report['bootstrap'].append({'name':binary['program_name'],'kind':kind,
                    'seconds':time.perf_counter()-tick,'json_bytes':len(json.dumps(data))})
        fixtures = request('/api/library')['fixtures']
        report['fixtures_before'] = fixtures
        assert all(f['available'] for f in fixtures), fixtures
        binary = ROOT/'professor_samples/function_overloading/original/FunctionOverloading.exe'
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        upload=request('/api/uploads?filename=FunctionOverloading.exe',raw=binary.read_bytes(),
                       headers={'Content-Type':'application/octet-stream'})
        assert upload['sha256'] == before and upload['format']=='PE'
        first=wait(request('/api/analysis',{'upload_id':upload['upload_id']}))
        second=wait(request('/api/analysis',{'upload_id':upload['upload_id']}))
        assert second['cache_hit'] and second['profile']['counts']['index_binary_calls']==0
        assert second['profile']['counts']['launcher_start_calls']==0
        assert second['profile']['counts']['database_saves']==0
        assert hashlib.sha256(binary.read_bytes()).hexdigest()==before
        selections = [('FunctionOverloading', first['binary_id'],
                       ['00412620','004126c0','00412790','00411028','004110cd','00411325'])]
        for fixture_id, addresses in (
            ('external:windows_getprocaddress',['140001480','140002740']),
            ('external:windows_tls_x86',['004116c0','00411730','00411800']),
            ('local:simple-elf',[]),
        ):
            fresh=wait(request('/api/analysis',{'fixture_id':fixture_id}))
            cached=wait(request('/api/analysis',{'fixture_id':fixture_id}))
            assert cached['cache_hit'] and cached['profile']['counts']['index_binary_calls']==0
            selections.append((fixture_id,fresh['binary_id'],addresses))
        for name,bid,addresses in selections:
            sid=request('/api/sessions',{'binary_id':bid})['session_id']
            evidence={'binary_id':bid,'functions':{}}
            for address in addresses:
                evidence['functions'][address]={tool_name:tool(sid,tool_name,function=address)
                    for tool_name in ('get_function','get_assembly','get_decompiled_text','crosscheck_function','get_callers',
                                      'get_callees','get_xrefs','get_function_strings','get_thunk_target')}
            report['evidence'][name]=evidence
        for content in (b'not a binary', b'MZ'+b'\0'*80):
            try:
                request('/api/uploads?filename=invalid.exe',raw=content,headers={'Content-Type':'application/octet-stream'})
                raise AssertionError('Invalid binary accepted')
            except HTTPError as exc:
                assert exc.code==400
                report['errors'].append(json.load(exc))
                exc.close()
        report['fixtures_after']=request('/api/library')['fixtures']
        assert sum(f['cached'] for f in report['fixtures_after'])>=4
        report['result']='passed'
    finally:
        server.shutdown()
        server.server_close()
        app.library.close()
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2))
    for job in report['jobs']:
        print(job['filename'], 'cached' if job['cache_hit'] else 'fresh', job['analysis_seconds'],flush=True)
    print('REPORT',args.output,flush=True)


if __name__=='__main__':
    main()
