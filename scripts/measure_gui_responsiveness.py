#!/usr/bin/env python3
"""Measure whether in-process GUI work blocks other HTTP requests.

Starts a private loopback GUI server (random port; never the user's 8767) on an
existing read-only analysis store. A probe thread requests /api/binaries every
100 ms while deterministic chat questions run. No model is called: the model
client raises if used. Writes one JSON summary line.

Usage: measure_gui_responsiveness.py STORE.sqlite OUTPUT_DIR [--rounds N]
"""
import argparse
import http.client
import json
from pathlib import Path
import statistics
import threading
import time

from aire.api.server import GuiApplication, GuiModelConfig, create_server


class NoModel:
    model = 'disabled'

    def generate(self, *args, **kwargs):
        raise RuntimeError('model call attempted during responsiveness measurement')

    def health(self):
        return {}


def request(port, method, path, body=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=120)
    try:
        headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{port}'} if body is not None else {}
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def summary(values):
    if not values:
        return None
    ordered = sorted(values)
    return {'n': len(values), 'median_ms': round(statistics.median(ordered) * 1000, 1),
            'p95_ms': round(ordered[int(0.95 * (len(ordered) - 1))] * 1000, 1),
            'max_ms': round(ordered[-1] * 1000, 1)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('store')
    parser.add_argument('output')
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    out = Path(args.output)
    app = GuiApplication(args.store, session_dir=out / 'sessions', upload_dir=out / 'uploads',
                         model_config=GuiModelConfig(model='disabled'), client_factory=NoModel)
    server = create_server(app, '127.0.0.1', 0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    probes, stop = [], threading.Event()

    def probe():
        while not stop.is_set():
            tick = time.perf_counter()
            request(port, 'GET', '/api/binaries')
            probes.append((time.monotonic(), time.perf_counter() - tick))
            time.sleep(0.1)

    # Idle probe baseline.
    worker = threading.Thread(target=probe, daemon=True)
    worker.start()
    time.sleep(10)
    idle = [latency for _, latency in probes]
    probes.clear()
    binaries = sorted(app.list_binaries(), key=lambda b: -(b.get('function_count') or 0))
    questions = ['What crypto APIs does this binary use?', 'Which functions call BCryptEncrypt?',
                 'What is this file?', 'Is this file corrupted?']
    chats = []
    for _ in range(args.rounds):
        for binary in binaries[:3]:
            status, data = request(port, 'POST', '/api/sessions', {'binary_id': binary['binary_id']})
            session = json.loads(data)['session_id']
            for question in questions:
                tick = time.perf_counter()
                status, data = request(port, 'POST', '/api/chat', {'session_id': session, 'question': question})
                elapsed = time.perf_counter() - tick
                last = json.loads(data.splitlines()[-1])
                chats.append({'binary': binary['binary_id'][:12], 'question': question, 'seconds': round(elapsed, 3),
                              'result': last['type'], 'status': last['data'].get('status') or last['data'].get('error')})
    # Heavier M10 deterministic routes on each binary's largest stored functions.
    import sqlite3
    with sqlite3.connect(f'file:{Path(args.store).resolve()}?mode=ro', uri=True) as db:
        largest = db.execute('SELECT binary_id, function_id FROM functions WHERE is_external=0 AND assembly IS NOT NULL '
                             'ORDER BY length(assembly) DESC LIMIT 6').fetchall()
    m10 = ['Does the decompiled code match the assembly?', 'What does this function do?',
           'Where is input validated?']
    for _ in range(args.rounds):
        for binary_id, function_id in largest:
            status, data = request(port, 'POST', '/api/sessions', {'binary_id': binary_id})
            session = json.loads(data)['session_id']
            request(port, 'POST', f'/api/sessions/{session}/select-function', {'function': function_id})
            for question in m10:
                tick, cpu = time.perf_counter(), time.process_time()
                status, data = request(port, 'POST', '/api/chat', {'session_id': session, 'question': question})
                elapsed, cpu = time.perf_counter() - tick, time.process_time() - cpu
                last = json.loads(data.splitlines()[-1])
                chats.append({'binary': binary_id[:12], 'function': function_id[-12:], 'question': question,
                              'seconds': round(elapsed, 3), 'process_cpu_s': round(cpu, 3), 'result': last['type'],
                              'status': last['data'].get('status') or last['data'].get('error')})
                worst_probe = max((lat for at, lat in probes if at >= time.monotonic() - elapsed - 0.2), default=None)
                print(json.dumps({**chats[-1], 'worst_probe_ms': round(worst_probe * 1000, 1) if worst_probe else None}),
                      flush=True)
    stop.set()
    worker.join()
    busy = [latency for _, latency in probes]
    server.shutdown()
    server.server_close()
    app.library.close()
    print(json.dumps({'idle_probe': summary(idle), 'probe_during_chat': summary(busy),
                      'chat': summary([c['seconds'] for c in chats]),
                      'chat_results': sorted({(c['result'], str(c['status'])) for c in chats}),
                      'slowest_chats': sorted(chats, key=lambda c: -c['seconds'])[:5]}))


if __name__ == '__main__':
    main()
