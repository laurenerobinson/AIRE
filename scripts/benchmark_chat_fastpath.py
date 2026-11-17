#!/usr/bin/env python3
"""End-to-end benchmark of deterministic chat answers through the real HTTP API.

Starts an in-process A.I.R.E. GUI server on a free loopback port (never the
user's running GUI), posts questions to /api/chat and reads the NDJSON stream
exactly as the browser does. Records time to first byte, first activity event,
the result packet (first meaningful answer content), total time, model calls
and correctness against tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json.

The model client raises on use: a supported question that reached the model
would be reported as a failure, and no local inference (or VM stress) occurs.

    scripts/benchmark_chat_fastpath.py DB OUT.jsonl [--rounds 3]
"""
import argparse
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from benchmark_m9 import StallDetector  # noqa: E402
from aire.api.server import GuiApplication, create_server  # noqa: E402

TRUTH = json.loads((ROOT / 'tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json').read_text())['programs']
ROLES = ('encryption', 'decryption', 'hashing', 'signing', 'verification')
# (label, program, selected function or None, question, checks: role -> expected addresses / callers)
CASES = [
    ('encdec(user)', 'aes_gcm', None, 'What functions in this binary perform encryption and decryption? '
                                      'Show their addresses and the API calls that support your answer.',
     ('encryption', 'decryption')),
    ('encdec', 'aes_gcm', None, 'Which functions perform encryption and decryption?', ('encryption', 'decryption')),
    ('where-encrypt', 'aes_gcm', None, 'Where does this program encrypt data?', ('encryption',)),
    ('encrypt', 'aes_gcm', None, 'Which function encrypts data?', ('encryption',)),
    ('api-lookup', 'aes_gcm', None, 'Find the function that calls BCryptEncrypt.', ('api:BCryptEncrypt:0041d160',)),
    ('callers', 'aes_gcm', 'FUN_0041d160', 'What calls this function?', ('edge:0041d2a0->0041d160',)),
    ('hash', 'sha256_hash', None, 'Which function hashes the input?', ('hashing',)),
    ('sha256', 'sha256_hash', None, 'Which function computes the SHA-256 hash?', ('hashing', 'text:SHA256')),
    ('evidence', 'sha256_hash', 'FUN_0041d0a0', 'Show the evidence for this function.', ('text:BCryptHashData',)),
    ('sign-verify', 'ecdsa_sign', None, 'Which function signs or verifies a digital signature?',
     ('signing', 'verification')),
    ('verify', 'ecdsa_sign', None, 'Which function verifies the digital signature?', ('verification',)),
    ('all-ops', 'ecdsa_sign', None, 'What cryptographic operations does this binary perform?',
     ('hashing', 'signing', 'verification')),
    ('fn-apis', 'ecdsa_sign', 'FUN_0041d1b0', 'What API calls does this function make?', ('text:BCryptSignHash',)),
    ('card-crypto', 'aes_gcm', None, 'Identify crypto or hashing routines in this binary', ('encryption', 'decryption')),
    ('sign+verify(demo)', 'ecdsa_sign', None, 'Which functions sign and verify a digital signature?',
     ('signing', 'verification')),
    ('damaged-file(demo)', 'import_dll_name_invalid', None, 'What is this file?',
     ('text:`import_dll_name` (error', 'text:No program purpose is stated', 'text:IMAGE_FILE_DLL not set')),
    ('damaged-overview', 'import_dll_name_invalid', None, 'What does this binary do?',
     ('text:Why no AI overview', 'text:structure damaged (partial analysis)')),
    ('m10-function', 'aes_gcm', 'FUN_0041d160', 'What does this function do?', ('text:BCryptEncrypt',)),
]


class CountingNoModel:
    model, num_ctx, calls = 'none', 4096, 0

    def generate(self, *args, **kwargs):
        CountingNoModel.calls += 1
        raise RuntimeError('model call on a deterministic path')


def check(program, result, checks):
    """Return a list of correctness problems (empty = correct), read from the structured verified facts."""
    truth = TRUTH.get(program, {}).get('functions', {})
    answer = result['answer']
    facts = (result.get('presentation') or {}).get('facts') or {}
    problems = []
    for item in checks:
        if item in ROLES:
            listed = {f['address'] for f in facts.get('roles', []) if f['role'] == item}
            expected = {f['address'] for f in truth.values() if f['role'] == item}
            if listed != expected:
                problems.append(f'{item}: listed {sorted(listed)} expected {sorted(expected)}')
            for address in expected:
                if f'`FUN_{address}` `0x{address}`' not in answer:
                    problems.append(f'{item}: {address} missing from the rendered table')
        elif item.startswith('api:'):
            _, api, address = item.split(':')
            if not any(f['api'] == api and f['address'] == address for f in facts.get('apis', [])):
                problems.append(f'{api} caller {address} missing')
        elif item.startswith('edge:'):
            caller, callee = item[5:].split('->')
            if f'FUN_{caller} → FUN_{callee}' not in answer:
                problems.append(f'edge {caller}->{callee} missing')
        elif item.startswith('text:') and item[5:] not in answer:
            problems.append(f'{item[5:]} missing')
    return problems


def post(base, session_id, question):
    marks, packets = {}, []
    tick = time.perf_counter()
    request = Request(base + '/api/chat', data=json.dumps({'session_id': session_id, 'question': question}).encode(),
                      method='POST', headers={'Content-Type': 'application/json', 'Origin': base})
    with urlopen(request, timeout=120) as response:
        marks['headers'] = time.perf_counter() - tick
        while True:
            line = response.readline()
            if not line:
                break
            now = time.perf_counter() - tick
            packet = json.loads(line)
            marks.setdefault('first_packet', now)
            marks.setdefault('first_' + packet['type'], now)
            packets.append(packet)
    marks['total'] = time.perf_counter() - tick
    return marks, packets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('database')
    parser.add_argument('out')
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        app = GuiApplication(args.database, session_dir=Path(tmp) / 's', upload_dir=Path(tmp) / 'u',
                             client_factory=CountingNoModel)
        server = create_server(app, '127.0.0.1', 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = 'http://127.0.0.1:%d' % server.server_address[1]
        binaries = {b['program_name']: b['binary_id'] for b in app.list_binaries()}
        seen = set()
        try:
            with open(args.out, 'a') as out, StallDetector(0.25) as stall:
                for rnd in range(args.rounds):
                    for label, program, select, question, checks in CASES:
                        binary_id = binaries[program + '.exe']
                        cold = binary_id not in seen
                        seen.add(binary_id)
                        session_id = app.new_session(binary_id)['session_id']
                        if select:
                            app.select_function(session_id, select)
                        before = CountingNoModel.calls
                        gap0 = stall.max_gap
                        marks, packets = post(base, session_id, question)
                        result = next((p['data'] for p in packets if p['type'] == 'result'), None)
                        error = next((p['data'] for p in packets if p['type'] == 'error'), None)
                        answer = result['answer'] if result else ''
                        problems = check(program, result, checks) if result else ['no result: ' + str(error)]
                        row = {'round': rnd, 'label': label, 'program': program, 'question': question,
                               'cold_workspace': cold, 'status': result and result['status'],
                               'path': app.last_performance.get('path'),
                               'model_calls': CountingNoModel.calls - before,
                               'server_seconds': app.last_performance.get('total_seconds'),
                               'evidence_seconds': app.last_performance.get('evidence_seconds'),
                               **{k + '_seconds': round(v, 4) for k, v in marks.items()},
                               'answer_chars': len(answer), 'events': sum(p['type'] == 'event' for p in packets),
                               'correct': not problems, 'problems': problems,
                               'vm_max_tick_gap_seconds': round(max(stall.max_gap, gap0), 3)}
                        out.write(json.dumps(row) + '\n')
                        print(f"r{rnd} {label:14} {program:12} path={row['path']} model={row['model_calls']} "
                              f"first_event={row.get('first_event_seconds')} result={row.get('first_result_seconds')} "
                              f"total={row['total_seconds']} correct={row['correct']} {problems or ''}", flush=True)
        finally:
            server.shutdown()
            server.server_close()
            app.library.close()


if __name__ == '__main__':
    main()
