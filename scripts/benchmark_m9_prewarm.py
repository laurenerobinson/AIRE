"""Measure GUI analyzer pre-warming with the real `aire gui` process.

Conditions (interleaved, rotating order per repetition; fresh database each run):
  no-prewarm         `aire gui --no-prewarm`, upload as soon as the GUI answers
  prewarm-immediate  pre-warm on, upload as soon as the GUI answers (job waits for warm-up)
  prewarm-ready      pre-warm on, upload once /api/library reports analyzer ready
Per run: GUI-ready time (process start -> /api/bootstrap 200), analyzer-ready time,
first-upload latency (POST /api/analysis -> job completed), worker RSS (idle after
pre-warm and at job end, including native decompiler children), detected VM freeze.

    PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/benchmark_m9_prewarm.py \
        --repeat 5 --output docs/m9/benchmarks/prewarm.json
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'professor_samples/function_overloading/original/FunctionOverloading.exe'


class Freeze:
    def __init__(self):
        self.stalled, self._stop = 0.0, threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        last = time.monotonic()
        while not self._stop.wait(0.5):
            now = time.monotonic()
            if now - last - 0.5 > 2.0:
                self.stalled += now - last - 0.5
            last = now

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()


def rss_tree_mib(pid):
    """RSS of pid plus its direct children (native decompiler processes)."""
    total = 0
    pids = [pid]
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            try:
                stat = (entry / 'stat').read_text()
                if int(stat[stat.rindex(')') + 2:].split()[1]) == pid:
                    pids.append(int(entry.name))
            except (OSError, ValueError, IndexError):
                pass
    for p in pids:
        try:
            for line in Path(f'/proc/{p}/status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    total += int(line.split()[1])
        except OSError:
            pass
    return total / 1024


def request(base, path, data=None, ctype='application/json'):
    req = urllib.request.Request(base + path, data=data, method='POST' if data is not None else 'GET',
                                 headers={'Origin': base, **({'Content-Type': ctype} if data is not None else {})})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())


def worker_pid(gui_pid):
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            try:
                cmd = (entry / 'cmdline').read_bytes().replace(b'\0', b' ')
                stat = (entry / 'stat').read_text()
                if b'aire.api.index_worker' in cmd and int(stat[stat.rindex(')') + 2:].split()[1]) == gui_pid:
                    return int(entry.name)
            except (OSError, ValueError, IndexError):
                pass
    return None


def run(condition, port):
    with tempfile.TemporaryDirectory(prefix='aire-prewarm-bench-') as tmp, Freeze() as freeze:
        tmp = Path(tmp)
        args = [str(ROOT / 'aire-server/.venv/bin/aire'), 'gui', '--database', str(tmp / 'db.sqlite'),
                '--session-dir', str(tmp / 'sessions'), '--upload-dir', str(tmp / 'uploads'),
                '--port', str(port), '--no-browser']
        if condition == 'no-prewarm':
            args.append('--no-prewarm')
        env = {**os.environ, 'PYTHONPATH': str(ROOT / 'aire-server/src')}
        env.pop('AIRE_PREWARM', None)
        base = f'http://127.0.0.1:{port}'
        started = time.perf_counter()
        gui = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        row = {'condition': condition}
        try:
            while True:
                try:
                    request(base, '/api/bootstrap')
                    break
                except (URLError, ConnectionError, OSError):
                    if time.perf_counter() - started > 120:
                        raise RuntimeError('GUI did not start')
                    time.sleep(0.05)
            row['gui_ready_seconds'] = time.perf_counter() - started
            row['gui_rss_mib_at_ready'] = rss_tree_mib(gui.pid)
            if condition == 'prewarm-ready':
                while True:
                    status = request(base, '/api/library')['analyzer']
                    if status['status'] in ('ready', 'failed'):
                        break
                    if time.perf_counter() - started > 600:
                        raise RuntimeError('pre-warm did not finish')
                    time.sleep(0.25)
                row['analyzer_ready_seconds'] = time.perf_counter() - started
                row['prewarm_status'] = status
                pid = worker_pid(gui.pid)
                row['worker_rss_mib_idle_warm'] = rss_tree_mib(pid) if pid else None
            uploaded = request(base, f'/api/uploads?filename={BINARY.name}', BINARY.read_bytes(),
                               'application/octet-stream')
            tick = time.perf_counter()
            job = request(base, '/api/analysis', json.dumps({'upload_id': uploaded['upload_id']}).encode())
            peak = 0.0
            while True:
                state = request(base, f"/api/analysis/{job['job_id']}")
                pid = worker_pid(gui.pid)
                if pid:
                    peak = max(peak, rss_tree_mib(pid))
                if state['status'] in ('completed', 'failed') and 'total_seconds' in state:
                    break
                time.sleep(0.25)
            row['first_upload_latency_seconds'] = time.perf_counter() - tick
            row['job_status'] = state['status']
            row['job_error'] = state.get('error')
            row['job_processing_seconds'] = state.get('analysis_seconds')
            row['job_queue_seconds'] = state.get('queue_seconds')
            row['launcher_start_calls_in_job'] = (state.get('profile') or {}).get('counts', {}).get('launcher_start_calls')
            row['runtime_startup_in_job'] = (state.get('profile') or {}).get('exclusive_seconds', {}).get('runtime_startup')
            row['worker_peak_rss_mib_during_job'] = peak
            row['time_to_first_result_from_launch_seconds'] = time.perf_counter() - started
            final = request(base, '/api/library')['analyzer']
            row['analyzer_status_final'] = final.get('status')
        finally:
            gui.terminate()
            try:
                gui.wait(timeout=30)
            except subprocess.TimeoutExpired:
                gui.kill()
        row['detected_freeze_seconds'] = freeze.stalled
        return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    conditions = ['no-prewarm', 'prewarm-immediate', 'prewarm-ready']
    rows = []
    for rep in range(args.repeat):
        order = conditions[rep % 3:] + conditions[:rep % 3]
        for condition in order:
            row = run(condition, 8790)
            row['rep'] = rep
            rows.append(row)
            print(json.dumps({k: (round(v, 3) if isinstance(v, float) else v) for k, v in row.items()
                              if k not in ('prewarm_status',)}), file=sys.stderr, flush=True)
            args.output.write_text(json.dumps({'rows': rows}, indent=1) + '\n')
    summary = {}
    for condition in conditions:
        sel = [r for r in rows if r['condition'] == condition and r['job_status'] == 'completed']
        def med(key, clean=False):
            values = [r[key] for r in sel if r.get(key) is not None and (not clean or r['detected_freeze_seconds'] < 1)]
            return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'n': len(values)} if values else None
        summary[condition] = {key: med(key) for key in (
            'gui_ready_seconds', 'analyzer_ready_seconds', 'first_upload_latency_seconds',
            'time_to_first_result_from_launch_seconds', 'worker_rss_mib_idle_warm',
            'worker_peak_rss_mib_during_job', 'gui_rss_mib_at_ready')}
        summary[condition]['first_upload_latency_freeze_free'] = med('first_upload_latency_seconds', clean=True)
    args.output.write_text(json.dumps({'rows': rows, 'summary': summary}, indent=1) + '\n')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
