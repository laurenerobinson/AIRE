"""Read-only end-to-end profiler for GuiApplication.run_chat (same path as /api/chat).

Usage: profile_chat.py DB OUT.jsonl CASES.json [--cold-first]
Each case: {"binary": name, "question": str, "select": optional function name/addr, "label": str}
"""
import json, sys, time, threading, urllib.request
sys.path.insert(0, '/home/laurene/aire/scripts')
from benchmark_m9 import StallDetector
from aire.api.server import GuiApplication, GuiError
from aire.ai.ollama_client import OllamaClient

DB, OUT, CASES = sys.argv[1], sys.argv[2], sys.argv[3]
COLD_FIRST = '--cold-first' in sys.argv
SCRATCH = '/tmp/claude-1000/-home-laurene-aire/7e9d874c-873c-4d09-928c-39068f5586c9/scratchpad'


class RecordingClient(OllamaClient):
    calls = []

    def generate(self, prompt, *, system='', response_schema=None, on_chunk=None):
        rec = {'prompt_chars': len(prompt), 'system_chars': len(system or ''),
               'schema_chars': len(json.dumps(response_schema)) if response_schema else 0,
               'streaming': on_chunk is not None, 'start': time.perf_counter()}
        first = {}
        def chunk(c):
            first.setdefault('t', time.perf_counter())
            on_chunk(c)
        try:
            r = super().generate(prompt, system=system, response_schema=response_schema,
                                 on_chunk=chunk if on_chunk else None)
            rec.update(ok=True, wall=time.perf_counter() - rec['start'], prompt_eval_count=r.prompt_eval_count,
                       eval_count=r.eval_count, **{k: v for k, v in r.timing.items() if isinstance(v, (int, float))})
            return r
        except Exception as exc:
            rec.update(ok=False, wall=time.perf_counter() - rec['start'], error=f'{type(exc).__name__}: {exc}'[:200])
            raise
        finally:
            if 't' in first:
                rec['first_chunk_after'] = first['t'] - rec['start']
            RecordingClient.calls.append(rec)


def ollama_ps():
    try:
        return json.load(urllib.request.urlopen('http://127.0.0.1:11434/api/ps', timeout=3))['models']
    except Exception as exc:
        return str(exc)


def unload(model):
    req = urllib.request.Request('http://127.0.0.1:11434/api/generate',
        data=json.dumps({'model': model, 'keep_alive': 0}).encode(), headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=30).read()
    time.sleep(2)


app = GuiApplication(DB, session_dir=SCRATCH + '/sessions', upload_dir=SCRATCH + '/uploads',
                     client_factory=lambda: RecordingClient(timeout_seconds=240))
binaries = {b['program_name']: b['binary_id'] for b in app.list_binaries()}
cases = json.load(open(CASES))
if COLD_FIRST:
    unload(app._client().model)

with open(OUT, 'a') as out:
    for i, case in enumerate(cases):
        if case.get('cold'):
            unload(app._client().model)
        binary_id = binaries[case['binary']]
        session = app.new_session(binary_id)['session_id']
        if case.get('select'):
            app.select_function(session, case['select'])
        RecordingClient.calls = []
        marks, events = {}, []
        t0 = time.perf_counter()
        def mark(name):
            marks.setdefault(name, time.perf_counter() - t0)
        def on_event(e):
            mark('first_event')
            events.append((round(time.perf_counter() - t0, 3), e.event_type, e.message, e.tool_name))
        def on_text(t):
            if t: mark('first_text')
        def on_context(t):
            mark('first_context')
        before = ollama_ps()
        error = None
        with StallDetector() as stall:
            try:
                result = app.run_chat(session, case['question'], on_event=on_event, on_text=on_text, on_context=on_context)
                status, answer = result.status, result.answer
            except Exception as exc:
                status, answer, error = 'exception', '', f'{type(exc).__name__}: {exc}'[:300]
        total = time.perf_counter() - t0
        for c in RecordingClient.calls:
            c['start'] = round(c['start'] - t0, 3)
        row = {'i': i, 'label': case.get('label'), 'binary': case['binary'], 'question': case['question'],
               'select': case.get('select'), 'cold': bool(case.get('cold') or (COLD_FIRST and i == 0)),
               'status': status, 'error': error, 'total_seconds': round(total, 3), 'marks': marks,
               'model_calls': RecordingClient.calls, 'events': events, 'perf': app.last_performance,
               'answer_chars': len(answer), 'answer_head': answer[:600], 'stall': stall.to_dict(),
               'model_loaded_before': [m.get('name') for m in before] if isinstance(before, list) else before}
        out.write(json.dumps(row, default=str) + '\n'); out.flush()
        print(f"[{i}] {case.get('label')} {case['binary']}: {status} total={total:.1f}s calls={len(RecordingClient.calls)} "
              f"first_event={marks.get('first_event')} first_text={marks.get('first_text')} stall={stall.max_gap:.2f}", flush=True)
