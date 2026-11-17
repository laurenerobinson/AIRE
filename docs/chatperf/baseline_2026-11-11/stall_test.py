import json, sys, time, urllib.request, random
sys.path.insert(0, '/home/laurene/aire/scripts')
from benchmark_m9 import StallDetector
OUT = sys.argv[1]
random.seed(1)
def body(n):  # ~2400-token unique prompt (defeats prefix cache)
    return 'Evidence %d.\n' % n + '\n'.join(f'FUNC:{i} FUN_{0x401000+i*16:08x} calls BCrypt{random.choice(["Encrypt","Decrypt","HashData","SignHash"])} at 0x{0x401000+i*16+5:08x}' for i in range(140))
def gen(threads, n):
    opts = {'temperature': 0.1, 'seed': 0, 'num_predict': 200, 'num_ctx': 4096}
    if threads: opts['num_thread'] = threads
    req = urllib.request.Request('http://127.0.0.1:11434/api/generate', headers={'Content-Type': 'application/json'},
        data=json.dumps({'model': 'qwen2.5-coder:1.5b', 'prompt': body(n) + '\nSummarize which functions encrypt.', 'stream': False,
                         'keep_alive': '10m', 'options': opts}).encode())
    return json.load(urllib.request.urlopen(req, timeout=900))
plan = ['idle', 4, 2, 'idle', 4, 2, 3, 'idle', 4, 2]
with open(OUT, 'a') as out:
    for n, cond in enumerate(plan):
        t = time.perf_counter()
        with StallDetector(0.25) as s:
            if cond == 'idle':
                time.sleep(45); r = {}
            else:
                r = gen(cond, n)
        row = {'n': n, 'cond': cond, 'wall': round(time.perf_counter() - t, 2), **s.to_dict(),
               'prompt_tokens': r.get('prompt_eval_count'), 'prefill_s': (r.get('prompt_eval_duration') or 0) / 1e9,
               'eval_tokens': r.get('eval_count'), 'eval_s': (r.get('eval_duration') or 0) / 1e9, 'load_s': (r.get('load_duration') or 0) / 1e9}
        out.write(json.dumps(row) + '\n'); out.flush(); print(row, flush=True)
