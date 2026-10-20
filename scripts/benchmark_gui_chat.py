"""Measure GUI chat with local Ollama and an already indexed, read-only binary.

Run from the repo root with the A.I.R.E. Python environment. --cold-model is
explicitly opt-in because it unloads the configured model before measuring.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import time

from aire.api.server import GuiApplication


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--function', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cold-model', action='store_true')
    args = parser.parse_args()
    before = hashlib.sha256(args.database.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='aire-benchmark-') as sessions:
        app = GuiApplication(args.database, initial_binary=args.binary, session_dir=sessions)
        client = app._client()
        version = client._request('/api/version')
        if args.cold_model:
            if not client.model:
                parser.error('Set AIRE_OLLAMA_MODEL before using --cold-model')
            client._request('/api/generate', {'model': client.model, 'prompt': '',
                'stream': False, 'keep_alive': 0})
        tick = time.perf_counter()
        app.bootstrap()
        workspace_seconds = time.perf_counter() - tick
        sid = app.new_session(app.initial_binary_id)['session_id']
        report = {'model': client.model, 'num_ctx': client.num_ctx,
                  'ollama_version': version, 'cold_model': args.cold_model,
                  'workspace_load_seconds': workspace_seconds, 'requests': []}
        for question in ('What does this binary do?', 'Find suspicious behavior in this binary',
                         'Explain ' + args.function, 'What does this binary do?', 'What calls it?'):
            result = app.run_chat(sid, question, on_text=lambda text: None, on_context=lambda text: None)
            row = {'question': question, 'status': result.status,
                   'timing': app.last_performance, 'answer_characters': len(result.answer),
                   'sizes': result.response.sizes if result.response else None,
                   'answer': result.answer}
            report['requests'].append(row)
            print(json.dumps(row), flush=True)
            args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        report['loaded_models_after'] = client._request('/api/ps')
        report['database_unchanged'] = before == hashlib.sha256(args.database.read_bytes()).hexdigest()
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        if not report['database_unchanged']:
            raise RuntimeError('Analysis database changed during benchmark')


if __name__ == '__main__':
    main()
