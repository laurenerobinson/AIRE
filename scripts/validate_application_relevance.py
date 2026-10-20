"""Validate stored PE/ELF relevance and optional local synthesis; no indexing/execution.

PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/validate_application_relevance.py \
    --database analysis.sqlite --output /tmp/aire-relevance.json --live --directed
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import tempfile
import time

from aire.agent.binary_scope import resolve_binary
from aire.agent.runner import AgentLimits
from aire.agent.tools import AgentTools
from aire.ai.prompt_builder import build_prompt
from aire.api.server import GuiApplication
from aire.knowledge.application_relevance import ApplicationRelevanceService, RELEVANCE_POLICY_VERSION
from aire.security.rule_engine import _ReadOnlyRuleStore

DIRECTED = ('Find functions that appear to implement the same operation for different parameter types. '
    'Compare their assembly and explain whether this binary demonstrates C++ function overloading.')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=Path('analysis.sqlite'))
    parser.add_argument('--binary', action='append', help='Repeat for multiple stored binaries')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--live', action='store_true', help='Use configured local Ollama')
    parser.add_argument('--directed', action='store_true', help='Also run the overloading query on PE')
    args = parser.parse_args()
    targets = args.binary or ['professor_samples/function_overloading/original/FunctionOverloading.exe',
                             'tests/fixtures/simple_elf/aire_test_binary']
    hashes = {p: digest(p) for p in targets if Path(p).is_file()}
    report = {'policy_version': RELEVANCE_POLICY_VERSION, 'hashes_before': hashes,
              'database_before': digest(args.database), 'binaries': []}
    def save():
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    for target in targets:
        with _ReadOnlyRuleStore(args.database) as store:
            binary = resolve_binary(store, target)
            tools = AgentTools(store, binary.binary_id)
            service = ApplicationRelevanceService(store)
            timings = []
            for _ in range(20):
                tick = time.perf_counter()
                ranking = service.rank_application_functions(binary.binary_id, limit=10)
                timings.append(time.perf_counter() - tick)
            row = {'binary': tools.metadata(), 'relevance': ranking,
                   'connectivity': tools.rank('unique_callees', limit=10),
                   'ranking_median_seconds': statistics.median(timings)}
        with tempfile.TemporaryDirectory(prefix='aire-relevance-') as sessions:
            app = GuiApplication(args.database, initial_binary=target, session_dir=sessions,
                                 limits=AgentLimits(timeout_seconds=600))
            tick = time.perf_counter()
            app.bootstrap()
            row['workspace_load_seconds'] = time.perf_counter() - tick
            with app.store() as store:
                workspace = app.workspace(binary.binary_id, store)
                row['seed_ids'] = workspace.seed_ids
                cached = workspace.tools(store)
                cached.registry.run('retrieve_evidence', {})
                bundle = cached.last_evidence
                row['evidence'] = [{'function_id': f.function.function_id,
                                    'name': f.function.current_name, 'address': f.function.address,
                                    'reason': f.inclusion_reason} for f in bundle.functions]
                row['application_relevance'] = bundle.metadata['application_relevance']
                prompt = build_prompt('What does this binary do?', bundle, policy='overview', compact=True)
                row['admitted_code_ids'] = sorted(prompt.code_source_ids)
                row['context_characters'] = prompt.context_characters
            report['binaries'].append(row)
            save()
            if args.live:
                sid = app.new_session(binary.binary_id)['session_id']
                questions = ['What does this binary do?', 'What does this binary do?']
                if args.directed and 'PE' in (binary.format or ''):
                    questions.append(DIRECTED)
                row['queries'] = []
                for question in questions:
                    result = app.run_chat(sid, question)
                    row['queries'].append({'question': question, 'status': result.status,
                        'summary': result.response.summary.claim if result.response else None,
                        'answer': result.answer, 'performance': app.last_performance,
                        'tools': [{'name': r['tool'], 'ok': r['ok']} for r in result.tool_results]})
                    print(binary.program_name, result.status,
                          row['queries'][-1]['summary'] or result.answer[:300], flush=True)
                    save()
    report['hashes_after'] = {p: digest(p) for p in hashes}
    report['database_after'] = digest(args.database)
    save()
    if report['hashes_after'] != hashes or report['database_after'] != report['database_before']:
        raise RuntimeError('Target or analysis database changed')
    if args.live and any(q['status'] != 'completed' for r in report['binaries'] for q in r['queries']):
        raise RuntimeError('One or more live queries did not complete; inspect report')


if __name__ == '__main__':
    main()
