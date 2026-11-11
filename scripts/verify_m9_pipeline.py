"""M9 real-pipeline acceptance: corrupted PEs and CNG crypto PEs.

Uses the GUI's own BinaryLibrary -> persistent worker process -> PyGhidra path
(no mocks). Targets are only read; nothing is executed. Writes a JSON report.

    GHIDRA_INSTALL_DIR=... JAVA_HOME=... PYTHONPATH=aire-server/src \
    aire-server/.venv/bin/python scripts/verify_m9_pipeline.py \
        --database demo_artifacts/m9/m9.sqlite --output docs/m9/pipeline_verification.json
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

from aire.api.binary_library import BinaryLibrary, BinaryValidationError, REPOSITORY
from aire.knowledge.database import BinaryKnowledgeStore
from aire.security.crypto_evidence import crypto_evidence
from aire.security.rule_engine import _ReadOnlyRuleStore

M9 = REPOSITORY / 'tests/fixtures/m9'


def wait(library, job, limit=1800):
    deadline = time.monotonic() + limit
    while True:
        row = library.job(job['job_id'])
        if row['status'] in ('completed', 'failed') and 'total_seconds' in row:
            return row
        if time.monotonic() > deadline:
            raise RuntimeError('job did not finish')
        time.sleep(0.2)


def run_fixture(library, fixture_id):
    started = time.perf_counter()
    try:
        job = library.start(fixture_id=fixture_id)
    except BinaryValidationError as exc:
        return {'outcome': 'rejected_at_intake', 'message': str(exc), 'validation': exc.report,
                'seconds': time.perf_counter() - started}
    except ValueError as exc:
        return {'outcome': 'rejected_at_intake', 'message': str(exc), 'seconds': time.perf_counter() - started}
    row = wait(library, job)
    keep = ('status', 'error', 'analysis_level', 'pe_valid', 'structure_issue_count', 'cache_hit',
            'analysis_seconds', 'total_seconds', 'warning_count', 'binary_id', 'decompile_workers')
    return {'outcome': 'analyzed' if row['status'] == 'completed' else 'analysis_failed',
            **{k: row.get(k) for k in keep},
            'issue_codes': sorted({i['code'] for i in row.get('structure_issues', [])})}


def check_crypto(store, binary_id, truth):
    report = crypto_evidence(store._db, binary_id)
    found = {row['address']: row for row in report['functions']}
    checks, problems = [], []
    expected_crypto = {name: spec for name, spec in truth['functions'].items() if spec.get('apis')}
    for name, spec in truth['functions'].items():
        row = found.get(spec['address'])
        if spec.get('apis'):
            if row is None:
                problems.append(f'{name} @{spec["address"]}: no crypto evidence')
                continue
            missing = sorted(set(spec['apis']) - set(row['apis']))
            if missing:
                problems.append(f'{name}: APIs not attributed: {missing}')
            strings = {s['value'] for s in row['identifier_strings']}
            missing_strings = sorted(set(spec.get('strings', [])) - strings)
            checks.append({'function': name, 'address': spec['address'], 'expected_role': spec['role'],
                           'found_operations': row['operations'], 'found_apis': row['apis'],
                           'callsites': [(c['address'], c['api']) for c in row['callsites']],
                           'identifier_strings': sorted(strings), 'missing_apis': missing,
                           'missing_identifier_strings': missing_strings})
        elif row is not None and name != 'main':
            problems.append(f'{name}: unexpected crypto evidence {row["apis"]}')
    unexpected = sorted(set(found) - {spec['address'] for spec in expected_crypto.values()})
    if unexpected:
        problems.append(f'crypto evidence at non-ground-truth addresses: {unexpected}')
    # Relationship: every crypto function main calls must list main as a direct caller.
    main = truth['functions'].get('main')
    relationships = []
    for callee in main.get('calls', []):
        spec = truth['functions'][callee]
        row = found.get(spec['address'])
        if row is None:
            continue
        linked = any(c['address'] == main['address'] for c in row['callers'])
        relationships.append({'caller': 'main', 'callee': callee, 'found': linked})
        if not linked:
            problems.append(f'main -> {callee} direct CALL relationship not found')
    return {'functions': checks, 'problems': problems, 'summary': report['summary'],
            'relationships': relationships, 'orchestrators': report['orchestrators']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    with BinaryKnowledgeStore(args.database):
        pass
    library = BinaryLibrary(args.database, directory=args.database.parent / 'uploads')
    expected = {f"m9:{row['name']}": row
                for row in json.loads((M9 / 'manifest.json').read_text())['fixtures']}
    truth = json.loads((M9 / 'crypto_pe/GROUND_TRUTH.json').read_text())['programs']
    before = {key: hashlib.sha256((M9 / row['binary_path']).read_bytes()).hexdigest()
              for key, row in expected.items()}
    report = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'corrupt': {}, 'crypto': {}}
    try:
        for key, row in expected.items():
            if not row['name'].startswith(('corrupt_', 'crypto_')):
                continue
            result = run_fixture(library, key)
            result['expected_analysis'] = row.get('expected_analysis')
            section = 'corrupt' if row['name'].startswith('corrupt_') else 'crypto'
            report[section][row['name']] = result
            print(f"{row['name']}: {result['outcome']} {result.get('error') or ''}"[:200], file=sys.stderr, flush=True)
        # GUI/worker still usable after every malformed input.
        report['post_corruption_valid_analysis'] = run_fixture(library, 'local:simple-elf')
        report['library_rows_after'] = len(library.list())
    finally:
        library.close()
        report['worker_exit_code'] = library._process.returncode if library._process else None
    with _ReadOnlyRuleStore(args.database) as store:
        for name, result in report['crypto'].items():
            program = name.removeprefix('crypto_')
            if result['outcome'] == 'analyzed':
                result['evidence_check'] = check_crypto(store, result['binary_id'], truth[program])
    after = {key: hashlib.sha256((M9 / row['binary_path']).read_bytes()).hexdigest()
             for key, row in expected.items()}
    report['fixture_hashes_unchanged'] = before == after
    # Pass criteria
    failures = []
    for name, result in report['corrupt'].items():
        level = result['expected_analysis']
        if level == 'none' and result['outcome'] != 'rejected_at_intake':
            failures.append(f'{name}: expected intake rejection')
        if level in ('partial', 'full') and result['outcome'] == 'rejected_at_intake':
            failures.append(f'{name}: unexpectedly rejected')
    for name, result in report['crypto'].items():
        if result['outcome'] != 'analyzed':
            failures.append(f'{name}: {result["outcome"]}')
        elif result['evidence_check']['problems']:
            failures.extend(f'{name}: {p}' for p in result['evidence_check']['problems'])
    if report['post_corruption_valid_analysis']['outcome'] != 'analyzed':
        failures.append('valid analysis after corrupt inputs failed')
    if report['worker_exit_code'] not in (0, None):
        failures.append(f'worker exit code {report["worker_exit_code"]}')
    if not report['fixture_hashes_unchanged']:
        failures.append('fixture bytes changed')
    report['failures'] = failures
    report['passed'] = not failures
    report['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1, default=str) + '\n')
    print(json.dumps({'passed': report['passed'], 'failures': failures}, indent=1))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
