"""Transient deterministic local agreement reports over stored function facts."""
from hashlib import sha256
import time

from aire.analysis.assembly_semantics import extract_assembly
from aire.analysis.decompiler_semantics import extract_decompiler
from aire.knowledge.retrieval import ProgramQueryService

CROSSCHECK_POLICY_VERSION = 'function-crosscheck-v1'
MAX_FUNCTIONS = 3


def evaluate_crosscheck(assembly, decompiler, *, missing_assembly=False, missing_decompiler=False, thunk=False):
    agreements, conflicts, uncertainties = [], [], []
    arows, drows = assembly['observations'], decompiler['observations']
    ac, dc = assembly['coverage'], decompiler['coverage']
    for a in arows:
        if a.get('context') == 'stack_adjustment' or a['operation_family'] == 'call':
            continue
        operation = a['operation_family'].removeprefix('scalar_double_').removeprefix('scalar_float_').removeprefix('integer_')
        for d in drows:
            if operation == d['operation'] and (not d['same_operand'] or a['same_operand']):
                row = {'operation': operation, 'assembly_family': a['operation_family'],
                       'instruction_address': a['address'], 'instruction_line': a['line'],
                       'decompiler_offset': d['offset'], 'same_operand': a['same_operand'] and d['same_operand'],
                       'scope': 'local operation agreement; not whole-function equivalence'}
                if row['same_operand'] and operation == 'multiplication':
                    row['likely_pattern'] = 'value_squared'
                if len(agreements) < 16:
                    agreements.append(row)
                break
    complete = not (missing_assembly or missing_decompiler or thunk or ac['bounded'] or ac['upstream_truncated'] or
                    ac['unsupported_architecture'] or ac['malformed_lines'] or ac['unsupported_mnemonics'] or
                    ac['observations_bounded'] or dc['bounded'] or dc['observations_bounded'] or dc['unrecognized_expressions'])
    # Only a returned computation with no calls/branches can exclude the other
    # instruction family locally. A missing SQRT alone cannot exclude helper sqrt.
    simple = (complete and assembly['control_flow']['call_count'] == 0 and
              assembly['control_flow']['conditional_branch_count'] == 0 and
              assembly['control_flow']['unconditional_branch_count'] == 0 and
              assembly['control_flow']['return_count'] == 1)
    returned = {r['operation_family'] for r in assembly['return_register_candidates']}
    dsqrt = any(r['operation'] == 'square_root' and r['in_return_expression'] for r in drows)
    dmul = any(r['operation'] == 'multiplication' and r['in_return_expression'] for r in drows)
    if simple and dsqrt and any(f.endswith('multiplication') for f in returned) and not assembly['sqrt_instruction_present']:
        conflicts.append('Decompiler return suggests square root; the locally returned assembly computation is multiplication, with no SQRTSS/SQRTSD instruction.')
    if simple and dmul and any(f.endswith('square_root') for f in returned) and not any(r['operation_family'].endswith('multiplication') for r in arows):
        conflicts.append('Decompiler return suggests multiplication; the locally returned assembly computation is scalar square root.')
    if missing_assembly:
        uncertainties.append('Stored assembly is unavailable.')
    if missing_decompiler:
        uncertainties.append('Stored decompilation is unavailable.')
    if ac['bounded'] or ac['upstream_truncated'] or dc['bounded'] or ac['observations_bounded'] or dc['observations_bounded']:
        uncertainties.append('Input or observation bounds omit evidence; agreement cannot be established.')
    if ac['unsupported_architecture']:
        uncertainties.append('Instruction semantics support Intel-syntax x86/x86-64 only.')
    if ac['unsupported_mnemonics'] or ac['malformed_lines']:
        uncertainties.append('Some stored instructions are unsupported or unparsed; local value tracking was cleared.')
    if dc['unrecognized_expressions']:
        uncertainties.append('Some decompiler expressions are outside the conservative recognizer.')
    if thunk:
        uncertainties.append('Thunk assembly and forwarded decompilation may cover different bodies.')
    if assembly['control_flow']['call_count']:
        uncertainties.append('Callee semantics and register clobbers are unknown; calls invalidate local value tracking.')
    if not assembly['return_register_candidates']:
        uncertainties.append('No computed return-register relationship was established; local operations alone do not prove the returned value.')
    hard_gap = (missing_assembly or missing_decompiler or ac['bounded'] or ac['upstream_truncated'] or
                ac['unsupported_architecture'] or dc['bounded'] or ac['observations_bounded'] or dc['observations_bounded'] or thunk)
    if hard_gap:
        status = 'INSUFFICIENT_EVIDENCE'
    elif conflicts:
        status = 'CONFLICT'
    elif agreements:
        # Agreement means matching supported operations locally. Other operations,
        # branches and helper calls remain outside this claim.
        status = 'AGREEMENT' if complete else 'PARTIAL_AGREEMENT'
    elif assembly['control_flow']['call_count'] and decompiler['calls']:
        status = 'PARTIAL_AGREEMENT'
        agreements.append({'operation': 'call', 'scope': 'Both contain calls; target/argument equivalence is not established.'})
    else:
        status = 'INSUFFICIENT_EVIDENCE'
    return status, agreements, conflicts, uncertainties


def analyze_record(function, *, architecture='x86', resolved_calls=(), include_timings=False):
    started = time.perf_counter()
    assembly = extract_assembly(function.assembly, truncated=function.assembly_truncated,
                                architecture=architecture, resolved_calls=resolved_calls)
    amid = time.perf_counter()
    decompiler = extract_decompiler(function.decompiled_text)
    dmid = time.perf_counter()
    status, agreements, conflicts, uncertainties = evaluate_crosscheck(assembly, decompiler,
        missing_assembly=not function.assembly, missing_decompiler=not function.decompiled_text,
        thunk=function.is_thunk or function.is_external)
    result = {
        'policy_version': CROSSCHECK_POLICY_VERSION,
        'function': {'function_id': function.function_id, 'binary_id': function.binary_id,
                     'address': function.address, 'current_name': function.current_name},
        'provenance': {'source_table': 'functions', 'source_id': function.function_id,
            'binary_id': function.binary_id, 'address': function.address,
            'reason': 'transient deterministic analysis of stored assembly and decompilation',
            'assembly_sha256': sha256((function.assembly or '').encode('utf-8', 'surrogatepass')).hexdigest(),
            'decompiler_sha256': sha256((function.decompiled_text or '').encode('utf-8', 'surrogatepass')).hexdigest()},
        'assembly_observations': assembly['observations'], 'decompiler_observations': decompiler['observations'],
        'agreements': agreements, 'disagreements': conflicts, 'uncertainties': uncertainties,
        'control_flow_summary': {**assembly['control_flow'], 'stored_basic_block_count': function.basic_block_count,
                                 'stored_branch_count': function.branch_count,
                                 'straight_line_observed': bool(function.assembly) and not assembly['coverage']['unsupported_architecture'] and
                                    not assembly['coverage']['malformed_lines'] and not assembly['coverage']['unsupported_mnemonics'] and
                                    not function.assembly_truncated and not assembly['coverage']['bounded'] and
                                    not assembly['control_flow']['conditional_branch_count'] and not assembly['control_flow']['unconditional_branch_count']},
        'data_flow_summary': {'return_register_candidates': assembly['return_register_candidates'],
                             'tracking_window_instructions': 16, 'input_origin_established': False},
        'likely_operation_families': assembly['operation_families'],
        'sqrt_instruction_present': assembly['sqrt_instruction_present'],
        'important_instructions': assembly['important_instructions'],
        'coverage': {'assembly': assembly['coverage'], 'decompiler': decompiler['coverage']},
        'cross_check_status': status,
        'limitations': ['Local recognizers, not symbolic execution, formal verification or original source recovery.',
                        'Only stored resolved direct CALL edges are linked; indirect targets are never guessed.',
                        'No function-to-string xrefs or input provenance are inferred. Static analysis only; no target execution.']}
    if include_timings:
        result['timings'] = {'assembly_seconds': amid - started, 'decompiler_seconds': dmid - amid,
                             'evaluation_seconds': time.perf_counter() - dmid,
                             'total_seconds': time.perf_counter() - started}
    return result


class FunctionCrossCheckService:
    """Resolve exactly one selected stored function in one read snapshot."""
    def __init__(self, store):
        self.query = ProgramQueryService(store)

    def analyze_function(self, binary_id, function, *, by='auto', include_timings=False):
        with self.query._snapshot(binary_id) as db:
            record = self.query._resolve(db, binary_id, function, by)
            architecture = db.execute('SELECT architecture FROM binaries WHERE binary_id=?', (binary_id,)).fetchone()[0]
            rows = db.execute('''SELECT e.callsite_address, e.caller_function_id, e.callee_function_id, e.edge_type,
                f.address AS callee_address, f.current_name AS callee_name
                FROM function_edges e JOIN functions f ON f.binary_id=e.binary_id AND f.function_id=e.callee_function_id
                WHERE e.binary_id=? AND e.caller_function_id=? AND e.edge_type='CALL'
                ORDER BY e.callsite_address, e.callee_function_id LIMIT 257''', (binary_id, record.function_id)).fetchall()
            resolved = [{**dict(r), 'source_table': 'function_edges'} for r in rows[:256]]
            result = analyze_record(record, architecture=architecture, resolved_calls=resolved, include_timings=include_timings)
            if len(rows) > 256:
                result['uncertainties'].append('Resolved CALL linkage bounded to 256 rows.')
            return result


def compact_report(report):
    """Small complete machine-derived block; full report remains in audit data."""
    return {k: report[k] for k in ('policy_version', 'function', 'cross_check_status',
        'likely_operation_families', 'sqrt_instruction_present')} | {
        'agreements': report['agreements'][:3], 'disagreements': report['disagreements'],
        'uncertainties': report['uncertainties'][:3],
        'scope': 'A.I.R.E. deterministic local observations/inferences, not stored source facts or full equivalence.'}
