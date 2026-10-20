"""Read-only stored PE/ELF cross-check validation; optional static stripped indexing.

Never executes a target. --index-stripped uses a disposable database/project.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import tempfile

from aire.analysis.function_crosscheck import FunctionCrossCheckService
from aire.agent.binary_scope import resolve_binary
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.retrieval import ProgramQueryService
from aire.security.rule_engine import _ReadOnlyRuleStore


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(store, binary_id, selectors):
    service = FunctionCrossCheckService(store)
    reports = []
    for selector in selectors:
        repetitions = [service.analyze_function(binary_id, selector, include_timings=True) for _ in range(11)]
        report = repetitions[-1]
        report['median_timings'] = {k: statistics.median(r['timings'][k] for r in repetitions) for k in report['timings']}
        reports.append(report)
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=Path('analysis.sqlite'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--index-stripped', action='store_true')
    args = parser.parse_args()
    pe = Path('professor_samples/function_overloading/original/FunctionOverloading.exe')
    elf = Path('tests/fixtures/simple_elf/aire_test_binary')
    stripped = Path('tests/fixtures/simple_elf/aire_test_binary_stripped')
    before = {str(p): digest(p) for p in (pe, elf, stripped, args.database)}
    result = {'hashes_before': before, 'binaries': []}
    with _ReadOnlyRuleStore(args.database) as store:
        pe_id, elf_id = resolve_binary(store, str(pe)).binary_id, resolve_binary(store, str(elf)).binary_id
        result['binaries'].append({'name': 'professor_pe', 'reports': measure(store, pe_id,
            ['00412620', '004126c0', '00412790'])})
        names = ['add_values', 'multiply_values', 'choose_operation', 'calculate_checksum']
        query = ProgramQueryService(store)
        selectors = [name for name in names if query.find_functions(elf_id, name)]
        addresses = [query.resolve_function(elf_id, name).address for name in selectors]
        result['binaries'].append({'name': 'small_elf', 'reports': measure(store, elf_id, selectors)})
    if args.index_stripped:
        from aire.pyghidra.indexer import index_binary
        index = index_binary(stripped)
        with tempfile.TemporaryDirectory(prefix='aire-crosscheck-') as directory:
            with BinaryKnowledgeStore(Path(directory) / 'stripped.sqlite') as store:
                store.save_program_index(index)
                available = {f.address for f in index.functions}
                selected = [a for a in addresses if a in available]
                result['binaries'].append({'name': 'stripped_elf', 'reports': measure(store, index.binary.binary_id, selected),
                                          'static_index_metadata': index.metadata})
    result['hashes_after'] = {str(p): digest(p) for p in (pe, elf, stripped, args.database)}
    result['hashes_unchanged'] = result['hashes_before'] == result['hashes_after']
    if not result['hashes_unchanged']:
        raise RuntimeError('Input/database hash changed')
    if before[str(pe)] != 'cfc8c5f031587c721d680d3dd9bd94bbc690667acf8651403fb8c7e70f2fab07':
        raise RuntimeError('Professor PE differs from the expected sample')
    integer, double, coordinator = result['binaries'][0]['reports']
    for report, family in [(integer, 'integer_multiplication'), (double, 'scalar_double_multiplication')]:
        assert family in report['likely_operation_families'], report['function']
        assert any(r.get('assembly_family') == family and r.get('likely_pattern') == 'value_squared'
                   for r in report['agreements']), report['function']
        assert report['sqrt_instruction_present'] is False
    assert coordinator['control_flow_summary']['call_count'] > 0
    for binary in result['binaries'][1:]:
        reports = binary['reports']
        assert len(reports) == 4, 'Expected all four representative function addresses'
        for report, family in zip(reports[:2], ['integer_addition', 'integer_multiplication']):
            assert family in report['likely_operation_families']
            assert report['cross_check_status'] == 'AGREEMENT'
        if binary['name'] == 'stripped_elf':
            assert all(r['function']['current_name'].startswith('FUN_') for r in reports)
    result['acceptance_checks_passed'] = True
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    for binary in result['binaries']:
        for report in binary['reports']:
            print(binary['name'], report['function']['current_name'], report['cross_check_status'],
                  report['likely_operation_families'], report['agreements'], report['median_timings'])


if __name__ == '__main__':
    main()
