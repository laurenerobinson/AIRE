"""Static-only AIRE fixture indexing and M9 store checks in disposable projects.

Invoke through external_fixture_sandbox.py or your own restricted sandbox.
The default six representatives include ELF, stripped ELF, C++, PE32, PE32+,
and a negative DLL. --all also indexes the other five small ELF samples.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile

from validate_external_fixtures import DEFAULT_MANIFEST, validate


REPRESENTATIVES = {'brancher', 'cpp_classes', 'langdetect_gcc_stripped_dyn',
                   'windows_getprocaddress', 'windows_tls_x86', 'windows_invalid_export_forwarder'}
BODY_ADDRESSES = {'brancher': '00400544', 'cpp_classes': '0010129d',
                  'langdetect_gcc_stripped_dyn': '00101149', 'windows_getprocaddress': '140001480',
                  'windows_tls_x86': '00411730', 'windows_invalid_export_forwarder': '180001000'}
EXPECTED_LOCAL_STRINGS = {'langdetect_gcc_stripped_dyn': 'sum = %d',
                          'windows_getprocaddress': 'Dynamic MessageBox'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    validation = validate()
    from aire.pyghidra.indexer import index_binary
    from aire.pyghidra.options import IndexOptions
    from aire.knowledge.database import BinaryKnowledgeStore
    from aire.knowledge.investigation import InvestigationService
    from aire.agent.tools import AgentTools

    manifest = json.loads(DEFAULT_MANIFEST.read_text())
    rows = []
    for fixture in manifest['fixtures']:
        name = fixture['name']
        if not args.all and name not in REPRESENTATIVES:
            continue
        path = DEFAULT_MANIFEST.parent / fixture['binary_path']
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        print('Indexing', name, flush=True)
        # Full decompilation for six representatives; lightweight facts for others.
        index = index_binary(path, IndexOptions(decompile=name in REPRESENTATIVES))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before == fixture['binary_sha256']
        assert index.metadata['analysis_completed'] and index.metadata['input_sha256_unchanged']
        assert ('Portable Executable' if fixture['file_details']['format'] == 'PE'
                else 'Executable and Linking Format') in index.binary.format
        assert index.binary.pointer_size * 8 == fixture['file_details']['bits']
        assert index.functions and index.references
        assert any(a.type == 'STRING' for a in index.artifacts)
        assert index.function_edges or fixture['negative_fixture']
        ids = {f.function_id for f in index.functions}
        assert all(e.caller_function_id in ids and e.callee_function_id in ids for e in index.function_edges)
        application_pairs = {
            'brancher': [('main', 'read'), ('main', 'puts')],
            'basic_buffer_overflows': [('main', 'overflow_1'), ('main', 'overflow_2'), ('main', 'overflow_3')],
            'bindiff_a': [('main', 'get_num'), ('main', 'print_bad')],
            'bindiff_b': [('main', 'get_num'), ('main', 'print_good'), ('main', 'print_bad')],
            'datadep_test': [('main', 'calc_sum'), ('main', 'gen_random'), ('main', 'buf_cpy')],
        }.get(name, [])
        functions = {f.function_id: f for f in index.functions}
        observed_pairs = {(functions[e.caller_function_id].current_name,
                           functions[e.callee_function_id].current_name) for e in index.function_edges}
        assert set(application_pairs) <= observed_pairs
        if name == 'argc_decide':
            assert not any(functions[e.caller_function_id].current_name == 'main' for e in index.function_edges)
        if name == 'cpp_classes':
            address_pairs = {(functions[e.caller_function_id].address,
                              functions[e.callee_function_id].address) for e in index.function_edges}
            assert {('0010129d', '00101512'), ('0010129d', '00101262')} <= address_pairs
        if name == 'datadep_test':
            assert sum(functions[e.caller_function_id].current_name == 'main' and
                       functions[e.callee_function_id].current_name == 'buf_cpy'
                       for e in index.function_edges) == 2
        computed = [r for r in index.references if r.is_indirect]
        assert all(r.target_function_id is None for r in computed)
        representative = name in REPRESENTATIVES
        checks = {'format': True, 'sha256_unchanged': True, 'functions': True, 'strings': True,
                  'references': True, 'call_endpoints': True, 'source_call_relationships': True,
                  'computed_targets_unresolved': True}
        limitations = []
        if name == 'brancher':
            for literal in ('>10', '<20', '>=20', 'odd', 'even', '<=10'):
                if not any(a.type == 'STRING' and a.value.rstrip('\0') == literal for a in index.artifacts):
                    limitations.append('Short source literal not recovered as a STRING artifact: ' + literal)
        if representative:
            function = next(f for f in index.functions if f.address == BODY_ADDRESSES[name])
            assert function.decompiled_text and function.assembly
            with tempfile.TemporaryDirectory(prefix='aire_external_store_') as work:
                with BinaryKnowledgeStore(Path(work) / 'facts.sqlite') as store:
                    store.save_program_index(index)
                    assert store.load_program_index(index.binary.binary_id) == index
                    service = InvestigationService(store)
                    page = service.references(index.binary.binary_id, function.function_id, strings_only=True, limit=100)
                    result = AgentTools(store, index.binary.binary_id).registry.run(
                        'get_function_strings', {'function': function.function_id, 'limit': 100})
                    assert result['ok'], result
                    if name in EXPECTED_LOCAL_STRINGS:
                        assert any(EXPECTED_LOCAL_STRINGS[name] in i['artifact']['value'] for i in page['items'])
                    if name == 'brancher':
                        assert any(r.source_function_id == function.function_id and r.target_address == '004006bc'
                                   for r in index.references)
                    checks['local_string_items'] = len(page['items'])
            checks.update(store_roundtrip=True, m9_string_query=True, cached_agent_tool=True,
                          body_decompiled=True, body_assembly=True)
        counts = Counter(a.type for a in index.artifacts)
        row = dict(name=name, status='PASS', sha256=before, format=index.binary.format,
                   architecture=index.binary.architecture, ghidra_version=index.metadata['ghidra_version'],
                   functions=len(index.functions), strings=counts['STRING'], imports=counts['IMPORT'],
                   exports=counts['EXPORT'], direct_calls=len(index.function_edges), references=len(index.references),
                   computed_references=len(computed), thunks=len(index.thunks), warnings=index.warnings,
                   checks=checks, representative=representative, limitations=limitations)
        rows.append(row)
        (args.output / (name + '.index.json')).write_text(json.dumps(index.to_dict(), indent=2) + '\n')
        print('PASS', name, row['functions'], 'functions,', row['strings'], 'strings,', row['direct_calls'], 'calls', flush=True)
    summary = dict(validation=validation, passed=len(rows), failed=0, skipped=11-len(rows),
                   method='Static only; disposable Ghidra projects and temporary SQLite stores; no model invoked', results=rows)
    (args.output / 'compatibility.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
