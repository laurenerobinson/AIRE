"""Application relevance is separate from M3; no model, JVM or target access."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.agent.tools import AgentTools
from aire.ai.context_builder import ContextBuilder
from aire.ai.evidence_selector import OverviewContextBuilder, overview_code_excerpt
from aire.ai.prompt_builder import build_prompt
from test_chat import catalog_from_prompt
from aire.knowledge.application_relevance import ApplicationRelevanceService, classify
from aire.knowledge.database import BinaryKnowledgeStore, BinaryNotFoundError
from aire.knowledge.evidence import EvidenceRequest
from aire.knowledge.models import BinaryRecord, FunctionEdge, FunctionRecord, ProgramIndex
from aire.knowledge.retrieval import ProgramQueryService


def program(names, edges, *, entry=None):
    fs = [FunctionRecord('b:' + str(i), 'b', f'{0x1000 + i * 16:08x}', n,
          None, 'int f(int x) { return x*x; }', '1000: RET', 12, 2, 1)
          for i, n in enumerate(names)]
    binary = BinaryRecord('b', '/never/opened', 'b', 'PE', 'x86:LE:32:default', '0', None,
                          entry_point=fs[entry].address if entry is not None else None)
    return ProgramIndex(binary, fs, function_edges=[
        FunctionEdge(fs[a].function_id, fs[b].function_id, f'{0x2000 + i:x}', 'CALL')
        for i, (a, b) in enumerate(edges)])


class RelevanceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'facts.sqlite')
        self.addCleanup(self.store.close)
        self.service = ApplicationRelevanceService(self.store)

    def rank(self, index, limit=100):
        self.store.save_program_index(index)
        return self.service.rank_application_functions('b', limit=limit)

    def bridge_program(self):
        return program(['entry', '__scrt_common_main', 'invoke_main', 'application_main', 'foo', 'bar'],
                       [(0, 1), (1, 2), (2, 3), (3, 4), (3, 5)], entry=0)

    def test_runtime_connectivity_wins_m3_and_loses_application_ranking(self):
        index = program(['__scrt_common_main', '__acrt_one', '__crt_two', '__vcrt_three',
                         'main', 'handle_input', 'calculate'],
                        [(0, 1), (0, 2), (0, 3), (4, 5), (5, 6)])
        rows = self.rank(index)['items']
        runtime = next(i for i, r in enumerate(rows) if r['function']['current_name'] == '__scrt_common_main')
        self.assertTrue(all(next(i for i, r in enumerate(rows) if r['function']['current_name'] == n)
                            < runtime for n in ('main', 'handle_input', 'calculate')))
        connectivity = ProgramQueryService(self.store).rank_functions('b', metric='unique_callees')
        self.assertEqual(connectivity[0].function.current_name, '__scrt_common_main')
        self.assertEqual(connectivity[0].unique_callees, 3)
        with self.assertRaises(ValueError):
            ProgramQueryService(self.store).rank_functions('b', metric='importance')

    def test_runtime_bridge_promotes_first_application_descendant(self):
        index = self.bridge_program()
        result = self.rank(index)
        rows = result['items']
        self.assertEqual([r['function']['current_name'] for r in rows[:3]], ['application_main', 'foo', 'bar'])
        self.assertIn('invoke_main', ' '.join(rows[0]['reasons']))
        self.assertEqual(len(rows[0]['path']), 3)
        bundle = OverviewContextBuilder(self.store).build(EvidenceRequest('b', max_functions=3))
        self.assertEqual([f.function.current_name for f in bundle.functions], ['application_main', 'foo', 'bar'])
        self.assertTrue(all(e.edge.edge_type == 'CALL' for e in bundle.edges))

    def test_stripped_elf_and_double_underscore_user_functions_stay_eligible(self):
        index = program(['_start', 'FUN_00001010', 'FUN_00001020', '__custom_algorithm'],
                        [(0, 1), (1, 2), (1, 3)], entry=0)
        index.binary.format = 'ELF'
        rows = self.rank(index)['items']
        types = {r['function']['current_name']: r['classification'] for r in rows}
        self.assertEqual(types['FUN_00001010'], 'UNKNOWN_INTERNAL')
        self.assertEqual(types['FUN_00001020'], 'UNKNOWN_INTERNAL')
        self.assertEqual(types['__custom_algorithm'], 'APPLICATION_CANDIDATE')
        self.assertEqual(rows[0]['function']['current_name'], 'FUN_00001010')

    def test_external_and_thunk_cannot_dominate(self):
        index = program(['outside', 'forwarder', 'work'], [(0, 1), (0, 2), (1, 2)])
        index.functions[0].is_external = True
        index.functions[1].is_thunk = True
        rows = self.rank(index)['items']
        self.assertEqual([r['classification'] for r in rows], ['APPLICATION_CANDIDATE', 'THUNK', 'EXTERNAL'])

    def test_order_and_reasons_are_independent_of_insert_order(self):
        index = self.bridge_program()
        first = self.rank(index)
        first_bundle = OverviewContextBuilder(self.store).build(EvidenceRequest('b', max_functions=3))
        index.functions.reverse()
        index.function_edges.reverse()
        index.function_edges.append(index.function_edges[0])
        self.assertEqual(first, self.rank(index))
        second = OverviewContextBuilder(self.store).build(EvidenceRequest('b', max_functions=3))
        self.assertEqual(first_bundle.to_dict(include_timings=False), second.to_dict(include_timings=False))
        json.dumps(first)

    def test_numeric_address_tie_break(self):
        index = program(['same', 'same'], [])
        index.functions[0].address = '10'
        index.functions[1].address = '2'
        self.assertEqual(self.rank(index)['items'][0]['function']['address'], '2')

    def test_large_graph_traversal_output_and_body_loading_are_bounded(self):
        index = program(['main'] + [f'FUN_{i:08x}' for i in range(1, 1800)],
                        [(0, i) for i in range(1, 1800)])
        for f in index.functions:
            f.decompiled_text = 'x' * 5000
            f.assembly = 'y' * 5000
        self.store.save_program_index(index)
        statements = []
        self.store._db.set_trace_callback(statements.append)
        changes = self.store._db.total_changes
        with patch.object(self.store, 'load_program_index', side_effect=AssertionError('bulk load')):
            result = self.service.rank_application_functions('b', limit=6)
            self.assertEqual(len(result['items']), 6)
            self.assertFalse(any('SELECT * FROM functions' in s for s in statements))
            self.assertFalse(any('decompiled_text' in r['function'] for r in result['items']))
            builder = OverviewContextBuilder(self.store)
            with patch.object(builder.query, '_resolve', wraps=builder.query._resolve) as resolve:
                bundle = builder.build(EvidenceRequest('b', max_functions=6, max_edges=12, max_total_chars=8000))
                self.assertEqual(resolve.call_count, 6)
                self.assertEqual(len(bundle.functions), 6)
                self.assertLessEqual(len(bundle.edges), 12)
        for name in ('visited_nodes', 'application_visited_nodes'):
            self.assertLessEqual(result['diagnostics'][name], self.service.MAX_VISITS)
        for name in ('scanned_links', 'application_scanned_links'):
            self.assertLessEqual(result['diagnostics'][name], self.service.MAX_LINKS)
        self.assertTrue(result['diagnostics']['traversal_truncated'])
        self.assertEqual(changes, self.store._db.total_changes)

    def test_depth_cycle_and_missing_path_are_bounded(self):
        index = program(['_start'] + [f'FUN_{i:08x}' for i in range(1, 30)],
                        [(i, i + 1) for i in range(29)] + [(5, 1)], entry=0)
        rows = self.rank(index)
        self.assertTrue(rows['diagnostics']['traversal_truncated'])
        self.assertTrue(all(len(r['path']) <= self.service.MAX_DEPTH for r in rows['items']))
        self.assertIn('not proof', rows['diagnostics']['scope'])

    def test_literal_thunk_jump_is_traversal_only_not_call_edge(self):
        index = program(['invoke_main', 'thunk', 'FUN_00001020', 'work'], [(0, 1), (2, 3)])
        index.functions[1].is_thunk = True
        index.functions[1].instruction_count = 1
        index.functions[1].assembly = '00001010: JMP 0x00001020'
        rows = self.rank(index)['items']
        self.assertEqual(rows[0]['function']['current_name'], 'FUN_00001020')
        self.assertEqual(rows[0]['path'][-1]['kind'], 'THUNK_JUMP')
        bundle = OverviewContextBuilder(self.store).build(EvidenceRequest('b', max_functions=2))
        actual = {(e.edge.caller_function_id, e.edge.callee_function_id) for e in bundle.edges}
        self.assertNotIn(('b:1', 'b:2'), actual)
        self.assertEqual(len(ProgramQueryService(self.store).get_callees('b', 'b:1')), 0)

    def test_indirect_or_multi_instruction_thunks_are_not_guessed(self):
        for assembly, count in [('00001010: JMP EAX', 1),
                                ('00001010: JMP [0x00001020]', 1),
                                ('00001010: JMP 0x00001020', 2)]:
            index = program(['invoke_main', 'thunk', 'FUN_00001020'], [(0, 1)])
            index.functions[1].is_thunk = True
            index.functions[1].instruction_count = count
            index.functions[1].assembly = assembly
            rows = self.rank(index)['items']
            candidate = next(r for r in rows if r['function']['current_name'] == 'FUN_00001020')
            self.assertFalse(candidate['path'])
            self.assertFalse(any('after bridge' in r for r in candidate['reasons']))

    def test_symbol_families_namespace_and_unreliable_library_flag(self):
        names = ['___scrt_initialize_crt', 'FID_conflict:___scrt_initialize_crt',
                 '__security_check_cookie', '__acrt_initialize', '__vcrt_cleanup',
                 '__crt_exit', '__libc_csu_init', 'frame_dummy', 'register_tm_clones',
                 '__RTC_CheckEsp', 'pre_cpp_initialization', 'user_policy']
        index = program(names, [])
        index.functions[-1].namespace = '__scrt_main_policy'
        rows = self.rank(index)['items']
        self.assertTrue(all(r['classification'] == 'RUNTIME' for r in rows))
        user = program(['__my_algorithm'], [])
        user.functions[0].is_library = True
        self.assertEqual(self.rank(user)['items'][0]['classification'], 'APPLICATION_CANDIDATE')

    def test_explicit_target_preserved_and_runtime_seed_hint_cannot_override(self):
        index = self.bridge_program()
        self.rank(index)
        request = EvidenceRequest('b', target='b:1')
        self.assertEqual(ContextBuilder(self.store).build(request).to_dict(include_timings=False),
            OverviewContextBuilder(self.store).build(request).to_dict(include_timings=False))
        bundle = OverviewContextBuilder(self.store, seed_functions=['b:1']).build(
            EvidenceRequest('b', max_functions=3))
        self.assertNotIn('__scrt_common_main', [f.function.current_name for f in bundle.functions])

    def test_tool_provenance_json_and_validation(self):
        self.rank(self.bridge_program())
        tools = AgentTools(self.store, 'b')
        result = tools.registry.run('rank_application_functions', {'limit': 3})
        self.assertTrue(result['ok'])
        self.assertEqual(result['data']['items'][0]['provenance']['source_table'], 'functions')
        json.dumps(result)
        for limit in (0, -1, True, 1.5, 101):
            with self.assertRaises(ValueError):
                self.service.rank_application_functions('b', limit=limit)
        with self.assertRaises(BinaryNotFoundError):
            self.service.rank_application_functions('missing')

    def test_bounded_overview_excerpt_keeps_declarations_and_final_operation(self):
        text = 'int f(int x) {' + ' /* compiler setup */' * 100 + 'return x*x; }'
        excerpt = overview_code_excerpt(text, 400)
        self.assertEqual(len(excerpt), 400)
        self.assertTrue(excerpt.startswith('int f'))
        self.assertTrue(excerpt.endswith('return x*x; }'))
        self.assertIn('middle omitted', excerpt)

    def test_three_priority_functions_keep_both_code_types_in_compact_budget(self):
        index = program(['main', 'integer_op', 'floating_op'], [(0, 1), (0, 2)])
        for f, instruction in zip(index.functions, ('CALL', 'IMUL', 'MULSD')):
            f.decompiled_text = f'int {f.current_name}(int x) {{' + ' /* setup */' * 100 + 'return x*x; }'
            f.assembly = '1000: PUSH EBP\n' + '1001: MOV EAX,EBX\n' * 100 + f'1800: {instruction} X,Y\n1804: RET'
        self.rank(index)
        bundle = OverviewContextBuilder(self.store).build(EvidenceRequest('b', max_functions=3,
            max_decompiled_chars_per_function=900, max_assembly_chars_per_function=1800,
            max_total_chars=60000))
        bundle.request_summary['max_total_chars'] = 5000
        prompt = build_prompt('Compare their assembly', bundle, policy='overview', compact=True)
        self.assertEqual(prompt.code_source_ids, {f.function_id for f in index.functions})
        code = [c['data'] for c in catalog_from_prompt(prompt.text) if c['kind'] == 'FUNC']
        self.assertEqual(len(code), 3)
        self.assertTrue(all('return x*x' in f['decompiled_text'] for f in code))
        self.assertIn('IMUL', code[1]['assembly'])
        self.assertIn('MULSD', code[2]['assembly'])
        self.assertLessEqual(prompt.context_characters, 5000)


if __name__ == '__main__':
    unittest.main()
