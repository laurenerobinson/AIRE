"""Pure static semantics, false-positive barriers, SQLite scope and integration."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.analysis.assembly_semantics import extract_assembly, MAX_INSTRUCTIONS, MAX_OBSERVATIONS
from aire.analysis.decompiler_semantics import extract_decompiler
from aire.analysis.function_crosscheck import analyze_record, FunctionCrossCheckService
from aire.agent.tools import AgentTools
from aire.agent.runner import AgentRunner
from aire.agent.session import AgentSession
from aire.ai.chat import AireChatService, check_operation_contradictions, validate_multiply_register_claims
from aire.ai.chat_models import Claim, ChatError
from aire.ai.prompt_builder import build_prompt, parse_response
from aire.ai.ollama_client import GenerationResult
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import FunctionRecord
from test_retrieval import fixture
from test_agent_runner import AgentModel


def function(assembly='mov eax, dword ptr [ebp + 0x8]\nimul eax,eax\nret', decompiler='int f(int x) { return x * x; }', **kwargs):
    return FunctionRecord('b:a', 'b', '00401234', 'FUN_00401234', None, decompiler, assembly, 3, 1, 0, **kwargs)


class SemanticsTests(unittest.TestCase):
    def test_integer_square_agreement(self):
        r = analyze_record(function())
        self.assertEqual(r['cross_check_status'], 'AGREEMENT')
        self.assertEqual(r['agreements'][0]['assembly_family'], 'integer_multiplication')
        self.assertTrue(r['agreements'][0]['same_operand'])
        self.assertEqual(r['agreements'][0]['likely_pattern'], 'value_squared')
        self.assertEqual(r['data_flow_summary']['return_register_candidates'][0]['register'], 'EAX')
        self.assertFalse(r['data_flow_summary']['input_origin_established'])

    def test_double_square_agreement(self):
        r = analyze_record(function('movsd xmm0,qword ptr [ebp + 0x8]\nmulsd xmm0,qword ptr [ebp + 0x8]\nret'))
        self.assertEqual(r['cross_check_status'], 'AGREEMENT')
        self.assertEqual(r['agreements'][0]['assembly_family'], 'scalar_double_multiplication')
        self.assertTrue(r['agreements'][0]['same_operand'])

    def test_float_and_double_multiply_distinct_from_sqrt(self):
        for suffix, kind in [('SS', 'float'), ('SD', 'double')]:
            mul = extract_assembly('MUL' + suffix + ' XMM0,XMM0\nRET')
            sqrt = extract_assembly('SQRT' + suffix + ' XMM0,XMM0\nRET')
            self.assertEqual(mul['operation_families'], ['scalar_' + kind + '_multiplication'])
            self.assertFalse(mul['sqrt_instruction_present'])
            self.assertEqual(sqrt['operation_families'], ['scalar_' + kind + '_square_root'])
            self.assertTrue(sqrt['sqrt_instruction_present'])
            self.assertNotIn('likely_pattern', sqrt['observations'][0])

    def test_conflicting_sqrt_decompiler(self):
        r = analyze_record(function('mulsd xmm0,xmm0\nret', 'double f(double x) { return sqrt(x); }'))
        self.assertEqual(r['cross_check_status'], 'CONFLICT')
        self.assertIn('multiplication', r['disagreements'][0])

    def test_reverse_conflict(self):
        r = analyze_record(function('sqrtsd xmm0,xmm0\nret'))
        self.assertEqual(r['cross_check_status'], 'CONFLICT')

    def test_missing_decompiler(self):
        r = analyze_record(function(decompiler=None))
        self.assertEqual(r['cross_check_status'], 'INSUFFICIENT_EVIDENCE')
        self.assertIn('integer_multiplication', r['likely_operation_families'])

    def test_missing_and_truncated_assembly(self):
        for f in [function(assembly=None), function(assembly_truncated=True)]:
            r = analyze_record(f)
            self.assertEqual(r['cross_check_status'], 'INSUFFICIENT_EVIDENCE')
            self.assertTrue(r['uncertainties'])

    def test_generic_name_independent(self):
        a = analyze_record(function())
        b = analyze_record(replace(function(), current_name='sqrt_in_name_only'))
        for k in ('agreements', 'assembly_observations', 'decompiler_observations', 'cross_check_status'):
            self.assertEqual(a[k], b[k])

    def test_unsupported_instruction_clears_tracking(self):
        r = analyze_record(function('mov eax,dword ptr [ebp+8]\nFUTUREOP eax\nimul eax,dword ptr [ebp+8]\nret'))
        self.assertIn('FUTUREOP', r['coverage']['assembly']['unsupported_mnemonics'])
        self.assertFalse(r['assembly_observations'][0]['same_operand'])
        self.assertNotEqual(r['cross_check_status'], 'AGREEMENT')

    def test_bounded_long_inputs(self):
        r = analyze_record(function('imul eax,eax\n' * 50000, 'int f() { ' + 'x=x*x;' * 50000 + 'return x; }'))
        self.assertLessEqual(r['coverage']['assembly']['parsed_instructions'], MAX_INSTRUCTIONS)
        self.assertLessEqual(len(r['assembly_observations']), MAX_OBSERVATIONS)
        self.assertLessEqual(len(r['decompiler_observations']), MAX_OBSERVATIONS)
        self.assertEqual(r['cross_check_status'], 'INSUFFICIENT_EVIDENCE')
        self.assertLess(len(json.dumps(r)), 60000)

    def test_call_and_store_barriers(self):
        for barrier in ['call 00401000', 'mov dword ptr [ebp+8],edx', 'jmp 00401000', 'mov al,3']:
            r = extract_assembly('mov eax,dword ptr [ebp+8]\n' + barrier + '\nimul eax,dword ptr [ebp+8]\nret')
            mul = next(o for o in r['observations'] if o['operation_family'] == 'integer_multiplication')
            self.assertFalse(mul['same_operand'], barrier)

    def test_base_register_changes_break_memory_identity(self):
        r = extract_assembly('mov eax,dword ptr [ebp+8]\nadd ebp,4\nimul eax,dword ptr [ebp+8]\nret')
        self.assertFalse(r['observations'][1]['same_operand'])

    def test_three_operand_multiply_not_square(self):
        r = extract_assembly('imul eax,ecx,4\nret')
        self.assertFalse(r['observations'][0]['same_operand'])
        self.assertNotIn('likely_pattern', r['observations'][0])

    def test_scalar_width_change_breaks_identity(self):
        r = extract_assembly('movsd xmm0,qword ptr [ebp+8]\nmovss xmm1,xmm0\nmulsd xmm1,qword ptr [ebp+8]\nret')
        self.assertFalse(r['observations'][0]['same_operand'])

    def test_malformed_line_breaks_identity(self):
        r = extract_assembly('mov eax,dword ptr [ebp+8]\n?? invalid ??\nimul eax,dword ptr [ebp+8]\nret')
        self.assertFalse(r['observations'][0]['same_operand'])
        self.assertEqual(r['coverage']['malformed_lines'], 1)

    def test_ambiguous_callsite_not_selected(self):
        r = extract_assembly('00401000: call 0x00402000', resolved_calls=[
            {'callsite_address': '00401000', 'callee_function_id': 'b:z'},
            {'callsite_address': '00401000', 'callee_function_id': 'b:x'}])
        self.assertEqual(r['observations'][0]['resolution'], 'ambiguous_stored_call')

    def test_window_expiration(self):
        r = extract_assembly('mov eax,dword ptr [ebp+8]\n' + 'nop\n' * 17 + 'imul eax,dword ptr [ebp+8]\nret')
        self.assertFalse(r['observations'][0]['same_operand'])

    def test_arbitrary_multiplication_not_square(self):
        self.assertFalse(extract_assembly('imul eax,edx\nret')['observations'][0]['same_operand'])

    def test_condition_loop_return_counts(self):
        r = extract_assembly('00401000: cmp eax,2\n00401003: jne 0x00401000\n00401005: jmp 0x00401009\n00401009: ret')
        self.assertEqual(r['control_flow']['conditional_branch_count'], 1)
        self.assertEqual(r['control_flow']['unconditional_branch_count'], 1)
        self.assertEqual(r['control_flow']['backward_branch_count'], 1)

    def test_direct_and_indirect_calls(self):
        r = extract_assembly('00401000: call 0x00402000\n00401005: call eax\n00401008: call dword ptr [ebp+8]\nret',
            resolved_calls=[{'callsite_address': '00401000', 'callee_function_id': 'b:z'}])
        self.assertEqual([o['resolution'] for o in r['observations']], ['resolved_stored_call', 'indirect_call_unresolved', 'indirect_call_unresolved'])

    def test_unresolved_call_does_not_exclude_sqrt(self):
        r = analyze_record(function('imul eax,eax\ncall 00402000\nret', 'int f(int x) { return sqrt(x); }'))
        self.assertNotEqual(r['cross_check_status'], 'CONFLICT')

    def test_unsupported_architecture(self):
        r = analyze_record(function(), architecture='ARM:LE:32')
        self.assertEqual(r['cross_check_status'], 'INSUFFICIENT_EVIDENCE')
        self.assertFalse(r['assembly_observations'])

    def test_decompiler_comments_strings_and_names_ignored(self):
        r = extract_decompiler('int sqrt_name(int x) { /* return sqrt(x); */ puts("return sqrt(x);"); return x*x; }')
        self.assertEqual([o['operation'] for o in r['observations']], ['multiplication'])

    def test_decompiler_parentheses_casts_and_concat(self):
        r = extract_decompiler('float10 f(int a,int b) { return (float10)((double)CONCAT44(b,a) * (double)CONCAT44(b,a)); }')
        self.assertTrue(r['observations'][0]['same_operand'])
        self.assertEqual(r['coverage']['unrecognized_expressions'], 0)

    def test_decompiler_calls_not_assumed_pure(self):
        r = extract_decompiler('int f() { return helper() * helper(); }')
        self.assertFalse(r['observations'][0]['same_operand'])

    def test_decompiler_constants_and_conditions(self):
        r = extract_decompiler('int f(int x) { if (x > 5) { x=x+3; } return x-2; }')
        self.assertEqual({o['operation'] for o in r['observations']}, {'comparison', 'addition', 'subtraction'})
        self.assertEqual(r['conditional_expression_count'], 1)

    def test_all_supported_families(self):
        for mnemonic in ['ADD','SUB','INC','DEC','MUL','IMUL','DIV','IDIV','NEG','AND','OR','XOR','NOT','SHL','SHR','SAR','ROL','ROR','CMP','TEST','ADDSS','ADDSD','SUBSS','SUBSD','DIVSS','DIVSD','COMISS','COMISD','UCOMISS','UCOMISD']:
            self.assertTrue(extract_assembly(mnemonic + ' EAX,EDX')['operation_families'], mnemonic)

    def test_thunk_no_false_conflict(self):
        r = analyze_record(function('jmp 0x00402000', is_thunk=True))
        self.assertEqual(r['cross_check_status'], 'INSUFFICIENT_EVIDENCE')


class CrosscheckIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'facts.sqlite')
        self.addCleanup(self.store.close)
        self.index, self.f = fixture()
        self.index.binary.architecture = 'x86:LE:64:default'
        self.f['a'].assembly = function().assembly
        self.f['a'].decompiled_text = function().decompiled_text
        self.store.save_program_index(self.index)
        self.tools = AgentTools(self.store, 'b')

    def test_exact_selectors_scope_and_read_only(self):
        before = self.store._db.total_changes
        service = FunctionCrossCheckService(self.store)
        for selector in ('b:a', self.f['a'].address, self.f['a'].current_name):
            self.assertEqual(service.analyze_function('b', selector)['cross_check_status'], 'AGREEMENT')
        other, _ = fixture('other')
        self.store.save_program_index(other)
        before = self.store._db.total_changes
        self.assertFalse(self.tools.registry.run('crosscheck_function', {'function': 'other:a'})['ok'])
        self.assertEqual(self.store._db.total_changes, before)

    def test_deterministic_database_order_and_provenance(self):
        first = self.tools.crosscheck('b:a')
        self.index.functions.reverse()
        self.index.function_edges.reverse()
        self.store.save_program_index(self.index)
        self.assertEqual(first, self.tools.crosscheck('b:a'))
        self.assertEqual(first['provenance']['source_id'], 'b:a')
        self.assertEqual(len(first['provenance']['assembly_sha256']), 64)

    def test_selected_body_only(self):
        with patch.object(self.tools.query, '_resolve', wraps=self.tools.query._resolve) as resolve:
            self.tools.evidence('b:a')
        self.assertLessEqual(len(self.tools.last_evidence.metadata['function_crosschecks']), 1)
        with patch.object(self.store, 'load_program_index', side_effect=AssertionError('bulk body load')):
            self.assertEqual(self.tools.crosscheck('b:a')['cross_check_status'], 'AGREEMENT')

    def test_tool_schema_count_and_validation(self):
        self.assertEqual(len(self.tools.registry.catalog()), 18)
        self.assertFalse(self.tools.registry.run('crosscheck_function', {})['ok'])
        self.assertFalse(self.tools.registry.run('crosscheck_function', {'function': 'start', 'binary_id': 'other'})['ok'])

    def test_agent_semantic_route_no_planning(self):
        model = AgentModel()
        result = AgentRunner(self.store, model).run(AgentSession('b'), 'Explain start and verify the decompiler against assembly.')
        self.assertEqual(result.status, 'completed')
        self.assertIn('crosscheck_function', [r['tool'] for r in result.tool_results])
        self.assertEqual(len(model.calls), 1)
        self.assertIn('CROSSCHECK', model.calls[0])

    def test_compare_two_functions(self):
        result = AgentRunner(self.store, AgentModel()).run(AgentSession('b'), 'Compare start and join assembly.')
        self.assertEqual(result.status, 'completed')
        self.assertEqual(len(result.response.evidence_bundle.metadata['function_crosschecks']), 2)

    def prepared(self, compact=False):
        self.tools.evidence('b:a')
        return build_prompt('Explain', self.tools.last_evidence, policy='test', compact=compact)

    def test_prompt_citations_and_fact_separation(self):
        for compact in (False, True):
            p = self.prepared(compact)
            identity = next(i for i, c in p.citations.items() if c.kind == 'CROSSCHECK')
            self.assertIn('instruction', p.system)
            raw = json.dumps({'summary': {'claim':'test','evidence_ids':[identity]}, 'fact_ids':[identity], 'interpretations':[], 'uncertainties':[]})
            with self.assertRaises(ChatError):
                parse_response(raw, p.citations)
            self.assertLessEqual(p.context_characters, 8000)

    def test_source_code_and_calls_survive_large_derived_report(self):
        self.tools.evidence('b:a', max_chars=6000)
        bundle = self.tools.last_evidence
        bundle.metadata['function_crosschecks'][0]['uncertainties'] = ['Analysis caveat: ' + 'x' * 4400]
        prompt = build_prompt('Explain start', bundle, policy='test')
        catalog = [json.loads(line) for line in prompt.text.splitlines() if line.startswith('{"data":')]
        target = next(row for row in catalog if row['kind'] == 'FUNC')
        self.assertTrue(target['data']['function']['assembly'])
        self.assertTrue(target['data']['function']['decompiled_text'])
        self.assertTrue(any(row['kind'] == 'EDGE' for row in catalog))
        self.assertLessEqual(prompt.context_characters, 6000)
        self.assertTrue(any(t.category == 'prompt_item' for t in prompt.truncations))

    def test_absent_multiply_register_rejected_in_cited_function(self):
        prompt = self.prepared()
        identity = next(i for i, c in prompt.citations.items() if c.kind == 'FUNC')
        for text in ('The IMUL instruction multiplies the EAX and EDX registers.',
                     'The imul instruction multiplies the eax and edx registers.'):
            with self.subTest(text=text), self.assertRaisesRegex(ChatError, 'EDX'):
                validate_multiply_register_claims([Claim(text, (identity,))], self.tools.last_evidence, prompt.citations)
        for text in ('The IMUL instruction uses the EAX register.',
                     'The IMUL instruction does not use the EDX register.'):
            validate_multiply_register_claims([Claim(text, (identity,))], self.tools.last_evidence, prompt.citations)

    def test_register_guard_defers_implicit_operands_and_incomplete_code(self):
        for assembly, truncated in (('imul ecx\nret', False), ('imul eax,eax\nret', True),
                                    ('?? invalid ??\nimul eax,eax\nret', False)):
            with self.subTest(assembly=assembly, truncated=truncated):
                self.f['a'].assembly = assembly
                self.f['a'].assembly_truncated = truncated
                self.store.save_program_index(self.index)
                prompt = self.prepared()
                identity = next(i for i, c in prompt.citations.items() if c.kind == 'FUNC')
                validate_multiply_register_claims([Claim('The IMUL instruction uses EAX and EDX registers.',
                    (identity,))], self.tools.last_evidence, prompt.citations)

    def test_bad_register_interpretation_omitted_without_extra_inference(self):
        self.tools.evidence('b:a')
        class WrongRegisterModel:
            calls = 0
            def generate(model, prompt, **kwargs):
                model.calls += 1
                catalog = [json.loads(line) for line in prompt.splitlines() if line.startswith('{"data":')]
                identity = next(row['id'] for row in catalog if row['kind'] == 'FUNC')
                return GenerationResult(json.dumps({'summary': {'claim': 'The function multiplies its argument by itself.',
                    'evidence_ids': [identity]}, 'fact_ids': [], 'interpretations': [{
                    'claim': 'The IMUL instruction multiplies the EAX and EDX registers.',
                    'evidence_ids': [identity], 'confidence': 'high'}], 'uncertainties': []}), 'mock', 0)
        for compact in (False, True):
            with self.subTest(compact=compact):
                client = WrongRegisterModel()
                response = AireChatService(self.store, client).ask('b', 'Explain start', 'b:a',
                    evidence_bundle=self.tools.last_evidence, require_behavior_grounding=True, compact=compact)
                self.assertEqual(client.calls, 1)
                self.assertFalse(response.interpretations)
                self.assertTrue(any('EDX' in text and 'omitted' in text for text in response.uncertainties))

    def test_narrow_model_contradiction_warning(self):
        p = self.prepared()
        identity = next(i for i, c in p.citations.items() if c.kind == 'CROSSCHECK')
        claim = Claim('This function computes the square root.', (identity,))
        summary, interpretations, warnings = check_operation_contradictions(claim, [claim], self.tools.last_evidence, p.citations)
        self.assertIn('multiplication', summary.claim)
        self.assertFalse(interpretations)
        self.assertTrue(warnings)
        negative = Claim('This function does not compute a square root.', (identity,))
        self.assertEqual(check_operation_contradictions(negative, [], self.tools.last_evidence, p.citations)[0], negative)

    def test_contradiction_guard_disabled_for_helper_calls(self):
        self.f['a'].assembly = 'imul eax,eax\ncall 00401000\nret'
        self.store.save_program_index(self.index)
        p = self.prepared()
        identity = next(i for i, c in p.citations.items() if c.kind == 'CROSSCHECK')
        claim = Claim('This function computes a square root.', (identity,))
        self.assertFalse(check_operation_contradictions(claim, [], self.tools.last_evidence, p.citations)[2])

    def test_model_contradiction_sanitized_without_extra_inference(self):
        self.tools.evidence('b:a')
        class WrongModel:
            calls = 0
            def generate(model, prompt, **kwargs):
                model.calls += 1
                catalog = [json.loads(line) for line in prompt.splitlines() if line.startswith('{"data":')]
                identity = next(i['id'] for i in catalog if i['kind'] == 'CROSSCHECK')
                return GenerationResult(json.dumps({'summary': {'claim': 'This function computes a square root.', 'evidence_ids': [identity]},
                    'fact_ids': [], 'interpretations': [], 'uncertainties': []}), 'mock', 0)
        client = WrongModel()
        response = AireChatService(self.store, client).ask('b', 'Explain start', 'b:a',
            evidence_bundle=self.tools.last_evidence, require_behavior_grounding=True)
        self.assertEqual(client.calls, 1)
        self.assertIn('multiplication', response.summary.claim)
        self.assertTrue(any('AI interpretation conflicts' in s for s in response.uncertainties))

    def test_crosscheck_metadata_cannot_create_code_grounding(self):
        self.f['a'].assembly = None
        self.f['a'].decompiled_text = None
        self.index.function_edges = []
        self.store.save_program_index(self.index)
        self.tools.evidence('b:a')
        client = AgentModel()
        with self.assertRaises(ChatError):
            AireChatService(self.store, client).ask('b', 'Explain start', 'b:a',
                evidence_bundle=self.tools.last_evidence, require_behavior_grounding=True)
        self.assertFalse(client.calls)

    def test_tool_transport_compact_audit_report_complete(self):
        data = self.tools.evidence('b:a')
        self.assertNotIn('assembly_observations', data['metadata']['function_crosschecks'][0])
        self.assertIn('assembly_observations', self.tools.last_evidence.metadata['function_crosschecks'][0])
        self.assertIn('assembly_observations', self.tools.registry.run('crosscheck_function', {'function': 'b:a'})['data'])
