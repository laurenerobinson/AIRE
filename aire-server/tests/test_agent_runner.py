import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.agent.runner import AgentLimits, AgentRunner, parse_action, action_schema, render_tool_facts
from aire.agent.session import AgentSession
from aire.agent.tools import AgentTools
from aire.ai.chat import AireChatService
from aire.ai.chat_models import ChatRequest
from aire.ai.ollama_client import GenerationResult
from aire.knowledge.database import BinaryKnowledgeStore
from test_chat import valid_output, catalog_from_prompt
from test_retrieval import fixture


class AgentModel:
    def __init__(self, actions=()):
        self.actions = list(actions)
        self.calls = []

    def generate(self, prompt, **kwargs):
        self.calls.append(prompt)
        if 'current_function_id' in prompt:
            action = self.actions.pop(0) if self.actions else {'action': 'answer'}
            text = action if isinstance(action, str) else json.dumps(action)
        else:
            text = valid_output(prompt)
        return GenerationResult(text, 'mock', 0)


def tool(name, **arguments):
    return {'action': 'tool', 'tool': name, 'arguments': arguments}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'facts.sqlite')
        self.addCleanup(self.store.close)
        self.index, self.functions = fixture()
        self.functions['a'].decompiled_text = 'void start() { shared(); }'
        self.functions['a'].assembly = 'CALL 10'
        self.store.save_program_index(self.index)
        self.session = AgentSession('b')

    def run_agent(self, actions=(), question='Explain this function', **options):
        self.model = AgentModel(actions)
        return AgentRunner(self.store, self.model, **options).run(self.session, question)

    def test_termination_grounding_and_events(self):
        result = self.run_agent([tool('get_function', function='start'), tool('get_callees', function='it')])
        self.assertEqual(result.status, 'completed')
        self.assertEqual(self.session.current_function_id, 'b:a')
        self.assertEqual(result.response.target, 'b:a')
        self.assertEqual(result.events[0].event_type, 'agent_started')
        self.assertEqual(result.events[-1].event_type, 'agent_finished')
        self.assertIn('get_callees', self.model.calls[2])
        for claim in [result.response.summary] + result.response.facts + result.response.interpretations:
            self.assertTrue(set(claim.evidence_ids).issubset(result.response.citations))
        json.dumps(result.to_dict())

    def test_current_function_follow_up(self):
        self.session.current_function_id = 'b:a'
        result = self.run_agent([tool('get_callers', function='it')], question='What calls it?')
        self.assertTrue(result.tool_results[0]['ok'])
        self.assertEqual(result.tool_results[0]['data']['selected_function']['function']['function_id'], 'b:a')

    def test_explicit_symbol_resolves_without_model_guess(self):
        result = self.run_agent(question='Why is start important?')
        self.assertEqual(result.tool_results[0]['tool'], 'get_function')
        self.assertEqual(result.response.target, 'b:a')

    def test_required_graph_queries_when_model_stops_early(self):
        result = self.run_agent(question='Show me the most important functions.')
        self.assertEqual(result.tool_results[0]['tool'], 'rank_functions')
        self.assertIn('Connectivity ranking', result.answer)
        self.assertEqual(len(self.model.calls), 1, 'Exact graph results do not require model synthesis')
        self.assertIsNone(result.response)
        self.session.current_function_id = 'b:a'
        result = self.run_agent(question='What calls it?')
        self.assertEqual(result.tool_results[0]['tool'], 'get_callers')
        self.assertIn('join -> start', result.answer)

    def test_requested_code_modalities_rendered_from_final_evidence(self):
        self.session.current_function_id = 'b:a'
        result = self.run_agent(question='Explain this function using decompiled code and assembly.')
        self.assertIn('void start()', result.answer)
        self.assertIn('CALL 10', result.answer)

    def test_missing_pronoun_selection_and_required_query_budget(self):
        result = self.run_agent(question='What calls it?')
        self.assertEqual(result.status, 'no_current_function')
        result = self.run_agent(question='Show me the most important functions.', limits=AgentLimits(max_tool_calls=1))
        self.assertEqual(result.status, 'partial')
        self.assertLessEqual(len(result.tool_results), 1)

    def test_behavior_claim_cannot_use_metadata_only_grounding(self):
        class MetadataModel(AgentModel):
            def generate(self, prompt, **kwargs):
                if 'current_function_id' in prompt:
                    return super().generate(prompt, **kwargs)
                data = json.loads(valid_output(prompt))
                identity = next(c['id'] for c in catalog_from_prompt(prompt) if c['kind'] == 'BINARY')
                data['summary']['evidence_ids'] = [identity]
                return GenerationResult(json.dumps(data), 'mock', 0)
        result = AgentRunner(self.store, MetadataModel()).run(self.session, 'What does this binary do?')
        self.assertNotEqual(result.status, 'completed')
        self.assertIsNone(result.response)
        self.assertIn('unsupported_grounding', [e.metadata.get('code') for e in result.events])

    def test_binary_overview_collects_structure_before_synthesis(self):
        self.functions['a'].current_name = 'main'
        self.index.binary.entry_point = '2'
        self.store.save_program_index(self.index)
        for question in ('What does this binary do?', 'Summarize this binary',
                         "What is the program's behavior?"):
            model = AgentModel([{'action': 'answer'}])
            result = AgentRunner(self.store, model).run(self.session, question)
            self.assertEqual(result.status, 'completed', question)
            names = [r['tool'] for r in result.tool_results]
            self.assertEqual(names[:4], ['binary_metadata', 'get_function', 'get_callees', 'rank_functions'])
            self.assertEqual(names[-1], 'retrieve_evidence')
            self.assertEqual(result.response.target, None)
            self.assertEqual(len(model.calls), 1, 'Only synthesis needs a model call')
            catalog = catalog_from_prompt(model.calls[0])
            self.assertTrue(any(c['kind'] == 'FUNC' and
                c['data']['function']['current_name'] == 'main' and
                c['data']['function']['decompiled_text'] for c in catalog))
            self.assertTrue(any(c['kind'] == 'EDGE' for c in catalog))
            self.assertTrue(all(any(result.response.citations[i].kind in ('FUNC', 'EDGE')
                for i in claim.evidence_ids) for claim in
                [result.response.summary] + result.response.interpretations))

    def test_stripped_overview_uses_ranked_stored_function(self):
        for function in self.functions.values():
            if not function.is_external:
                function.current_name = 'FUN_' + function.address
        self.store.save_program_index(self.index)
        model = AgentModel()
        result = AgentRunner(self.store, model).run(self.session, 'What does this binary do?')
        self.assertEqual(result.status, 'completed')
        self.assertFalse(next(r for r in result.tool_results if r['tool'] == 'get_function')['ok'])
        self.assertEqual([r['tool'] for r in result.tool_results[:3]],
                         ['binary_metadata', 'get_function', 'rank_functions'])
        self.assertIn('b:a', result.response.evidence_bundle.metadata['priority_function_ids'])
        self.assertTrue(any(c['kind'] == 'FUNC' and c['data']['function']['function_id'] == 'b:a'
            and c['data']['function']['decompiled_text'] for c in catalog_from_prompt(model.calls[0])))

    def test_overview_without_code_or_calls_fails_before_model(self):
        self.index.function_edges = []
        self.functions['a'].decompiled_text = None
        self.functions['a'].assembly = None
        self.store.save_program_index(self.index)
        model = AgentModel()
        result = AgentRunner(self.store, model).run(self.session, 'Summarize this binary')
        self.assertNotEqual(result.status, 'completed')
        self.assertIsNone(result.response)
        self.assertFalse(model.calls)
        self.assertIn('insufficient_evidence', [e.metadata.get('code') for e in result.events])

    def test_overview_preflight_respects_tool_call_limit(self):
        model = AgentModel()
        result = AgentRunner(self.store, model, limits=AgentLimits(max_tool_calls=4)).run(
            self.session, 'What does this binary do?')
        self.assertLessEqual(len(result.tool_results), 4)
        self.assertEqual(result.tool_results[-1]['tool'], 'retrieve_evidence')

    def test_code_retained_when_synthesis_fails(self):
        self.session.current_function_id = 'b:a'
        with patch.object(AireChatService, 'ask', side_effect=RuntimeError('SECRET')):
            result = self.run_agent(question='Explain this function using decompiled code and assembly.')
        self.assertEqual(result.status, 'partial')
        self.assertIn('Decompiled text:', result.answer)
        self.assertIn('CALL 10', result.answer)
        self.assertNotIn('SECRET', result.answer)

    def test_no_partial_facts_when_planning_fails_before_retrieval(self):
        with patch.object(AgentModel, 'generate', side_effect=RuntimeError('SECRET')):
            result = self.run_agent(question='Explain this function using decompiled code and assembly.')
        self.assertEqual(result.status, 'error')
        self.assertNotIn('Retrieved tool facts', result.answer)

    def test_iterations_and_tool_budget(self):
        actions = [tool('binary_metadata')] * 20
        result = self.run_agent(actions, limits=AgentLimits(max_iterations=2))
        self.assertEqual(len(result.tool_results), 3)
        self.assertIn('max_iterations', [e.metadata.get('code') for e in result.events])
        result = self.run_agent(actions, limits=AgentLimits(max_tool_calls=2))
        self.assertEqual(len(result.tool_results), 2)
        self.assertEqual(result.tool_results[-1]['tool'], 'retrieve_evidence')
        self.assertIn('max_tool_calls', [e.metadata.get('code') for e in result.events])

    def test_malformed_model_actions(self):
        for raw in ('bad', '{"action":"answer","reasoning":"SECRET"}', '{"action":"answer","action":"tool"}', '{"action":NaN}', '[' * 2000):
            result = self.run_agent([raw])
            self.assertEqual(result.status, 'completed')
            self.assertIn('malformed_action', [e.metadata.get('code') for e in result.events])
            self.assertNotIn('SECRET', json.dumps([e.to_dict() for e in result.events]))

    def test_unknown_tool_and_invalid_arguments(self):
        result = self.run_agent([tool('missing'), tool('get_function', function=123)])
        self.assertEqual([r['error']['code'] for r in result.tool_results[:2]], ['unknown_tool', 'invalid_arguments'])
        self.assertEqual(result.status, 'completed')

    def test_tool_exception(self):
        with patch.object(AgentTools, 'callers', side_effect=RuntimeError('SECRET')):
            result = self.run_agent([tool('get_callers', function='start')])
        self.assertFalse(result.tool_results[0]['ok'])
        self.assertEqual(result.status, 'completed')
        self.assertNotIn('SECRET', json.dumps([e.to_dict() for e in result.events]))

    def test_model_exception(self):
        with patch.object(AgentModel, 'generate', side_effect=RuntimeError('SECRET')):
            result = self.run_agent()
        self.assertEqual(result.status, 'error')
        self.assertNotIn('SECRET', result.answer)
        self.assertEqual(result.events[-1].event_type, 'agent_finished')

    def test_cancellation_and_deadline(self):
        model = AgentModel()
        runner = AgentRunner(self.store, model)
        result = runner.run(self.session, 'Question', cancelled=lambda: True)
        self.assertEqual(result.status, 'cancelled')
        self.assertFalse(model.calls)
        ticks = iter([0, 200])
        result = AgentRunner(self.store, model, monotonic=lambda: next(ticks)).run(self.session, 'Question')
        self.assertEqual(result.status, 'deadline')

    def test_binary_isolation(self):
        other, _ = fixture('other')
        self.store.save_program_index(other)
        self.session.current_function_id = 'other:a'
        result = self.run_agent()
        self.assertEqual(result.status, 'error')
        self.assertFalse(self.model.calls)

    def test_stripped_lookup(self):
        self.functions['a'].current_name = 'FUN_00000002'
        self.store.save_program_index(self.index)
        result = self.run_agent([tool('get_function', function='2')])
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.response.target, 'b:a')

    def test_existing_chat_accepts_same_bundle_and_rejects_foreign(self):
        tools = AgentTools(self.store, 'b')
        tools.evidence('b:a')
        model = AgentModel()
        service = AireChatService(self.store, model)
        with patch.object(service.context_builder, 'build', side_effect=AssertionError('retrieval repeated')):
            response = service.ask(request=ChatRequest('b', 'Explain', 'b:a'), evidence_bundle=tools.last_evidence)
        self.assertEqual(response.evidence_bundle, tools.last_evidence)
        with self.assertRaises(ValueError):
            service.ask(request=ChatRequest('other', 'Explain', 'b:a'), evidence_bundle=tools.last_evidence)

    def test_limit_validation(self):
        for values in ({'max_iterations': True}, {'max_tool_calls': 0}, {'timeout_seconds': float('nan')}):
            with self.assertRaises(ValueError):
                AgentLimits(**values)

    def test_action_grammar_matches_catalog_and_tool_facts(self):
        tools = AgentTools(self.store, 'b')
        schema = action_schema(tools.registry.catalog())
        self.assertEqual(len(schema['anyOf']), 13)
        rank = tools.registry.run('rank_functions', {'limit': 2})
        self.assertIn('join', render_tool_facts([rank]))
        self.assertIn('Connectivity', render_tool_facts([rank]))
