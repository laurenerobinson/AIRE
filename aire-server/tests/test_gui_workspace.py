"""Workspace correctness, audit presentation and GUI session reuse."""
import json
import sqlite3
import unittest
from unittest.mock import patch

from aire.agent.tools import AgentTools
from aire.ai.chat import SummaryPreview, validate_compact_claims
from aire.ai.chat_models import Claim, ChatError
from aire.ai.prompt_builder import build_prompt
from aire.api.server import GuiError
from aire.knowledge.database import BinaryKnowledgeStore
from test_chat import catalog_from_prompt
import test_gui_server
from test_retrieval import fixture


class WorkspaceTests(unittest.TestCase):
    setUp = test_gui_server.GuiServerTests.setUp

    def test_crosscheck_cache_identity_and_policy_invalidation(self):
        w = self.workspace()
        with self.app.store() as store:
            tools = w.tools(store)
            first = tools.registry.run('crosscheck_function', {'function': 'start'})
            self.assertTrue(first['ok'])
            # Warm the metadata alias before checking the analysis producer.
            tools.registry.run('get_function', {'function': 'b:a'})
            with patch('aire.agent.tools.FunctionCrossCheckService.analyze_function', side_effect=AssertionError('cached')):
                self.assertEqual(first, tools.registry.run('crosscheck_function', {'function': 'b:a'}))
            with patch('aire.api.workspace.CROSSCHECK_POLICY_VERSION', 'test-new-policy'):
                misses = w.misses
                tools.registry.run('crosscheck_function', {'function': 'b:a'})
                self.assertGreater(w.misses, misses)
            with patch('aire.api.server.CROSSCHECK_POLICY_VERSION', 'test-new-policy'):
                sid = self.app.new_session('b')['session_id']
                self.app.run_chat(sid, 'What does this binary do?')
            sid = self.app.new_session('b')['session_id']
            self.app.run_chat(sid, 'What does this binary do?')
            self.assertFalse(self.app.last_performance['overview_cache_hit'])

    def test_crosscheck_explanation_is_separate_from_stored_facts(self):
        sid = self.app.new_session('b')['session_id']
        result = self.app.run_chat(sid, 'Explain start assembly and decompiler.')
        self.assertEqual(result.status, 'completed')
        self.assertIn('Decompiler / assembly cross-check', result.answer)
        self.assertTrue(result.response.evidence_bundle.metadata['function_crosschecks'])
        self.assertFalse(any(row['evidence_id'].startswith('CROSSCHECK') for row in result.presentation['evidence']))

    def workspace(self, binary='b'):
        with self.app.store() as store:
            return self.app.workspace(binary, store)

    def test_creation_preloads_bounded_metadata_and_overview(self):
        w = self.workspace()
        self.assertEqual(w.binary_id, 'b')
        self.assertEqual(w.sha256, 'a' * 64)
        self.assertEqual(w.metadata['counts']['functions'], 7)
        names = {r['tool'] for r in w.preloaded}
        self.assertTrue({'list_functions', 'rank_functions', 'get_artifacts', 'security_findings', 'get_callees'} <= names)
        listing = w.preloaded[0]['data']['items']
        self.assertTrue(all('assembly' not in f['function'] and 'decompiled_text' not in f['function'] for f in listing))
        self.assertIs(self.workspace(), w)

    def test_normalized_defaults_copy_isolation_and_lazy_code(self):
        w = self.workspace()
        with self.app.store() as store:
            tools = w.tools(store)
            first = tools.registry.run('list_functions', {})
            misses = w.misses
            second = tools.registry.run('list_functions', {'offset': 0, 'limit': 20})
            self.assertEqual(first, second)
            self.assertEqual(w.misses, misses)
            first['data']['items'].clear()
            self.assertTrue(tools.registry.run('list_functions', {})['data']['items'])
            misses = w.misses
            code = tools.registry.run('get_decompiled_text', {'function': 'start'})
            self.assertIn('void start()', code['data']['text'])
            self.assertGreater(w.misses, misses)
            misses = w.misses
            self.assertEqual(tools.registry.run('get_decompiled_text', {'function': 'start'}), code)
            self.assertEqual(w.misses, misses)

    def test_cached_tools_preserve_agent_tools_results_and_errors(self):
        w = self.workspace()
        with self.app.store() as store:
            cached, original = w.tools(store), AgentTools(store, 'b')
            for name, args in [('binary_metadata', {}), ('list_functions', {}),
                    ('get_function', {'function': 'start'}), ('get_function', {'function': 'other:a'}),
                    ('get_callers', {'function': 'start'}), ('get_callees', {'function': 'start'}),
                    ('get_artifacts', {'kind': 'IMPORT'}), ('security_findings', {}),
                    ('get_assembly', {'function': 'start'}), ('rank_functions', {}),
                    ('rank_application_functions', {}),
                    ('list_functions', {'limit': True}), ('save_program_index', {})]:
                self.assertEqual(cached.registry.run(name, args), original.registry.run(name, args), name)

    def test_workspaces_are_isolated_between_binaries(self):
        other, _ = fixture('other')
        with BinaryKnowledgeStore(self.database) as store:
            store.save_program_index(other)
        a, b = self.workspace(), self.workspace('other')
        self.assertIsNot(a, b)
        with self.app.store() as store:
            for workspace in (a, b):
                rows = workspace.tools(store).registry.run('list_functions', {})['data']['items']
                self.assertTrue(all(f['function']['binary_id'] == workspace.binary_id for f in rows))
                foreign = 'other:a' if workspace is a else 'b:a'
                self.assertFalse(workspace.tools(store).registry.run('get_function', {'function': foreign})['ok'])

    def test_database_changes_invalidate_tools_and_overview_answers(self):
        w = self.workspace()
        w.overview_answers['example'] = {'old': True}
        with BinaryKnowledgeStore(self.database) as store:
            index = store.load_program_index('b')
            index.binary.program_name = 'changed'
            store.save_program_index(index)
        updated = self.workspace()
        self.assertIsNot(w, updated)
        self.assertEqual(updated.metadata['binary']['program_name'], 'changed')
        self.assertFalse(updated.overview_answers)

    def test_wal_updates_invalidate_workspace(self):
        writer = sqlite3.connect(self.database)
        self.addCleanup(writer.close)
        writer.execute('PRAGMA journal_mode=WAL')
        w = self.workspace()
        writer.execute("UPDATE binaries SET program_name='wal change' WHERE binary_id='b'")
        writer.commit()
        self.assertIsNot(w, self.workspace())
        self.assertEqual(self.workspace().metadata['binary']['program_name'], 'wal change')

    def test_session_selection_and_overview_cache_reuse(self):
        sid = self.app.new_session('b')['session_id']
        result = self.app.run_chat(sid, 'What does this binary do?')
        self.assertEqual(result.status, 'completed')
        client = self.app._client()
        count = len(client.calls)
        self.app.select_function(sid, 'start')
        cached = self.app.run_chat(sid, 'What does this binary do?')
        self.assertEqual(cached.answer, result.answer)
        self.assertEqual(len(client.calls), count)
        self.assertTrue(self.app.last_performance['overview_cache_hit'])
        self.assertEqual(self.app.session(sid)['current_function_id'], 'b:a')
        result = self.app.run_chat(sid, 'What calls it?')
        self.assertIn('join → start', result.answer)
        self.assertEqual(len(client.calls), count)
        self.assertIn(sid, self.app.sessions._agents)

    def test_concise_response_preserves_full_audit_and_security_details(self):
        sid = self.app.new_session('b')['session_id']
        result = self.app.run_chat(sid, 'What does this binary do?')
        for noisy in ('Evidence provenance', 'Retrieved tool facts', 'NOT_APPLICABLE', 'Character bounds', 'Citation existence'):
            self.assertNotIn(noisy, result.answer)
        self.assertTrue(result.presentation['evidence'])
        self.assertTrue(result.presentation['relationships'])
        self.assertTrue(result.presentation['security'])
        raw = result.presentation['raw']
        self.assertTrue(raw['response']['evidence_bundle']['provenance'])
        self.assertTrue(raw['response']['uncertainties'])
        self.assertEqual(raw['response']['model'], 'mock')
        self.assertIn('Static analysis only', result.presentation['footer'])
        saved = self.app.session(sid)['messages'][-1]
        self.assertEqual(saved['presentation'], json.loads(json.dumps(result.presentation)))

    def test_suspicious_card_uses_deterministic_checks_without_model_guess(self):
        sid = self.app.new_session('b')['session_id']
        result = self.app.run_chat(sid, 'Find suspicious behavior in this binary')
        self.assertEqual(result.status, 'completed')
        self.assertFalse(self.app._client().calls)
        self.assertIn('Security check coverage', result.answer)
        self.assertTrue(result.presentation['security'])

    def test_function_cards_require_selection_and_use_selected_evidence(self):
        sid = self.app.new_session('b')['session_id']
        with self.assertRaises(GuiError):
            self.app.run_chat(sid, 'Summarize this function')
        self.app.select_function(sid, 'start')
        result = self.app.run_chat(sid, 'Summarize this function')
        self.assertEqual(result.response.target, 'b:a')
        self.assertEqual(len(self.app._client().calls), 1)
        result = self.app.run_chat(sid, 'Explain this assembly')
        self.assertEqual(result.response.target, 'b:a')
        self.assertIn('CALL 10', result.presentation['raw']['response']['evidence_bundle']['rendered_text'])

    def test_workspace_chat_is_read_only_and_never_executes_target(self):
        before = self.database.read_bytes()
        with patch('subprocess.Popen', side_effect=AssertionError('No target execution')), \
                patch('os.system', side_effect=AssertionError('No target execution')):
            sid = self.app.new_session('b')['session_id']
            self.app.run_chat(sid, 'What does this binary do?')
            self.app.select_function(sid, 'start')
            self.app.run_chat(sid, 'Explain this assembly')
        self.assertEqual(before, self.database.read_bytes())
        with self.app.store() as store:
            with self.assertRaises(sqlite3.OperationalError):
                store._connection.execute('DELETE FROM binaries')

    def test_compact_prompt_preserves_behavior_and_artifact_grounding(self):
        with self.app.store() as store:
            tools = self.app.workspace('b', store).tools(store)
            tools.registry.run('retrieve_evidence', {})
            prompt = build_prompt('What does this binary do?', tools.last_evidence, policy='overview', compact=True)
            catalog = catalog_from_prompt(prompt.text)
            kinds = {c['kind'] for c in catalog}
            self.assertTrue({'BINARY', 'FUNC', 'EDGE'} <= kinds)
            self.assertTrue(any(c['kind'] == 'FUNC' and c['data'].get('decompiled_text') for c in catalog))
            self.assertTrue(all('provenance' not in c['data'] for c in catalog))
            self.assertTrue(all(len(c['id']) < 14 for c in catalog))

    def test_overview_retains_assembly_when_requested(self):
        with self.app.store() as store:
            tools = self.app.workspace('b', store).tools(store, assembly=True)
            tools.registry.run('retrieve_evidence', {})
            self.assertTrue(any(f.function.assembly for f in tools.last_evidence.functions))
            prompt = build_prompt('Compare their assembly', tools.last_evidence, policy='overview', compact=True)
            self.assertTrue(any(c['kind'] == 'FUNC' and c['data'].get('assembly')
                                for c in catalog_from_prompt(prompt.text)))

    def test_cache_is_bounded(self):
        w = self.workspace()
        w.MAX_ENTRIES = 2
        for i in range(5):
            w.memo(str(i), lambda: ({'ok': True, 'data': i}, None))
        self.assertEqual(len(w.cache), 2)
        self.assertGreater(w.cache_bytes, 0)

    def test_relevance_policy_version_invalidates_evidence_and_answer_cache(self):
        sid = self.app.new_session('b')['session_id']
        self.app.run_chat(sid, 'What does this binary do?')
        self.app.run_chat(sid, 'What does this binary do?')
        self.assertTrue(self.app.last_performance['overview_cache_hit'])
        w = self.workspace()
        with self.app.store() as store:
            tools = w.tools(store)
            tools.registry.run('retrieve_evidence', {})
            misses = w.misses
            with patch('aire.api.workspace.RELEVANCE_POLICY_VERSION', 'test-next-policy'):
                tools.registry.run('retrieve_evidence', {})
            self.assertGreater(w.misses, misses)
        with patch('aire.api.server.RELEVANCE_POLICY_VERSION', 'test-next-policy'):
            result = self.app.run_chat(sid, 'What does this binary do?')
        self.assertEqual(result.status, 'completed')
        self.assertFalse(self.app.last_performance['overview_cache_hit'])

    def test_immediate_overview_preview_and_performance_are_separate_from_answer(self):
        sid = self.app.new_session('b')['session_id']
        previews = []
        result = self.app.run_chat(sid, 'What does this binary do?', on_context=previews.append)
        self.assertEqual(result.status, 'completed')
        self.assertTrue(previews)
        self.assertIn('stored functions', previews[0])
        self.assertIn('Stored CALL graph', previews[0])
        self.assertEqual(self.app.last_performance['model_requests'], 1)
        self.assertIn('model_seconds', self.app.last_performance)
        self.assertNotIn('total_seconds', result.answer)

    def test_summary_preview_handles_escaped_partial_text_and_hides_other_fields(self):
        seen = []
        preview = SummaryPreview(seen.append)
        value = json.dumps({'summary': {'claim': 'Input "text" → result\n', 'evidence_ids': ['FUNC:1']},
                            'private_reasoning': 'NEVER DISPLAY'})
        for char in value:
            preview(char)
        self.assertEqual(seen[-1], 'Input "text" → result\n')
        self.assertFalse(any('NEVER DISPLAY' in s for s in seen))

    def test_compact_named_call_and_absence_assertions_are_checked(self):
        with self.app.store() as store:
            tools = self.app.workspace('b', store).tools(store)
            tools.registry.run('retrieve_evidence', {})
            bundle = tools.last_evidence
            validate_compact_claims([Claim('start calls shared.', ('EDGE:1',))], bundle)
            with self.assertRaises(ChatError):
                validate_compact_claims([Claim('shared calls start.', ('EDGE:1',))], bundle)
            with self.assertRaises(ChatError):
                validate_compact_claims([Claim('The binary has no external dependencies.', ('FUNC:1',))], bundle)
            with self.assertRaises(ChatError):
                validate_compact_claims([Claim('main is the entry point of the binary.', ('FUNC:1',))], bundle)

    def test_function_prompt_sends_code_only_for_the_target(self):
        with self.app.store() as store:
            tools = self.app.workspace('b', store).tools(store)
            tools.registry.run('retrieve_evidence', {'function': 'b:a'})
            prompt = build_prompt('Explain start', tools.last_evidence, policy='target', compact=True)
            self.assertEqual(prompt.code_source_ids, {'b:a'})
            for row in catalog_from_prompt(prompt.text):
                if row['kind'] == 'FUNC' and row['data']['current_name'] != 'start':
                    self.assertNotIn('decompiled_text', row['data'])

    def test_function_reply_has_prose_bounds_without_extending_deadline(self):
        sid = self.app.new_session('b')['session_id']
        client = self.app._client()
        original = client.generate
        schemas, systems = [], []
        def record(prompt, **kwargs):
            schemas.append(kwargs['response_schema'])
            systems.append(kwargs['system'])
            return original(prompt, **kwargs)
        timeout = self.app.limits.timeout_seconds
        with patch.object(client, 'generate', side_effect=record):
            result = self.app.run_chat(sid, 'Explain start assembly.')
        self.assertEqual(result.status, 'completed')
        properties = schemas[0]['properties']
        self.assertEqual(properties['summary']['properties']['claim']['maxLength'], 400)
        self.assertEqual(properties['interpretations']['items']['properties']['claim']['maxLength'], 300)
        self.assertEqual(properties['interpretations']['maxItems'], 1)
        self.assertEqual(properties['uncertainties']['maxItems'], 1)
        self.assertIn('Explain only the selected function', systems[0])
        self.assertEqual(self.app.limits.timeout_seconds, timeout)


if __name__ == '__main__':
    unittest.main()
