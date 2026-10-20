"""Exact stored evidence controls; no new binaries, JVM, model, or network."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.agent.tools import AgentTools
from aire.agent.runner import AgentRunner, AgentLimits
from aire.agent.session import AgentSession
from aire.ai.context_builder import ContextBuilder
from aire.ai.prompt_builder import build_prompt, parse_response
from aire.knowledge.application_relevance import ApplicationRelevanceService
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.evidence import EvidenceRequest
from aire.knowledge.investigation import InvestigationService
from aire.knowledge.models import ArtifactRecord, ReferenceRecord, ThunkRecord
from aire.knowledge.retrieval import BinaryMismatchError, ProgramQueryService
from aire.security.rule_engine import _ReadOnlyRuleStore
from aire.knowledge.reference_views import require_references
from test_retrieval import fixture


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'facts.sqlite')
        self.addCleanup(self.store.close)
        self.index, self.f = fixture()
        self.index.metadata['reference_facts_version'] = 1
        self.index.artifacts = [ArtifactRecord('global', 'b', 'STRING', '1', 'unrelated'),
                                ArtifactRecord('local', 'b', 'STRING', '500', 'local string')]
        self.f['a'].assembly = '2: MOV EAX,0x500'
        self.f['a'].decompiled_text = 'void start() { puts("local string"); }'
        self.index.references = [
            ReferenceRecord('r1', 'b', '2f', '500', 'DATA', 'b:a', target_artifact_id='local', source_instruction='MOV EAX,0x500'),
            ReferenceRecord('r2', 'b', '2f', '500', 'READ', 'b:a', target_artifact_id='local', operand_index=1, is_read=True),
            ReferenceRecord('r3', 'b', '2e', 'EXTERNAL:1', 'COMPUTED_CALL', 'b:a', is_call=True, is_indirect=True),
            ReferenceRecord('r4', 'b', '900', '500', 'DATA', target_artifact_id='local')]
        self.index.thunks = [ThunkRecord('b:t', 'b:z', '30', '40', 'JMP 0x40', True)]
        self.store.save_program_index(self.index)
        self.service = InvestigationService(self.store)
        self.tools = AgentTools(self.store, 'b')

    def test_string_pages_preserve_instruction_operand_and_artifact_identity(self):
        result = self.service.references('b', 'start', strings_only=True, limit=1)
        self.assertEqual(result['observed_count'], 2)
        self.assertTrue(result['has_more'])
        self.assertEqual(result['items'][0]['reference']['source_address'], '2f')
        self.assertEqual(result['items'][0]['artifact']['artifact_id'], 'local')
        next_page = self.service.references('b', 'start', strings_only=True, limit=1, offset=1)
        self.assertFalse(next_page['has_more'])
        self.assertEqual(next_page['items'][0]['reference']['operand_index'], 1)
        self.assertEqual(next_page['items'][0]['provenance']['source_id'], 'r2')
        self.assertEqual(self.service.references('b', 'start', offset=100)['items'], [])

    def test_computed_call_does_not_assert_a_callee(self):
        result = self.service.references('b', 'start')
        indirect = next(r for r in result['items'] if r['reference']['is_indirect'])
        self.assertIsNone(indirect['reference']['target_function_id'])
        self.assertEqual(indirect['resolution'], 'UNRESOLVED_COMPUTED_CALL')
        self.assertEqual(self.service.references('b', 'b:e', direction='incoming')['observed_count'], 0)

    def test_legacy_computed_jump_is_normalized_without_database_write(self):
        self.index.references.append(ReferenceRecord('legacy_jump', 'b', '2d', '40', 'COMPUTED_JUMP', 'b:a', 'b:z'))
        self.store.save_program_index(self.index)
        before = self.store._db.total_changes
        query = ProgramQueryService(self.store)
        refs = query.get_function_references('b', 'start')
        jump = next(r for r in refs if r.reference_id == 'legacy_jump')
        self.assertTrue(jump.is_indirect)
        self.assertIsNone(jump.target_function_id)
        self.assertEqual(query.get_function_referrers('b', 'b:z'), [])
        self.assertEqual(self.service.references('b', 'b:z', direction='incoming')['items'], [])
        bundle = ContextBuilder(self.store).build(EvidenceRequest('b', 'start'))
        self.assertIsNone(next(r.reference for r in bundle.references if r.reference.reference_id == 'legacy_jump').target_function_id)
        self.assertEqual(self.store._db.total_changes, before)
        self.assertEqual(self.store.load_program_index('b'), self.index)

    def test_demo_views_accept_old_and_current_reference_formats(self):
        for version in (1, 2):
            self.index.metadata['reference_facts_version'] = version
            require_references(self.index)
        for version in (None, True, '2', 99):
            self.index.metadata['reference_facts_version'] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                require_references(self.index)

    def test_thunk_chain_never_changes_call_graph(self):
        query = ProgramQueryService(self.store)
        before = query.get_callees('b', 'start')
        result = self.service.thunk_chain('b', 'b:t')
        self.assertEqual(result['terminal_function_id'], 'b:z')
        self.assertEqual(result['hops'][0]['relationship'], 'VERIFIED_DIRECT_JUMP')
        self.assertEqual(query.get_callees('b', 'start'), before)
        self.assertNotIn('b:z', [e.callee.function_id for e in before])
        self.assertEqual(query.get_callers('b', 'b:z'), [])

    def test_indirect_binding_not_labeled_verified_jump(self):
        self.index.thunks[0].is_direct_jump = False
        self.store.save_program_index(self.index)
        hop = self.service.thunk_chain('b', 'b:t')['hops'][0]
        self.assertEqual(hop['relationship'], 'GHIDRA_THUNK_BINDING')
        self.assertEqual(hop['provenance']['source_table'], 'thunk_relations')

    def test_chain_depth_cycle_ambiguity_and_unresolved(self):
        self.assertEqual(self.service.thunk_chain('b', 'b:t', max_depth=0)['status'], 'DEPTH_LIMIT')
        self.f['z'].is_thunk = True
        self.index.thunks.append(ThunkRecord('b:z', 'b:t', '40', '30'))
        self.store.save_program_index(self.index)
        self.assertEqual(self.service.thunk_chain('b', 'b:t')['status'], 'CYCLE')
        self.assertEqual(self.service.thunk_chain('b', 'b:t', max_depth=1)['status'], 'DEPTH_LIMIT')
        self.index.thunks.append(ThunkRecord('b:t', 'b:e', '30', 'EXTERNAL:1'))
        self.store.save_program_index(self.index)
        self.assertEqual(self.service.thunk_chain('b', 'b:t')['status'], 'AMBIGUOUS_BINDING')
        self.index.thunks = []
        self.store.save_program_index(self.index)
        self.assertEqual(self.service.thunk_chain('b', 'b:t')['status'], 'UNRESOLVED_THUNK')

    def test_scope_bounds_and_unknown_function(self):
        other, _ = fixture('other')
        self.store.save_program_index(other)
        with self.assertRaises(BinaryMismatchError):
            self.service.references('b', 'other:a')
        for kwargs in ({'limit': True}, {'limit': 101}, {'offset': -1}, {'direction': 'either'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.service.references('b', 'start', **kwargs)
        self.assertFalse(self.tools.registry.run('get_xrefs', {'function': 'missing'})['ok'])

    def test_queries_and_tools_are_offline_read_only(self):
        before = self.store._db.total_changes
        with patch.dict('sys.modules', {'pyghidra': None, 'jpype': None}):
            for name in ('get_xrefs', 'get_function_strings', 'get_thunk_target', 'classify_function'):
                result = self.tools.registry.run(name, {'function': 'b:t' if name == 'get_thunk_target' else 'start'})
                self.assertTrue(result['ok'], result)
                json.dumps(result)
        self.assertEqual(self.store._db.total_changes, before)
        self.assertEqual(self.store.load_program_index('b'), self.index)

    def test_tool_string_truncation_disclosed(self):
        self.index.artifacts[1].value = 'x' * 10000
        self.store.save_program_index(self.index)
        data = self.tools.registry.run('get_function_strings', {'function': 'start', 'limit': 1})['data']
        self.assertEqual(len(data['items'][0]['artifact']['value']), 512)
        self.assertTrue(data['items'][0]['value_truncated'])
        self.assertEqual(data['items'][0]['observed_value_chars'], 10000)

    def test_agent_evidence_bounds_relationship_transport_without_cutting_records(self):
        self.index.references = [ReferenceRecord(f'r{i}:' + 'x' * 6000, 'b', f'{100+i:x}', '500', 'DATA',
                                                'b:a', target_artifact_id='local') for i in range(20)]
        self.store.save_program_index(self.index)
        result = self.tools.registry.run('retrieve_evidence', {'function': 'start'})
        self.assertTrue(result['ok'], result)
        self.assertLessEqual(len(json.dumps(result['data'], ensure_ascii=True)), 100000)
        self.assertTrue(any(t['category'] == 'references' and t['observed_count_or_size'] == 20
                            for t in result['data']['truncations']))
        self.assertLess(result['data']['request_summary']['max_references'], 8)
        self.assertTrue(all(r['reference']['target_address'] == '500' for r in result['data']['references']))

    def test_local_strings_precede_globals_with_exact_reference_evidence(self):
        bundle = ContextBuilder(self.store).build(EvidenceRequest('b', 'start', max_artifacts=1, max_total_chars=30000))
        self.assertEqual(bundle.artifacts[0].artifact.artifact_id, 'local')
        self.assertEqual(bundle.artifacts[0].scope, 'function-reference')
        self.assertEqual(bundle.artifacts[0].provenance.related_function_ids, ('b:a',))
        self.assertTrue(any(r.reference.reference_id == 'r1' for r in bundle.references))
        self.assertIn('OBSERVED REFERENCE', bundle.render_text())
        self.assertTrue(bundle.thunks)
        self.assertNotIn(('b:t', 'b:z'), [(e.edge.caller_function_id, e.edge.callee_function_id) for e in bundle.edges])

    def test_reference_limits_do_not_imply_unseen_local_links(self):
        request = EvidenceRequest('b', 'start', max_references=0, max_thunks=0, max_total_chars=30000)
        bundle = ContextBuilder(self.store).build(request)
        self.assertEqual(bundle.references, [])
        self.assertTrue(all(a.scope == 'binary' for a in bundle.artifacts))
        self.assertEqual({t.category for t in bundle.truncations} & {'references', 'thunks'}, {'references', 'thunks'})
        for maximum in (0, 11, 1000):
            tiny = ContextBuilder(self.store).build(replace(request, max_total_chars=maximum))
            self.assertLessEqual(len(tiny.render_text()), maximum)

    def test_prompt_cites_reference_and_thunk_as_separate_facts(self):
        bundle = ContextBuilder(self.store).build(EvidenceRequest('b', 'start', max_total_chars=30000))
        for compact in (False, True):
            prepared = build_prompt('Show references', bundle, policy='test', compact=compact)
            refs = [c for c in prepared.citations.values() if c.kind == 'XREF']
            thunks = [c for c in prepared.citations.values() if c.kind == 'THUNK']
            self.assertTrue(refs)
            self.assertTrue(thunks)
            self.assertTrue(all(c.provenance.source_table == 'binary_references' for c in refs))
            self.assertIn('separate from direct CALL', thunks[0].fact)
            parsed = parse_response(json.dumps({'summary': {'claim': 'Observed references', 'evidence_ids': [refs[0].evidence_id]},
                'fact_ids': [refs[0].evidence_id, thunks[0].evidence_id], 'interpretations': [], 'uncertainties': []}), prepared.citations)
            self.assertEqual(len(parsed[1]), 2)

    def test_repeat_save_and_reload_is_deterministic(self):
        request = EvidenceRequest('b', 'start', max_total_chars=30000)
        before = ContextBuilder(self.store).build(request).to_dict(include_timings=False)
        self.index.references.reverse()
        self.index.thunks.reverse()
        self.store.save_program_index(self.index)
        after = ContextBuilder(self.store).build(request).to_dict(include_timings=False)
        self.assertEqual(before, after)

    def test_classification_keeps_custom_cpp_eligible_and_labels_loader_entries(self):
        self.f['a'].current_name = 'my_app::process'
        self.f['b'].current_name = 'std::vector<int>::size'
        self.f['c'].namespace = 'std::ostream'
        self.index.artifacts.append(ArtifactRecord('entry', 'b', 'EXPORT', self.f['a'].address, 'entry'))
        self.store.save_program_index(self.index)
        self.assertEqual(self.service.classification('b', 'b:a')['category'], 'APPLICATION_CANDIDATE')
        self.assertTrue(self.service.classification('b', 'b:a')['is_entry_point'])
        for identity in ('b:b', 'b:c'):
            self.assertEqual(self.service.classification('b', identity)['category'], 'STANDARD_LIBRARY')
        ranked = ApplicationRelevanceService(self.store).rank_application_functions('b', limit=100)['items']
        self.assertEqual(len(ranked), len(self.f))
        self.assertTrue(all(r['score'] < 0 for r in ranked if r['classification'] == 'STANDARD_LIBRARY'))

    def test_ranking_uses_persisted_thunk_binding_without_assembly_guess(self):
        self.f['a'].current_name = 'invoke_main'
        self.f['t'].assembly = None
        self.store.save_program_index(self.index)
        rows = ApplicationRelevanceService(self.store).rank_application_functions('b', limit=100)['items']
        terminal = next(r for r in rows if r['function']['function_id'] == 'b:z')
        self.assertEqual(terminal['path'][-1]['source_table'], 'thunk_relations')
        self.assertEqual(terminal['path'][-1]['kind'], 'THUNK_JUMP')

    def test_entry_and_import_classification_sources(self):
        self.index.binary.entry_point = self.f['a'].address
        self.index.artifacts.append(ArtifactRecord('import', 'b', 'IMPORT', self.f['e'].address, 'socket'))
        self.store.save_program_index(self.index)
        entry = self.service.classification('b', 'start')
        self.assertTrue(entry['is_entry_point'])
        self.assertIn('binaries', [p['source_table'] for p in entry['sources']])
        imported = self.service.classification('b', 'b:e')
        self.assertEqual(imported['category'], 'EXTERNAL')
        self.assertTrue(imported['is_import'])
        self.assertIn('import', [p['source_id'] for p in imported['sources']])

    def test_reference_questions_route_without_model_inference(self):
        from unittest.mock import Mock
        model = Mock()
        model.generate.side_effect = AssertionError('Exact stored relationships need no inference')
        for question, name, selected in (
            ('Which strings are used by start?', 'get_function_strings', None),
            ('Show xrefs for start', 'get_xrefs', None),
            ('Show incoming xrefs', 'get_xrefs', 'b:a'),
            ('Resolve the thunk target', 'get_thunk_target', 'b:t'),
        ):
            with self.subTest(question=question):
                session = AgentSession('b', current_function_id=selected)
                result = AgentRunner(self.store, model).run(session, question)
                self.assertEqual(result.status, 'completed', result.answer)
                self.assertIn(name, [r['tool'] for r in result.tool_results])
                self.assertIsNone(result.response)
        model.generate.assert_not_called()

    def test_reference_routing_reports_insufficient_tool_budget(self):
        from unittest.mock import Mock
        session = AgentSession('b', current_function_id='b:a')
        result = AgentRunner(self.store, Mock(), limits=AgentLimits(max_tool_calls=1)).run(session, 'Show local strings')
        self.assertEqual(result.status, 'partial')
        self.assertEqual(len(result.tool_results), 1)

    def test_legacy_read_only_queries_do_not_migrate(self):
        path = self.store.path
        self.store.close()
        import sqlite3
        with sqlite3.connect(path) as db:
            for table in ('binary_references', 'thunk_relations', 'program_information'):
                db.execute(f'DROP TABLE {table}')
            db.execute('DROP INDEX artifacts_owner_idx')
            db.execute("UPDATE schema_metadata SET value='1' WHERE key='schema_version'")
        before = path.read_bytes()
        with _ReadOnlyRuleStore(path) as store:
            service = InvestigationService(store)
            result = service.references('b', 'start', strings_only=True)
            self.assertEqual(result['items'], [])
            self.assertEqual(result['coverage']['schema_version'], 1)
            self.assertEqual(service.thunk_chain('b', 'b:t')['status'], 'LEGACY_NO_REFERENCE_FACTS')
            bundle = ContextBuilder(store).build(EvidenceRequest('b', 'start'))
            self.assertEqual(bundle.references, [])
            self.assertEqual(bundle.thunks, [])
        self.assertEqual(path.read_bytes(), before)
