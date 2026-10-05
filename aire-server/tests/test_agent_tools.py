import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.agent.tools import AgentTools, Tool, ToolRegistry
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import ArtifactRecord
from test_retrieval import fixture


class AgentToolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'facts.sqlite')
        self.addCleanup(self.store.close)
        self.index, self.f = fixture()
        self.f['a'].decompiled_text = 'void start() {}'
        self.f['a'].assembly = 'RET'
        self.index.artifacts = [ArtifactRecord('s1', 'b', 'STRING', '100', 'binary string')]
        self.store.save_program_index(self.index)
        self.tools = AgentTools(self.store, 'b')

    def run_tool(self, name, **args):
        result = self.tools.registry.run(name, args)
        self.assertTrue(result['ok'], result)
        json.dumps(result, allow_nan=False)
        return result['data']

    def test_registration(self):
        self.assertEqual(len(self.tools.registry.catalog()), 12)
        with self.assertRaises(ValueError):
            self.tools.registry.register(Tool('get_function', '', {}, lambda: None))
        with self.assertRaises(ValueError):
            self.tools.registry.register(Tool('new_tool', '', {'value': {'type': 'integer'}}, lambda: None))
        catalog = self.tools.registry.catalog()
        catalog[1]['parameters']['limit']['maximum'] = 100000
        self.assertFalse(self.tools.registry.run('list_functions', {'limit': 101})['ok'])

    def test_validation(self):
        for name, args in [('get_function', {}), ('get_function', {'function': ''}),
                           ('get_function', {'function': 'start', 'binary_id': 'foreign'}),
                           ('list_functions', {'limit': True}), ('find_call_path',
                           {'source': 'start', 'target': 'join', 'max_depth': 9})]:
            self.assertEqual(self.tools.registry.run(name, args)['error']['code'], 'invalid_arguments')
        self.assertEqual(self.tools.registry.run('missing', {})['error']['code'], 'unknown_tool')

    def test_lookup_metadata_and_lists(self):
        data = self.run_tool('get_function', function='start')
        self.assertEqual(data['function']['function_id'], 'b:a')
        self.assertNotIn('assembly', data['function'])
        self.assertEqual(data['provenance']['binary_id'], 'b')
        self.assertEqual(self.run_tool('binary_metadata')['counts']['functions'], 7)
        self.assertTrue(self.run_tool('list_functions', limit=2)['has_more'])

    def test_callers_callees_and_path(self):
        self.assertEqual(self.run_tool('get_callers', function='start')['items'][0]['caller']['function']['function_id'], 'b:d')
        self.assertEqual(self.run_tool('get_callees', function='start')['observed_count'], 4)
        path = self.run_tool('find_call_path', source='start', target='join', max_depth=2)
        self.assertEqual([f['function']['function_id'] for f in path['functions']], ['b:a', 'b:c', 'b:d'])
        self.assertFalse(self.run_tool('find_call_path', source='start', target='join', max_depth=1)['found'])

    def test_ranking(self):
        self.assertEqual([i['function']['function_id'] for i in self.run_tool('rank_functions', limit=2)['items']], ['b:d', 'b:e'])

    def test_evidence_and_text(self):
        data = self.run_tool('retrieve_evidence', function='start')
        self.assertEqual(data['metadata']['resolved_target_id'], 'b:a')
        self.assertTrue(data['provenance'])
        self.assertEqual(self.run_tool('get_assembly', function='start')['text'], 'RET')
        self.assertTrue(self.run_tool('get_decompiled_text', function='start', max_chars=4)['truncated'])
        self.assertFalse(self.run_tool('get_assembly', function='isolated')['available'])

    def test_security_artifacts_and_read_only(self):
        before = self.store._db.total_changes
        self.run_tool('security_findings')
        self.assertIn('binary', self.run_tool('get_artifacts')['scope'])
        artifact = self.run_tool('get_artifacts')['items'][0]
        self.assertEqual(artifact['provenance']['source_table'], 'artifacts')
        self.assertEqual(artifact['scope'], 'binary')
        for name, args in [('get_function', {'function': 'start'}), ('rank_functions', {}), ('retrieve_evidence', {})]:
            self.run_tool(name, **args)
        self.assertEqual(self.store._db.total_changes, before)
        self.assertEqual(self.store.load_program_index('b'), self.index)

    def test_clean_failures_and_scope(self):
        self.assertFalse(self.tools.registry.run('get_function', {'function': 'unknown'})['ok'])
        other, _ = fixture('other')
        self.store.save_program_index(other)
        self.assertEqual(self.tools.registry.run('get_function', {'function': 'other:a'})['error']['code'], 'BinaryMismatchError')
        with patch.object(self.tools.query, 'get_callers', side_effect=RuntimeError('broken')):
            self.assertEqual(self.tools.registry.run('get_callers', {'function': 'start'})['error']['code'], 'RuntimeError')

    def test_stripped_names_do_not_gain_semantics(self):
        self.f['a'].current_name = 'FUN_00000002'
        self.store.save_program_index(self.index)
        self.assertFalse(self.tools.registry.run('get_function', {'function': 'start'})['ok'])
        self.assertEqual(self.run_tool('get_function', function='2')['function']['current_name'], 'FUN_00000002')
