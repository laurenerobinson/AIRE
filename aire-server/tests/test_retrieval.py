"""Synthetic persisted graphs: no Ghidra or JVM required."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aire.knowledge.database import BinaryKnowledgeStore, BinaryNotFoundError, KnowledgeStoreError
from aire.knowledge.models import BinaryRecord, FunctionEdge, FunctionRecord, ProgramIndex
from aire.knowledge.retrieval import (
    AmbiguousFunctionError, BinaryMismatchError, FunctionNotFoundError, ProgramQueryService,
)


def fixture(binary='b'):
    specs = [('a', '2', 'start', False, False), ('b', '10', 'shared', False, False),
             ('c', '3', 'shared', False, False), ('d', '20', 'join', False, False),
             ('e', 'EXTERNAL:1', 'socket', True, False), ('t', '30', 'socket', False, True),
             ('z', '40', 'isolated', False, False)]
    functions = {key: FunctionRecord(f'{binary}:{key}', binary, address, name,
                                     None, None, None, 0, 0, 0, external, thunk)
                 for key, address, name, external, thunk in specs}
    edges = [('a', 'b', '2b'), ('a', 'c', '2c'), ('a', 'b', '2a'), ('a', 't', '2d'),
             ('b', 'd', '10a'), ('c', 'd', '3a'), ('d', 'a', '20a'),
             ('d', 'e', '20b'), ('t', 'e', '30a'), ('a', 'b', '2a')]
    index = ProgramIndex(BinaryRecord(binary, '/not/executed', binary, 'ELF', None, '0', None),
                         list(reversed(list(functions.values()))), function_edges=[
                             FunctionEdge(functions[a].function_id, functions[b].function_id, site, 'CALL')
                             for a, b, site in edges])
    index.function_edges.append(FunctionEdge(functions['a'].function_id, functions['z'].function_id, '2e', 'REFERENCE'))
    return index, functions


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'graph.sqlite')
        self.addCleanup(self.store.close)
        self.index, self.f = fixture()
        self.store.save_program_index(self.index)
        self.query = ProgramQueryService(self.store)

    def test_direct_callers(self):
        edges = self.query.get_callers('b', 'b:b')
        self.assertEqual([r.callsite_address for r in edges], ['2a', '2b'])
        self.assertTrue(all(r.caller == self.f['a'] and r.callee == self.f['b'] for r in edges))
        self.assertTrue(all(r.edge_type == 'CALL' for r in edges))

    def test_direct_callees_numeric_order(self):
        edges = self.query.get_callees('b', 'start')
        self.assertEqual([r.callee.address for r in edges], ['3', '10', '10', '30'])
        self.assertEqual([r.callsite_address for r in edges], ['2c', '2a', '2b', '2d'])

    def test_callsites_between_functions(self):
        self.assertEqual([r.callsite_address for r in self.query.get_callsites('b', '2', '10')], ['2a', '2b'])
        self.assertEqual(self.query.get_callsites('b', '2', '40'), [])

    def test_forward_depth_one(self):
        nodes = self.query.get_reachable('b', 'b:a', max_depth=1)
        self.assertEqual([n.function.function_id for n in nodes], ['b:c', 'b:b', 'b:t'])
        self.assertTrue(all(n.depth == 1 and n.predecessor == 'b:a' for n in nodes))

    def test_forward_depth_two_and_provenance(self):
        nodes = self.query.get_reachable('b', 'b:a', max_depth=2)
        self.assertEqual([(n.function.function_id, n.depth) for n in nodes],
                         [('b:c', 1), ('b:b', 1), ('b:t', 1), ('b:d', 2), ('b:e', 2)])
        self.assertEqual(nodes[3].predecessor, 'b:c')
        self.assertEqual(nodes[3].callsite_address, '3a')
        for node in nodes:
            self.assertEqual(node.edge.caller.function_id, node.predecessor)
            self.assertEqual(node.edge.callee, node.function)

    def test_cycles_and_self_calls(self):
        self.index.function_edges.append(FunctionEdge('b:b', 'b:b', '10b', 'CALL'))
        self.store.save_program_index(self.index)
        nodes = self.query.get_reachable('b', 'b:a', max_depth=64)
        self.assertEqual(len(nodes), 5)
        self.assertEqual(len({n.function.function_id for n in nodes}), 5)
        self.assertNotIn('b:a', [n.function.function_id for n in nodes])

    def test_reverse(self):
        nodes = self.query.get_reverse_reachable('b', 'b:e', max_depth=2)
        self.assertEqual([(n.function.function_id, n.depth) for n in nodes],
                         [('b:d', 1), ('b:t', 1), ('b:c', 2), ('b:b', 2), ('b:a', 2)])
        for node in nodes:
            self.assertEqual(node.edge.caller, node.function)
            self.assertEqual(node.edge.callee.function_id, node.predecessor)

    def test_shortest_path_and_tie_break(self):
        path = self.query.find_call_path('b', 'start', 'join', max_depth=2)
        self.assertEqual([f.function_id for f in path.functions], ['b:a', 'b:c', 'b:d'])
        self.assertEqual([r.callsite_address for r in path.edges], ['2c', '3a'])
        self.assertEqual(path.hop_count, 2)
        direct = self.query.find_call_path('b', '2', '10')
        self.assertEqual(direct.edges[0].callsite_address, '2a')

    def test_path_not_found_within_bound(self):
        self.assertIsNone(self.query.find_call_path('b', 'start', 'join', max_depth=1))
        self.assertIsNone(self.query.find_call_path('b', 'start', 'isolated', max_depth=64))
        self.assertIsNotNone(self.query.find_call_path('b', 'start', 'join', max_depth=2))

    def test_zero_depth_and_identity_path(self):
        self.assertEqual(self.query.get_reachable('b', 'start', max_depth=0), [])
        self.assertEqual(self.query.get_reverse_reachable('b', 'start', max_depth=0), [])
        path = self.query.find_call_path('b', 'start', '2', max_depth=0)
        self.assertEqual(path.functions, [self.f['a']])
        self.assertEqual(path.hop_count, 0)
        self.assertIsNone(self.query.find_call_path('b', '2', '10', max_depth=0))

    def test_ambiguous_name(self):
        with self.assertRaises(AmbiguousFunctionError) as error:
            self.query.get_callers('b', 'socket')
        self.assertEqual([f.function_id for f in error.exception.matches], ['b:t', 'b:e'])
        self.assertEqual([f.address for f in self.query.find_functions('b', 'shared', by='name')], ['3', '10'])

    def test_exact_address_resolution(self):
        self.assertEqual(self.query.resolve_function('b', 'EXTERNAL:1', by='address'), self.f['e'])
        self.assertEqual(self.query.resolve_function('b', '10'), self.f['b'])
        with self.assertRaises(FunctionNotFoundError):
            self.query.resolve_function('b', '0010', by='address')

    def test_id_and_record_resolution(self):
        self.assertEqual(self.query.resolve_function('b', 'b:b', by='id'), self.f['b'])
        stale = deepcopy(self.f['a'])
        stale.current_name = 'stale'
        self.assertEqual(self.query.resolve_function('b', stale).current_name, 'start')

    def test_selector_kind_collision_is_ambiguous(self):
        self.index.functions[-1].current_name = '10'
        self.store.save_program_index(self.index)
        with self.assertRaises(AmbiguousFunctionError):
            self.query.resolve_function('b', '10')
        self.assertEqual(self.query.resolve_function('b', '10', by='address'), self.f['b'])
        self.assertEqual(self.query.resolve_function('b', '10', by='name').function_id, 'b:a')

    def test_external_and_thunk(self):
        edges = self.query.get_callers('b', self.f['e'])
        self.assertEqual(len(edges), 2)
        self.assertTrue(all(edge.callee.is_external for edge in edges))
        self.assertTrue(edges[1].caller.is_thunk)
        self.assertEqual(self.query.get_callees('b', self.f['e']), [])
        self.assertTrue(self.query.get_summary('b', self.f['t']).is_thunk)
        self.assertTrue(self.query.get_summary('b', self.f['e']).is_external)

    def test_summary_counts_distinct_callsites(self):
        summary = self.query.get_summary('b', 'start')
        self.assertEqual((summary.unique_callers, summary.incoming_callsites,
                          summary.unique_callees, summary.outgoing_callsites), (1, 1, 3, 4))
        self.assertFalse(summary.is_leaf)
        self.assertFalse(summary.is_root)
        isolated = self.query.get_summary('b', 'isolated')
        self.assertTrue(isolated.is_leaf and isolated.is_root)

    def test_ranking_callers(self):
        rows = self.query.rank_functions('b', metric='unique_callers', limit=2)
        self.assertEqual([r.function.function_id for r in rows], ['b:d', 'b:e'])
        self.assertEqual([r.unique_callers for r in rows], [2, 2])

    def test_ranking_callees(self):
        rows = self.query.rank_functions('b', metric='unique_callees', limit=2)
        self.assertEqual([r.function.function_id for r in rows], ['b:a', 'b:d'])
        self.assertEqual([r.unique_callees for r in rows], [3, 2])

    def test_ranking_callsite_counts(self):
        incoming = self.query.rank_functions('b', metric='incoming_callsites', limit=3)
        self.assertEqual([r.function.function_id for r in incoming], ['b:b', 'b:d', 'b:e'])
        self.assertEqual([r.incoming_callsites for r in incoming], [2, 2, 2])
        outgoing = self.query.rank_functions('b', metric='outgoing_callsites', limit=2)
        self.assertEqual([r.outgoing_callsites for r in outgoing], [4, 2])

    def test_order_independent_of_persisted_row_order(self):
        before = (self.query.get_callees('b', 'start'), self.query.get_reachable('b', 'start'),
                  self.query.find_call_path('b', 'start', 'join'), self.query.rank_functions('b'))
        self.index.functions.reverse()
        self.index.function_edges.reverse()
        self.store.save_program_index(self.index)
        after = (self.query.get_callees('b', 'start'), self.query.get_reachable('b', 'start'),
                 self.query.find_call_path('b', 'start', 'join'), self.query.rank_functions('b'))
        self.assertEqual(before, after)

    def test_binary_isolation(self):
        other, functions = fixture('other')
        self.store.save_program_index(other)
        with self.assertRaises(BinaryMismatchError):
            self.query.find_call_path('b', self.f['a'], functions['e'])
        with self.assertRaises(BinaryMismatchError):
            self.query.find_call_path('b', 'b:a', 'other:e')
        # A foreign ID must not silently resolve as an unrelated local name.
        self.index.functions[0].current_name = 'other:e'
        self.store.save_program_index(self.index)
        with self.assertRaises(BinaryMismatchError):
            self.query.resolve_function('b', 'other:e')
        self.assertEqual(self.query.resolve_function('b', 'other:e', by='name').binary_id, 'b')
        self.assertEqual(len(self.query.get_callees('b', 'start')), 4)
        self.assertTrue(all(n.function.binary_id == 'b' for n in self.query.get_reachable('b', 'start')))
        self.assertTrue(all(r.function.binary_id == 'b' for r in self.query.rank_functions('b')))

    def test_unknown_binary(self):
        with self.assertRaises(BinaryNotFoundError):
            self.query.get_callers('missing', 'start')
        with self.assertRaises(BinaryNotFoundError):
            self.query.rank_functions('missing')

    def test_unknown_function(self):
        for operation in (self.query.get_callers, self.query.get_callees, self.query.get_reachable,
                          self.query.get_reverse_reachable, self.query.get_summary):
            with self.subTest(operation=operation), self.assertRaises(FunctionNotFoundError):
                operation('b', 'missing')
        self.assertEqual(self.query.find_functions('b', 'missing'), [])
        with self.assertRaises(FunctionNotFoundError):
            self.query.find_call_path('b', 'start', 'missing')

    def test_invalid_depth_and_options(self):
        for depth in (-1, 65, True, 1.5, None, '3'):
            for method in (self.query.get_reachable, self.query.get_reverse_reachable):
                with self.subTest(depth=depth, method=method), self.assertRaises(ValueError):
                    method('b', 'start', max_depth=depth)
            with self.assertRaises(ValueError):
                self.query.find_call_path('b', 'start', 'join', max_depth=depth)
        for limit in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                self.query.rank_functions('b', limit=limit)
        with self.assertRaises(ValueError):
            self.query.rank_functions('b', metric='importance')
        with self.assertRaises(ValueError):
            self.query.resolve_function('b', 'start', by='fuzzy')

    def test_no_whole_index_load_or_writes(self):
        writes = self.store._db.total_changes
        with patch.object(self.store, 'load_program_index', side_effect=AssertionError('whole index loaded')):
            self.query.get_callers('b', 'join')
            self.query.get_callees('b', 'start')
            self.query.get_reachable('b', 'start')
            self.query.rank_functions('b')
        self.assertEqual(self.store._db.total_changes, writes)
        self.assertFalse(self.store._db.in_transaction)

    def test_sql_input_is_data(self):
        self.assertEqual(self.query.find_functions('b', "x'; DROP TABLE functions; --"), [])
        self.assertEqual(len(self.query.rank_functions('b', limit=100)), 7)

    def test_closed_store(self):
        self.store.close()
        with self.assertRaises(KnowledgeStoreError):
            self.query.get_callers('b', 'join')

    def test_import_does_not_load_ghidra(self):
        subprocess.run([sys.executable, '-c',
                        'import aire.knowledge.retrieval,sys; assert "pyghidra" not in sys.modules; assert "jpype" not in sys.modules'],
                       check=True)


if __name__ == '__main__':
    unittest.main()
