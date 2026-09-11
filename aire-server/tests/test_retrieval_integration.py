"""Real persisted M1 graph queries; opt in with AIRE_RUN_GHIDRA_TESTS=1."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.retrieval import ProgramQueryService
from aire.pyghidra.indexer import index_binary

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'tests/binaries/aire_test_stripped'


def edge_key(edge):
    return (edge.caller.function_id, edge.callee.function_id, edge.callsite_address, edge.edge_type)


def describe(function):
    return {'name': function.current_name, 'address': function.address,
            'is_external': function.is_external, 'is_thunk': function.is_thunk}


def timed(operation, repeats=20):
    started = time.perf_counter()
    for _ in range(repeats):
        operation()
    return (time.perf_counter() - started) * 1000 / repeats


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class RetrievalIntegrationTests(unittest.TestCase):
    def test_real_queries(self):
        before = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        try:
            index = index_binary(BINARY)
            binary_id = index.binary.binary_id
            persisted = {(e.caller_function_id, e.callee_function_id, e.callsite_address, e.edge_type)
                         for e in index.function_edges}
            with tempfile.TemporaryDirectory(prefix='aire_m3_') as directory:
                path = Path(directory) / 'analysis.sqlite'
                with BinaryKnowledgeStore(path) as store:
                    store.save_program_index(index)
                with BinaryKnowledgeStore(path) as store:
                    query = ProgramQueryService(store)
                    resolutions, candidate_edges = {}, []
                    for name in ('socket', 'write', 'memset'):
                        matches = query.find_functions(binary_id, name, by='name')
                        self.assertTrue(matches, name)
                        resolutions[name] = []
                        for match in matches:
                            callers = query.get_callers(binary_id, match)
                            self.assertTrue(all(edge_key(edge) in persisted for edge in callers))
                            resolutions[name].append({**describe(match), 'caller_callsites': len(callers)})
                            candidate_edges.extend(callers)
                    self.assertTrue(candidate_edges, 'No resolved callers to any of the observed imports/thunks')
                    chosen = candidate_edges[0]
                    caller, callee = chosen.caller, chosen.callee
                    incoming = query.get_callers(binary_id, callee)
                    outgoing = query.get_callees(binary_id, caller)
                    reachable = query.get_reachable(binary_id, caller, max_depth=3)
                    reverse = query.get_reverse_reachable(binary_id, callee, max_depth=3)
                    call_path = query.find_call_path(binary_id, caller, callee, max_depth=3)
                    self.assertTrue(outgoing and reachable and reverse)
                    self.assertIsNotNone(call_path)
                    self.assertEqual(call_path.hop_count, 1)
                    self.assertEqual(len(reachable), len({n.function.function_id for n in reachable}))
                    for edge in incoming + outgoing + call_path.edges + [n.edge for n in reachable + reverse]:
                        self.assertIn(edge_key(edge), persisted)
                    for node in reachable + reverse:
                        self.assertEqual(node.function.binary_id, binary_id)
                        self.assertLessEqual(node.depth, 3)
                    self.assertEqual(incoming, query.get_callers(binary_id, callee))
                    self.assertEqual(outgoing, query.get_callees(binary_id, caller))
                    self.assertEqual(reachable, query.get_reachable(binary_id, caller, max_depth=3))
                    self.assertEqual(reverse, query.get_reverse_reachable(binary_id, callee, max_depth=3))
                    self.assertEqual(call_path, query.find_call_path(binary_id, caller, callee, max_depth=3))
                    top = query.rank_functions(binary_id, metric='unique_callers', limit=5)
                    self.assertEqual(top, query.rank_functions(binary_id, metric='unique_callers', limit=5))
                    report = {
                        'resolutions': resolutions,
                        'example': {'caller': describe(caller), 'callee': describe(callee),
                                    'callsite_address': chosen.callsite_address},
                        'outgoing_relationships': len(outgoing), 'depth_3_nodes': len(reachable),
                        'reverse_depth_3_nodes': len(reverse),
                        'top_unique_callers': [{**describe(row.function), 'unique_callers': row.unique_callers,
                                                'incoming_callsites': row.incoming_callsites} for row in top],
                        'mean_query_ms_20_repeats': {
                            'callers': timed(lambda: query.get_callers(binary_id, callee)),
                            'callees': timed(lambda: query.get_callees(binary_id, caller)),
                            'depth_3': timed(lambda: query.get_reachable(binary_id, caller, max_depth=3)),
                            'top_unique_callers': timed(lambda: query.rank_functions(binary_id, metric='unique_callers', limit=5)),
                        },
                        'sha256_before': before, 'sha256_after': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                    }
                    self.assertEqual(store._db.total_changes, 0, 'Queries must not write database rows')
                    print('\nM3 queries: ' + json.dumps(report, sort_keys=True), flush=True)
                    report_path = os.environ.get('AIRE_QUERY_REPORT')
                    if report_path:
                        Path(report_path).write_text(json.dumps(report, indent=2))
        finally:
            self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
