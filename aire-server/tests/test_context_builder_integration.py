"""Real M1–M4 context validation; never executes or modifies the target."""
from collections import Counter
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from aire.ai.context_builder import ContextBuilder, EvidenceRequest
from aire.knowledge.database import BinaryKnowledgeStore
from aire.pyghidra.indexer import index_binary

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'tests/binaries/aire_test_stripped'


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class ContextIntegrationTests(unittest.TestCase):
    def test_real_context(self):
        before = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        try:
            index = index_binary(BINARY)
            with tempfile.TemporaryDirectory(prefix='aire_m4_') as directory:
                path = Path(directory) / 'context.sqlite'
                with BinaryKnowledgeStore(path) as store:
                    store.save_program_index(index)
                with BinaryKnowledgeStore(path) as store:
                    builder = ContextBuilder(store)
                    request = EvidenceRequest(index.binary.binary_id, '00101efe', target_by='address',
                                              max_depth=2, traversal_direction='forward',
                                              max_functions=12, max_artifacts=8)
                    bundle = builder.build(request)
                    self.assertEqual(bundle.functions[0].function.address, '00101efe')
                    self.assertEqual(bundle.functions[0].inclusion_reason, 'target function')
                    self.assertTrue(bundle.functions[0].function.decompiled_text)
                    self.assertTrue(bundle.functions[0].function.assembly)
                    self.assertLessEqual(len(bundle.functions), 12)
                    self.assertLessEqual(len(bundle.artifacts), 8)
                    self.assertLessEqual(len(bundle.edges), request.max_edges)
                    self.assertLessEqual(len(bundle.render_text()), request.max_total_chars)
                    known = {f.function_id: f for f in index.functions}
                    stored_edges = {(e.caller_function_id, e.callee_function_id, e.callsite_address, e.edge_type)
                                    for e in index.function_edges}
                    socket = next(e for e in bundle.edges if e.edge.callsite_address == '00101f39')
                    self.assertEqual(socket.callee.address, '00101060')
                    for item in bundle.edges:
                        self.assertIn(tuple(vars(item.edge).values()), stored_edges)
                    for item in bundle.functions:
                        self.assertIn(item.function.function_id, known)
                        original = known[item.function.function_id]
                        self.assertEqual(item.function.address, original.address)
                        for field in ('decompiled_text', 'assembly'):
                            retained = getattr(item.function, field)
                            if retained is not None:
                                self.assertTrue((getattr(original, field) or '').startswith(retained))
                    self.assertTrue(all(a.scope == 'binary' for a in bundle.artifacts if a.artifact.type == 'STRING'))
                    self.assertLess(len(bundle.warnings), len(index.warnings))
                    self.assertEqual(bundle.metadata['omitted_warning_count'], len(index.warnings) - len(bundle.warnings))
                    again = builder.build(request)
                    self.assertEqual(bundle.render_text(), again.render_text())
                    self.assertEqual(bundle.to_dict(include_timings=False), again.to_dict(include_timings=False))
                    small = builder.build(replace(request, max_functions=2, max_edges=1, max_artifacts=1,
                                                  max_decompiled_chars_per_function=40,
                                                  max_assembly_chars_per_function=20, max_total_chars=2000))
                    self.assertLessEqual(len(small.render_text()), 2000)
                    self.assertTrue(any(t.category == 'total_chars' for t in small.truncations))
                    for address in ('00101060', '00101090', '00101269'):
                        focused = builder.build(replace(request, target=address))
                        self.assertEqual(focused.functions[0].function.address, address)
                    benchmark_requests = {
                        'target_only': replace(request, max_depth=0, traversal_direction=None,
                                               include_callers=False, include_callees=False,
                                               include_strings=False, include_imports=False),
                        'direct_neighbors': replace(request, max_depth=1, traversal_direction=None),
                        'depth_3': replace(request, max_depth=3),
                    }
                    means = {}
                    for label, benchmark_request in benchmark_requests.items():
                        builder.build(benchmark_request)
                        tick = time.perf_counter()
                        for _ in range(10):
                            builder.build(benchmark_request)
                        means[label] = (time.perf_counter() - tick) * 1000 / 10
                    self.assertEqual(store._db.total_changes, 0)
                    json.dumps(bundle.to_dict())
                    report = {
                        'target': bundle.functions[0].function.current_name,
                        'selected_functions': len(bundle.functions), 'selected_edges': len(bundle.edges),
                        'selected_artifacts': len(bundle.artifacts), 'selected_warnings': len(bundle.warnings),
                        'omitted_warnings': bundle.metadata['omitted_warning_count'],
                        'rendered_chars': len(bundle.render_text()),
                        'truncations': dict(Counter(t.category for t in bundle.truncations)),
                        'socket_edge': {'caller': socket.caller.current_name, 'callee': socket.callee.current_name,
                                        'callee_address': socket.callee.address, 'callsite': socket.edge.callsite_address},
                        'mean_build_ms_10_repeats': means, 'build_timings_seconds': bundle.metadata['timings'],
                        'small_bundle_chars': len(small.render_text()),
                        'sha256_before': before, 'sha256_after': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                    }
                    print('\nM4 context: ' + json.dumps(report, sort_keys=True), flush=True)
                    output = os.environ.get('AIRE_CONTEXT_REPORT')
                    if output:
                        Path(output).write_text(json.dumps(report, indent=2))
                    example = os.environ.get('AIRE_CONTEXT_EXAMPLE')
                    if example:
                        Path(example).write_text(bundle.render_text())
        finally:
            self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
