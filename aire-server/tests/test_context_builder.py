"""M4 evidence selection and rendered budgets without Ghidra."""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aire.ai.context_builder import ContextBuilder, EvidenceRequest
from aire.knowledge.database import BinaryKnowledgeStore, BinaryNotFoundError
from aire.knowledge.models import ArtifactRecord
from aire.knowledge.retrieval import AmbiguousFunctionError, BinaryMismatchError, FunctionNotFoundError
from test_retrieval import fixture


class ContextBuilderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'context.sqlite')
        self.addCleanup(self.store.close)
        self.index, self.f = fixture()
        for f in self.index.functions:
            if not f.is_external:
                f.decompiled_text = 'void f() { /* 雪 */ }\n' * 10
                f.assembly = '0010: MOV RAX, RBX\n' * 12
        self.index.artifacts = [
            ArtifactRecord('s2', 'b', 'STRING', '100', 'second'),
            ArtifactRecord('s1', 'b', 'STRING', '50', 'first\x00雪'),
            ArtifactRecord('i1', 'b', 'IMPORT', 'EXTERNAL:1', 'libc::socket'),
            ArtifactRecord('e1', 'b', 'EXPORT', '2', 'start')]
        self.index.warnings = ['Import: loader message', 'Indirect call at 0010; omitted',
                               'Function b:a warning with no structured association', 'Analysis: global diagnostic']
        self.store.save_program_index(self.index)
        self.builder = ContextBuilder(self.store)

    def request(self, **options):
        base = EvidenceRequest('b', 'b:a', include_callers=False, include_callees=False,
                               include_strings=False, include_imports=False, include_warnings=False)
        return replace(base, **options)

    def build(self, **options):
        return self.builder.build(self.request(**options))

    def test_exact_target_only(self):
        bundle = self.build()
        self.assertEqual([f.function.function_id for f in bundle.functions], ['b:a'])
        self.assertEqual(bundle.functions[0].function, self.f['a'])
        self.assertEqual(bundle.edges, [])
        self.assertIn('TARGET FUNCTION', bundle.render_text())

    def test_direct_callers(self):
        bundle = self.build(include_callers=True)
        self.assertEqual([f.function.function_id for f in bundle.functions], ['b:a', 'b:d'])
        self.assertEqual(bundle.edges[0].edge.callsite_address, '20a')
        self.assertEqual(bundle.functions[1].inclusion_reason, 'direct caller of target')

    def test_direct_callees(self):
        bundle = self.build(include_callees=True)
        self.assertEqual([f.function.function_id for f in bundle.functions], ['b:a', 'b:c', 'b:b', 'b:t'])
        self.assertEqual(len(bundle.edges), 4)
        self.assertEqual({e.edge.callsite_address for e in bundle.edges}, {'2a', '2b', '2c', '2d'})

    def test_forward_depth_two(self):
        bundle = self.build(traversal_direction='forward', max_depth=2)
        depths = {f.function.function_id: f.depth for f in bundle.functions}
        self.assertEqual(depths, {'b:a': 0, 'b:c': 1, 'b:b': 1, 'b:t': 1, 'b:d': 2, 'b:e': 2})
        self.assertTrue(any(e.edge.callsite_address == '3a' and e.depth == 2 for e in bundle.edges))

    def test_reverse_traversal(self):
        bundle = self.build(target='b:e', traversal_direction='reverse', max_depth=2)
        self.assertEqual({f.function.function_id for f in bundle.functions}, {'b:e', 'b:d', 'b:t', 'b:c', 'b:b', 'b:a'})
        self.assertTrue(any(e.edge.caller_function_id == 'b:d' and e.edge.callee_function_id == 'b:e' for e in bundle.edges))

    def test_deterministic_order_independent_of_rows(self):
        request = self.request(include_callers=True, include_callees=True, include_strings=True,
                               traversal_direction='both', max_depth=3)
        first = self.builder.build(request)
        self.index.functions.reverse()
        self.index.artifacts.reverse()
        self.index.function_edges.reverse()
        self.store.save_program_index(self.index)
        second = self.builder.build(request)
        self.assertEqual(first.to_dict(include_timings=False), second.to_dict(include_timings=False))
        self.assertEqual(first.render_text(), second.render_text())

    def test_ambiguous_target(self):
        with self.assertRaises(AmbiguousFunctionError):
            self.build(target='socket')

    def test_unknown_target_and_binary(self):
        with self.assertRaises(FunctionNotFoundError):
            self.build(target='missing')
        with self.assertRaises(BinaryNotFoundError):
            self.build(binary_id='missing')

    def test_function_limit(self):
        bundle = self.build(include_callers=True, include_callees=True, max_functions=2)
        self.assertEqual([f.function.function_id for f in bundle.functions], ['b:a', 'b:d'])
        trunc = next(t for t in bundle.truncations if t.category == 'functions')
        self.assertEqual((trunc.observed_count_or_size, trunc.retained_count_or_size), (5, 2))
        # Edges retain lightweight endpoint identity even when a body is excluded.
        self.assertEqual(len(bundle.edges), 5)

    def test_edge_limit(self):
        bundle = self.build(include_callees=True, max_edges=1)
        self.assertEqual(len(bundle.edges), 1)
        self.assertTrue(any(t.category == 'edges' and t.observed_count_or_size == 4 for t in bundle.truncations))

    def test_artifact_limit_and_binary_scope(self):
        bundle = self.build(include_strings=True, include_imports=True, include_exports=True, max_artifacts=2)
        self.assertEqual([a.artifact.artifact_id for a in bundle.artifacts], ['s1', 's2'])
        self.assertTrue(all(a.scope == 'binary' and not a.provenance.related_function_ids for a in bundle.artifacts))
        self.assertTrue(any(t.category == 'artifacts' for t in bundle.truncations))
        self.assertIn('artifacts: 4 observed -> 2 retained', bundle.render_text())

    def test_decompiled_limit_unicode(self):
        original = self.f['a'].decompiled_text
        bundle = self.build(max_decompiled_chars_per_function=19)
        self.assertEqual(bundle.functions[0].function.decompiled_text, original[:19])
        trunc = next(t for t in bundle.truncations if t.category == 'decompiled_text')
        self.assertEqual((trunc.observed_count_or_size, trunc.retained_count_or_size), (len(original), 19))

    def test_assembly_limit(self):
        bundle = self.build(max_assembly_chars_per_function=13)
        self.assertEqual(bundle.functions[0].function.assembly, self.f['a'].assembly[:13])
        self.assertTrue(any(t.category == 'assembly' for t in bundle.truncations))

    def test_upstream_assembly_truncation(self):
        self.f['a'].assembly_truncated = True
        self.store.save_program_index(self.index)
        bundle = self.build()
        trunc = next(t for t in bundle.truncations if t.reason == 'already truncated by M1 indexer')
        self.assertIsNone(trunc.observed_count_or_size)

    def test_total_budget_including_escaping_and_labels(self):
        for budget in (0, 1, 10, 11, 30, 100, 1000, 2200, 3000, 6000):
            with self.subTest(budget=budget):
                bundle = self.build(include_callees=True, include_strings=True, max_total_chars=budget)
                self.assertLessEqual(len(bundle.render_text()), budget)
                bodies = sum(len(f.function.decompiled_text or '') + len(f.function.assembly or '') for f in bundle.functions)
                values = sum(len(a.artifact.value) for a in bundle.artifacts)
                self.assertLessEqual(bodies + values, budget)
                if budget < 100:
                    self.assertTrue(any(t.category == 'total_chars' for t in bundle.truncations))
                    self.assertEqual(bundle.functions[0].function.function_id, 'b:a')

    def test_partial_text_budget_records_retained_size(self):
        self.f['a'].decompiled_text = '雪' * 5000
        self.store.save_program_index(self.index)
        bundle = self.build(max_total_chars=2100)
        self.assertLessEqual(len(bundle.render_text()), 2100)
        self.assertTrue(any(t.category == 'total_chars' for t in bundle.truncations))
        self.assertGreater(len(bundle.functions[0].function.decompiled_text), 0)
        self.assertLess(len(bundle.functions[0].function.decompiled_text), 5000)
        self.assertEqual(bundle.render_text(), bundle.render_text())

    def test_provenance_for_every_item(self):
        bundle = self.build(include_callees=True, include_imports=True, include_warnings=True)
        for item in bundle.functions + bundle.edges + bundle.artifacts + bundle.warnings:
            self.assertTrue(item.provenance.reason)
            self.assertTrue(item.provenance.source_id)
            self.assertEqual(item.provenance.binary_id, 'b')
            self.assertIn(item.provenance, bundle.provenance)
        for edge in bundle.edges:
            self.assertEqual(edge.provenance.address, edge.edge.callsite_address)

    def test_binary_isolation(self):
        other, other_functions = fixture('other')
        other.artifacts = [ArtifactRecord('foreign', 'other', 'STRING', '1', 'foreign')]
        self.store.save_program_index(other)
        with self.assertRaises(BinaryMismatchError):
            self.build(target=other_functions['a'])
        bundle = self.build(include_callees=True, include_strings=True)
        self.assertTrue(all(f.function.binary_id == 'b' for f in bundle.functions))
        self.assertNotIn('foreign', [a.artifact.artifact_id for a in bundle.artifacts])

    def test_external_import_address_association(self):
        bundle = self.build(target='EXTERNAL:1', include_strings=True, include_imports=True, max_artifacts=1)
        self.assertTrue(bundle.functions[0].function.is_external)
        self.assertEqual(bundle.artifacts[0].artifact.artifact_id, 'i1')
        self.assertEqual(bundle.artifacts[0].scope, 'external-address-match')
        self.assertEqual(bundle.artifacts[0].provenance.related_function_ids, ('b:e',))

    def test_thunk_does_not_invent_import_linkage(self):
        bundle = self.build(target='30', include_imports=True)
        self.assertTrue(bundle.functions[0].function.is_thunk)
        self.assertEqual(bundle.artifacts[0].scope, 'binary')

    def test_no_duplicate_evidence_and_cycle_safety(self):
        bundle = self.build(include_callers=True, include_callees=True, traversal_direction='both', max_depth=64)
        identities = [f.function.function_id for f in bundle.functions]
        self.assertEqual(len(identities), len(set(identities)))
        edges = [tuple(vars(e.edge).values()) for e in bundle.edges]
        self.assertEqual(len(edges), len(set(edges)))

    def test_request_validation(self):
        for depth in (-1, 65, True, 1.5, None):
            with self.assertRaises(ValueError):
                self.request(max_depth=depth)
        for name in ('max_functions', 'max_artifacts', 'max_edges', 'max_total_chars',
                     'max_decompiled_chars_per_function', 'max_assembly_chars_per_function', 'max_warnings'):
            for value in (-1, None, True, float('inf'), 10**9):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    self.request(**{name: value})
        with self.assertRaises(ValueError):
            self.request(include_assembly=1)
        with self.assertRaises(ValueError):
            self.request(traversal_direction='semantic')

    def test_all_zero_disabled(self):
        bundle = self.build(include_function=False, include_decompiled_text=False, include_assembly=False,
                            max_functions=0, max_artifacts=0, max_edges=0, max_warnings=0,
                            max_decompiled_chars_per_function=0, max_assembly_chars_per_function=0,
                            max_total_chars=0, max_depth=0)
        self.assertFalse(bundle.functions or bundle.edges or bundle.artifacts or bundle.warnings)
        self.assertEqual(bundle.render_text(), '')

    def test_global_warning_handling(self):
        bundle = self.build(include_warnings=True)
        self.assertEqual([w.ordinal for w in bundle.warnings], [0, 3])
        self.assertEqual(bundle.metadata['omitted_warning_count'], 2)
        self.assertTrue(all(not w.provenance.related_function_ids for w in bundle.warnings))
        bounded = self.build(include_warnings=True, max_warnings=1, max_warning_chars=7)
        self.assertEqual(bounded.warnings[0].text, 'Import:')
        self.assertEqual(bounded.metadata['omitted_warning_count'], 3)

    def test_json_safe_and_timing_independent(self):
        first = self.build(target=self.f['a'])
        second = self.build(target=self.f['a'])
        data = json.loads(json.dumps(first.to_dict()))
        self.assertEqual(data['request_summary']['target'], 'b:a')
        self.assertIn('timings', data['metadata'])
        self.assertEqual(first.to_dict(include_timings=False), second.to_dict(include_timings=False))
        self.assertEqual(first.render_text(), second.render_text())

    def test_target_none_binary_overview(self):
        bundle = self.build(target=None, include_strings=True, include_exports=True)
        self.assertEqual(bundle.functions, [])
        self.assertEqual(bundle.edges, [])
        self.assertEqual(len(bundle.artifacts), 3)

    def test_embedded_nul_preserved(self):
        bundle = self.build(include_strings=True)
        self.assertEqual(bundle.artifacts[0].artifact.value, 'first\x00雪')
        self.assertIn('first\\u0000雪', bundle.render_text())

    def test_reads_only_and_m3_reuse(self):
        changes = self.store._db.total_changes
        with patch.object(self.builder.query, '_walk', wraps=self.builder.query._walk) as walk:
            self.build(traversal_direction='forward', max_depth=2)
            walk.assert_called_once()
        self.assertEqual(self.store._db.total_changes, changes)
        self.assertEqual(self.store.load_program_index('b'), self.index)

    def test_no_jvm_import(self):
        subprocess.run([sys.executable, '-c',
                        'import aire.ai.context_builder,sys; assert "pyghidra" not in sys.modules; assert "jpype" not in sys.modules'], check=True)


if __name__ == '__main__':
    unittest.main()
