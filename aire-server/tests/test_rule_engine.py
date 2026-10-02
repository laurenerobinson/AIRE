"""Pure M7 contract, provenance, deterministic execution and read-only tests."""
from contextlib import redirect_stdout
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aire.knowledge.database import BinaryKnowledgeStore
from aire.security.contracts import RuleMetadata, RuleRegistry, SecurityRule
from aire.security.facts import load_rule_facts
from aire.security.findings import EvaluationState as State, EvidenceStrength, stable_id
from aire.security.rule_engine import RuleEngine, default_registry, render_scan, main, _ReadOnlyRuleStore
from aire.security.rules import UnboundedCopyRule, DangerousApiRule
from test_security_rules import program, COPY, GETS


class CallbackRule(SecurityRule):
    def __init__(self, callback, identity='ZZZ-TEST-FAILURE'):
        self.metadata = replace(UnboundedCopyRule.metadata, rule_id=identity)
        self.callback = callback

    def evaluate(self, facts):
        return self.callback(facts)


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'analysis.sqlite'
        self.store = BinaryKnowledgeStore(self.path)
        self.addCleanup(self.store.close)
        self.store.save_program_index(program())
        self.engine = RuleEngine(self.store)

    def test_metadata_and_versions(self):
        metadata = self.engine.registry.list_rules()
        self.assertEqual([m.rule_id for m in metadata], [COPY, GETS])
        self.assertEqual([m.cwe_id for m in metadata], ['CWE-120', 'CWE-242'])
        for m in metadata:
            self.assertEqual(m.version, '1.0.0')
            self.assertTrue(m.required_facts)
            self.assertTrue(m.cwe_title)
            self.assertIsNone(m.severity_hint)
            json.dumps(m.to_dict(), allow_nan=False)

    def test_bad_metadata_rejected(self):
        for changes in ({'version':'latest'}, {'cwe_id':'120'}, {'rule_id':'bad id'},
                        {'required_facts':['imports']}, {'title':''}):
            with self.assertRaises(ValueError):
                replace(UnboundedCopyRule.metadata, **changes)

    def test_registry_duplicates_and_order(self):
        registry = RuleRegistry()
        registry.register(DangerousApiRule())
        registry.register(UnboundedCopyRule())
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            registry.register(UnboundedCopyRule())
        newer = UnboundedCopyRule()
        newer.metadata = replace(newer.metadata, version='2.0.0')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            registry.register(newer)
        self.assertEqual(registry.list_rules(), default_registry().list_rules())
        self.assertEqual([r.metadata.rule_id for r in registry.select([GETS, COPY])], [COPY, GETS])

    def test_selection(self):
        result = self.engine.scan_binary('b', [GETS])
        self.assertEqual([e.rule_id for e in result.evaluations], [GETS])
        self.assertEqual(result.rule_counts['selected'], 1)
        self.assertFalse(self.engine.scan_binary('b', []).evaluations)
        for selection in ([COPY, COPY], ['unknown'], COPY, [3]):
            with self.assertRaises(ValueError):
                self.engine.scan_binary('b', selection)

    def test_repeat_serialization_and_renderer(self):
        a, b = self.engine.scan_binary('b'), self.engine.scan_binary('b')
        self.assertEqual(a.to_dict(include_timings=False), b.to_dict(include_timings=False))
        self.assertEqual(render_scan(a), render_scan(b))
        wire = json.loads(json.dumps(a.to_dict(), allow_nan=False))
        self.assertEqual(wire['findings'][0]['status'], 'SIGNAL')
        self.assertIn('CWE-120', render_scan(a))
        self.assertIn('not a confirmed', render_scan(a))
        self.assertEqual(set(a.timing['per_rule_seconds']), {COPY, GETS})
        self.assertGreaterEqual(a.timing['total_scan_seconds'], sum(a.timing['per_rule_seconds'].values()))

    def test_stable_identity_is_version_and_binary_scoped(self):
        first = self.engine.scan_binary('b').findings[0]
        rule = UnboundedCopyRule()
        rule.metadata = replace(rule.metadata, version='1.1.0')
        registry = RuleRegistry()
        registry.register(rule)
        second = RuleEngine(self.store, registry).scan_binary('b').findings[0]
        self.assertNotEqual(first.finding_id, second.finding_id)
        self.store.save_program_index(program('other'))
        third = self.engine.scan_binary('other').findings[0]
        self.assertNotEqual(first.finding_id, third.finding_id)
        self.assertEqual(first.finding_id, stable_id('FINDING','b',COPY,'1.0.0','b:caller','110',first.discriminator))

    def test_rule_failure_preserves_completed_results(self):
        def fail(_):
            raise RuntimeError('controlled rule failure')
        self.engine.registry.register(CallbackRule(fail))
        result = self.engine.scan_binary('b')
        self.assertEqual(result.rule_counts['evaluated'], 2)
        self.assertEqual(result.rule_counts['failed'], 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.errors[0].error_type, 'RuntimeError')
        self.assertIn('controlled rule failure', render_scan(result))
        self.assertIn('incomplete', ' '.join(result.warnings))

    def scan_modified(self, mutate):
        def evaluate(facts):
            return mutate(UnboundedCopyRule().evaluate(facts), facts)
        registry = RuleRegistry()
        registry.register(CallbackRule(evaluate, COPY))
        return RuleEngine(self.store, registry).scan_binary('b')

    def test_candidate_contract_without_builtin_escalation(self):
        # A contract exercise only; no production rule promotes these facts.
        def promote(evaluation, _):
            finding = replace(evaluation.findings[0], status=State.CANDIDATE)
            return replace(evaluation, status=State.CANDIDATE, findings=(finding,))
        result = self.scan_modified(promote)
        self.assertFalse(result.errors)
        self.assertEqual(result.findings[0].status, State.CANDIDATE)
        self.assertEqual(self.engine.scan_binary('b').findings[0].status, State.SIGNAL)

    def test_invalid_aggregate_state_rejected(self):
        result = self.scan_modified(lambda e, _: replace(e, status=State.CANDIDATE))
        self.assertEqual(len(result.errors), 1)
        self.assertFalse(result.findings)

    def test_contradicting_evidence_supported_without_inventing_it(self):
        def add(evaluation, facts):
            # Context can be supplied as a contradiction by a future rule; the
            # framework validates provenance, not the author's logical argument.
            item = facts.source('functions', 'b:caller')
            finding = replace(evaluation.findings[0], contradicting_evidence=[item])
            return replace(evaluation, findings=(finding,), contradicting_evidence=(item,))
        result = self.scan_modified(add)
        self.assertFalse(result.errors)
        self.assertEqual(result.findings[0].contradicting_evidence[0].function_id, 'b:caller')

    def test_forged_evidence_description_rejected(self):
        def forge(evaluation, _):
            f = evaluation.findings[0]
            f.supporting_evidence[0] = replace(f.supporting_evidence[0], description='invented behavior')
            return evaluation
        result = self.scan_modified(forge)
        self.assertEqual(len(result.errors), 1)
        self.assertIn('exact item', result.errors[0].message)

    def test_cross_binary_evidence_rejected(self):
        self.store.save_program_index(program('other'))
        foreign = load_rule_facts(self.store, 'other').evidence[0]
        def forge(e, _):
            e.findings[0].supporting_evidence.append(foreign)
            return e
        self.assertTrue(self.scan_modified(forge).errors)

    def test_bad_identity_and_probability_rejected(self):
        for field, value in [('finding_id','random'), ('binary_id','other'), ('cwe_id','CWE-999'),
                             ('evidence_strength',0.99), ('status','CONFIRMED')]:
            def mutate(e, _, field=field, value=value):
                setattr(e.findings[0], field, value)
                return e
            result = self.scan_modified(mutate)
            self.assertTrue(result.errors, field)
            self.assertFalse(result.findings)

    def test_invalid_evaluation_identity_and_type(self):
        for mutate in (lambda e, _: replace(e, binary_id='other'), lambda e, _: 'SIGNAL'):
            self.assertTrue(self.scan_modified(mutate).errors)

    def test_facts_are_immutable_without_model_text_or_handles(self):
        facts = load_rule_facts(self.store, 'b')
        with self.assertRaises(FrozenInstanceError):
            facts.functions[0].current_name = 'renamed'
        with self.assertRaises(FrozenInstanceError):
            facts.calls = ()
        for field in ('store','program','model','chat_service','executable_path'):
            self.assertFalse(hasattr(facts, field))
        self.assertFalse(hasattr(facts.functions[0], 'decompiled_text'))

    def test_scan_no_database_file_process_or_network_mutation(self):
        before = self.store.load_program_index('b')
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        changes = self.store._db.total_changes
        self.store._db.execute('PRAGMA query_only=ON')
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('process forbidden')), \
             patch('os.system', side_effect=AssertionError('shell forbidden')), \
             patch('builtins.open', side_effect=AssertionError('file open forbidden')):
            result = self.engine.scan_binary('b')
        self.assertFalse(result.errors)
        self.assertEqual(self.store._db.total_changes, changes)
        self.assertEqual(self.store.load_program_index('b'), before)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)

    def test_no_ai_ghidra_or_ollama_import_dependency(self):
        code = '''import sys
class DenyAnalysisAndModels:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(('aire.ai', 'aire.pyghidra', 'pyghidra', 'ghidra', 'jpype', 'ollama')):
            raise AssertionError('Forbidden dependency: ' + fullname)
sys.meta_path.insert(0, DenyAnalysisAndModels())
from aire.security.rule_engine import RuleEngine, _ReadOnlyRuleStore
with _ReadOnlyRuleStore(sys.argv[1]) as store:
    result = RuleEngine(store).scan_binary('b')
    assert not result.errors and len(result.findings) == 1
'''
        completed = subprocess.run([sys.executable, '-c', code, str(self.path)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_cli_read_only_json_selection(self):
        before = self.path.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([str(self.path),'b','--rule',COPY,'--json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())['rule_counts']['selected'], 1)
        self.assertEqual(self.path.read_bytes(), before)
        with _ReadOnlyRuleStore(self.path) as store:
            with self.assertRaises(Exception):
                store._db.execute('DELETE FROM functions')

    def test_cli_does_not_create_database(self):
        path = Path(self.tmp.name)/'absent.sqlite'
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(path),'b']), 1)
        self.assertFalse(path.exists())

    def test_renderer_escapes_binary_control_characters(self):
        index = program()
        index.functions[0].current_name = 'FUN_100\x1b[31m\nforge'
        self.store.save_program_index(index)
        rendered = render_scan(self.engine.scan_binary('b'))
        self.assertNotIn('\x1b', rendered)
        self.assertIn('forge', rendered)


if __name__ == '__main__':
    unittest.main()
