"""Opt-in compile/index-only security controls. Never execute a fixture."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from aire.knowledge.database import BinaryKnowledgeStore
from aire.security.findings import EvaluationState as State, EvidenceType, EvidenceStrength
from aire.security.rule_engine import RuleEngine

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / 'tests/fixtures/security_rules'
COPY = 'AIRE-CWE-120-UNBOUNDED-COPY'
GETS = 'AIRE-CWE-242-DANGEROUS-API'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in static security integration')
class SecurityIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('gcc') is None:
            raise unittest.SkipTest('Security fixture compilation requires the existing gcc toolchain')
        from aire.pyghidra.indexer import index_binary
        from aire.pyghidra.options import IndexOptions
        cls.directory = tempfile.TemporaryDirectory(prefix='aire_m7_')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.output = Path(cls.directory.name)
        # Only the compiler/build script is launched, never its target outputs.
        environment = dict(os.environ, AIRE_SECURITY_FIXTURE_OUTPUT_DIR=str(cls.output))
        subprocess.run(['bash', str(SOURCES/'build.sh')], check=True, env=environment)
        cls.paths = {name: cls.output/name for name in ('unsafe_copy','safe_copy','dangerous_gets')}
        cls.before = {name: digest(path) for name, path in cls.paths.items()}
        cls.index_times = {}
        cls.path = cls.output/'analysis.sqlite'
        cls.reports = {}
        with BinaryKnowledgeStore(cls.path) as store:
            for name, path in cls.paths.items():
                tick = time.perf_counter()
                try:
                    # No decompiler prose required by M7.
                    index = index_binary(path, IndexOptions(decompile=False, include_assembly=False))
                    store.save_program_index(index)
                finally:
                    if digest(path) != cls.before[name]:
                        raise AssertionError('Fixture modified during static indexing')
                cls.index_times[name] = time.perf_counter() - tick

    @classmethod
    def tearDownClass(cls):
        after = {name: digest(path) for name, path in cls.paths.items()}
        if after != cls.before:
            raise AssertionError('Security fixtures modified')
        if os.environ.get('AIRE_SECURITY_REPORT'):
            Path(os.environ['AIRE_SECURITY_REPORT']).write_text(json.dumps(cls.reports, indent=2))

    def run_control(self, name, expected_rule=None, api=None, caller_name=None):
        binary_id = self.before[name]
        with BinaryKnowledgeStore(self.path) as store:
            original = store.load_program_index(binary_id)
            db_before = digest(self.path)
            changes = store._db.total_changes
            store._db.execute('PRAGMA query_only=ON')
            try:
                with patch('socket.socket', side_effect=AssertionError('No network in M7')), \
                     patch('subprocess.Popen', side_effect=AssertionError('No execution in M7')):
                    result = RuleEngine(store).scan_binary(binary_id)
                    repeated = RuleEngine(store).scan_binary(binary_id)
                self.assertFalse(result.errors)
                self.assertEqual(result.to_dict(include_timings=False), repeated.to_dict(include_timings=False))
                self.assertEqual(len(result.evaluations), 2)
                if expected_rule is None:
                    self.assertFalse(result.findings)
                    self.assertTrue(all(e.status == State.NOT_APPLICABLE for e in result.evaluations))
                    self.assertTrue(any(f.current_name == 'memcpy' and f.is_external for f in original.functions))
                else:
                    self.assertEqual(len(result.findings), 1)
                    finding = result.findings[0]
                    self.assertEqual(finding.rule_id, expected_rule)
                    self.assertEqual(finding.status, State.SIGNAL)
                    self.assertEqual(finding.cwe_id, 'CWE-120' if api == 'strcpy' else 'CWE-242')
                    caller = next(f for f in original.functions if f.function_id == finding.primary_function_id)
                    self.assertEqual(caller.current_name, caller_name)
                    call = next(e for e in finding.supporting_evidence if e.type == EvidenceType.CALL_EDGE)
                    identity = json.loads(call.source_id)
                    self.assertTrue(any([e.caller_function_id,e.callee_function_id,e.callsite_address,e.edge_type] == identity
                                        for e in original.function_edges))
                    self.assertEqual(call.callsite, finding.primary_address)
                    target = next(f for f in original.functions if f.function_id == identity[1])
                    self.assertEqual(target.current_name, api)
                    self.assertTrue(target.is_external or target.is_thunk)
                    self.assertEqual(finding.evidence_strength, EvidenceStrength.MEDIUM if target.is_external else EvidenceStrength.LOW)
                    imports = [e for e in finding.supporting_evidence if e.type == EvidenceType.IMPORT]
                    self.assertEqual(len(imports), 1)
                    self.assertTrue(any(a.artifact_id == imports[0].artifact_id and a.type == 'IMPORT'
                                        for a in original.artifacts))
                    self.assertTrue(finding.limitations)
                    self.assertTrue(any('not a confirmed' in limit for limit in finding.limitations))
            finally:
                self.assertEqual(store._db.total_changes, changes)
                self.assertEqual(store.load_program_index(binary_id), original)
                self.assertEqual(digest(self.path), db_before)
                self.assertEqual({key:digest(path) for key,path in self.paths.items()}, self.before)
        self.reports[name] = {
            'sha256_before': binary_id, 'sha256_after': digest(self.paths[name]),
            'index_and_persist_seconds': self.index_times[name],
            'database_unchanged': True, 'target_executed': False,
            'scan_network_and_process_creation_blocked': True, 'result': result.to_dict()}

    def test_positive_strcpy(self):
        self.run_control('unsafe_copy', COPY, 'strcpy', 'copy_input')

    def test_positive_gets(self):
        self.run_control('dangerous_gets', GETS, 'gets', 'read_input')

    def test_negative_bounded_copy(self):
        self.run_control('safe_copy')


if __name__ == '__main__':
    unittest.main()
