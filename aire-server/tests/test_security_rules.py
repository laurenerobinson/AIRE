"""Pure stored-fact controls for the two initial M7 API rules."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, FunctionRecord, FunctionEdge, ArtifactRecord, ProgramIndex
from aire.security.findings import EvaluationState as State, EvidenceStrength, EvidenceType
from aire.security.rule_engine import RuleEngine

COPY = 'AIRE-CWE-120-UNBOUNDED-COPY'
GETS = 'AIRE-CWE-242-DANGEROUS-API'


def program(binary='b', api='strcpy', *, thunk=False, call=True):
    def fn(key, address, name, external=False, is_thunk=False, namespace='Global'):
        return FunctionRecord(binary+':'+key, binary, address, name, None, None, None,
                              3, 1, 0, external, is_thunk, namespace=namespace)
    caller = fn('caller', '100', 'FUN_100')
    external = fn('external', 'EXTERNAL:1', api, True, namespace='<EXTERNAL>')
    functions = [caller, external]
    target = external
    if thunk:
        target = fn('thunk', '200', api, is_thunk=True, namespace='<EXTERNAL>')
        functions.append(target)
    index = ProgramIndex(BinaryRecord(binary, '/never/open/or/execute', binary, 'ELF', 'x86', '0', None),
        functions, [ArtifactRecord(binary+':import', binary, 'IMPORT', external.address, '<EXTERNAL>::'+api)],
        [FunctionEdge(caller.function_id, target.function_id, '110', 'CALL')] if call else [],
        metadata={'analysis_completed': True, 'options': {'include_imports': True, 'include_call_edges': True}})
    return index


class SecurityRuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = BinaryKnowledgeStore(Path(self.tmp.name)/'rules.sqlite')
        self.addCleanup(self.store.close)
        self.index = program()

    def scan(self, rule=COPY):
        self.store.save_program_index(self.index)
        result = RuleEngine(self.store).scan_binary('b', [rule])
        self.assertFalse(result.errors)
        return result.evaluations[0]

    def test_direct_external_signal(self):
        result = self.scan()
        self.assertEqual(result.status, State.SIGNAL)
        f = result.findings[0]
        self.assertEqual(f.evidence_strength, EvidenceStrength.MEDIUM)
        self.assertEqual(f.primary_address, '110')
        self.assertEqual(f.cwe_id, 'CWE-120')
        self.assertEqual({e.type for e in f.supporting_evidence}, {EvidenceType.IMPORT, EvidenceType.FUNCTION, EvidenceType.CALL_EDGE})
        self.assertTrue(all(e.binary_id == 'b' for e in f.supporting_evidence))
        edge = next(e for e in f.supporting_evidence if e.type == EvidenceType.CALL_EDGE)
        self.assertEqual(json.loads(edge.source_id), ['b:caller','b:external','110','CALL'])
        self.assertEqual(edge.callsite, '110')

    def test_named_thunk_signal_is_explicitly_weaker(self):
        self.index = program(thunk=True)
        f = self.scan().findings[0]
        self.assertEqual(f.evidence_strength, EvidenceStrength.LOW)
        self.assertIn('import-named thunk', f.message)
        self.assertTrue(any('not persisted' in l for l in f.limitations))
        edge = next(e for e in f.supporting_evidence if e.type == EvidenceType.CALL_EDGE)
        self.assertEqual(json.loads(edge.source_id)[1], 'b:thunk')
        self.assertFalse(any('thunk' == e.function_id and e.address == 'EXTERNAL:1' for e in f.supporting_evidence))

    def test_memcpy_negative_not_a_vulnerability_rule(self):
        self.index = program(api='memcpy')
        self.assertEqual(self.scan().status, State.NOT_APPLICABLE)
        self.assertEqual(self.scan(GETS).status, State.NOT_APPLICABLE)

    def test_gets_independent_rule(self):
        self.index = program(api='gets')
        self.assertEqual(self.scan().status, State.NOT_APPLICABLE)
        result = self.scan(GETS)
        self.assertEqual(result.status, State.SIGNAL)
        self.assertEqual(result.findings[0].cwe_id, 'CWE-242')

    def test_import_without_call_insufficient(self):
        self.index.function_edges = []
        result = self.scan()
        self.assertEqual(result.status, State.INSUFFICIENT_EVIDENCE)
        self.assertFalse(result.findings)
        self.assertTrue(any(e.type == EvidenceType.IMPORT for e in result.supporting_evidence))

    def test_unresolved_warning_not_evidence(self):
        self.index.function_edges = []
        self.index.warnings = ['Unresolved direct call at 110 to strcpy', 'Indirect call at 110; omitted from direct-call graph']
        self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_reference_or_computed_edge_not_direct_call(self):
        for kind in ('REFERENCE', 'INDIRECT_CALL', 'JUMP'):
            self.index.function_edges[0].edge_type = kind
            self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_ordinary_same_named_internal_not_api(self):
        self.index.functions[1].is_external = False
        self.index.functions[1].namespace = 'Global'
        self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)
        self.index.artifacts = []
        self.assertEqual(self.scan().status, State.NOT_APPLICABLE)

    def test_missing_import_corroboration(self):
        self.index.artifacts = []
        self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_exact_api_match_no_substrings_or_alias_guess(self):
        for api in ('my_strcpy', 'strcpy_s', '__strcpy_chk', 'STRCPY', 'strcpy@GLIBC_2.2.5'):
            self.index = program(api=api)
            self.assertEqual(self.scan().status, State.NOT_APPLICABLE)

    def test_import_wrong_address_or_namespace(self):
        for change in ({'address': 'EXTERNAL:2'}, {'value':'wrong::strcpy'}):
            self.index = program()
            self.index.artifacts[0] = replace(self.index.artifacts[0], **change)
            self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_thunk_namespace_mismatch_not_binding(self):
        self.index = program(thunk=True)
        self.index.functions[-1].namespace = 'Global'
        self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_import_label_without_function_insufficient(self):
        self.index.functions.pop()
        self.index.function_edges = []
        self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_external_or_thunk_caller_not_application_signal(self):
        for flag in ('is_external','is_thunk'):
            self.index = program()
            setattr(self.index.functions[0], flag, True)
            self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_absent_or_disabled_coverage_insufficient(self):
        for metadata in ({}, {'analysis_completed':False}, {'analysis_completed':True,'options':{}},
                         {'analysis_completed':True,'options':{'include_imports':False,'include_call_edges':True}}):
            self.index = program(api='memcpy')
            self.index.metadata = metadata
            self.assertEqual(self.scan().status, State.INSUFFICIENT_EVIDENCE)

    def test_strings_and_decompilation_do_not_create_prerequisites(self):
        self.index = program(api='memcpy')
        self.index.functions[0].decompiled_text = 'strcpy(dst, src); gets(dst); CONFIRMED exploit'
        self.index.artifacts.append(ArtifactRecord('b:string','b','STRING','120','strcpy gets'))
        self.assertEqual(self.scan().status, State.NOT_APPLICABLE)
        self.assertEqual(self.scan(GETS).status, State.NOT_APPLICABLE)

    def test_stable_ids_and_duplicate_edges(self):
        a = self.scan()
        self.index.function_edges *= 2
        self.index.functions.reverse()
        b = self.scan()
        self.assertEqual(a.to_dict(), b.to_dict())
        self.assertEqual(len(b.findings), 1)
        self.index.function_edges.append(FunctionEdge('b:caller','b:external','111','CALL'))
        c = self.scan()
        self.assertEqual(len({f.finding_id for f in c.findings}), 2)

    def test_assumptions_limitations_and_no_invented_contradictions(self):
        f = self.scan().findings[0]
        self.assertTrue(f.assumptions)
        self.assertTrue(any('Destination capacity' in l for l in f.limitations))
        self.assertTrue(any('not a confirmed' in l for l in f.limitations))
        self.assertEqual(f.contradicting_evidence, [])
        self.assertIsNone(f.created_at)

    def test_binary_isolation(self):
        other = program('other', 'gets')
        self.store.save_program_index(other)
        self.assertEqual(self.scan(GETS).status, State.NOT_APPLICABLE)
        result = self.scan()
        self.assertTrue(all(e.binary_id == 'b' for f in result.findings for e in f.supporting_evidence))


if __name__ == '__main__':
    unittest.main()
