"""Verify evidence containers cannot leak between independent records."""
import unittest
from aire.knowledge.models import BehaviorTag
from aire.security.findings import SecurityFinding, EvaluationState, EvidenceStrength, stable_id


class EvidenceIsolationTests(unittest.TestCase):
    def test_behavior_evidence_is_independent(self):
        first, second = BehaviorTag("f1", "crypto"), BehaviorTag("f2", "crypto")
        first.evidence.append("call to EVP_EncryptUpdate")
        self.assertEqual(second.evidence, [])

    def test_finding_evidence_is_independent(self):
        def finding(address):
            return SecurityFinding(stable_id('FINDING', 'b', 'r', '1.0.0', 'f', address, 'test'),
                'b', 'r', '1.0.0', 'CWE-120', 'Test signal', EvaluationState.SIGNAL,
                EvidenceStrength.LOW, 'f', address, 'Static test only', 'test')
        first, second = finding('0x1'), finding('0x2')
        first.supporting_evidence.append("observed fact")
        self.assertEqual(first.contradicting_evidence, [])
        self.assertEqual(second.supporting_evidence, [])


if __name__ == "__main__":
    unittest.main()
