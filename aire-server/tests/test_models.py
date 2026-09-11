"""Verify evidence containers cannot leak between independent records."""
import unittest
from aire.knowledge.models import BehaviorTag
from aire.security.findings import SecurityFinding


class EvidenceIsolationTests(unittest.TestCase):
    def test_behavior_evidence_is_independent(self):
        first, second = BehaviorTag("f1", "crypto"), BehaviorTag("f2", "crypto")
        first.evidence.append("call to EVP_EncryptUpdate")
        self.assertEqual(second.evidence, [])

    def test_finding_evidence_is_independent(self):
        first = SecurityFinding("a", "r", None, "0x1", "candidate", 0.0)
        second = SecurityFinding("b", "r", None, "0x2", "candidate", 0.0)
        first.supporting_evidence.append("observed fact")
        self.assertEqual(first.contradicting_evidence, [])
        self.assertEqual(second.supporting_evidence, [])


if __name__ == "__main__":
    unittest.main()
