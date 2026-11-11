"""M9 Phase 3: deterministic crypto API evidence over stored facts (no JVM/model)."""
from pathlib import Path
import tempfile
import unittest

from aire.agent.tools import AgentTools
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import (ArtifactRecord, BinaryRecord, FunctionEdge, FunctionRecord, ProgramIndex,
                                   ReferenceRecord, ThunkRecord)
from aire.security.crypto_evidence import classify_api, crypto_evidence

B = 'c' * 64


def fn(address, name, external=False, thunk=False):
    return FunctionRecord(f'{B}:{address}', B, address, name, None, None, None, None, None, None,
                          is_external=external, is_thunk=thunk)


def snapshot():
    # A stripped binary: application functions carry no meaningful names.
    functions = [
        fn('140001000', 'FUN_140001000'),          # key setup + encrypt via IAT computed call
        fn('140001100', 'FUN_140001100'),          # decrypt via thunk chain
        fn('140001200', 'FUN_140001200'),          # hashing with identifier string
        fn('140001300', 'FUN_140001300'),          # orchestrator (main)
        fn('140001400', 'FUN_140001400'),          # non-crypto: printf only
        fn('140002000', 'BCryptDecrypt', thunk=True),
        fn('EXTERNAL:00000001', 'BCryptEncrypt', external=True),
        fn('EXTERNAL:00000002', 'BCryptDecrypt', external=True),
        fn('EXTERNAL:00000003', 'BCryptOpenAlgorithmProvider', external=True),
        fn('EXTERNAL:00000004', 'BCryptHash', external=True),
        fn('EXTERNAL:00000005', 'printf', external=True),
    ]
    artifacts = [
        ArtifactRecord('a-enc', B, 'IMPORT', 'EXTERNAL:00000001', 'BCRYPT.DLL::BCryptEncrypt'),
        ArtifactRecord('a-dec', B, 'IMPORT', 'EXTERNAL:00000002', 'BCRYPT.DLL::BCryptDecrypt'),
        ArtifactRecord('a-open', B, 'IMPORT', 'EXTERNAL:00000003', 'BCRYPT.DLL::BCryptOpenAlgorithmProvider'),
        ArtifactRecord('a-hash', B, 'IMPORT', 'EXTERNAL:00000004', 'BCRYPT.DLL::BCryptHash'),
        ArtifactRecord('a-printf', B, 'IMPORT', 'EXTERNAL:00000005', 'MSVCRT.DLL::printf'),
        ArtifactRecord('s-aes', B, 'STRING', '140005000', 'AES'),
        ArtifactRecord('s-gcm', B, 'STRING', '140005010', 'ChainingModeGCM'),
        ArtifactRecord('s-sha', B, 'STRING', '140005030', 'SHA256'),
        ArtifactRecord('s-hello', B, 'STRING', '140005040', 'hello SHA256 world'),  # not an exact identifier
    ]
    def call(rid, source, owner, artifact, target='EXTERNAL:00000001'):
        return ReferenceRecord(rid, B, source, target, 'COMPUTED_CALL', f'{B}:{owner}', None, artifact,
                               'CALL qword ptr [0x140008000]', 0, True, True, False)
    def data(rid, source, owner, artifact, target):
        return ReferenceRecord(rid, B, source, target, 'DATA', f'{B}:{owner}', None, artifact,
                               'LEA RDX,[0x140005000]', 1, False, False, False)
    references = [
        call('r1', '140001010', '140001000', 'a-open', 'EXTERNAL:00000003'),
        data('r2', '140001008', '140001000', 's-aes', '140005000'),
        data('r3', '140001018', '140001000', 's-gcm', '140005010'),
        call('r4', '140001040', '140001000', 'a-enc'),
        data('r5', '140001208', '140001200', 's-sha', '140005030'),
        call('r6', '140001210', '140001200', 'a-hash', 'EXTERNAL:00000004'),
        data('r7', '140001220', '140001200', 's-hello', '140005040'),
        call('r8', '140001410', '140001400', 'a-printf', 'EXTERNAL:00000005'),
        # unowned call references (e.g. in data) must be ignored
        ReferenceRecord('r9', B, '140009000', 'EXTERNAL:00000001', 'COMPUTED_CALL', None, None, 'a-enc',
                        None, 0, True, True, False),
    ]
    edges = [
        FunctionEdge(f'{B}:140001100', f'{B}:140002000', '140001120', 'CALL'),  # into thunk
        FunctionEdge(f'{B}:140001300', f'{B}:140001000', '140001310', 'CALL'),
        FunctionEdge(f'{B}:140001300', f'{B}:140001100', '140001320', 'CALL'),
        FunctionEdge(f'{B}:140001300', f'{B}:140001200', '140001330', 'CALL'),
        FunctionEdge(f'{B}:140001300', f'{B}:140001400', '140001340', 'CALL'),
    ]
    thunks = [ThunkRecord(f'{B}:140002000', f'{B}:EXTERNAL:00000002', '140002000', 'EXTERNAL:00000002',
                          'JMP qword ptr [0x140008008]', False)]
    return ProgramIndex(BinaryRecord(B, '/fixture.exe', B, 'PE', 'x86:LE:64:default', '140000000', None),
                        functions, artifacts, edges, [], {}, references, thunks)


class CryptoEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(Path(directory.name) / 'a.sqlite')
        self.addCleanup(self.store.close)
        self.store.save_program_index(snapshot())
        self.report = crypto_evidence(self.store._db, B)
        self.rows = {row['address']: row for row in self.report['functions']}

    def test_operations_attributed_from_callsites_not_names(self):
        self.assertEqual(set(self.rows), {'140001000', '140001100', '140001200'})
        self.assertEqual(self.rows['140001000']['primary_operations'], ['encryption'])
        self.assertIn('provider', self.rows['140001000']['operations'])
        self.assertEqual(self.rows['140001100']['primary_operations'], ['decryption'])
        self.assertEqual(self.rows['140001200']['primary_operations'], ['hashing'])

    def test_exact_callsites_with_provenance(self):
        calls = {c['api']: c for c in self.rows['140001000']['callsites']}
        self.assertEqual(calls['BCryptEncrypt']['address'], '140001040')
        self.assertEqual(calls['BCryptEncrypt']['source_table'], 'binary_references')
        self.assertEqual(calls['BCryptEncrypt']['source_id'], 'r4')
        self.assertEqual(calls['BCryptEncrypt']['dll'], 'BCRYPT.DLL')
        thunk_call = self.rows['140001100']['callsites'][0]
        self.assertEqual((thunk_call['api'], thunk_call['address'], thunk_call['source_table']),
                         ('BCryptDecrypt', '140001120', 'function_edges'))

    def test_algorithm_identifiers_require_exact_owned_strings(self):
        self.assertEqual(self.rows['140001000']['algorithm_identifiers'], ['AES', 'GCM mode'])
        self.assertEqual(self.rows['140001200']['algorithm_identifiers'], ['SHA-256'])
        values = {s['value'] for s in self.rows['140001200']['identifier_strings']}
        self.assertNotIn('hello SHA256 world', values)

    def test_relationships_and_summary(self):
        callers = {c['address'] for c in self.rows['140001100']['callers']}
        self.assertEqual(callers, {'140001300'})
        self.assertEqual(self.report['orchestrators'][0]['address'], '140001300')
        self.assertEqual(self.report['orchestrators'][0]['calls'], ['140001000', '140001100', '140001200'])
        summary = self.report['summary']
        self.assertEqual(summary['crypto_api_imports'], 4)
        self.assertEqual(summary['crypto_api_imports_called'], 4)
        self.assertEqual(summary['families'], ['cng'])
        self.assertNotIn('printf', {row['api'] for row in self.report['imports']})
        self.assertTrue(self.report['limitations'])

    def test_no_crypto_binary_reports_empty(self):
        other = 'd' * 64
        plain = ProgramIndex(BinaryRecord(other, '/p', other, 'PE', None, '0', None),
                             [FunctionRecord(f'{other}:1', other, '1', 'FUN_1', None, None, None, None, None, None)])
        self.store.save_program_index(plain)
        report = crypto_evidence(self.store._db, other)
        self.assertEqual(report['functions'], [])
        self.assertEqual(report['summary']['crypto_api_imports'], 0)

    def test_registered_agent_tool(self):
        tools = AgentTools(self.store, B)
        result = tools.registry.run('crypto_evidence', {'limit': 2})
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(result['data']['functions']), 2)
        self.assertTrue(result['data']['truncated'])

    def test_classify_api(self):
        self.assertEqual(classify_api('BCRYPT.DLL::BCryptSignHash'), ('cng', 'signing'))
        self.assertEqual(classify_api('BCryptVerifySignature'), ('cng', 'verification'))
        self.assertEqual(classify_api('ADVAPI32.DLL::CryptAcquireContextW'), ('cryptoapi', 'provider'))
        self.assertEqual(classify_api('EVP_EncryptUpdate'), ('openssl', 'encryption'))
        self.assertEqual(classify_api('SHA256_Final'), ('openssl', 'hashing'))
        self.assertEqual(classify_api('BCryptFutureThing'), ('cng', 'other'))
        self.assertIsNone(classify_api('printf'))
        self.assertIsNone(classify_api('CryptoNothing'.lower()))


if __name__ == '__main__':
    unittest.main()
