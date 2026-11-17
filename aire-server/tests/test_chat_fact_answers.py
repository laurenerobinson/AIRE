"""Chat-performance Step 1: deterministic routing for factual crypto/API/graph questions.

Uses real PyGhidra index facts for the M9 AES-256-GCM, SHA-256 and ECDSA PEs
(tests/fixtures/chatperf, exported by scripts/export_chat_crypto_fixture.py) and
checks answers against the independent source/PDB ground truth. No model is
ever called on these paths; any model call fails the test.
"""
import json
from pathlib import Path
import re
import shutil
import tempfile
import time
import unittest

from aire.agent import fact_answers as fa
from aire.api.server import GuiApplication, GuiError

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/fixtures/chatperf/crypto_pe_index.sqlite'
TRUTH = json.loads((ROOT / 'tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json').read_text())['programs']
NAMES = {'aes_gcm': 'aes_gcm.exe', 'sha256_hash': 'sha256_hash.exe', 'ecdsa_sign': 'ecdsa_sign.exe'}
ROLE_QUESTIONS = {
    'encryption': 'Which function encrypts data?',
    'decryption': 'Which function decrypts data?',
    'hashing': 'Which function hashes the input?',
    'signing': 'Which function signs the data?',
    'verification': 'Which function verifies the digital signature?',
}
LABEL = {'encryption': 'Encryption', 'decryption': 'Decryption', 'hashing': 'Hashing',
         'signing': 'Signature creation', 'verification': 'Signature verification'}


class NoModel:
    model, num_ctx = 'none', 4096
    calls = 0

    def generate(self, *args, **kwargs):
        NoModel.calls += 1
        raise AssertionError('model must not be called on a deterministic path')


def table_rows(answer, label):
    """Rows of the role table for one role label: [{'function', 'apis', 'callers'}] or [{'absent': True}]."""
    rows = []
    for line in answer.splitlines():
        cells = [c.strip() for c in re.split(r'(?<!\\)\|', line.strip())[1:-1]] if line.startswith('|') else []
        if not cells or cells[0] != label:
            continue
        match = re.match(r'`FUN_([0-9a-f]{8})` `0x\1`', cells[1])
        rows.append({'function': match.group(1), 'apis': cells[2], 'callers': cells[3]} if match else {'absent': True})
    return rows


def role_facts(result, role):
    """Function addresses the structured (verified) facts attribute to one role."""
    return {f['address'] for f in result.presentation['facts'].get('roles', []) if f['role'] == role}


def addresses(text):
    return set(re.findall(r'0x([0-9a-f]{8})', text))


class RoutingTests(unittest.TestCase):
    def test_requested_natural_variations(self):
        cases = {
            'Which functions perform encryption and decryption?': ('crypto_operations', ['encryption', 'decryption']),
            'Where does this program encrypt data?': ('crypto_operations', ['encryption']),
            'Find the function that calls BCryptEncrypt.': ('crypto_api', None),
            'Which function verifies the digital signature?': ('crypto_operations', ['verification']),
            'What cryptographic operations does this binary perform?': ('crypto_operations', []),
            'Which function signs or verifies a digital signature?': ('crypto_operations', ['signing', 'verification']),
            'Which function computes the SHA-256 hash?': ('crypto_operations', ['hashing']),
            'What API calls does this function make?': ('function_apis', None),
            'What calls this function?': ('callers', None),
            'Who calls FUN_0041d160?': ('callers', None),
            'What does FUN_0041d2a0 call?': ('callees', None),
            'Show the evidence for this function.': ('evidence', None),
            'Does this binary use crypto or hashing?': ('crypto_operations', ['hashing']),
        }
        for question, (intent, operations) in cases.items():
            with self.subTest(question):
                routed = fa.classify(question)
                self.assertIsNotNone(routed)
                self.assertEqual(routed['intent'], intent)
                if operations is not None:
                    self.assertEqual(routed['operations'], operations)
        self.assertEqual(fa.classify('Find the function that calls BCryptEncrypt.')['apis'], ['BCryptEncrypt'])

    def test_unsupported_or_evaluative_questions_fall_through(self):
        for question in ('What does this binary do?', 'Is the encryption secure?', 'Why does it encrypt the buffer?',
                         'How does this binary encrypt data?', 'Explain this function', 'Summarize this function',
                         'Explain this assembly', 'What does this function do?', 'Show me the most important functions.',
                         'Find suspicious behavior in this binary', 'Where is input validation performed?',
                         'What happens when the branch at 0x4011e1 is true?',
                         'Where does the value of EAX at 0x4011dc come from?'):
            with self.subTest(question):
                self.assertIsNone(fa.classify(question))

    def test_integer_and_prototype_vocabulary_is_not_crypto(self):
        for question in ('What is the signature of FUN_0041d160?', 'Which instruction does a signed comparison?',
                         'Where does it sign-extend EAX?', 'Which function opens the registry key?',
                         'Where does the program verify the input length?'):
            with self.subTest(question):
                routed = fa.classify(question)
                self.assertTrue(routed is None or not routed['operations'], routed)

    def test_algorithm_names_are_not_api_tokens(self):
        self.assertEqual(fa.api_tokens('Which function computes SHA256 or MD5 with AES?'), [])
        self.assertEqual(fa.api_tokens('Who calls BCryptHashData and CryptEncrypt?'), ['BCryptHashData', 'CryptEncrypt'])


class FixtureAnswerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        database = Path(cls.directory.name) / 'crypto.sqlite'
        shutil.copyfile(FIXTURE, database)  # never touch the tracked fixture
        cls.app = GuiApplication(database, session_dir=Path(cls.directory.name) / 's',
                                 upload_dir=Path(cls.directory.name) / 'u', client_factory=NoModel)
        cls.binaries = {b['program_name']: b['binary_id'] for b in cls.app.list_binaries()}

    @classmethod
    def tearDownClass(cls):
        cls.app.library.close()
        cls.directory.cleanup()

    def setUp(self):
        NoModel.calls = 0

    def ask(self, program, question, select=None):
        sid = self.app.new_session(self.binaries[NAMES[program]])['session_id']
        if select:
            self.app.select_function(sid, select)
        tick = time.perf_counter()
        result = self.app.run_chat(sid, question)
        elapsed = time.perf_counter() - tick
        self.assertEqual(self.app.last_performance['path'], 'deterministic_facts', question)
        self.assertEqual(self.app.last_performance['model_requests'], 0)
        self.assertEqual(NoModel.calls, 0)
        self.assertEqual(result.status, 'completed')
        self.assertLess(elapsed, 3.0, 'deterministic answers must meet the 3 s target')
        self.assertNoFabricatedAddresses(result)
        return result, sid

    def assertNoFabricatedAddresses(self, result):
        """Every cited 0x address appears in the stored tool results that produced the answer."""
        stored = json.dumps(result.tool_results)
        for address in addresses(result.answer):
            self.assertIn(address, stored, f'0x{address} cited without stored evidence')

    def test_every_ground_truth_role_is_answered_with_its_exact_function(self):
        for program, truth in TRUTH.items():
            for role, question in ROLE_QUESTIONS.items():
                expected = {f['address'] for f in truth['functions'].values() if f['role'] == role}
                with self.subTest(program=program, role=role):
                    result, _ = self.ask(program, question)
                    self.assertEqual(role_facts(result, role), expected)
                    rows = table_rows(result.answer, LABEL[role])
                    self.assertTrue(rows, result.answer)
                    if expected:
                        self.assertEqual({r['function'] for r in rows}, expected)
                        apis = ' '.join(r['apis'] for r in rows)
                        for function in (f for f in truth['functions'].values() if f['role'] == role):
                            for api in function['apis']:
                                if role == 'hashing' and api not in ('BCryptCreateHash', 'BCryptHashData',
                                                                     'BCryptFinishHash'):
                                    continue  # provider/cleanup calls are not hashing operations
                                self.assertIn(api, apis)
                        self.assertTrue(result.answer.startswith('**Answer:** '))
                    else:
                        self.assertEqual(rows, [{'absent': True}], 'absent role must not be attributed')
                        self.assertIn('call site is stored', result.answer.split('\n')[0])

    def test_encryption_and_decryption_cannot_be_swapped(self):
        result, _ = self.ask('aes_gcm', 'Which functions perform encryption and decryption?')
        encryption, decryption = table_rows(result.answer, 'Encryption'), table_rows(result.answer, 'Decryption')
        self.assertEqual([(r['function'], r['apis']) for r in encryption], [('0041d160', '`BCryptEncrypt` @ `0x0041d1c3`')])
        self.assertEqual([(r['function'], r['apis']) for r in decryption], [('0041d1e0', '`BCryptDecrypt` @ `0x0041d24c`')])
        self.assertEqual(role_facts(result, 'encryption'), {'0041d160'})
        self.assertEqual(role_facts(result, 'decryption'), {'0041d1e0'})
        first = result.answer.split('\n')[0]
        self.assertLess(first.index('Encryption in `FUN_0041d160`'), first.index('decryption in `FUN_0041d1e0`'))
        # The previously observed model failure named non-crypto functions.
        self.assertNotIn('00401160', result.answer)
        evidence = {e['label'] for e in result.presentation['evidence']}
        self.assertIn('BCryptEncrypt call @ 0x0041d1c3 in FUN_0041d160 (encryption)', evidence)
        self.assertIn('BCryptDecrypt call @ 0x0041d24c in FUN_0041d1e0 (decryption)', evidence)
        self.assertFalse(result.presentation['interpretation'])
        self.assertTrue(result.presentation['verified'])
        self.assertIn('No target execution', result.presentation['footer'])

    def test_signing_and_verification_cannot_be_swapped(self):
        result, _ = self.ask('ecdsa_sign', 'Which function signs or verifies a digital signature?')
        signing = table_rows(result.answer, 'Signature creation')
        verification = table_rows(result.answer, 'Signature verification')
        self.assertEqual({r['function'] for r in signing}, {'0041d1b0'})
        self.assertIn('BCryptSignHash', signing[0]['apis'])
        self.assertEqual({r['function'] for r in verification}, {'0041d1f0'})
        self.assertIn('BCryptVerifySignature', verification[0]['apis'])

    def test_sha256_identity_comes_from_the_stored_identifier_string(self):
        result, _ = self.ask('sha256_hash', 'Which function computes the SHA-256 hash?')
        self.assertEqual(role_facts(result, 'hashing'), {'0041d0a0'})
        self.assertIn('`FUN_0041d0a0` references `SHA256` (SHA-256)', result.answer)
        result, _ = self.ask('aes_gcm', 'Which function computes the SHA-256 hash?')
        self.assertEqual(table_rows(result.answer, 'Hashing'), [{'absent': True}])
        self.assertIn('the algorithm is not established', result.answer)

    def test_crypto_api_lookup_and_absent_api(self):
        result, sid = self.ask('aes_gcm', 'Find the function that calls BCryptEncrypt.')
        self.assertTrue(result.answer.startswith('**Answer:** `BCryptEncrypt` (encryption) is called by `FUN_0041d160`'))
        self.assertEqual(result.presentation['facts']['apis'][0]['callsites'], ['0041d1c3'])
        self.assertNotIn('0041d1e0', result.answer)
        self.assertEqual(self.app.session(sid)['current_function_id'].split(':')[1], '0041d160')
        result, _ = self.ask('aes_gcm', 'Which function calls BCryptSignHash?')
        self.assertIn('is not among the stored crypto API imports', result.answer)

    def test_all_operations_summary_matches_ground_truth(self):
        for program, truth in TRUTH.items():
            with self.subTest(program):
                result, _ = self.ask(program, 'What cryptographic operations does this binary perform?')
                listed = {f['address'] for f in result.presentation['facts']['roles']}
                for function in truth['functions'].values():
                    if function['role'] in LABEL:
                        self.assertIn(function['address'], listed)

    def test_combined_intents_return_every_requested_operation(self):
        """Issue A: multi-operation questions return all requested roles, expectations from ground truth."""
        cases = {
            'ecdsa_sign': ['Which functions sign and verify a digital signature?',
                           'Which functions handle signing and verification?',
                           'Where is data signed and verified?',
                           'Which function creates and checks the signature?',
                           'List the functions for signature creation and signature verification.'],
            'aes_gcm': ['Which functions encrypt or decrypt data?', 'Where does it encrypt and decrypt?',
                        'Which functions handle encryption as well as decryption?',
                        'Find the encryption and decryption routines.'],
        }
        roles = {'ecdsa_sign': ('signing', 'verification'), 'aes_gcm': ('encryption', 'decryption')}
        for program, questions in cases.items():
            truth = TRUTH[program]['functions']
            for question in questions:
                with self.subTest(question):
                    result, _ = self.ask(program, question)
                    for role in roles[program]:
                        expected = {f['address'] for f in truth.values() if f['role'] == role}
                        self.assertEqual(role_facts(result, role), expected, f'{role} for {question!r}')
                        self.assertEqual({r.get('function') for r in table_rows(result.answer, LABEL[role])}, expected)

    def test_combined_routing_covers_three_operations_and_ignores_integer_signs(self):
        self.assertEqual(fa.classify('What handles hashing, signing and verification?')['operations'],
                         ['hashing', 'signing', 'verification'])
        self.assertEqual(fa.classify('Which function handles the digital signature?')['operations'],
                         ['signing', 'verification'])
        self.assertIsNone(fa.classify('Which instruction compares signed values and verifies the flag?'))

    def test_crypto_or_hashing_card_lists_every_present_operation(self):
        prompt = 'Identify crypto or hashing routines in this binary'  # GUI prompt card
        result, _ = self.ask('aes_gcm', prompt)
        self.assertEqual(role_facts(result, 'encryption'), {'0041d160'})
        self.assertEqual(role_facts(result, 'decryption'), {'0041d1e0'})
        self.assertEqual(table_rows(result.answer, 'Hashing'), [{'absent': True}])
        result, _ = self.ask('sha256_hash', prompt)
        self.assertEqual(role_facts(result, 'hashing'), {'0041d0a0'})

    def test_function_api_calls_match_ground_truth(self):
        for program, truth in TRUTH.items():
            for name, function in truth['functions'].items():
                if not function.get('apis'):
                    continue
                with self.subTest(program=program, function=name):
                    result, _ = self.ask(program, f"What API calls does FUN_{function['address']} make?")
                    found = {f['api'] for f in result.presentation['facts']['api_calls']
                             if re.match(r'(?:BCrypt|NCrypt|Crypt)', f['api'])}
                    self.assertEqual(found, set(function['apis']))
                    shown = set(re.findall(r'^\| `((?:BCrypt|NCrypt|Crypt)\w+)`', result.answer, re.M))
                    self.assertEqual(shown, set(function['apis']))

    def test_callers_and_callees_match_ground_truth_driver(self):
        truth = TRUTH['aes_gcm']['functions']
        main = truth['main']['address']
        result, _ = self.ask('aes_gcm', f'What does FUN_{main} call?')
        callees = {e['callee'].removeprefix('FUN_') for e in result.presentation['facts']['edges']}
        for callee in truth['main']['calls']:
            self.assertIn(truth[callee]['address'], callees)
        result, _ = self.ask('aes_gcm', 'What calls this function?', select='FUN_0041d160')
        self.assertIn(f'| FUN_{main} → FUN_0041d160 | `0x0041d2f7` |', result.answer)
        self.assertTrue(result.answer.startswith('**Answer:** `FUN_0041d160` (`0x0041d160`) has 1 stored caller'))
        self.assertTrue(result.presentation['relationships'])

    def test_follow_up_uses_function_selected_by_previous_answer(self):
        result, sid = self.ask('aes_gcm', 'Which function encrypts data?')
        follow = self.app.run_chat(sid, 'What calls it?')
        self.assertEqual(self.app.last_performance['path'], 'deterministic_facts')
        self.assertTrue(follow.answer.startswith('**Answer:** `FUN_0041d160`'))

    def test_evidence_view_combines_crypto_and_m10_instruction_facts(self):
        result, _ = self.ask('sha256_hash', 'Show the evidence for this function.', select='FUN_0041d0a0')
        self.assertIn('| `BCryptHashData` | `0x0041d139` | hashing |', result.answer)
        self.assertIn('Instruction-level evidence (M10)', result.answer)
        self.assertIn('Ghidra P-code', result.answer)

    def test_presentation_is_concise_with_details_preserved(self):
        """Phase 2: no long identifiers or tool dumps in the visible answer; everything kept in the record."""
        for program, question, select in (
                ('aes_gcm', 'Which functions perform encryption and decryption?', None),
                ('ecdsa_sign', 'What cryptographic operations does this binary perform?', None),
                ('aes_gcm', 'What calls this function?', 'FUN_0041d160'),
                ('aes_gcm', 'Find the function that calls BCryptEncrypt.', None)):
            with self.subTest(question):
                result, sid = self.ask(program, question, select)
                self.assertTrue(result.answer.startswith('**Answer:** '))
                self.assertNotIn('Retrieved tool facts', result.answer)
                self.assertNotIn(':reference:', result.answer)
                self.assertNotRegex(result.answer, r'[0-9a-f]{40,}')  # no full binary IDs / long citation IDs
                self.assertLess(len(result.answer), 2500)
                presentation = result.presentation
                self.assertTrue(presentation['limitations'])
                self.assertTrue(presentation['tool_facts'])  # full identifiers kept, expandable
                stored = self.app.session(sid)['messages'][-1]['presentation']
                self.assertEqual(stored['tool_facts'], presentation['tool_facts'])
                self.assertEqual(stored['raw']['tool_results'], json.loads(json.dumps(result.tool_results)))
                for row in presentation['evidence']:
                    self.assertTrue(row['evidence_id'] and row['provenance']['source_table'])

    def test_missing_selection_is_reported_not_guessed(self):
        sid = self.app.new_session(self.binaries['aes_gcm.exe'])['session_id']
        with self.assertRaisesRegex(GuiError, 'Select a function'):
            self.app.run_chat(sid, 'What calls this function?')
        self.assertEqual(NoModel.calls, 0)

    def test_unsupported_question_still_reaches_existing_model_path(self):
        sid = self.app.new_session(self.binaries['aes_gcm.exe'])['session_id']
        result = self.app.run_chat(sid, 'Is the encryption secure?')
        self.assertNotEqual(self.app.last_performance.get('path'), 'deterministic_facts')
        self.assertGreaterEqual(NoModel.calls, 1)
        self.assertNotEqual(result.status, 'completed')


if __name__ == '__main__':
    unittest.main()
