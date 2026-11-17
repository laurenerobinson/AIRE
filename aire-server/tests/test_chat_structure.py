"""Structural validation is authoritative in chat (GUI/UX Phase 1, issue B).

Uses the real M9 corrupted/valid PE fixtures and their EXPECTED.json. Stores are
synthesized (no Ghidra) but point at the real files with their real SHA-256, so
the chat path re-validates the actual bytes. File names are never evidence.
"""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from aire.analysis.file_structure import assess
from aire.api.server import GuiApplication
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, FunctionRecord, ProgramIndex

ROOT = Path(__file__).resolve().parents[2]
CORRUPT = ROOT / 'tests/fixtures/m9/corrupt_pe'
EXPECTED = {Path(f['binary_path']).name: f for f in json.loads((CORRUPT / 'EXPECTED.json').read_text())['fixtures']}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RecordingModel:
    model, num_ctx = 'recording', 4096
    prompts = []

    def generate(self, prompt, *, system='', **kwargs):
        RecordingModel.prompts.append(system + '\n' + prompt)
        raise ConnectionError('model unavailable in tests')


def make_store(directory, files):
    """One stored binary per (path, display name), each with a single function."""
    database = Path(directory) / 'structure.sqlite'
    with BinaryKnowledgeStore(database) as store:
        for path, name in files:
            digest = sha(path) if Path(path).exists() else 'f' * 64
            function = FunctionRecord(f'{digest}:00401000', digest, '00401000', 'FUN_00401000', 'void FUN_00401000(void)',
                                      'void FUN_00401000(void)\n{\n  return;\n}\n', 'RET', 1, 1, 0)
            store.save_program_index(ProgramIndex(
                BinaryRecord(digest, str(path), digest, 'Portable Executable (PE)', 'x86:LE:32:default', '00400000',
                             None, program_name=name), [function]))
    return database


class AssessTests(unittest.TestCase):
    def test_every_m9_fixture_matches_expected_analysis_and_codes(self):
        for name, expected in EXPECTED.items():
            with self.subTest(name):
                path = CORRUPT / name
                result = assess({'path': str(path), 'sha256': expected['binary_sha256']})
                self.assertEqual(result['status'], expected['expected_analysis'])
                codes = {i['code'] for i in result['issues']}
                self.assertLessEqual(set(expected['expected_issue_codes']), codes)
                if result['status'] != 'full':
                    self.assertTrue(result['impacts'], 'damage must state which evidence is unreliable')

    def test_missing_or_changed_file_is_unverified_not_valid(self):
        path = CORRUPT / 'valid_renamed_sections.exe'
        self.assertEqual(assess({'path': '/nonexistent/x.exe', 'sha256': 'a' * 64})['status'], 'unverified')
        changed = assess({'path': str(path), 'sha256': '0' * 64})
        self.assertEqual(changed['status'], 'unverified')
        self.assertIn('SHA-256 mismatch', changed['reason'])


class ChatStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        tmp = Path(cls.directory.name)
        # A valid file under a misleading name: the name must never become evidence.
        misleading = tmp / 'ransomware_dll_loader.exe'
        shutil.copyfile(CORRUPT / 'valid_renamed_sections.exe', misleading)
        cls.files = {
            'valid': (CORRUPT / 'valid_renamed_sections.exe', 'valid_renamed_sections.exe'),
            'partial': (CORRUPT / 'import_dll_name_invalid.exe', 'import_dll_name_invalid.exe'),
            'invalid': (CORRUPT / 'dos_signature_invalid.exe', 'dos_signature_invalid.exe'),
            'misleading': (misleading, 'ransomware_dll_loader.exe'),
            'missing': (tmp / 'gone.exe', 'gone.exe'),
        }
        database = make_store(tmp, cls.files.values())
        cls.app = GuiApplication(database, session_dir=tmp / 's', upload_dir=tmp / 'u', client_factory=RecordingModel)
        cls.ids = {key: (sha(path) if Path(path).exists() else 'f' * 64) for key, (path, _) in cls.files.items()}

    @classmethod
    def tearDownClass(cls):
        cls.app.library.close()
        cls.directory.cleanup()

    def setUp(self):
        RecordingModel.prompts = []

    def ask(self, key, question, select=None):
        sid = self.app.new_session(self.ids[key])['session_id']
        if select:
            self.app.select_function(sid, select)
        return self.app.run_chat(sid, question)

    def body(self, answer):
        """Answer text without the File label line (the only place a name may appear)."""
        return '\n'.join(line for line in answer.splitlines() if not line.startswith(('**File:**', '**Binary:**')))

    def test_partial_file_reports_condition_completeness_and_no_purpose(self):
        result = self.ask('partial', 'What is this file?')
        self.assertEqual(self.app.last_performance['path'], 'deterministic_facts')
        self.assertEqual(RecordingModel.prompts, [])
        answer = result.answer
        self.assertTrue(answer.startswith('**Answer:** PE executable — structure damaged (partial analysis) (import_dll_name)'))
        self.assertIn('`import_dll_name` (error', answer)
        self.assertIn('Partial static analysis only', answer)
        self.assertIn('**Missing or unreliable evidence:**', answer)
        self.assertIn('cannot be attributed to a library', answer)
        self.assertIn('No program purpose is stated', answer)
        self.assertIn('executable image (IMAGE_FILE_DLL not set)', answer)
        self.assertNotIn('loader', answer.lower())
        evidence = {e['label'] for e in result.presentation['evidence']}
        self.assertTrue(any(label.startswith('structure import_dll_name') for label in evidence))

    def test_invalid_file_says_no_reliable_analysis(self):
        answer = self.ask('invalid', 'Is this file corrupted?').answer
        self.assertIn('structure invalid (no reliable analysis)', answer)
        self.assertIn('No reliable static analysis is possible', answer)
        self.assertIn('treat them as unreliable', answer)
        self.assertIn('Not described: the structure is invalid', answer)

    def test_valid_file_is_reported_valid_without_damage_claims(self):
        answer = self.ask('valid', 'What kind of file is this?').answer
        self.assertTrue(answer.startswith('**Answer:** PE executable — structure valid.'))
        self.assertIn('Full static analysis is possible', answer)
        self.assertNotIn('Missing or unreliable evidence', answer)

    def test_missing_file_is_unverified(self):
        answer = self.ask('missing', 'What is this file?').answer
        self.assertTrue(answer.startswith('**Answer:** File — structure unverified.'))
        self.assertIn('**Why unverified:**', answer)
        self.assertIn('not available at its stored path', answer)

    def test_damaged_overview_is_deterministic_and_valid_overview_uses_model_path(self):
        result = self.ask('partial', 'What does this binary do?')
        self.assertEqual(self.app.last_performance['path'], 'deterministic_facts')
        self.assertIn('Why no AI overview', result.answer)
        self.assertEqual(RecordingModel.prompts, [])
        self.ask('valid', 'What does this binary do?')  # model path (fails: model unavailable)
        self.assertTrue(RecordingModel.prompts)

    def test_file_name_is_never_evidence(self):
        answer = self.ask('misleading', 'What is this file?').answer
        self.assertNotIn('ransomware', self.body(answer).lower())
        self.assertIn('not used as evidence', answer)
        self.ask('misleading', 'Summarize this function', select='FUN_00401000')
        self.assertTrue(RecordingModel.prompts, 'function summary still uses the model path')
        for prompt in RecordingModel.prompts:
            self.assertNotIn('ransomware', prompt)
            self.assertNotIn('dll_loader', prompt)

    def test_model_path_answers_about_damaged_files_carry_the_structural_banner(self):
        result = self.ask('partial', 'Summarize this function', select='FUN_00401000')
        self.assertTrue(result.answer.startswith('**Structural condition:** Damaged (partial analysis) (import_dll_name)'))
        self.assertEqual(result.presentation['structure']['status'], 'partial')

    def test_deterministic_answers_about_damaged_files_state_the_condition(self):
        answer = self.ask('partial', 'Which function encrypts data?').answer
        self.assertIn('**Structural condition:** Damaged (partial analysis) (import_dll_name)', answer)


if __name__ == '__main__':
    unittest.main()
