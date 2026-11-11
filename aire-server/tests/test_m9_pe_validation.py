"""M9 Phase 2: malformed PE detection, graceful intake/GUI failure and recovery.

Pure Python: fixtures are only read and parsed, never executed. Expected
outcomes are documented in tests/fixtures/m9/corrupt_pe/EXPECTED.json and
docs/M9_CORRUPT_PE.md; regenerate with scripts/make_corrupt_pe_fixtures.py.
"""
from dataclasses import asdict
import hashlib
from io import BytesIO
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import threading

from aire.analysis.versions import analyzer_versions
from aire.api.binary_library import (BinaryLibrary, BinaryValidationError, REPOSITORY,
                                     inspect_binary)
from aire.api.server import GuiApplication, create_server
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, ProgramIndex
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION
from aire.validation.pe_structure import validate_pe

M9 = REPOSITORY / 'tests/fixtures/m9'
EXPECTED = json.loads((M9 / 'corrupt_pe/EXPECTED.json').read_text())['fixtures']
VALID_PES = [
    REPOSITORY / 'tests/fixtures/external/angr/windows_tls_x86/TLS.exe',
    REPOSITORY / 'tests/fixtures/external/angr/windows_getprocaddress/GetProcAddress.exe',
    REPOSITORY / 'professor_samples/function_overloading/original/FunctionOverloading.exe',
    M9 / 'large_pe/sleigh.exe', M9 / 'large_pe/decompile.exe',
]
ELF = REPOSITORY / 'tests/fixtures/simple_elf/aire_test_binary'


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class CorruptFixtureExpectationTests(unittest.TestCase):
    def test_generator_is_deterministic_and_originals_unchanged(self):
        subprocess.run([sys.executable, str(REPOSITORY / 'scripts/make_corrupt_pe_fixtures.py'), '--check'],
                       check=True, capture_output=True)
        for row in EXPECTED:
            self.assertEqual(_sha(REPOSITORY / row['derived_from']), row['derived_from_sha256'])

    def test_every_fixture_matches_documented_outcome(self):
        self.assertGreaterEqual(len(EXPECTED), 18)
        for row in EXPECTED:
            with self.subTest(row['name']):
                data = (M9 / row['binary_path']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), row['binary_sha256'])
                report = validate_pe(data)
                codes = {issue.code for issue in report.issues if issue.severity != 'info'}
                self.assertEqual(report.analysis, row['expected_analysis'])
                self.assertTrue(set(row['expected_issue_codes']) <= codes, codes)
                if row['expected_analysis'] == 'full':
                    self.assertEqual(codes, set(), 'unusual-but-valid PE flagged as corrupt')
                    self.assertTrue(report.pe_valid)
                if row['expected_analysis'] == 'none':
                    self.assertFalse(report.pe_valid)

    def test_required_corruption_classes_are_covered(self):
        codes = {code for row in EXPECTED for code in row['expected_issue_codes']}
        for required in ('dos_signature', 'pe_signature', 'truncated_section_table', 'section_truncated',
                         'section_beyond_eof', 'section_raw_offset', 'section_overlap',
                         'import_directory', 'import_dll_name', 'import_thunks'):
            self.assertIn(required, codes)
        self.assertGreaterEqual(sum(row['expected_analysis'] == 'full' for row in EXPECTED), 2)

    def test_real_pes_have_no_false_positives(self):
        for path in VALID_PES:
            with self.subTest(path.name):
                report = validate_pe(path.read_bytes())
                self.assertEqual(report.analysis, 'full')
                self.assertEqual([i for i in report.issues if i.severity != 'info'], [])
                self.assertIn('KERNEL32.dll', report.imports)

    def test_architecture_determined_when_headers_allow(self):
        rows = {row['name']: row for row in EXPECTED}
        report = validate_pe((M9 / rows['corrupt_optional_magic_invalid']['binary_path']).read_bytes())
        self.assertEqual(report.architecture, 'x86_64')
        report = validate_pe((M9 / rows['corrupt_dos_signature_invalid']['binary_path']).read_bytes())
        self.assertIsNone(report.architecture)
        self.assertIn('ZM', report.issues[0].message)

    def test_parser_never_raises_on_fuzzed_input(self):
        rng = random.Random(20261110)
        bases = [p.read_bytes() for p in VALID_PES[:3]]
        for i in range(600):
            data = bytearray(rng.choice(bases))
            if i % 3 == 0:
                data = data[:rng.randrange(0, len(data))]
            for _ in range(rng.randrange(1, 12)):
                position = rng.randrange(0, min(len(data), 0x600)) if data else 0
                if data:
                    data[position] = rng.randrange(256)
            report = validate_pe(bytes(data))  # must not raise
            self.assertIn(report.analysis, ('full', 'partial', 'none'))
            json.dumps(report.to_dict())


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / 'analysis.sqlite'
        with BinaryKnowledgeStore(self.database):
            pass
        self.library = BinaryLibrary(self.database, directory=self.root / 'uploads')
        self.addCleanup(self.library.close)
        self.rows = {row['name']: row for row in EXPECTED}

    def fixture(self, name):
        return M9 / self.rows[name]['binary_path']

    def test_inspect_rejects_fatal_with_specific_report(self):
        with self.assertRaises(BinaryValidationError) as caught:
            inspect_binary(self.fixture('corrupt_pe_signature_invalid'))
        self.assertIn('Invalid PE signature', str(caught.exception))
        report = caught.exception.report
        self.assertEqual(report['analysis_level'], 'none')
        self.assertFalse(report['pe_valid'])
        self.assertEqual(report['structure_issues'][0]['code'], 'pe_signature')
        json.dumps(report)

    def test_inspect_accepts_partial_with_issues(self):
        details = inspect_binary(self.fixture('corrupt_import_dll_name_invalid'))
        self.assertEqual(details['format'], 'PE')
        self.assertEqual(details['architecture'], 'x86')
        self.assertEqual(details['analysis_level'], 'partial')
        self.assertFalse(details['pe_valid'])
        self.assertIn('import_dll_name', {i['code'] for i in details['structure_issues']})

    def test_valid_and_elf_inputs_report_full(self):
        self.assertEqual(inspect_binary(VALID_PES[0])['analysis_level'], 'full')
        self.assertTrue(inspect_binary(VALID_PES[0])['pe_valid'])
        elf = inspect_binary(ELF)
        self.assertEqual((elf['format'], elf['analysis_level'], elf['pe_valid']), ('ELF', 'full', None))

    def test_non_binary_is_rejected_with_report(self):
        path = self.root / 'notes.exe'
        path.write_bytes(b'plain text pretending to be an executable')
        with self.assertRaises(BinaryValidationError) as caught:
            inspect_binary(path)
        self.assertEqual(caught.exception.report['analysis_level'], 'none')

    def test_every_fixture_upload_matches_expectation_and_leaves_no_partial_files(self):
        for row in EXPECTED:
            with self.subTest(row['name']):
                content = (M9 / row['binary_path']).read_bytes()
                if row['expected_analysis'] == 'none':
                    with self.assertRaises(BinaryValidationError):
                        self.library.upload(BytesIO(content), len(content), row['name'] + '.exe')
                else:
                    uploaded = self.library.upload(BytesIO(content), len(content), row['name'] + '.exe')
                    self.assertEqual(uploaded['analysis_level'], row['expected_analysis'])
                    self.assertEqual(uploaded['sha256'], row['binary_sha256'])
        self.assertEqual(list(self.library.directory.glob('.upload-*')), [])

    def test_library_lists_m9_fixtures_with_status(self):
        rows = {row['fixture_id']: row for row in self.library.list()}
        fatal = rows['m9:corrupt_dos_signature_invalid']
        self.assertFalse(fatal['available'])
        self.assertEqual(fatal['validation']['analysis_level'], 'none')
        partial = rows['m9:corrupt_section_overlap']
        self.assertTrue(partial['available'])
        self.assertEqual(partial['analysis_level'], 'partial')
        self.assertEqual(rows['m9:corrupt_valid_overlay_appended']['analysis_level'], 'full')
        self.assertEqual(rows['m9:large_pe_decompile']['architecture'], 'x86_64')
        json.dumps(list(rows.values()))

    def test_start_rejects_fatal_and_allows_partial(self):
        calls = []
        self.library._run_analysis = lambda path, progress: calls.append(path) or {
            'binary_id': inspect_binary(path)['sha256']}
        with self.assertRaises(BinaryValidationError):
            self.library.start(fixture_id='m9:corrupt_zero_sections')
        job = self.library.start(fixture_id='m9:corrupt_import_thunks_invalid')
        self.assertEqual(job['analysis_level'], 'partial')
        deadline = time.monotonic() + 5
        while self.library.job(job['job_id'])['status'] not in ('completed', 'failed'):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(len(calls), 1)

    def test_http_rejection_carries_validation_and_server_stays_usable(self):
        application = GuiApplication(self.database, session_dir=self.root / 'sessions',
                                     upload_dir=self.root / 'http-uploads')
        self.addCleanup(application.library.close)
        server = create_server(application, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_address[1]}'
        def post(name):
            content = self.fixture(name).read_bytes()
            request = Request(f'{base}/api/uploads?filename={name}.exe', data=content, method='POST',
                              headers={'Content-Type': 'application/octet-stream', 'Origin': base})
            return urlopen(request, timeout=10)
        for name in ('corrupt_dos_signature_invalid', 'corrupt_truncated_section_table',
                     'corrupt_e_lfanew_out_of_range'):
            with self.subTest(name), self.assertRaises(HTTPError) as caught:
                post(name)
            self.assertEqual(caught.exception.code, 400)
            body = json.loads(caught.exception.read())
            self.assertEqual(body['validation']['analysis_level'], 'none')
            self.assertTrue(body['validation']['structure_issues'])
        with post('corrupt_section_offset_beyond_eof') as response:
            body = json.loads(response.read())
        self.assertEqual(response.status, 201)
        self.assertEqual(body['analysis_level'], 'partial')
        with urlopen(Request(f'{base}/api/library', headers={'Origin': base}), timeout=10) as response:
            self.assertEqual(response.status, 200)  # GUI still serves after rejections


class WatchdogTests(unittest.TestCase):
    def test_hung_worker_is_killed_and_next_job_recovers(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        database = root / 'analysis.sqlite'
        digest = _sha(ELF)
        with BinaryKnowledgeStore(database) as store:
            store.save_program_index(ProgramIndex(
                BinaryRecord(digest, str(ELF), digest, 'ELF', 'x86_64', '0', None),
                metadata={'options': asdict(IndexOptions()), 'analyzer_versions': analyzer_versions(),
                          'ghidra_version': analyzer_versions()['ghidra'],
                          'reference_facts_version': REFERENCE_FACTS_VERSION}))
        library = BinaryLibrary(database, directory=root / 'uploads')
        self.addCleanup(library.close)
        library.analysis_timeout = 0.5
        # Stand-in for an analyzer stuck on a malformed input: reads the
        # request and never answers.
        library._process = subprocess.Popen(
            [sys.executable, '-c', 'import sys,time; sys.stdin.readline(); time.sleep(60)'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        hung = library._process
        def wait(job):
            deadline = time.monotonic() + 30
            while True:
                row = library.job(job['job_id'])
                if row['status'] in ('completed', 'failed') and 'total_seconds' in row:
                    return row
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
        failed = wait(library.start(fixture_id='local:simple-elf'))
        self.assertEqual(failed['status'], 'failed')
        self.assertIn('exceeded 0.5 s', failed['error'])
        self.assertIsNotNone(hung.wait(timeout=5))
        library.analysis_timeout = 120
        recovered = wait(library.start(fixture_id='local:simple-elf'))
        self.assertEqual(recovered['status'], 'completed', recovered.get('error'))
        self.assertTrue(recovered['cache_hit'])
        self.assertIsNot(library._process, hung)


if __name__ == '__main__':
    unittest.main()
