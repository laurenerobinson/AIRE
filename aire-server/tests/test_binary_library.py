"""Binary intake trust boundary, queue failures and cache-aware fixture listing."""
from dataclasses import asdict
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from aire.analysis.versions import analyzer_versions
from aire.api.binary_library import BinaryLibrary, MAX_UPLOAD, REPOSITORY, inspect_binary
from aire.api.server import GuiApplication, create_server
from aire.api.index_worker import run_analysis
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, ProgramIndex
from aire.pyghidra.options import IndexOptions
from aire.pyghidra.references import REFERENCE_FACTS_VERSION
from aire.analysis.versions import INSTRUCTION_IR_VERSION

ELF = REPOSITORY / 'tests/fixtures/simple_elf/aire_test_binary'
PE = REPOSITORY / 'professor_samples/function_overloading/original/FunctionOverloading.exe'


class BinaryLibraryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / 'analysis.sqlite'
        with BinaryKnowledgeStore(self.database):
            pass
        self.library = BinaryLibrary(self.database, directory=self.root / 'uploads')
        self.addCleanup(self.library.close)

    def wait(self, job):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.library.job(job['job_id'])
            if result['status'] in ('completed', 'failed') and 'total_seconds' in result:
                return result
            time.sleep(.01)
        self.fail('Analysis worker did not finish')

    def test_real_headers_and_fake_or_truncated_inputs(self):
        self.assertEqual(inspect_binary(ELF)['format'], 'ELF')
        self.assertEqual(inspect_binary(PE)['format'], 'PE')
        for content in (b'', b'source code', b'\x7fELF' + b'\0'*80, b'MZ' + b'\0'*100,
                        PE.read_bytes()[:300], ELF.read_bytes()[:100]):
            with self.subTest(prefix=content[:10]), self.assertRaises(ValueError):
                self.library.upload(BytesIO(content), len(content), 'looks-valid.exe')
        with self.assertRaises(ValueError):
            self.library.upload(BytesIO(b''), MAX_UPLOAD+1, 'oversized.exe')
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            self.library.upload(BytesIO(b'xx'), 100, 'partial')
        self.assertEqual(list(self.library.directory.glob('.upload-*')), [])

    def test_upload_hash_paths_and_bytes_preserved(self):
        content = PE.read_bytes()
        for name in ('../../escaped.exe', '..\\..\\escaped.exe', '<script>.exe'):
            result = self.library.upload(BytesIO(content), len(content), name)
            self.assertNotIn('/', result['filename'])
            self.assertNotIn('\\', result['filename'])
            target, _ = self.library._uploads[result['upload_id']]
            self.assertTrue(target.is_relative_to(self.library.directory))
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
        with self.assertRaises(ValueError):
            self.library.start(fixture_id='../../FunctionOverloading.cpp')
        with self.assertRaises(ValueError):
            self.library.start(upload_id='unknown')

    def test_failed_job_recovers_and_writer_uses_worker_thread(self):
        # Runtime-free unit backend; real subprocess/JVM is covered by the demo
        # acceptance script. Java and DB objects never cross this interface.
        self.library._run_analysis = lambda path, progress: run_analysis(path, self.database, progress)
        content = ELF.read_bytes()
        uploaded = self.library.upload(BytesIO(content), len(content), ELF.name)
        creator = threading.get_ident()
        def fake_index(path, options):
            self.assertNotEqual(threading.get_ident(), creator)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return ProgramIndex(BinaryRecord(digest, str(path), digest, 'ELF', 'x86_64', '0', None),
                metadata={'options':asdict(options), 'analyzer_versions':analyzer_versions(),
                          'ghidra_version':analyzer_versions()['ghidra'], 'reference_facts_version':REFERENCE_FACTS_VERSION, 'instruction_ir': {'version': INSTRUCTION_IR_VERSION}})
        with patch('aire.analysis.cache.index_binary', side_effect=RuntimeError('controlled analysis failure')):
            result = self.wait(self.library.start(upload_id=uploaded['upload_id']))
        self.assertEqual(result['status'], 'failed')
        self.assertIn('controlled analysis failure', result['error'])
        with patch('aire.analysis.cache.index_binary', side_effect=fake_index) as indexer:
            fresh = self.wait(self.library.start(upload_id=uploaded['upload_id']))
            cached = self.wait(self.library.start(upload_id=uploaded['upload_id']))
        self.assertEqual(fresh['status'], 'completed')
        self.assertFalse(fresh['cache_hit'])
        self.assertTrue(cached['cache_hit'])
        self.assertEqual(indexer.call_count, 1)
        self.assertEqual(cached['profile']['counts']['analyze_calls'], 0)
        self.assertGreater(cached['analysis_seconds'], 0)
        self.assertTrue(any(row['cached'] for row in self.library.list() if row['sha256'] == uploaded['sha256']))

    def test_malformed_optional_demo_binary_does_not_abort_startup(self):
        # Codex review P2: a truncated/unreadable local demo binary must be
        # listed as unavailable, never prevent BinaryLibrary/GUI construction.
        repository = self.root / 'repository'
        broken = repository / 'professor_samples/function_overloading/original/FunctionOverloading.exe'
        broken.parent.mkdir(parents=True)
        broken.write_bytes(PE.read_bytes()[:300])
        good = repository / 'tests/fixtures/simple_elf/aire_test_binary'
        good.parent.mkdir(parents=True)
        good.write_bytes(ELF.read_bytes())
        library = BinaryLibrary(self.database, directory=self.root / 'uploads2', repository=repository)
        self.addCleanup(library.close)
        rows = {row['fixture_id']: row for row in library.list()}
        self.assertFalse(rows['professor:overloading']['available'])
        self.assertIn('Malformed or truncated', rows['professor:overloading']['error'])
        self.assertTrue(rows['local:simple-elf']['available'])
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            library.start(fixture_id='professor:overloading')
        application = GuiApplication(self.database, session_dir=self.root / 'sessions',
                                     upload_dir=self.root / 'uploads3', repository=repository)
        self.addCleanup(application.library.close)
        self.assertFalse(next(r for r in application.library.list()
                              if r['fixture_id'] == 'professor:overloading')['available'])

    def test_fixture_manifest_hash_change_is_rejected(self):
        fixture = self.library._fixtures['local:simple-elf']
        fixture['expected_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.library.start(fixture_id='local:simple-elf')
        row = next(row for row in self.library.list() if row['fixture_id'] == 'local:simple-elf')
        self.assertFalse(row['available'])

    def test_cached_requests_reuse_child_process_and_exit_cleanly(self):
        content = ELF.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        index = ProgramIndex(BinaryRecord(digest, str(ELF), digest, 'ELF', 'x86_64', '0', None),
            metadata={'options':asdict(IndexOptions()), 'analyzer_versions':analyzer_versions(),
                      'ghidra_version':analyzer_versions()['ghidra'], 'reference_facts_version':REFERENCE_FACTS_VERSION, 'instruction_ir': {'version': INSTRUCTION_IR_VERSION}})
        with BinaryKnowledgeStore(self.database) as store:
            store.save_program_index(index)
        first = self.wait(self.library.start(fixture_id='local:simple-elf'))
        process = self.library._process
        second = self.wait(self.library.start(fixture_id='local:simple-elf'))
        self.assertIs(process, self.library._process)
        for job in (first, second):
            self.assertTrue(job['cache_hit'])
            self.assertEqual(job['profile']['counts']['launcher_start_calls'], 0)
            self.assertEqual(job['profile']['counts']['index_binary_calls'], 0)
        self.library.close()
        self.assertEqual(process.returncode, 0)

    def test_queue_coalesces_and_serializes_requests(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def controlled(path, progress):
            calls.append(path)
            entered.set()
            if not release.wait(3):
                raise RuntimeError('Unit test worker was not released')
            return {'binary_id':inspect_binary(path)['sha256']}
        self.library._run_analysis = controlled
        first = self.library.start(fixture_id='local:simple-elf')
        self.assertTrue(entered.wait(2))
        try:
            duplicate = self.library.start(fixture_id='local:simple-elf')
            second = self.library.start(fixture_id='professor:overloading')
            self.assertEqual(first['job_id'], duplicate['job_id'])
            self.assertEqual(second['status'], 'queued')
            self.assertEqual(len(calls), 1)
        finally:
            release.set()
        self.assertEqual(self.wait(first)['status'], 'completed')
        self.assertEqual(self.wait(second)['status'], 'completed')
        self.assertEqual(len(calls), 2)

    def test_symlink_storage_escape_is_rejected(self):
        content = ELF.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        outside = self.root / 'outside'
        outside.mkdir()
        self.library.directory.mkdir()
        (self.library.directory / digest).symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            self.library.upload(BytesIO(content), len(content), 'escape')
        self.assertEqual(list(outside.iterdir()), [])

    def test_empty_database_http_upload_and_origin_boundary(self):
        app = GuiApplication(self.database, session_dir=self.root/'sessions', upload_dir=self.root/'http-uploads')
        self.addCleanup(app.library.close)
        server = create_server(app, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_address[1]}'
        with urlopen(base+'/api/bootstrap') as response:
            self.assertIsNone(json.load(response)['selected_binary_id'])
        for data, status in ((PE.read_bytes(),201), (b'not PE',400)):
            request = Request(base+'/api/uploads?filename=demo.exe', data=data, headers={'Content-Type':'application/octet-stream', 'Origin':base})
            if status == 201:
                with urlopen(request) as response:
                    self.assertEqual(json.load(response)['format'],'PE')
            else:
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request)
                self.assertEqual(caught.exception.code,status)
                caught.exception.close()
        request = Request(base+'/api/uploads', data=PE.read_bytes(), headers={'Content-Type':'application/octet-stream','Origin':'https://untrusted.example'})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code,403)
        caught.exception.close()


if __name__ == '__main__':
    unittest.main()
