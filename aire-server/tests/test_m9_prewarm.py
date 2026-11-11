"""M9: optional GUI analyzer pre-warming (pure Python; JVM paths patched)."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.api import index_worker
from aire.api.binary_library import BinaryLibrary
from aire.knowledge.database import BinaryKnowledgeStore


class PrewarmTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.status = self.root / 'prewarm.json'

    def test_worker_prewarm_success_records_steps(self):
        with patch('aire.pyghidra.indexer.prewarm_runtime', return_value={'runtime_start': 1.5}):
            index_worker.prewarm(self.status)
        record = json.loads(self.status.read_text())
        self.assertEqual(record['status'], 'ready')
        self.assertEqual(record['steps'], {'runtime_start': 1.5})
        self.assertGreaterEqual(record['seconds'], 0)

    def test_worker_prewarm_failure_is_not_fatal(self):
        with patch('aire.pyghidra.indexer.prewarm_runtime', side_effect=RuntimeError('no JDK')):
            index_worker.prewarm(self.status)  # must not raise
        record = json.loads(self.status.read_text())
        self.assertEqual(record['status'], 'failed')
        self.assertIn('no JDK', record['error'])

    def test_library_prewarm_spawns_worker_with_flag_once(self):
        database = self.root / 'a.sqlite'
        with BinaryKnowledgeStore(database):
            pass
        library = BinaryLibrary(database, directory=self.root / 'uploads')
        calls = []

        class FakeProcess:
            stdin = stdout = None
            returncode = None
            def poll(self):
                return None
        def fake_popen(command, **kwargs):
            calls.append(command)
            return FakeProcess()
        with patch('aire.api.binary_library.subprocess.Popen', side_effect=fake_popen):
            self.assertEqual(library.analyzer_status()['status'], 'not_started')
            self.assertTrue(library.prewarm())
            self.assertTrue(library.prewarm())  # already alive: no second process
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][-1].startswith('--prewarm='))
        self.assertEqual(library.analyzer_status()['status'], 'warming')
        library.prewarm_status_path.write_text(json.dumps({'status': 'ready', 'seconds': 4.2}))
        self.assertEqual(library.analyzer_status()['status'], 'ready')
        library._process = None
        library._worker_log.close()

    def test_spawn_failure_falls_back(self):
        database = self.root / 'b.sqlite'
        with BinaryKnowledgeStore(database):
            pass
        library = BinaryLibrary(database, directory=self.root / 'uploads-b')
        self.addCleanup(library.close)
        with patch('aire.api.binary_library.subprocess.Popen', side_effect=OSError('fork failed')):
            self.assertFalse(library.prewarm())
        status = library.analyzer_status()
        self.assertEqual(status['status'], 'failed')
        self.assertIn('first analysis', status['fallback'])

    def test_normal_spawn_has_no_prewarm_flag(self):
        database = self.root / 'c.sqlite'
        with BinaryKnowledgeStore(database):
            pass
        library = BinaryLibrary(database, directory=self.root / 'uploads-c')
        with patch('aire.api.binary_library.subprocess.Popen') as popen:
            popen.return_value.poll.return_value = None
            library._ensure_worker()
        self.assertFalse(any(str(a).startswith('--prewarm') for a in popen.call_args[0][0]))
        library._process = None
        library._worker_log.close()


if __name__ == '__main__':
    unittest.main()
