"""Offline corpus integrity and malformed-download controls; no target execution."""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('external_fixture_validator', ROOT / 'scripts/validate_external_fixtures.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
CORPUS = ROOT / 'tests/fixtures/external'


class ExternalFixtureTests(unittest.TestCase):
    def test_corpus_integrity_and_all_formats(self):
        result = validator.validate()
        self.assertEqual(result['binaries'], 11)
        self.assertEqual(result['source_files'], 11)
        entries = json.loads((CORPUS / 'manifest.json').read_text())['fixtures']
        self.assertEqual({f['file_details']['format'] for f in entries}, {'ELF', 'PE'})
        self.assertEqual(sum(f['file_details']['binary_kind'] == 'dll' for f in entries), 1)

    def test_reject_download_pages_and_lfs_pointers(self):
        for prefix in (b'<!DOCTYPE html>', b'<html>', b'version https://git-lfs.github.com/spec/v1'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                validator.identify(prefix + b' ' * 200)

    def test_reject_mz_without_pe_signature(self):
        data = bytearray(256)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3c, 64)
        with self.assertRaisesRegex(ValueError, 'PE signature'):
            validator.identify(data)

    def test_reject_truncated_pe_section(self):
        data = (CORPUS / 'angr/windows_getprocaddress/GetProcAddress.exe').read_bytes()
        with self.assertRaisesRegex(ValueError, 'outside input'):
            validator.identify(data[:1024])

    def test_reject_elf_program_range_beyond_file(self):
        data = bytearray((CORPUS / 'angr/brancher/brancher').read_bytes())
        phoff, = struct.unpack_from('<Q', data, 32)
        struct.pack_into('<Q', data, phoff + 8, len(data) + 1)
        with self.assertRaisesRegex(ValueError, 'outside input'):
            validator.identify(data)

    def test_intentional_non_utf8_forwarder_is_structurally_valid_pe(self):
        data = (CORPUS / 'angr/windows_invalid_export_forwarder/invalid_export_forwarder.dll').read_bytes()
        self.assertIn(b'u\x9fer32.MessageBoxA\0', data)
        self.assertEqual(validator.identify(data)['binary_kind'], 'dll')

    def test_detect_modified_original_source(self):
        with tempfile.TemporaryDirectory() as work:
            copy = Path(work) / 'external'
            shutil.copytree(CORPUS, copy)
            source = copy / 'angr/brancher/brancher.c'
            source.write_bytes(source.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'Integrity mismatch'):
                validator.validate(copy / 'manifest.json')

    def test_reject_manifest_path_traversal(self):
        manifest = json.loads((CORPUS / 'manifest.json').read_text())
        manifest['files'][0]['path'] = '../outside'
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'manifest.json'
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'Unsafe path'):
                validator.validate(path)


if __name__ == '__main__':
    unittest.main()
