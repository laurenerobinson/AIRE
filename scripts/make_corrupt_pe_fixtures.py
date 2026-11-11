"""Generate controlled malformed PE fixtures from disposable copies of valid,
source-backed binaries. Originals are only read (SHA-256 verified before and
after); outputs are deterministic, written non-executable, and never run.

    python3 scripts/make_corrupt_pe_fixtures.py          # regenerate + manifest
    python3 scripts/make_corrupt_pe_fixtures.py --check  # verify hashes only

Each fixture records its documented expected outcome (analysis level and the
issue codes aire.validation.pe_structure must report). Unusual-but-valid
variants guard against false positives.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'tests/fixtures/m9/corrupt_pe'
SOURCES = {
    'tls32': ('tests/fixtures/external/angr/windows_tls_x86/TLS.exe',
              '5a9327f87f994a76c84c986a498e105be183a558b520fe6004ceb6e498a7489d'),
    'gpa64': ('tests/fixtures/external/angr/windows_getprocaddress/GetProcAddress.exe',
              'fac8a1f6e2351b870ebb426a2339ff817b195a437be0f7f6fc91f739579d246c'),
}
BAD_RVA = 0x7FFFFF00


class Pe:
    """Minimal offsets needed to place each mutation precisely."""

    def __init__(self, data):
        self.data = bytearray(data)
        self.e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
        self.coff = self.e_lfanew + 4
        self.nsections = struct.unpack_from('<H', data, self.coff + 2)[0]
        self.optional_size = struct.unpack_from('<H', data, self.coff + 16)[0]
        self.opt = self.coff + 20
        self.magic = struct.unpack_from('<H', data, self.opt)[0]
        self.table = self.opt + self.optional_size
        directories = self.opt + (96 if self.magic == 0x10b else 112)
        self.import_dir = directories + 8
        self.import_rva = struct.unpack_from('<I', data, self.import_dir)[0]

    def section(self, index):
        base = self.table + index * 40
        name = bytes(self.data[base:base + 8]).rstrip(b'\0').decode('latin-1')
        vsize, rva, raw_size, raw_offset = struct.unpack_from('<IIII', self.data, base + 8)
        return {'base': base, 'name': name, 'vsize': vsize, 'rva': rva,
                'raw_size': raw_size, 'raw_offset': raw_offset}

    def code_section(self):
        for i in range(self.nsections):
            row = self.section(i)
            # First executable section that has file data (skips MSVC .textbss).
            if struct.unpack_from('<I', self.data, row['base'] + 36)[0] & 0x20000020 and row['raw_size']:
                return row
        return self.section(0)

    def rva_to_offset(self, rva):
        for i in range(self.nsections):
            s = self.section(i)
            if s['rva'] <= rva < s['rva'] + max(s['vsize'], s['raw_size']):
                return s['raw_offset'] + rva - s['rva']
        raise ValueError(f'RVA {rva:#x} not in a section')

    def put32(self, offset, value):
        struct.pack_into('<I', self.data, offset, value)

    def put16(self, offset, value):
        struct.pack_into('<H', self.data, offset, value)


def mutations():
    """name -> (source, mutate(pe) -> bytes, expected analysis, required codes, description)."""
    def m(fn):
        def run(pe):
            result = fn(pe)
            return bytes(pe.data if result is None else result)
        return run

    rows = {}
    def add(name, source, fn, level, codes, description):
        rows[name] = (source, m(fn), level, codes, description)

    # --- header corruption: rejected, no analysis possible
    add('dos_signature_invalid', 'tls32', lambda pe: pe.data.__setitem__(slice(0, 2), b'ZM'),
        'none', ['dos_signature'], 'DOS magic MZ replaced by ZM')
    add('pe_signature_invalid', 'gpa64', lambda pe: pe.data.__setitem__(pe.e_lfanew + 1, ord('X')),
        'none', ['pe_signature'], 'PE\\0\\0 signature replaced by PX\\0\\0')
    add('e_lfanew_out_of_range', 'tls32', lambda pe: pe.put32(0x3c, len(pe.data) + 0x1000),
        'none', ['pe_header_offset'], 'e_lfanew points past end of file')
    add('optional_magic_invalid', 'gpa64', lambda pe: pe.put16(pe.opt, 0x0999),
        'none', ['optional_magic'], 'Optional header magic is neither PE32 nor PE32+')
    add('zero_sections', 'tls32', lambda pe: pe.put16(pe.coff + 2, 0),
        'none', ['no_sections'], 'COFF NumberOfSections set to 0')
    add('truncated_in_optional_header', 'gpa64', lambda pe: pe.data[:pe.opt + 40],
        'none', ['truncated_optional_header'], 'File cut inside the optional header')
    add('truncated_section_table', 'tls32', lambda pe: pe.data[:pe.table + 40 + 12],
        'none', ['truncated_section_table'], 'File cut after the first section header')
    add('truncated_tiny', 'gpa64', lambda pe: pe.data[:40],
        'none', ['truncated_dos_header'], 'Only 40 bytes remain')
    # --- body/section/import damage: headers parse; partial analysis with warnings
    add('truncated_half', 'tls32', lambda pe: pe.data[:len(pe.data) // 2],
        'partial', ['section_truncated'], 'Last half of the file removed')
    add('section_offset_beyond_eof', 'gpa64',
        lambda pe: pe.put32(pe.code_section()['base'] + 20, len(pe.data) + 0x10000),
        'partial', ['section_beyond_eof'], 'Code section PointerToRawData past end of file')
    add('section_size_oversized', 'tls32',
        lambda pe: pe.put32(pe.code_section()['base'] + 16, 0x7FFF0000),
        'partial', ['section_truncated'], 'Code section SizeOfRawData set to 0x7FFF0000')
    add('section_offset_into_headers', 'gpa64',
        lambda pe: pe.put32(pe.code_section()['base'] + 20, 0x10),
        'partial', ['section_raw_offset'], 'Code section raw data offset points into the headers')
    add('section_overlap', 'tls32',
        lambda pe: pe.put32(pe.section(1)['base'] + 12, pe.section(0)['rva']),
        'partial', ['section_overlap'], 'Second section VirtualAddress equals the first')
    add('import_directory_invalid', 'gpa64', lambda pe: pe.put32(pe.import_dir, BAD_RVA),
        'partial', ['import_directory'], 'Import directory RVA maps to no file data')
    add('import_dll_name_invalid', 'tls32',
        lambda pe: pe.put32(pe.rva_to_offset(pe.import_rva) + 12, BAD_RVA),
        'partial', ['import_dll_name'], 'First import descriptor DLL-name RVA invalid')
    add('import_thunks_invalid', 'gpa64',
        lambda pe: (pe.put32(pe.rva_to_offset(pe.import_rva), BAD_RVA),
                    pe.put32(pe.rva_to_offset(pe.import_rva) + 16, BAD_RVA)) and None,
        'partial', ['import_thunks'], 'First import descriptor thunk arrays point nowhere')
    # --- unusual but valid: must NOT be reported as corruption
    add('valid_overlay_appended', 'gpa64', lambda pe: bytes(pe.data) + b'\xcc' * 4096,
        'full', [], '4 KiB overlay appended after the last section (common for installers)')
    def rename(pe):
        for i in range(pe.nsections):
            base = pe.section(i)['base']
            pe.data[base:base + 8] = f'S{i}!@#'.encode().ljust(8, b'\0')
    add('valid_renamed_sections', 'tls32', rename, 'full', [],
        'All section names replaced with nonstandard names')
    return rows


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    originals = {}
    for key, (relative, expected) in SOURCES.items():
        data = (ROOT / relative).read_bytes()
        if sha256(data) != expected:
            sys.exit(f'{relative}: SHA-256 differs from manifest; refusing to derive fixtures')
        originals[key] = data
    entries = []
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (source, mutate, level, codes, description) in mutations().items():
        data = mutate(Pe(originals[source]))
        target = OUT / f'{name}.exe'
        if args.check:
            if sha256(target.read_bytes()) != sha256(data):
                sys.exit(f'{target}: content differs from deterministic generator')
        else:
            if target.exists():
                target.chmod(0o644)
            target.write_bytes(data)
            target.chmod(0o444)
        entries.append({'name': f'corrupt_{name}', 'binary_path': f'corrupt_pe/{name}.exe',
                        'binary_sha256': sha256(data), 'collection': 'M9 corrupted PE',
                        'negative_fixture': level != 'full', 'expected_analysis': level,
                        'expected_issue_codes': codes, 'description': description,
                        'derived_from': SOURCES[source][0], 'derived_from_sha256': SOURCES[source][1]})
    for key, (relative, expected) in SOURCES.items():
        if sha256((ROOT / relative).read_bytes()) != expected:
            sys.exit(f'{relative}: original changed during generation')
    if args.check:
        print(f'{len(entries)} corrupt fixtures match the generator')
        return
    (OUT / 'EXPECTED.json').write_text(json.dumps({'fixtures': entries}, indent=1) + '\n')
    # Merge into the M9 GUI library manifest, replacing only corrupt_* rows.
    manifest = OUT.parent / 'manifest.json'
    rows = json.loads(manifest.read_text())['fixtures'] if manifest.is_file() else []
    rows = [row for row in rows if not row['name'].startswith('corrupt_')] + entries
    manifest.write_text(json.dumps({'fixtures': rows}, indent=1) + '\n')
    print(f'wrote {len(entries)} fixtures to {OUT.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
