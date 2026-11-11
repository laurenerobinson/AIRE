"""Derive ground truth for the M9 CNG crypto fixtures.

The analysis targets (<name>.exe) carry no COFF symbols or debug sections; the
linker wrote function names only to a PDB, kept as
build/<name>.groundtruth.pdb (never given to A.I.R.E.). This script reads the
PDB's public symbols (S_PUB32 in the DBI symbol-record stream), checks the PDB
is the one referenced by the PE's CodeView debug record (GUID + age), maps
each source function to its virtual address, and records the hand-documented
expected CNG imports and call relationships (from src/*.c). Nothing executes.

    python3 scripts/crypto_ground_truth.py   # writes tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/m9/crypto_pe'

# Expected behaviour per source function: CNG APIs called directly, and the
# A.I.R.E. operation category each implies. Written from src/*.c, not from
# analysis output.
EXPECTED = {
    'aes_gcm': {
        'algorithm': 'AES-256-GCM',
        'functions': {
            'create_aes_gcm_key': {'apis': ['BCryptOpenAlgorithmProvider', 'BCryptSetProperty',
                                            'BCryptGenerateSymmetricKey'], 'role': 'key_handling',
                                   'strings': ['AES', 'ChainingModeGCM', 'ChainingMode']},
            'aes_gcm_encrypt': {'apis': ['BCryptEncrypt'], 'role': 'encryption'},
            'aes_gcm_decrypt': {'apis': ['BCryptDecrypt'], 'role': 'decryption'},
            'destroy_aes_key': {'apis': ['BCryptDestroyKey', 'BCryptCloseAlgorithmProvider'],
                                'role': 'key_cleanup'},
            'init_auth_info': {'apis': [], 'role': 'auth_mode_setup'},
            'main': {'calls': ['create_aes_gcm_key', 'aes_gcm_encrypt', 'aes_gcm_decrypt',
                               'destroy_aes_key'], 'role': 'driver'},
        },
    },
    'sha256_hash': {
        'algorithm': 'SHA-256',
        'functions': {
            'prepare_sample_input': {'apis': [], 'role': 'input_processing'},
            'sha256_digest': {'apis': ['BCryptOpenAlgorithmProvider', 'BCryptCreateHash', 'BCryptHashData',
                                       'BCryptFinishHash', 'BCryptDestroyHash',
                                       'BCryptCloseAlgorithmProvider'], 'role': 'hashing',
                              'strings': ['SHA256']},
            'print_digest': {'apis': [], 'role': 'output'},
            'main': {'calls': ['prepare_sample_input', 'sha256_digest', 'print_digest'], 'role': 'driver'},
        },
    },
    'ecdsa_sign': {
        'algorithm': 'ECDSA P-256 with SHA-256',
        'functions': {
            'generate_signing_key': {'apis': ['BCryptOpenAlgorithmProvider', 'BCryptGenerateKeyPair',
                                              'BCryptFinalizeKeyPair'], 'role': 'key_handling',
                                     'strings': ['ECDSA_P256']},
            'export_public_key': {'apis': ['BCryptExportKey'], 'role': 'key_handling'},
            'import_verification_key': {'apis': ['BCryptImportKeyPair'], 'role': 'key_handling'},
            'hash_message': {'apis': ['BCryptOpenAlgorithmProvider', 'BCryptCreateHash', 'BCryptHashData',
                                      'BCryptFinishHash', 'BCryptDestroyHash', 'BCryptCloseAlgorithmProvider'],
                             'role': 'hashing', 'strings': ['SHA256']},
            'sign_digest': {'apis': ['BCryptSignHash'], 'role': 'signing'},
            'verify_signature': {'apis': ['BCryptVerifySignature'], 'role': 'verification'},
            # main also releases keys/provider itself (see the done: label in src/ecdsa_sign.c).
            'main': {'calls': ['generate_signing_key', 'export_public_key', 'import_verification_key',
                               'hash_message', 'sign_digest', 'verify_signature'],
                     'apis': ['BCryptDestroyKey', 'BCryptCloseAlgorithmProvider'], 'role': 'driver_and_cleanup'},
        },
    },
}


def pe_layout(data):
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    coff = e_lfanew + 4
    nsections, optional_size = struct.unpack_from('<H', data, coff + 2)[0], struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    debug_rva, debug_size = struct.unpack_from('<II', data, opt + 112 + 6 * 8)
    sections = []
    for i in range(nsections):
        base = opt + optional_size + i * 40
        vsize, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, base + 8)
        sections.append({'name': data[base:base + 8].rstrip(b'\0').decode('latin-1'), 'rva': rva,
                         'vsize': vsize, 'raw_offset': raw_offset, 'raw_size': raw_size})
    def offset(rva):
        for section in sections:
            if section['rva'] <= rva < section['rva'] + max(section['vsize'], section['raw_size']):
                return section['raw_offset'] + rva - section['rva']
        raise ValueError(f'RVA {rva:#x} unmapped')
    codeview = None
    if debug_rva:
        for i in range(debug_size // 28):
            entry = offset(debug_rva) + i * 28
            kind, size, _, pointer = struct.unpack_from('<IIII', data, entry + 12)
            if kind == 2 and data[pointer:pointer + 4] == b'RSDS':
                codeview = (data[pointer + 4:pointer + 20], struct.unpack_from('<I', data, pointer + 20)[0])
    return image_base, sections, codeview


class Msf:
    """Minimal MSF 7.0 reader (PDB container)."""
    MAGIC = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'

    def __init__(self, data):
        if not data.startswith(self.MAGIC):
            raise ValueError('not an MSF 7.0 PDB')
        self.data = data
        self.block, _, _, directory_bytes, _, map_block = struct.unpack_from('<6I', data, 32)
        count = -(-directory_bytes // self.block)
        blocks = struct.unpack_from(f'<{count}I', data, map_block * self.block)
        directory = b''.join(self._block(b) for b in blocks)[:directory_bytes]
        streams = struct.unpack_from('<I', directory, 0)[0]
        sizes = struct.unpack_from(f'<{streams}I', directory, 4)
        position, self.streams = 4 + 4 * streams, []
        for size in sizes:
            size = 0 if size == 0xFFFFFFFF else size
            n = -(-size // self.block)
            ids = struct.unpack_from(f'<{n}I', directory, position)
            position += 4 * n
            self.streams.append(b''.join(self._block(b) for b in ids)[:size])

    def _block(self, index):
        return self.data[index * self.block:(index + 1) * self.block]


def pdb_publics(data):
    msf = Msf(data)
    info = msf.streams[1]
    guid, age = info[12:28], struct.unpack_from('<I', info, 8)[0]
    dbi = msf.streams[3]
    symbol_stream = struct.unpack_from('<H', dbi, 20)[0]
    records, position, publics = msf.streams[symbol_stream], 0, {}
    while position + 4 <= len(records):
        length, kind = struct.unpack_from('<HH', records, position)
        if kind == 0x110E:  # S_PUB32: flags, offset, segment, name
            flags, offset, segment = struct.unpack_from('<IIH', records, position + 4)
            end = records.index(b'\0', position + 14)
            publics[records[position + 14:end].decode('latin-1')] = (segment, offset, bool(flags & 2))
        position += 2 + length
    # Procedure records in module streams (S_LPROC32/S_GPROC32 and _ID forms):
    # functions internalized by the linker never appear as publics.
    for stream in msf.streams[4:]:
        if len(stream) < 8 or struct.unpack_from('<I', stream, 0)[0] != 4:  # CV_SIGNATURE_C13
            continue
        position = 4
        while position + 4 <= len(stream):
            length, kind = struct.unpack_from('<HH', stream, position)
            if length < 2 or position + 2 + length > len(stream):
                break
            if kind in (0x110F, 0x1110, 0x1146, 0x1147) and length >= 37:
                offset, segment = struct.unpack_from('<IH', stream, position + 32)
                end = stream.find(b'\0', position + 39, position + 2 + length)
                if end > 0:
                    publics.setdefault(stream[position + 39:end].decode('latin-1'), (segment, offset, True))
            position += 2 + length
    return guid, age, publics


def main():
    report = {'note': 'Ground truth from source + linker PDB publics; analysis targets carry no symbols.',
              'programs': {}}
    for program, spec in EXPECTED.items():
        target = (FIXTURES / f'{program}.exe').read_bytes()
        image_base, sections, codeview = pe_layout(target)
        guid, age, publics = pdb_publics((FIXTURES / 'build' / f'{program}.groundtruth.pdb').read_bytes())
        if codeview is None or codeview[0] != guid:
            sys.exit(f'{program}: PDB GUID does not match the PE CodeView record')
        functions = {}
        for name, expected in spec['functions'].items():
            if name not in publics:
                sys.exit(f'{program}: public symbol {name} missing (inlined or static?)')
            segment, offset, is_function = publics[name]
            section = sections[segment - 1]
            if not section['name'].startswith('.text'):
                sys.exit(f'{program}: {name} is not in .text')
            functions[name] = {'address': f'{image_base + section["rva"] + offset:08x}', **expected}
        report['programs'][program] = {
            'binary': f'tests/fixtures/m9/crypto_pe/{program}.exe',
            'sha256': hashlib.sha256(target).hexdigest(), 'image_base': f'{image_base:08x}',
            'pdb_guid': guid.hex(), 'algorithm': spec['algorithm'],
            'source': f'tests/fixtures/m9/crypto_pe/src/{program}.c', 'functions': functions,
        }
    (FIXTURES / 'GROUND_TRUTH.json').write_text(json.dumps(report, indent=1) + '\n')
    for program, row in report['programs'].items():
        print(program, row['sha256'][:16], {k: v['address'] for k, v in row['functions'].items()})


if __name__ == '__main__':
    main()
