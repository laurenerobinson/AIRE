"""Offline integrity/format checks for external fixtures; never executes a target.

Paths in the manifest are relative to its directory. Only the standard library
is needed. This is a bounded structural check, not a complete ELF/PE loader.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

MAX_FILE_SIZE = 2 * 1024 * 1024
DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / 'tests/fixtures/external/manifest.json'


def identify(data):
    """Validate header/table/file ranges and report independently observed facts."""
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def unpack(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), 'Truncated header')
        return struct.unpack_from(fmt, data, offset)

    def span(offset, size):
        require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
                'File range outside input')

    require(64 <= len(data) <= MAX_FILE_SIZE, 'Input outside size limits')
    require(not data.startswith(b'version https://git-lfs.github.com/spec/v1'), 'Git LFS pointer')
    require(not data.lstrip().lower().startswith((b'<!doctype html', b'<html')), 'HTML download')
    if data[:4] == b'\x7fELF':
        require(data[4:7] == b'\x02\x01\x01', 'Expected ELF64 little endian version 1')
        kind, machine, version = unpack('<HHI', 16)
        require(kind in (2, 3) and machine == 62 and version == 1, 'Unsupported ELF target')
        phoff, shoff = unpack('<QQ', 32)
        ehsize, phsize, phnum, shsize, shnum, stridx = unpack('<6H', 52)
        require(ehsize == 64 and phnum > 0 and phsize == 56, 'Invalid ELF program headers')
        require(shnum > 0 and shsize == 64 and 0 < stridx < shnum, 'Invalid ELF section headers')
        span(phoff, phsize * phnum)
        span(shoff, shsize * shnum)
        for i in range(phnum):
            _, _, offset, _, _, filesz, memsz = unpack('<IIQQQQQ', phoff + i * phsize)
            span(offset, filesz)
            require(filesz <= memsz, 'ELF segment file size exceeds memory size')
        sections = [unpack('<IIQQQQIIQQ', shoff + i * shsize) for i in range(shnum)]
        for section in sections:
            if section[1] != 8:  # SHT_NOBITS occupies no file bytes.
                span(section[4], section[5])
        strings = sections[stridx]
        table = data[strings[4]:strings[4] + strings[5]]
        for section in sections:
            require(section[0] < len(table) and b'\0' in table[section[0]:], 'Invalid ELF section name')
        symtab = any(s[1] == 2 for s in sections)
        names = [table[s[0]:].split(b'\0', 1)[0] for s in sections]
        return dict(format='ELF', architecture='x86_64', bits=64, binary_kind='executable',
                    symbol_status='elf-symbol-table' if symtab else 'elf-stripped',
                    debug_status='dwarf' if b'.debug_info' in names else 'none',
                    elf_type='ET_EXEC' if kind == 2 else 'ET_DYN')
    require(data[:2] == b'MZ', 'Expected ELF or DOS MZ header')
    peoff, = unpack('<I', 0x3c)
    require(peoff >= 64 and data[peoff:peoff + 4] == b'PE\0\0', 'Missing PE signature')
    machine, count, _, symoff, symcount, optsize, flags = unpack('<HHIIIHH', peoff + 4)
    require(1 <= count <= 96 and flags & 2, 'Invalid PE executable characteristics/sections')
    opt = peoff + 24
    span(opt, optsize)
    magic, = unpack('<H', opt)
    require((machine, magic) in ((0x8664, 0x20b), (0x14c, 0x10b)), 'PE machine/optional header mismatch')
    bits = 64 if magic == 0x20b else 32
    require(optsize >= (112 if bits == 64 else 96), 'Truncated PE optional header')
    sections = opt + optsize
    span(sections, count * 40)
    headersz, = unpack('<I', opt + 60)
    require(sections + count * 40 <= headersz <= len(data), 'Invalid PE header size')
    for i in range(count):
        rawsize, rawoff = unpack('<II', sections + i * 40 + 16)
        if rawsize:
            require(rawoff >= headersz, 'PE section overlaps headers')
            span(rawoff, rawsize)
    if symcount:
        span(symoff, symcount * 18 + 4)
        strsize, = unpack('<I', symoff + symcount * 18)
        require(strsize >= 4, 'Invalid COFF string table')
        span(symoff + symcount * 18, strsize)
    return dict(format='PE', architecture='x86_64' if bits == 64 else 'x86', bits=bits,
                binary_kind='dll' if flags & 0x2000 else 'executable',
                symbol_status='pe-coff-symbol-table' if symcount else 'pe-no-coff-symbol-table',
                debug_status='external-pdb-reference' if b'RSDS' in data else 'none')


def validate(manifest_path=DEFAULT_MANIFEST):
    manifest_path = Path(manifest_path).resolve()
    base = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())
    if manifest['schema_version'] != 1:
        raise ValueError('Unsupported manifest schema')
    files = {}
    for row in manifest['files']:
        relative = Path(row['path'])
        path = (base / relative).resolve()
        if relative.is_absolute() or '..' in relative.parts or not path.is_relative_to(base):
            raise ValueError(f'Unsafe path: {relative}')
        if row['path'] in files or not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
            raise ValueError(f'Duplicate, missing or oversized file: {relative}')
        data = path.read_bytes()
        if len(data) != row['size'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError(f'Integrity mismatch: {relative}')
        if 'upstream_path' in row:
            if not re.fullmatch(r'[0-9a-f]{40}', row['upstream_commit']):
                raise ValueError(f'Unpinned upstream: {relative}')
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if blob != row['git_blob_sha1']:
                raise ValueError(f'Upstream blob mismatch: {relative}')
        files[row['path']] = (row, data)
    names, binaries = set(), set()
    for fixture in manifest['fixtures']:
        if fixture['name'] in names:
            raise ValueError('Duplicate fixture name')
        names.add(fixture['name'])
        row, data = files[fixture['binary_path']]
        digest = hashlib.sha256(data).hexdigest()
        if digest in binaries or digest != fixture['binary_sha256']:
            raise ValueError('Duplicate binary or inconsistent binary hash')
        binaries.add(digest)
        if not fixture['source_paths'] or len(fixture['source_paths']) != len(fixture['upstream_source_paths']):
            raise ValueError('Missing source paths')
        observed = identify(data)
        if observed != fixture['file_details']:
            raise ValueError(f'Format metadata mismatch: {fixture["name"]}: {observed}')
        if row['role'] != 'binary' or row['upstream_path'] != fixture['upstream_binary_path']:
            raise ValueError('Inconsistent binary provenance')
        for ref, upstream in zip(fixture['source_paths'], fixture['upstream_source_paths']):
            if files[ref][0]['role'] != 'source' or Path(ref).suffix not in ('.c', '.cpp', '.h'):
                raise ValueError('Missing original C/C++ source')
            if files[ref][0]['upstream_path'] != upstream:
                raise ValueError('Inconsistent source provenance')
        for ref in fixture['license']['notice_paths']:
            if files[ref][0]['role'] != 'license':
                raise ValueError('Missing license notice')
        if files[fixture['ground_truth_path']][0]['role'] != 'ground_truth':
            raise ValueError('Missing ground truth')
        if fixture['ground_truth_eligible'] and fixture['source_match']['confidence'] != 'high':
            raise ValueError('Unverified fixture included in accuracy benchmarks')
        for relative in [fixture['binary_path'], *fixture['source_paths'], *fixture['support_paths']]:
            record = files[relative][0]
            if (record['upstream_commit'], record['upstream_url']) != (fixture['upstream_commit'], fixture['upstream_url']):
                raise ValueError('Inconsistent source/binary upstream')
    expected = set(files) | {manifest_path.name}
    actual = {p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file()}
    if actual != expected:
        raise ValueError(f'Unmanifested/missing files: {sorted(actual ^ expected)}')
    return dict(fixtures=len(names), files=len(files), binaries=len(binaries),
                source_files=sum(r['role'] == 'source' for r, _ in files.values()), status='PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.manifest), indent=2))
    except (ValueError, KeyError, OSError, TypeError, struct.error) as exc:
        parser.exit(1, f'Fixture validation failed: {exc}\n')


if __name__ == '__main__':
    main()
