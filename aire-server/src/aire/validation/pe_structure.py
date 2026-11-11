"""Read-only PE/COFF structure validation for intake and GUI reporting.

Never executes, maps or modifies the input: it parses bytes already read into
memory. The report says what is determinable (format, architecture), whether
the PE structure is valid, every specific issue found, and which analysis level
is safe to attempt:

* ``none``    - not a PE, or headers too damaged for a loader (rejected).
* ``partial`` - headers parse, but section data, imports or other directories
                are damaged; Ghidra can still load what is present (allowed,
                with warnings carried into the job).
* ``full``    - no structural errors (informational notes may still exist,
                e.g. unusual-but-valid layouts, which must not be flagged as
                corruption).

Severity: ``fatal`` forces ``none``; ``error`` forces at least ``partial``;
``warning`` forces at least ``partial`` (damage that a loader tolerates but that
reduces evidence completeness); ``info`` never changes the level.
"""
from dataclasses import asdict, dataclass, field
import struct

MACHINES = {0x14c: 'x86', 0x8664: 'x86_64', 0xaa64: 'AArch64', 0x1c4: 'ARM', 0x1c0: 'ARM',
            0x200: 'IA64', 0x5064: 'RISC-V64'}
SCN_CNT_CODE = 0x20
SCN_MEM_EXECUTE = 0x20000000
SCN_UNINITIALIZED = 0x80
MAX_IMPORT_DESCRIPTORS = 4096
MAX_THUNKS_PER_DLL = 65536
LEVELS = ('full', 'partial', 'none')


@dataclass
class Issue:
    severity: str  # fatal | error | warning | info
    code: str
    message: str
    offset: int | None = None


@dataclass
class PeReport:
    format: str | None = None
    architecture: str | None = None
    bits: int | None = None
    machine: int | None = None
    pe_valid: bool = False
    analysis: str = 'none'
    size: int = 0
    sections: list = field(default_factory=list)
    imports: dict = field(default_factory=dict)
    entry_point_rva: int | None = None
    is_dll: bool = False
    issues: list = field(default_factory=list)

    def add(self, severity, code, message, offset=None):
        self.issues.append(Issue(severity, code, message, offset))

    def finish(self):
        severities = {issue.severity for issue in self.issues}
        if 'fatal' in severities:
            self.analysis, self.pe_valid = 'none', False
        elif severities & {'error', 'warning'}:
            self.analysis, self.pe_valid = 'partial', 'error' not in severities
        else:
            self.analysis, self.pe_valid = 'full', True
        return self

    @property
    def summary(self):
        if self.analysis == 'full':
            return 'Valid PE structure; full static analysis possible'
        if self.analysis == 'partial':
            return 'PE headers parse but structure is damaged; partial static analysis only'
        return 'PE structure is invalid; static analysis is not possible'

    def to_dict(self):
        data = asdict(self)
        data['summary'] = self.summary
        return data


class _Reader:
    def __init__(self, data):
        self.data = data

    def has(self, offset, size):
        return offset >= 0 and size >= 0 and offset + size <= len(self.data)

    def u16(self, offset):
        return struct.unpack_from('<H', self.data, offset)[0]

    def u32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]

    def u64(self, offset):
        return struct.unpack_from('<Q', self.data, offset)[0]

    def cstring(self, offset, limit=256):
        if not self.has(offset, 1):
            return None
        end = self.data.find(b'\0', offset, offset + limit)
        if end < 0:
            return None
        return self.data[offset:end]


def validate_pe(data: bytes) -> PeReport:
    """Validate PE structure from raw bytes. Never raises for malformed input."""
    report = PeReport(size=len(data))
    reader = _Reader(data)
    try:
        _validate(reader, report)
    except (struct.error, IndexError, ValueError, OverflowError) as exc:  # defensive: never crash intake
        report.add('fatal', 'parser_bounds', f'Structure parsing stopped unexpectedly: {exc}')
    return report.finish()


def _validate(r, report):
    data = r.data
    if len(data) < 2 or data[:2] != b'MZ':
        if len(data) >= 2 and data[:2] in (b'ZM', b'mz', b'Mz'):
            report.add('fatal', 'dos_signature', f'Invalid DOS signature {data[:2]!r}; expected b"MZ"', 0)
        else:
            report.add('fatal', 'dos_signature', 'Missing DOS/MZ signature; not a PE executable', 0)
        return
    report.format = 'PE?'
    if not r.has(0, 64):
        report.add('fatal', 'truncated_dos_header', f'File is {len(data)} bytes; DOS header needs 64', 0)
        return
    e_lfanew = r.u32(0x3c)
    if e_lfanew < 0x40 or not r.has(e_lfanew, 4):
        report.add('fatal', 'pe_header_offset',
                   f'e_lfanew {e_lfanew:#x} points outside the {len(data)}-byte file', 0x3c)
        return
    if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
        report.add('fatal', 'pe_signature',
                   f'Invalid PE signature {data[e_lfanew:e_lfanew + 4]!r} at {e_lfanew:#x}; expected b"PE\\0\\0"',
                   e_lfanew)
        return
    report.format = 'PE'
    coff = e_lfanew + 4
    if not r.has(coff, 20):
        report.add('fatal', 'truncated_coff_header', 'File ends inside the COFF file header', coff)
        return
    machine, nsections = r.u16(coff), r.u16(coff + 2)
    optional_size, characteristics = r.u16(coff + 16), r.u16(coff + 18)
    report.machine = machine
    report.architecture = MACHINES.get(machine, f'PE machine {machine:#x}')
    report.is_dll = bool(characteristics & 0x2000)
    if machine not in MACHINES:
        report.add('warning', 'unknown_machine', f'Unrecognized machine type {machine:#x}', coff)
    if not characteristics & 0x0002:
        report.add('warning', 'not_executable_image', 'IMAGE_FILE_EXECUTABLE_IMAGE flag is clear', coff + 18)
    if nsections == 0:
        report.add('fatal', 'no_sections', 'COFF header declares zero sections', coff + 2)
        return
    if nsections > 96:
        report.add('error', 'section_count', f'{nsections} sections exceeds the PE limit of 96', coff + 2)
    opt = coff + 20
    if optional_size < 2 or not r.has(opt, 2):
        report.add('fatal', 'truncated_optional_header', 'Optional header is missing or truncated', opt)
        return
    magic = r.u16(opt)
    if magic not in (0x10b, 0x20b):
        report.add('fatal', 'optional_magic', f'Invalid optional header magic {magic:#x}', opt)
        return
    report.bits = 32 if magic == 0x10b else 64
    minimum = 96 if magic == 0x10b else 112
    if optional_size < minimum or not r.has(opt, minimum):
        report.add('fatal', 'truncated_optional_header',
                   f'Optional header is {min(optional_size, len(data) - opt)} bytes; needs {minimum}', opt)
        return
    if not r.has(opt, optional_size):
        report.add('fatal', 'truncated_optional_header', 'File ends inside the declared optional header', opt)
        return
    entry = r.u32(opt + 16)
    report.entry_point_rva = entry
    image_base = r.u32(opt + 28) if magic == 0x10b else r.u64(opt + 24)
    section_alignment, file_alignment = r.u32(opt + 32), r.u32(opt + 36)
    size_of_image, size_of_headers = r.u32(opt + 56), r.u32(opt + 60)
    directories_offset = opt + (96 if magic == 0x10b else 112)
    directory_count = r.u32(opt + (92 if magic == 0x10b else 108))
    if file_alignment == 0 or file_alignment & (file_alignment - 1):
        report.add('warning', 'file_alignment', f'FileAlignment {file_alignment:#x} is not a power of two', opt + 36)
    if section_alignment == 0 or section_alignment & (section_alignment - 1):
        report.add('warning', 'section_alignment',
                   f'SectionAlignment {section_alignment:#x} is not a power of two', opt + 32)
    if image_base % 0x10000 and not report.is_dll:
        report.add('info', 'image_base', f'ImageBase {image_base:#x} is not 64 KiB aligned')

    table = opt + optional_size
    if not r.has(table, nsections * 40):
        available = max(0, (len(data) - table) // 40)
        report.add('fatal', 'truncated_section_table',
                   f'Section table needs {nsections * 40} bytes at {table:#x}; only {available} '
                   f'complete header(s) present', table)
        return

    sections = []
    for index in range(nsections):
        header = table + index * 40
        raw_name = data[header:header + 8]
        name = raw_name.rstrip(b'\0').decode('latin-1')
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, header + 8)
        flags = r.u32(header + 36)
        row = {'index': index, 'name': name, 'virtual_address': rva, 'virtual_size': virtual_size,
               'raw_offset': raw_offset, 'raw_size': raw_size, 'characteristics': flags,
               'executable': bool(flags & (SCN_MEM_EXECUTE | SCN_CNT_CODE))}
        sections.append(row)
        label = f'Section {index} {name!r}'
        if raw_size:
            if raw_offset < table + nsections * 40 and raw_offset < size_of_headers:
                report.add('error', 'section_raw_offset',
                           f'{label} raw data offset {raw_offset:#x} overlaps the PE headers', header + 20)
            if raw_offset >= len(data):
                report.add('error', 'section_beyond_eof',
                           f'{label} raw data starts at {raw_offset:#x}, beyond end of file '
                           f'({len(data):#x})', header + 20)
            elif raw_offset + raw_size > len(data):
                report.add('warning', 'section_truncated',
                           f'{label} raw data {raw_offset:#x}+{raw_size:#x} extends '
                           f'{raw_offset + raw_size - len(data)} bytes past end of file', header + 16)
        elif not flags & SCN_UNINITIALIZED and virtual_size:
            report.add('info', 'section_no_raw_data',
                       f'{label} has no file data (loaded as zero-filled memory)', header + 16)
        if virtual_size > 0x40000000 or (size_of_image and rva > size_of_image):
            report.add('error', 'section_virtual_range',
                       f'{label} virtual range {rva:#x}+{virtual_size:#x} is implausible for '
                       f'SizeOfImage {size_of_image:#x}', header + 8)
    report.sections = sections

    ordered = sorted((s for s in sections if s['virtual_size'] or s['raw_size']),
                     key=lambda s: s['virtual_address'])
    for previous, current in zip(ordered, ordered[1:]):
        # Memory span is VirtualSize (raw size is file-aligned and may exceed it).
        span = previous['virtual_size'] or previous['raw_size']
        if previous['virtual_address'] + span > current['virtual_address']:
            report.add('error', 'section_overlap',
                       f'Sections {previous["name"]!r} and {current["name"]!r} overlap in memory')

    def section_for(rva):
        for section in sections:
            size = section['virtual_size'] or section['raw_size']  # memory span
            if section['virtual_address'] <= rva < section['virtual_address'] + size:
                return section
        return None

    def rva_to_offset(rva):
        if rva < size_of_headers and rva < len(data):
            return rva
        section = section_for(rva)
        if section is None or not section['raw_size']:
            return None
        delta = rva - section['virtual_address']
        if delta >= section['raw_size']:
            return None
        offset = section['raw_offset'] + delta
        return offset if offset < len(data) else None

    if entry:
        section = section_for(entry)
        if section is None:
            report.add('error', 'entry_point', f'Entry point RVA {entry:#x} is outside every section', opt + 16)
        elif not section['executable']:
            report.add('info', 'entry_point_section',
                       f'Entry point is in non-executable section {section["name"]!r} (unusual but loadable)')
    elif not report.is_dll:
        report.add('info', 'entry_point_zero', 'Executable has a zero entry point')

    directories = {}
    names = ('export', 'import', 'resource', 'exception', 'security', 'basereloc', 'debug',
             'architecture', 'globalptr', 'tls', 'load_config', 'bound_import', 'iat',
             'delay_import', 'clr', 'reserved')
    for index in range(min(directory_count, 16)):
        offset = directories_offset + index * 8
        if offset + 8 > opt + optional_size:
            report.add('error', 'data_directories',
                       f'Optional header declares {directory_count} data directories but holds only {index}',
                       offset)
            break
        directories[names[index]] = (r.u32(offset), r.u32(offset + 4))

    import_rva, import_size = directories.get('import', (0, 0))
    if import_rva:
        _validate_imports(r, report, import_rva, import_size, report.bits, rva_to_offset)

    if len(data) > 0 and sections:
        end = max((s['raw_offset'] + s['raw_size'] for s in sections if s['raw_size']), default=0)
        if end and len(data) > end:
            report.add('info', 'overlay', f'{len(data) - end} bytes of overlay data follow the last section')


def _validate_imports(r, report, import_rva, import_size, bits, rva_to_offset):
    offset = rva_to_offset(import_rva)
    if offset is None:
        report.add('error', 'import_directory',
                   f'Import directory RVA {import_rva:#x} does not map to file data')
        return
    pointer = 8 if bits == 64 else 4
    ordinal_flag = 1 << (63 if bits == 64 else 31)
    imports = {}
    for index in range(MAX_IMPORT_DESCRIPTORS):
        descriptor = offset + index * 20
        if not r.has(descriptor, 20):
            report.add('error', 'import_descriptor_truncated',
                       f'Import descriptor {index} at {descriptor:#x} runs past end of file', descriptor)
            break
        original_thunk, _, _, name_rva, first_thunk = struct.unpack_from('<IIIII', r.data, descriptor)
        if not any((original_thunk, name_rva, first_thunk)):
            break  # terminator
        name_offset = rva_to_offset(name_rva) if name_rva else None
        name = r.cstring(name_offset) if name_offset is not None else None
        if not name or any(byte < 0x20 or byte > 0x7e for byte in name):
            report.add('error', 'import_dll_name',
                       f'Import descriptor {index} DLL name RVA {name_rva:#x} is invalid', descriptor + 12)
            dll = f'<invalid #{index}>'
        else:
            dll = name.decode('ascii')
        thunk_rva = original_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva) if thunk_rva else None
        functions = []
        if thunk_offset is None:
            report.add('error', 'import_thunks',
                       f'Import {dll}: thunk RVA {thunk_rva:#x} does not map to file data', descriptor)
        else:
            for slot in range(MAX_THUNKS_PER_DLL):
                position = thunk_offset + slot * pointer
                if not r.has(position, pointer):
                    report.add('error', 'import_thunks_truncated',
                               f'Import {dll}: thunk array runs past end of file', position)
                    break
                value = r.u64(position) if pointer == 8 else r.u32(position)
                if value == 0:
                    break
                if value & ordinal_flag:
                    functions.append(f'#{value & 0xffff}')
                    continue
                hint_offset = rva_to_offset(value & 0x7fffffff)
                symbol = r.cstring(hint_offset + 2) if hint_offset is not None else None
                if not symbol or any(byte < 0x20 or byte > 0x7e for byte in symbol):
                    report.add('error', 'import_name',
                               f'Import {dll}: name entry RVA {value & 0x7fffffff:#x} is invalid', position)
                    break
                functions.append(symbol.decode('ascii'))
            else:
                report.add('error', 'import_thunks_unterminated', f'Import {dll}: thunk array is not terminated')
        imports[dll] = functions
    else:
        report.add('error', 'import_descriptors_unterminated', 'Import descriptor table is not terminated')
    report.imports = imports
