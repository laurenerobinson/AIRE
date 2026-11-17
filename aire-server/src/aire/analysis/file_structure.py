"""Authoritative structural condition of an analyzed binary, for chat answers.

Re-validates the original file with the same read-only intake validators M9
uses (``aire.validation.pe_structure`` for PE, ``inspect_binary`` for ELF). The
result is trusted only when the file at the stored path is byte-identical to
the analyzed one (same SHA-256); otherwise the condition is ``unverified``.
Nothing is executed, mapped or modified, and the file name is never evidence.

Statuses: ``full`` (valid structure), ``partial`` (damaged but loadable: some
evidence missing or unreliable), ``none`` (invalid: no reliable static
analysis), ``unverified`` (original file unavailable or changed).
"""
import hashlib
from pathlib import Path

from aire.validation.pe_structure import validate_pe

MAX_BYTES = 32 * 1024 * 1024

# Issue code -> which stored evidence the condition makes missing or unreliable.
_IMPORTS = ('Import table damaged: imported API names or their DLL attribution may be missing or wrong, so '
            'import-based conclusions (including crypto API use) can be incomplete.')
_SECTIONS = ('Section data damaged: code and data in the affected sections may be missing or misplaced, so '
             'functions, strings and references there are incomplete or unreliable.')
_HEADERS = 'Headers unusable: no reliable static analysis is possible; any stored facts for this file are unreliable.'
IMPACT = {
    'import_descriptors_unterminated': _IMPORTS, 'import_descriptor_truncated': _IMPORTS, 'import_directory': _IMPORTS,
    'import_dll_name': _IMPORTS, 'import_name': _IMPORTS, 'import_thunks': _IMPORTS,
    'import_thunks_truncated': _IMPORTS, 'import_thunks_unterminated': _IMPORTS,
    'section_beyond_eof': _SECTIONS, 'section_count': _SECTIONS, 'section_overlap': _SECTIONS,
    'section_raw_offset': _SECTIONS, 'section_virtual_range': _SECTIONS, 'section_truncated': _SECTIONS,
    'data_directories': 'Data directories damaged: imports, exports or resources may be unreadable.',
    'entry_point': 'Entry point invalid: start-up code cannot be located reliably.',
    'file_alignment': 'Non-standard alignment: the loaded layout may differ from file offsets.',
    'section_alignment': 'Non-standard alignment: the loaded layout may differ from file offsets.',
    'not_executable_image': 'Not marked as an executable image: a loader may refuse it; runtime layout is uncertain.',
    'unknown_machine': 'Unknown CPU type: disassembly may be wrong or missing.',
}
LEVEL_TEXT = {
    'full': 'Full static analysis is possible.',
    'partial': 'Partial static analysis only: the loadable parts were analyzed, but some evidence is missing or unreliable.',
    'none': 'No reliable static analysis is possible.',
    'unverified': 'The structural condition could not be verified, so completeness of the stored evidence is unknown.',
}


def _unverified(reason, **extra):
    return {'status': 'unverified', 'reason': reason, 'issues': [], 'impacts': [], 'summary': LEVEL_TEXT['unverified'],
            **extra}


def assess(binary):
    """Structural condition for a stored binary record (dict with path, sha256, format)."""
    path = Path(binary.get('path') or '')
    if not binary.get('path') or not path.is_file():
        return _unverified('The original file is not available at its stored path.')
    try:
        size = path.stat().st_size
        if not 0 < size <= MAX_BYTES:
            return _unverified('The original file size is outside the 32 MiB validation limit.')
        data = path.read_bytes()
    except OSError as exc:
        return _unverified(f'The original file could not be read ({type(exc).__name__}).')
    if hashlib.sha256(data).hexdigest() != (binary.get('sha256') or '').lower():
        return _unverified('The file at the stored path differs from the analyzed file (SHA-256 mismatch).')
    if data.startswith(b'\x7fELF'):
        from aire.api.binary_library import inspect_binary
        try:
            report = inspect_binary(path)
        except ValueError as exc:
            return {'status': 'none', 'format': 'ELF', 'issues': [{'severity': 'fatal', 'code': 'elf_headers',
                                                                    'message': str(exc)[:200], 'offset': None}],
                    'impacts': [_HEADERS], 'summary': 'ELF headers are invalid; ' + LEVEL_TEXT['none'].lower(),
                    'size': size}
        return {'status': 'full', 'format': 'ELF', 'architecture': report['architecture'], 'bits': report['bits'],
                'issues': [], 'impacts': [], 'summary': 'Valid ELF headers. ' + LEVEL_TEXT['full'], 'size': size,
                'is_dll': None, 'unnamed_import_groups': []}
    report = validate_pe(data).to_dict()
    issues = [i for i in report['issues']]
    impacts = list(dict.fromkeys(_HEADERS if i['severity'] == 'fatal' else IMPACT.get(i['code'], '')
                                 for i in issues if i['severity'] != 'info'))
    unnamed = [{'descriptor': name, 'functions': len(functions)}
               for name, functions in (report.get('imports') or {}).items() if name.startswith('<invalid')]
    return {'status': report['analysis'], 'format': report['format'] or 'unknown',
            'architecture': report['architecture'], 'bits': report['bits'], 'is_dll': report['is_dll'],
            'issues': issues, 'impacts': [i for i in impacts if i], 'summary': report['summary'], 'size': size,
            'unnamed_import_groups': unnamed}
