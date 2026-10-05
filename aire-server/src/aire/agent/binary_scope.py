"""Resolve a user-facing binary selector to one persisted A.I.R.E. analysis."""
import hashlib
from pathlib import Path


def resolve_binary(store, value):
    binaries = store.list_binaries()
    exact = [binary for binary in binaries if binary.binary_id == value]
    if exact:
        return exact[0]
    path = Path(value).expanduser()
    if path.is_file():
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        matches = [binary for binary in binaries if binary.sha256 == digest.hexdigest()]
    else:
        matches = [binary for binary in binaries
                   if binary.program_name == value or Path(binary.path).name == value]
    if len(matches) != 1:
        raise ValueError(
            'Binary must identify one stored analysis by ID, matching file hash, or unique name; index it first')
    return matches[0]
