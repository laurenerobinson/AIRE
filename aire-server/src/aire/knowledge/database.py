"""SQLite persistence of complete ProgramIndex snapshots, without Ghidra imports.

Instances own one connection and must be used on their creating thread. M2 is
intended for a single-process/single-writer workflow. Each save/delete commits
independently; a store context manager closes the connection, not a transaction.
"""
from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime
import json
from pathlib import Path
import sqlite3

from aire.knowledge.models import (
    ArtifactRecord, BinaryRecord, FunctionEdge, FunctionRecord, ProgramIndex,
)

SCHEMA_VERSION = 1


class KnowledgeStoreError(RuntimeError):
    """Base error for storage operations, including use after close."""


class DatabaseOpenError(KnowledgeStoreError):
    """The database or its parent directory cannot be opened/created."""


class UnsupportedSchemaError(KnowledgeStoreError):
    """The database has an absent, malformed, or unsupported schema version."""


class BinaryNotFoundError(KnowledgeStoreError):
    """No stored analysis has the requested binary_id."""


class PersistedDataError(KnowledgeStoreError):
    """Stored data cannot be reconstructed reliably."""


class TransactionError(KnowledgeStoreError):
    """A write failed; the transaction was rolled back."""


_SCHEMA = (
    '''CREATE TABLE schema_metadata (
        key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
    )''',
    '''CREATE TABLE binaries (
        binary_id TEXT PRIMARY KEY NOT NULL,
        path TEXT NOT NULL, sha256 TEXT NOT NULL, format TEXT, architecture TEXT,
        image_base TEXT NOT NULL, analyzed_at TEXT, compiler_spec TEXT,
        endianness TEXT, pointer_size INTEGER, entry_point TEXT,
        executable_size INTEGER, program_name TEXT
    )''',
    '''CREATE TABLE functions (
        function_id TEXT PRIMARY KEY NOT NULL,
        binary_id TEXT NOT NULL REFERENCES binaries(binary_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        address TEXT NOT NULL, current_name TEXT NOT NULL, signature TEXT,
        decompiled_text TEXT, assembly TEXT, instruction_count INTEGER,
        basic_block_count INTEGER, branch_count INTEGER,
        is_external INTEGER NOT NULL CHECK (is_external IN (0, 1)),
        is_thunk INTEGER NOT NULL CHECK (is_thunk IN (0, 1)),
        is_library INTEGER CHECK (is_library IN (0, 1)),
        namespace TEXT, calling_convention TEXT,
        assembly_truncated INTEGER NOT NULL CHECK (assembly_truncated IN (0, 1)),
        UNIQUE (binary_id, ordinal), UNIQUE (binary_id, function_id)
    )''',
    '''CREATE TABLE artifacts (
        artifact_id TEXT PRIMARY KEY NOT NULL,
        binary_id TEXT NOT NULL REFERENCES binaries(binary_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        type TEXT NOT NULL, address TEXT, value TEXT NOT NULL,
        UNIQUE (binary_id, ordinal)
    )''',
    '''CREATE TABLE function_edges (
        binary_id TEXT NOT NULL REFERENCES binaries(binary_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        caller_function_id TEXT NOT NULL, callee_function_id TEXT NOT NULL,
        callsite_address TEXT NOT NULL, edge_type TEXT NOT NULL,
        PRIMARY KEY (binary_id, ordinal),
        FOREIGN KEY (binary_id, caller_function_id)
            REFERENCES functions(binary_id, function_id) ON DELETE CASCADE,
        FOREIGN KEY (binary_id, callee_function_id)
            REFERENCES functions(binary_id, function_id) ON DELETE CASCADE
    )''',
    '''CREATE TABLE warnings (
        id INTEGER PRIMARY KEY,
        binary_id TEXT NOT NULL REFERENCES binaries(binary_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0), warning_text TEXT NOT NULL,
        UNIQUE (binary_id, ordinal)
    )''',
    '''CREATE TABLE analysis_metadata (
        binary_id TEXT NOT NULL REFERENCES binaries(binary_id) ON DELETE CASCADE,
        key TEXT NOT NULL, value TEXT NOT NULL,
        PRIMARY KEY (binary_id, key)
    )''',
    'CREATE INDEX functions_address_idx ON functions(address)',
    'CREATE INDEX functions_name_idx ON functions(current_name)',
    'CREATE INDEX artifacts_type_idx ON artifacts(type)',
    'CREATE INDEX artifacts_value_idx ON artifacts(value)',
    'CREATE INDEX edges_caller_idx ON function_edges(caller_function_id)',
    'CREATE INDEX edges_callee_idx ON function_edges(callee_function_id)',
)

# SQL identifiers below come exclusively from these internal dataclass mappings,
# never caller values. Ordinal-bearing UNIQUE/PRIMARY KEY indexes cover binary_id.
_COLUMNS = {
    'binaries': tuple(f.name for f in fields(BinaryRecord)),
    'functions': tuple(f.name for f in fields(FunctionRecord)),
    'artifacts': tuple(f.name for f in fields(ArtifactRecord)),
    'function_edges': tuple(f.name for f in fields(FunctionEdge)),
}
_BOOLEAN_FIELDS = ('is_external', 'is_thunk', 'is_library', 'assembly_truncated')


def _reject_json_constant(value):
    raise ValueError(f'Non-finite JSON number: {value}')


class BinaryKnowledgeStore:
    """Open and initialize schema v1; missing loads raise BinaryNotFoundError.

    Paths are database paths only. This class never opens/deletes executable
    paths stored in BinaryRecord. Metadata reloads as M1's JSON-safe values.
    """

    def __init__(self, db_path: Path | str):
        self.path = Path(db_path).expanduser()
        self._connection = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.path), isolation_level=None)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute('PRAGMA foreign_keys = ON')
            if self._connection.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
                raise sqlite3.DatabaseError('Cannot enable foreign keys')
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise DatabaseOpenError(f'Cannot open database {self.path}: {exc}') from exc
        try:
            self.initialize()
        except BaseException:
            self.close()
            raise

    @property
    def _db(self):
        if self._connection is None:
            raise KnowledgeStoreError('BinaryKnowledgeStore is closed')
        return self._connection

    @contextmanager
    def _transaction(self, write=False):
        db = self._db
        db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise

    def initialize(self) -> None:
        """Create an empty schema atomically, or validate v1 without migrating."""
        try:
            with self._transaction(write=True) as db:
                tables = {row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*'"
                )}
                if not tables:
                    for statement in _SCHEMA:
                        db.execute(statement)
                    db.execute('INSERT INTO schema_metadata(key, value) VALUES (?, ?)',
                               ('schema_version', str(SCHEMA_VERSION)))
                else:
                    if 'schema_metadata' not in tables:
                        raise UnsupportedSchemaError('Existing database has no A.I.R.E. schema version')
                    version = db.execute(
                        'SELECT value FROM schema_metadata WHERE key = ?', ('schema_version',)
                    ).fetchone()
                    if version is None or version[0] != str(SCHEMA_VERSION):
                        found = None if version is None else version[0]
                        raise UnsupportedSchemaError(
                            f'Unsupported schema version {found!r}; expected {SCHEMA_VERSION}')
                for table, columns in _COLUMNS.items():
                    extra = () if table == 'binaries' else ('ordinal',)
                    if table == 'function_edges':
                        extra += ('binary_id',)
                    db.execute(f'SELECT {", ".join(columns + extra)} FROM {table} LIMIT 0')
                db.execute('SELECT id, binary_id, ordinal, warning_text FROM warnings LIMIT 0')
                db.execute('SELECT binary_id, key, value FROM analysis_metadata LIMIT 0')
        except sqlite3.Error as exc:
            raise UnsupportedSchemaError(f'Cannot initialize/validate schema in {self.path}: {exc}') from exc

    def save_program_index(self, program_index: ProgramIndex) -> None:
        """Replace all facts for one binary atomically, preserving list order.

        A conflicting ID owned by another binary, invalid edge, duplicate record
        ID, or insertion failure rolls back deletion as well as all insertions.
        """
        self._db
        try:
            data = program_index.to_dict()
            binary = data['binary']
            identity = binary['binary_id']
            for kind in ('functions', 'artifacts'):
                if any(record['binary_id'] != identity for record in data[kind]):
                    raise ValueError(f'{kind} contain a different binary_id')
            metadata = [(identity, key, json.dumps(value, ensure_ascii=True, allow_nan=False))
                        for key, value in data['metadata'].items()]
            with self._transaction(write=True) as db:
                db.execute('DELETE FROM binaries WHERE binary_id = ?', (identity,))
                columns = _COLUMNS['binaries']
                db.execute(self._insert_sql('binaries', columns), tuple(binary[c] for c in columns))
                for table in ('functions', 'artifacts'):
                    columns = _COLUMNS[table] + ('ordinal',)
                    db.executemany(self._insert_sql(table, columns),
                                   (tuple(record[c] for c in _COLUMNS[table]) + (ordinal,)
                                    for ordinal, record in enumerate(data[table])))
                columns = _COLUMNS['function_edges'] + ('binary_id', 'ordinal')
                db.executemany(self._insert_sql('function_edges', columns),
                               (tuple(edge[c] for c in _COLUMNS['function_edges']) + (identity, ordinal)
                                for ordinal, edge in enumerate(data['function_edges'])))
                db.executemany('INSERT INTO warnings(binary_id, ordinal, warning_text) VALUES (?, ?, ?)',
                               ((identity, ordinal, warning) for ordinal, warning in enumerate(data['warnings'])))
                db.executemany('INSERT INTO analysis_metadata(binary_id, key, value) VALUES (?, ?, ?)', metadata)
        except (sqlite3.Error, TypeError, ValueError, KeyError, AttributeError) as exc:
            raise TransactionError(f'Cannot save ProgramIndex; no changes committed: {exc}') from exc

    @staticmethod
    def _insert_sql(table, columns):
        return f'INSERT INTO {table} ({", ".join(columns)}) VALUES ({", ".join("?" for _ in columns)})'

    @staticmethod
    def _binary_record(row):
        values = dict(row)
        if values['analyzed_at'] is not None:
            values['analyzed_at'] = datetime.fromisoformat(values['analyzed_at'])
        return BinaryRecord(**values)

    def load_program_index(self, binary_id: str) -> ProgramIndex:
        """Load one consistent snapshot, restoring datetime and bool fields."""
        try:
            with self._transaction() as db:
                row = db.execute('SELECT * FROM binaries WHERE binary_id = ?', (binary_id,)).fetchone()
                if row is None:
                    raise BinaryNotFoundError(f'No stored analysis for binary_id {binary_id!r}')
                binary = self._binary_record(row)
                records = {}
                for table, cls in [('functions', FunctionRecord), ('artifacts', ArtifactRecord),
                                   ('function_edges', FunctionEdge)]:
                    rows = db.execute(f'SELECT * FROM {table} WHERE binary_id = ? ORDER BY ordinal', (binary_id,))
                    records[table] = []
                    for ordinal, item in enumerate(rows):
                        if item['ordinal'] != ordinal:
                            raise ValueError(f'Non-contiguous {table} ordering')
                        values = {name: item[name] for name in _COLUMNS[table]}
                        if table == 'functions':
                            for name in _BOOLEAN_FIELDS:
                                if values[name] is not None:
                                    if values[name] not in (0, 1):
                                        raise ValueError(f'Invalid persisted boolean: {name}')
                                    values[name] = bool(values[name])
                        records[table].append(cls(**values))
                warnings = []
                for ordinal, item in enumerate(db.execute(
                    'SELECT ordinal, warning_text FROM warnings WHERE binary_id = ? ORDER BY ordinal', (binary_id,)
                )):
                    if item['ordinal'] != ordinal:
                        raise ValueError('Non-contiguous warning ordering')
                    warnings.append(item['warning_text'])
                metadata = {}
                for item in db.execute('SELECT key, value FROM analysis_metadata WHERE binary_id = ?', (binary_id,)):
                    try:
                        metadata[item['key']] = json.loads(item['value'], parse_constant=_reject_json_constant)
                    except (TypeError, ValueError) as exc:
                        raise ValueError(f'Malformed metadata JSON for key {item["key"]!r}: {exc}') from exc
                known = {function.function_id for function in records['functions']}
                if any(edge.caller_function_id not in known or edge.callee_function_id not in known
                       for edge in records['function_edges']):
                    raise ValueError('Stored call edge references a missing function')
                return ProgramIndex(binary, records['functions'], records['artifacts'],
                                    records['function_edges'], warnings, metadata)
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistedDataError(f'Cannot load analysis {binary_id!r}: {exc}') from exc

    def has_binary(self, binary_id: str) -> bool:
        try:
            return self._db.execute('SELECT 1 FROM binaries WHERE binary_id = ?', (binary_id,)).fetchone() is not None
        except sqlite3.Error as exc:
            raise KnowledgeStoreError(f'Cannot check binary: {exc}') from exc

    def list_binaries(self) -> list[BinaryRecord]:
        """Return only binary metadata, ordered by ID; never fetch function text."""
        try:
            return [self._binary_record(row) for row in self._db.execute('SELECT * FROM binaries ORDER BY binary_id')]
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistedDataError(f'Cannot list binaries: {exc}') from exc

    def delete_binary(self, binary_id: str) -> bool:
        """Delete database rows only; return whether an analysis existed."""
        try:
            with self._transaction(write=True) as db:
                return db.execute('DELETE FROM binaries WHERE binary_id = ?', (binary_id,)).rowcount > 0
        except sqlite3.Error as exc:
            raise TransactionError(f'Cannot delete analysis {binary_id!r}: {exc}') from exc

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self):
        self._db
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
