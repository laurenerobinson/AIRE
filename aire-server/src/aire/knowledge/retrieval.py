"""M3 deterministic queries over persisted CALL facts. No semantic retrieval.

All public queries read one SQLite snapshot through the store's transaction
helper. The store owns its connection/lifecycle; do not close it during queries.
Only CALL edges participate. No warnings are parsed into inferred relationships.
"""
from collections import deque
from contextlib import contextmanager
from dataclasses import fields
import re
import sqlite3

from aire.knowledge.database import BinaryKnowledgeStore, BinaryNotFoundError, KnowledgeStoreError
from aire.knowledge.graph import CallPath, CallRelationship, FunctionRelationshipSummary, TraversalNode
from aire.knowledge.models import FunctionRecord, ReferenceRecord, ThunkRecord

MAX_DEPTH = 64
_METRICS = ('unique_callers', 'unique_callees', 'incoming_callsites', 'outgoing_callsites')
_FUNCTION_FIELDS = tuple(f.name for f in fields(FunctionRecord))


class QueryError(KnowledgeStoreError):
    """A relationship query could not complete."""


class FunctionNotFoundError(QueryError):
    """No exact function match exists in the requested binary."""


class AmbiguousFunctionError(QueryError):
    """Several exact matches exist; use an explicit ID or address."""
    def __init__(self, selector, matches):
        self.matches = matches
        details = ', '.join(f'{f.address} ({f.function_id})' for f in matches)
        super().__init__(f'Ambiguous function {selector!r}: {details}')


class BinaryMismatchError(QueryError):
    """A supplied function belongs to a different binary."""


def _address_key(address):
    """Sort hex offsets numerically within address space; preserve original text."""
    space, separator, offset = address.rpartition(':')
    if not separator:
        space, offset = '', address
    if re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]+', offset):
        return (space, 0, int(offset, 16), address)
    return (space, 1, 0, address)


def _function_key(function):
    return (_address_key(function.address), function.function_id)


def _depth(value):
    if type(value) is not int or not 0 <= value <= MAX_DEPTH:
        raise ValueError(f'max_depth must be an integer between 0 and {MAX_DEPTH}')


def _record(row):
    values = {name: row[name] for name in _FUNCTION_FIELDS}
    for name in ('is_external', 'is_thunk', 'is_library', 'assembly_truncated'):
        if values[name] is not None:
            if values[name] not in (0, 1):
                raise QueryError(f'Invalid persisted boolean: {name}')
            values[name] = bool(values[name])
    return FunctionRecord(**values)


class ProgramQueryService:
    """Exact, binary-scoped queries. No ProgramIndex loads or persistent cache.

    Strings match ID, exact stored address, or exact current_name. Use
    resolve_function(..., by='name'/'address'/'id') to disambiguate selector kinds.
    FunctionRecord inputs are resolved again by ID; stale caller fields are ignored.
    """
    def __init__(self, store: BinaryKnowledgeStore):
        self.store = store

    @contextmanager
    def _snapshot(self, binary_id):
        try:
            with self.store._transaction() as db:
                if db.execute('SELECT 1 FROM binaries WHERE binary_id = ?', (binary_id,)).fetchone() is None:
                    raise BinaryNotFoundError(f'No stored analysis for binary_id {binary_id!r}')
                yield db
        except sqlite3.Error as exc:
            raise QueryError(f'Relationship query failed: {exc}') from exc

    def _matches(self, db, binary_id, selector, by):
        if by not in ('auto', 'id', 'address', 'name'):
            raise ValueError('by must be auto, id, address, or name')
        if isinstance(selector, FunctionRecord):
            if selector.binary_id != binary_id:
                raise BinaryMismatchError(f'Function {selector.function_id!r} belongs to {selector.binary_id!r}')
            selector, by = selector.function_id, 'id'
        if not isinstance(selector, str) or not selector:
            raise ValueError('function selector must be a nonempty string or FunctionRecord')
        predicates = {'id': 'function_id = ?', 'address': 'address = ?', 'name': 'current_name = ?',
                      'auto': '(function_id = ? OR address = ? OR current_name = ?)'}
        parameters = (binary_id,) + (selector,) * (3 if by == 'auto' else 1)
        rows = db.execute(f'SELECT * FROM functions WHERE binary_id = ? AND {predicates[by]}', parameters)
        matches = sorted((_record(row) for row in rows), key=_function_key)
        if by in ('auto', 'id'):
            owner = db.execute('SELECT binary_id FROM functions WHERE function_id = ?', (selector,)).fetchone()
            if owner is not None and owner['binary_id'] != binary_id:
                raise BinaryMismatchError(f'Function {selector!r} belongs to {owner["binary_id"]!r}')
        return matches

    def _resolve(self, db, binary_id, selector, by='auto'):
        matches = self._matches(db, binary_id, selector, by)
        if not matches:
            raise FunctionNotFoundError(f'Unknown function {selector!r} in binary {binary_id!r}')
        if len(matches) > 1:
            raise AmbiguousFunctionError(selector, matches)
        return matches[0]

    def find_functions(self, binary_id: str, value: str, *, by='auto') -> list[FunctionRecord]:
        """All exact matches, ordered by address/ID; unknown values return []."""
        with self._snapshot(binary_id) as db:
            return self._matches(db, binary_id, value, by)

    def resolve_function(self, binary_id: str, function, *, by='auto') -> FunctionRecord:
        with self._snapshot(binary_id) as db:
            return self._resolve(db, binary_id, function, by)

    def _relationships(self, db, binary_id, function, reverse, cache):
        endpoint = 'callee_function_id' if reverse else 'caller_function_id'
        rows = db.execute(
            f'''SELECT DISTINCT caller_function_id, callee_function_id, callsite_address, edge_type
                FROM function_edges WHERE binary_id = ? AND {endpoint} = ? AND edge_type = ?''',
            (binary_id, function.function_id, 'CALL'))
        relationships = []
        for row in rows:
            ends = []
            for key in ('caller_function_id', 'callee_function_id'):
                identity = row[key]
                if identity not in cache:
                    item = db.execute('SELECT * FROM functions WHERE binary_id = ? AND function_id = ?',
                                      (binary_id, identity)).fetchone()
                    if item is None:
                        raise QueryError(f'Stored edge references missing function {identity!r}')
                    cache[identity] = _record(item)
                ends.append(cache[identity])
            relationships.append(CallRelationship(*ends, row['callsite_address'], row['edge_type']))
        relationships.sort(key=lambda r: (
            _function_key(r.caller if reverse else r.callee),
            _address_key(r.callsite_address), r.caller.function_id, r.callee.function_id, r.edge_type))
        return relationships

    def get_callers(self, binary_id: str, function) -> list[CallRelationship]:
        with self._snapshot(binary_id) as db:
            target = self._resolve(db, binary_id, function)
            return self._relationships(db, binary_id, target, True, {target.function_id: target})

    def get_callees(self, binary_id: str, function) -> list[CallRelationship]:
        with self._snapshot(binary_id) as db:
            source = self._resolve(db, binary_id, function)
            return self._relationships(db, binary_id, source, False, {source.function_id: source})

    @staticmethod
    def _reference_rows(db, binary_id, predicate, identity):
        from aire.knowledge.investigation import reference_record
        version = db.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0]
        if version == '1':
            return []  # Legacy analyses contain no persisted reference facts.
        result = []
        for row in db.execute(f'SELECT * FROM binary_references WHERE binary_id = ? AND {predicate} = ? '
                              'ORDER BY ordinal', (binary_id, identity)):
            try:
                record = reference_record(row)
            except ValueError as exc:
                raise QueryError(str(exc)) from exc
            if predicate == 'target_function_id' and record.target_function_id != identity:
                continue  # Legacy computed-jump destinations do not resolve functions.
            result.append(record)
        return result

    def get_function_references(self, binary_id: str, function) -> list[ReferenceRecord]:
        """Observed outgoing references; computed calls remain explicitly marked."""
        with self._snapshot(binary_id) as db:
            source = self._resolve(db, binary_id, function)
            return self._reference_rows(db, binary_id, 'source_function_id', source.function_id)

    def get_function_referrers(self, binary_id: str, function) -> list[ReferenceRecord]:
        """References to an exact entry; computed calls do not assert a target."""
        with self._snapshot(binary_id) as db:
            target = self._resolve(db, binary_id, function)
            return self._reference_rows(db, binary_id, 'target_function_id', target.function_id)

    def get_artifact_references(self, binary_id: str, artifact_id: str) -> list[ReferenceRecord]:
        with self._snapshot(binary_id) as db:
            if db.execute('SELECT 1 FROM artifacts WHERE binary_id = ? AND artifact_id = ?',
                          (binary_id, artifact_id)).fetchone() is None:
                raise QueryError(f'Unknown artifact {artifact_id!r} in binary {binary_id!r}')
            return self._reference_rows(db, binary_id, 'target_artifact_id', artifact_id)

    def get_thunk_bindings(self, binary_id: str, function) -> list[ThunkRecord]:
        """Immediate Ghidra bindings from this thunk; never synthesized CALL edges."""
        with self._snapshot(binary_id) as db:
            source = self._resolve(db, binary_id, function)
            version = db.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0]
            if version == '1':
                return []
            result = []
            for row in db.execute('SELECT * FROM thunk_relations WHERE binary_id = ? AND thunk_function_id = ? '
                                  'ORDER BY ordinal', (binary_id, source.function_id)):
                values = {field.name: row[field.name] for field in fields(ThunkRecord)}
                if values['is_direct_jump'] not in (0, 1):
                    raise QueryError('Invalid persisted thunk boolean')
                values['is_direct_jump'] = bool(values['is_direct_jump'])
                result.append(ThunkRecord(**values))
            return result

    def get_callsites(self, binary_id: str, source, target) -> list[CallRelationship]:
        """Exact stored CALL relationships connecting two resolved functions."""
        with self._snapshot(binary_id) as db:
            caller = self._resolve(db, binary_id, source)
            callee = self._resolve(db, binary_id, target)
            cache = {f.function_id: f for f in (caller, callee)}
            return [edge for edge in self._relationships(db, binary_id, caller, False, cache)
                    if edge.callee.function_id == callee.function_id]

    def _walk(self, db, binary_id, start, max_depth, reverse=False, target=None):
        cache = {start.function_id: start}
        seen = {start.function_id}
        queue = deque([(start, 0)])
        nodes = []
        while queue:
            parent, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._relationships(db, binary_id, parent, reverse, cache):
                function = edge.caller if reverse else edge.callee
                if function.function_id in seen:
                    continue
                seen.add(function.function_id)
                nodes.append(TraversalNode(function, depth + 1, parent.function_id, edge))
                if function.function_id == target:
                    return nodes
                queue.append((function, depth + 1))
        return nodes

    def get_reachable(self, binary_id: str, start_function, *, max_depth=3) -> list[TraversalNode]:
        """BFS discovery order; excludes start. One shortest-path predecessor per node."""
        _depth(max_depth)
        with self._snapshot(binary_id) as db:
            start = self._resolve(db, binary_id, start_function)
            return self._walk(db, binary_id, start, max_depth)

    def get_reverse_reachable(self, binary_id: str, start_function, *, max_depth=3) -> list[TraversalNode]:
        """Predecessor is toward start; edge still records the original CALL direction."""
        _depth(max_depth)
        with self._snapshot(binary_id) as db:
            start = self._resolve(db, binary_id, start_function)
            return self._walk(db, binary_id, start, max_depth, reverse=True)

    def find_call_path(self, binary_id: str, source_function, target_function, *, max_depth=3) -> CallPath | None:
        """A deterministic shortest path, or None if none is found within max_depth.

        Source==target yields a zero-hop path. None makes no global reachability claim.
        """
        _depth(max_depth)
        with self._snapshot(binary_id) as db:
            source = self._resolve(db, binary_id, source_function)
            target = self._resolve(db, binary_id, target_function)
            if source.function_id == target.function_id:
                return CallPath([source], [])
            nodes = self._walk(db, binary_id, source, max_depth, target=target.function_id)
            parents = {node.function.function_id: node for node in nodes}
            if target.function_id not in parents:
                return None
            functions, edges = [target], []
            current = target.function_id
            while current != source.function_id:
                node = parents[current]
                edges.append(node.edge)
                functions.append(node.edge.caller)
                current = node.predecessor
            return CallPath(list(reversed(functions)), list(reversed(edges)))

    def get_summary(self, binary_id: str, function) -> FunctionRelationshipSummary:
        with self._snapshot(binary_id) as db:
            target = self._resolve(db, binary_id, function)
            counts = []
            for endpoint, other in [('callee_function_id', 'caller_function_id'),
                                    ('caller_function_id', 'callee_function_id')]:
                row = db.execute(
                    f'''SELECT count(DISTINCT {other}) AS neighbors,
                               count(DISTINCT callsite_address) AS sites
                        FROM function_edges WHERE binary_id = ? AND {endpoint} = ? AND edge_type = ?''',
                    (binary_id, target.function_id, 'CALL')).fetchone()
                counts.extend((row['neighbors'], row['sites']))
            return FunctionRelationshipSummary(target, *counts)

    def rank_functions(self, binary_id: str, *, metric='unique_callers', limit=10) -> list[FunctionRelationshipSummary]:
        """Descending connectivity count; address/ID break ties. Includes zero-degree nodes.

        Callsites count distinct stored addresses per endpoint; exact duplicate
        rows are not additional callsites. No behavioral importance is inferred.
        """
        if metric not in _METRICS:
            raise ValueError(f'metric must be one of {_METRICS}')
        if type(limit) is not int or limit < 1:
            raise ValueError('limit must be a positive integer')
        with self._snapshot(binary_id) as db:
            # Aggregate only IDs/addresses/counts, then load full records for the top N.
            rows = db.execute('''
                WITH incoming AS (
                    SELECT callee_function_id AS id, count(DISTINCT caller_function_id) AS neighbors,
                           count(DISTINCT callsite_address) AS sites
                    FROM function_edges WHERE binary_id = ? AND edge_type = ? GROUP BY callee_function_id
                ), outgoing AS (
                    SELECT caller_function_id AS id, count(DISTINCT callee_function_id) AS neighbors,
                           count(DISTINCT callsite_address) AS sites
                    FROM function_edges WHERE binary_id = ? AND edge_type = ? GROUP BY caller_function_id
                )
                SELECT f.function_id, f.address,
                       coalesce(i.neighbors, 0) AS unique_callers, coalesce(i.sites, 0) AS incoming_callsites,
                       coalesce(o.neighbors, 0) AS unique_callees, coalesce(o.sites, 0) AS outgoing_callsites
                FROM functions f LEFT JOIN incoming i ON i.id = f.function_id
                                 LEFT JOIN outgoing o ON o.id = f.function_id
                WHERE f.binary_id = ?''', (binary_id, 'CALL', binary_id, 'CALL', binary_id)).fetchall()
            rows.sort(key=lambda r: (-r[metric], _address_key(r['address']), r['function_id']))
            return [FunctionRelationshipSummary(
                self._resolve(db, binary_id, r['function_id'], 'id'),
                r['unique_callers'], r['incoming_callsites'], r['unique_callees'], r['outgoing_callsites'])
                for r in rows[:limit]]
