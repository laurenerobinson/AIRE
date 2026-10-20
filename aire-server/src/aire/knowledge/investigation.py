"""Read-only investigation views over v1/v2 snapshots; no JVM or target access."""
from dataclasses import asdict, fields
import json

from aire.knowledge.application_relevance import classify
from aire.knowledge.models import ArtifactRecord, ReferenceRecord, ThunkRecord
from aire.knowledge.retrieval import ProgramQueryService

INVESTIGATION_POLICY_VERSION = 'investigation-v1'


def provenance(binary_id, table, identity, address, **extra):
    return dict(binary_id=binary_id, source_table=table, source_id=identity,
                address=address, **extra)


def reference_record(row):
    values = {f.name: row[f.name] for f in fields(ReferenceRecord)}
    for name in ('is_call', 'is_indirect', 'is_read'):
        if values[name] not in (0, 1):
            raise ValueError('Invalid reference boolean: ' + name)
        values[name] = bool(values[name])
    # Old format-v1 snapshots may have asserted entry targets for computed JMPs.
    # Read-only views conservatively normalize them without rewriting history.
    if 'COMPUTED' in values['reference_type'].upper():
        values['is_indirect'] = True
    if values['is_indirect']:
        values['target_function_id'] = None
    return ReferenceRecord(**values)


def reference_item(record):
    return {'reference': asdict(record), 'provenance': provenance(
        record.binary_id, 'binary_references', record.reference_id, record.source_address,
        origin='GHIDRA_REFERENCE', target_address=record.target_address),
        'resolution': ('UNRESOLVED_COMPUTED_CALL' if record.is_call else 'UNRESOLVED_COMPUTED_FLOW')
                      if record.is_indirect else 'OBSERVED_REFERENCE'}


def thunk_item(binary_id, record):
    # Canonical composite identity: thunk_relations has no independent ID column.
    identity = json.dumps([record.thunk_function_id, record.target_function_id,
                           record.source_address, record.target_address], separators=(',', ':'))
    return {'binding': asdict(record), 'provenance': provenance(
        binary_id, 'thunk_relations', identity, record.source_address,
        origin='GHIDRA_THUNK_BINDING'),
        'relationship': 'VERIFIED_DIRECT_JUMP' if record.is_direct_jump else 'GHIDRA_THUNK_BINDING'}


class InvestigationService:
    """Paged exact relationships. CALL graph APIs retain their original semantics."""
    def __init__(self, store):
        self.query = ProgramQueryService(store)

    @staticmethod
    def _bounds(limit, offset):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('limit must be an integer from 1 to 100')
        if type(offset) is not int or not 0 <= offset <= 1000000:
            raise ValueError('offset must be an integer from 0 to 1000000')

    @staticmethod
    def coverage(db, binary_id):
        version = db.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0]
        row = db.execute("SELECT value FROM analysis_metadata WHERE binary_id=? AND key='reference_facts_version'",
                         (binary_id,)).fetchone()
        return {'schema_version': int(version), 'reference_facts_version': json.loads(row[0]) if row and version != '1' else None,
                'scope': 'Stored static facts only; empty results do not prove absence. Legacy snapshots require fresh indexing.'}

    def references(self, binary_id, function, *, direction='outgoing', strings_only=False, limit=20, offset=0):
        self._bounds(limit, offset)
        if direction not in ('outgoing', 'incoming'):
            raise ValueError('direction must be outgoing or incoming')
        if type(strings_only) is not bool or (strings_only and direction != 'outgoing'):
            raise ValueError('strings_only requires outgoing references')
        with self.query._snapshot(binary_id) as db:
            selected = self.query._resolve(db, binary_id, function)
            coverage = self.coverage(db, binary_id)
            items, total = [], 0
            if coverage['schema_version'] >= 2:
                column = 'source_function_id' if direction == 'outgoing' else 'target_function_id'
                join = (' JOIN artifacts a ON a.binary_id=r.binary_id AND a.artifact_id=r.target_artifact_id'
                        " AND a.type='STRING'" if strings_only else '')
                predicate = f' FROM binary_references r{join} WHERE r.binary_id=? AND r.{column}=?'
                if strings_only:
                    predicate += " AND r.is_call=0 AND r.is_indirect=0 AND r.reference_type NOT LIKE '%COMPUTED%'"
                elif direction == 'incoming':
                    predicate += " AND r.is_indirect=0 AND r.reference_type NOT LIKE '%COMPUTED%'"
                params = (binary_id, selected.function_id)
                total = db.execute('SELECT count(*)' + predicate, params).fetchone()[0]
                extra = ', a.artifact_id,a.type,a.address,a.value' if strings_only else ''
                rows = db.execute('SELECT r.*' + extra + predicate +
                    ' ORDER BY r.source_address,r.target_address,r.reference_type,r.operand_index,r.reference_id LIMIT ? OFFSET ?',
                    (*params, limit, offset)).fetchall()
                for row in rows:
                    item = reference_item(reference_record(row))
                    if strings_only:
                        item['artifact'] = asdict(ArtifactRecord(row['artifact_id'], binary_id, row['type'], row['address'], row['value']))
                        item['artifact_provenance'] = provenance(binary_id, 'artifacts', row['artifact_id'], row['address'])
                    items.append(item)
        return {'function_id': selected.function_id, 'direction': direction, 'items': items,
                'observed_count': total, 'offset': offset, 'has_more': offset + len(items) < total,
                'omitted_count': total - len(items), 'coverage': coverage}

    def thunk_chain(self, binary_id, function, *, max_depth=8):
        if type(max_depth) is not int or not 0 <= max_depth <= 16:
            raise ValueError('max_depth must be an integer from 0 to 16')
        with self.query._snapshot(binary_id) as db:
            current = self.query._resolve(db, binary_id, function)
            coverage = self.coverage(db, binary_id)
            seen, hops = {current.function_id}, []
            status = 'LEGACY_NO_REFERENCE_FACTS'
            if coverage['schema_version'] >= 2:
                while True:
                    rows = db.execute('SELECT * FROM thunk_relations WHERE binary_id=? AND thunk_function_id=? '
                                      'ORDER BY ordinal LIMIT 2', (binary_id, current.function_id)).fetchall()
                    if not rows:
                        status = 'UNRESOLVED_THUNK' if current.is_thunk else 'TERMINAL_FUNCTION'
                        break
                    if len(rows) > 1:
                        status = 'AMBIGUOUS_BINDING'
                        break
                    if len(hops) >= max_depth:
                        status = 'DEPTH_LIMIT'
                        break
                    values = {f.name: rows[0][f.name] for f in fields(ThunkRecord)}
                    values['is_direct_jump'] = bool(values['is_direct_jump'])
                    record = ThunkRecord(**values)
                    hops.append(thunk_item(binary_id, record))
                    if record.target_function_id in seen:
                        status = 'CYCLE'
                        break
                    seen.add(record.target_function_id)
                    current = self.query._resolve(db, binary_id, record.target_function_id, 'id')
        return {'hops': hops, 'status': status, 'terminal_function_id': current.function_id if status == 'TERMINAL_FUNCTION' else None,
                'max_depth': max_depth, 'coverage': coverage,
                'scope': 'Immediate stored Ghidra bindings, with direct JMP verification separately labeled. No CALL edges are synthesized.'}

    def classification(self, binary_id, function):
        with self.query._snapshot(binary_id) as db:
            selected = self.query._resolve(db, binary_id, function)
            category, reason = classify(asdict(selected))
            binary = db.execute('SELECT entry_point FROM binaries WHERE binary_id=?', (binary_id,)).fetchone()
            artifacts = db.execute("SELECT artifact_id,type,address FROM artifacts WHERE binary_id=? AND address=? AND type IN ('IMPORT','EXPORT') ORDER BY artifact_id",
                                   (binary_id, selected.address)).fetchall()
        return {'category': category, 'reason': reason, 'derived': True,
                'stored_is_library': selected.is_library,
                'is_entry_point': selected.address == binary['entry_point'] or any(a['type'] == 'EXPORT' for a in artifacts),
                'entry_point_scope': 'Loader external entry/export address; does not establish main or execution order',
                'is_import': selected.is_external and any(a['type'] == 'IMPORT' for a in artifacts),
                'sources': [provenance(binary_id, 'functions', selected.function_id, selected.address)] +
                    ([provenance(binary_id, 'binaries', binary_id, binary['entry_point'])]
                     if selected.address == binary['entry_point'] else []) +
                    [provenance(binary_id, 'artifacts', a['artifact_id'], a['address']) for a in artifacts],
                'scope': 'Conservative symbol/flag heuristic; unknown internal functions remain eligible. Not proof of source authorship.'}
