"""M4: select persisted evidence, bound text, preserve provenance. No AI calls."""
from dataclasses import replace
import json
import time

from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.evidence import (
    ArtifactEvidence, EdgeEvidence, EvidenceBundle, EvidenceRequest, FunctionEvidence,
    FunctionReference, Provenance, Truncation, WarningEvidence, ReferenceEvidence, ThunkEvidence, render_bundle,
)
from aire.knowledge.models import ArtifactRecord, FunctionEdge, ThunkRecord
from aire.knowledge.retrieval import ProgramQueryService, _address_key, _function_key
from aire.knowledge.investigation import InvestigationService, reference_record, thunk_item


def _edge_key(edge):
    return (edge.caller.function_id, edge.callee.function_id, edge.callsite_address, edge.edge_type)


def _limit(bundle, category, items, count):
    if len(items) > count:
        bundle.truncations.append(Truncation(category, f'max_{category}', count, len(items), count))
    return items[:count]


def _text_limit(bundle, text, count, category, source_id):
    if text is not None and len(text) > count:
        bundle.truncations.append(Truncation(category, 'per-item text limit', count, len(text), count, source_id))
        return text[:count]
    return text


class ContextBuilder:
    """Build a deterministic evidence snapshot using M3's exact graph algorithms.

    Shares M3's internal snapshot/resolution/relationship/walk helpers so one build
    sees a single SQLite snapshot without changing M1–M3 or nesting transactions.
    The caller owns the store, on its creating thread. No executable is accessed.
    """
    def __init__(self, store: BinaryKnowledgeStore):
        self.store = store
        self.query = ProgramQueryService(store)

    def build(self, request: EvidenceRequest) -> EvidenceBundle:
        if not isinstance(request, EvidenceRequest):
            raise TypeError('request must be EvidenceRequest')
        started = time.perf_counter()
        with self.query._snapshot(request.binary_id) as db:
            binary = self.store._binary_record(db.execute(
                'SELECT * FROM binaries WHERE binary_id = ?', (request.binary_id,)).fetchone())
            bundle = EvidenceBundle(binary, request.summary())
            bundle.provenance.append(Provenance('binaries', binary.binary_id, binary.binary_id,
                                                 binary.image_base, 'requested binary metadata'))
            tick = time.perf_counter()
            target = self.query._resolve(db, request.binary_id, request.target, request.target_by) if request.target is not None else None
            timings = {'target_resolution_seconds': time.perf_counter() - tick}
            bundle.metadata.update({
                'schema_version': 1,
                'resolved_target_id': target.function_id if target is not None else None,
                'artifact_linkage': 'Function-local only with exact stored reference provenance; other artifacts remain binary-level',
                'warning_policy': 'Only global Import:/Analysis: diagnostics; no inferred function association',
                'ordering': 'target; direct edges; callers; callees; shallow traversal; address-associated artifacts; binary artifacts',
            })
            tick = time.perf_counter()
            functions, edges = self._graph(db, request, target)
            for _, depth, record, reason in _limit(bundle, 'functions', functions, request.max_functions):
                copied = replace(record,
                    decompiled_text=_text_limit(bundle, record.decompiled_text,
                        request.max_decompiled_chars_per_function, 'decompiled_text', record.function_id)
                        if request.include_decompiled_text else None,
                    assembly=_text_limit(bundle, record.assembly, request.max_assembly_chars_per_function,
                        'assembly', record.function_id) if request.include_assembly else None)
                if request.include_assembly and record.assembly_truncated:
                    bundle.truncations.append(Truncation('assembly', 'already truncated by M1 indexer',
                                                        None, None, len(copied.assembly or ''), record.function_id))
                provenance = Provenance('functions', record.function_id, binary.binary_id, record.address,
                                        reason, (target.function_id,) if target else (), depth)
                bundle.functions.append(FunctionEvidence(copied, reason, depth, provenance))
                bundle.provenance.append(provenance)
            for _, depth, relationship, reason in _limit(bundle, 'edges', edges, request.max_edges):
                identity = json.dumps(_edge_key(relationship), separators=(',', ':'))
                provenance = Provenance('function_edges', identity, binary.binary_id,
                                        relationship.callsite_address, reason,
                                        (relationship.caller.function_id, relationship.callee.function_id), depth)
                def reference(function):
                    return FunctionReference(function.function_id, function.address, function.current_name)
                bundle.edges.append(EdgeEvidence(FunctionEdge(*_edge_key(relationship)),
                    reference(relationship.caller), reference(relationship.callee), reason, depth, provenance))
                bundle.provenance.append(provenance)
            timings['graph_selection_seconds'] = time.perf_counter() - tick
            tick = time.perf_counter()
            self._references(db, request, bundle)
            self._artifacts(db, request, bundle)
            timings['artifact_selection_seconds'] = time.perf_counter() - tick
            self._warnings(db, request, bundle)
        tick = time.perf_counter()
        render_bundle(bundle)
        timings['rendering_seconds'] = time.perf_counter() - tick
        timings['total_context_seconds'] = time.perf_counter() - started
        bundle.metadata['timings'] = timings
        return bundle

    def _graph(self, db, request, target):
        functions, edges = {}, {}
        if target is None:
            return [], []
        def add_function(record, priority, depth, reason):
            if record.function_id == target.function_id and not request.include_function:
                return
            candidate = (priority, depth, record, reason)
            previous = functions.get(record.function_id)
            if previous is None or (priority, depth, reason) < (previous[0], previous[1], previous[3]):
                functions[record.function_id] = candidate
        def add_edge(edge, priority, depth, reason):
            key = _edge_key(edge)
            previous = edges.get(key)
            if previous is None or (priority, depth, reason) < (previous[0], previous[1], previous[3]):
                edges[key] = (priority, depth, edge, reason)
        if request.include_function:
            add_function(target, 0, 0, 'target function')
        cache = {target.function_id: target}
        if request.max_depth:
            for enabled, reverse, priority, reason in (
                (request.include_callers, True, 2, 'direct caller of target'),
                (request.include_callees, False, 3, 'direct callee of target')):
                if enabled:
                    for edge in self.query._relationships(db, request.binary_id, target, reverse, cache):
                        add_function(edge.caller if reverse else edge.callee, priority, 1, reason)
                        add_edge(edge, 1, 1, reason + '; exact stored callsite')
            for direction, reverse in (('forward', False), ('reverse', True)):
                if request.traversal_direction in (direction, 'both'):
                    for node in self.query._walk(db, request.binary_id, target, request.max_depth, reverse):
                        reason = f'{direction} reachable at depth {node.depth}'
                        add_function(node.function, 4, node.depth, reason)
                        add_edge(node.edge, 1 if node.depth == 1 else 4, node.depth,
                                 reason + '; exact stored predecessor edge')
        function_list = sorted(functions.values(), key=lambda x: (x[0], x[1], _function_key(x[2]), x[3]))
        edge_list = sorted(edges.values(), key=lambda x: (
            x[0], x[1], _function_key(x[2].caller), _function_key(x[2].callee),
            _address_key(x[2].callsite_address), x[2].edge_type))
        return function_list, edge_list

    def _references(self, db, request, bundle):
        coverage = InvestigationService.coverage(db, request.binary_id)
        bundle.metadata['reference_coverage'] = coverage
        identities = [f.function.function_id for f in bundle.functions]
        if coverage['schema_version'] < 2 or not identities:
            return
        placeholders = ','.join('?' for _ in identities)
        params = (request.binary_id, *identities)
        # Bound materialized rows independently from function and artifact caps.
        if request.include_references:
            predicate = f' FROM binary_references WHERE binary_id=? AND source_function_id IN ({placeholders})'
            total = db.execute('SELECT count(*)' + predicate, params).fetchone()[0]
            # Selected target's data/string evidence precedes graph-neighbor references.
            rows = db.execute('SELECT *' + predicate +
                ' ORDER BY (source_function_id=? ) DESC,is_call,source_address,target_address,reference_id LIMIT ?',
                (*params, bundle.metadata.get('resolved_target_id'), request.max_references)).fetchall()
            for row in rows:
                record = reference_record(row)
                record.source_instruction = _text_limit(bundle, record.source_instruction, 200, 'reference_instruction', record.reference_id)
                p = Provenance('binary_references', record.reference_id, request.binary_id, record.source_address,
                    'observed Ghidra reference; computed calls do not resolve a target function',
                    tuple(i for i in (record.source_function_id, record.target_function_id) if i))
                bundle.references.append(ReferenceEvidence(record, p))
                bundle.provenance.append(p)
            if total > len(rows):
                bundle.truncations.append(Truncation('references', 'max_references', request.max_references, total, len(rows)))
        if request.include_thunks:
            predicate = f' FROM thunk_relations WHERE binary_id=? AND (thunk_function_id IN ({placeholders}) OR target_function_id IN ({placeholders}))'
            args = (*params, *identities)
            total = db.execute('SELECT count(*)' + predicate, args).fetchone()[0]
            rows = db.execute('SELECT *' + predicate + ' ORDER BY source_address,target_address LIMIT ?',
                              (*args, request.max_thunks)).fetchall()
            for row in rows:
                record = ThunkRecord(**{k: row[k] for k in ThunkRecord.__dataclass_fields__})
                record.is_direct_jump = bool(record.is_direct_jump)
                record.source_instruction = _text_limit(bundle, record.source_instruction, 200, 'thunk_instruction', record.thunk_function_id)
                p = Provenance('thunk_relations', thunk_item(request.binary_id, record)['provenance']['source_id'],
                    request.binary_id, record.source_address, 'Ghidra immediate thunk binding; direct JMP verification is a separate flag',
                    (record.thunk_function_id, record.target_function_id))
                bundle.thunks.append(ThunkEvidence(record, p))
                bundle.provenance.append(p)
            if total > len(rows):
                bundle.truncations.append(Truncation('thunks', 'max_thunks', request.max_thunks, total, len(rows)))

    def _artifacts(self, db, request, bundle):
        kinds = [kind for kind, enabled in [('STRING', request.include_strings),
                 ('IMPORT', request.include_imports), ('EXPORT', request.include_exports)] if enabled]
        if not kinds:
            return
        placeholders = ','.join('?' for _ in kinds)
        rows = db.execute(f'''SELECT artifact_id, type, address
                              FROM artifacts WHERE binary_id = ? AND type IN ({placeholders})''',
                          (request.binary_id, *kinds)).fetchall()
        externals = {item.function.address: item.function.function_id for item in bundle.functions
                     if item.function.is_external}
        local = {}
        for item in bundle.references:
            ref = item.reference
            if ref.target_artifact_id and not ref.is_indirect and not ref.is_call:
                local.setdefault(ref.target_artifact_id, []).append(ref)
        def associated(row):
            return row['type'] == 'IMPORT' and row['address'] in externals
        rows.sort(key=lambda row: (0 if row['artifact_id'] in local else 1 if associated(row) else 2,
            ('STRING', 'IMPORT', 'EXPORT').index(row['type']), _address_key(row['address'] or ''), row['artifact_id']))
        for row in _limit(bundle, 'artifacts', rows, request.max_artifacts):
            # Measure in Python: SQLite length(TEXT)/substr stop at embedded NULs.
            original = db.execute('SELECT value FROM artifacts WHERE binary_id = ? AND artifact_id = ?',
                                  (request.binary_id, row['artifact_id'])).fetchone()[0]
            value = _text_limit(bundle, original, request.max_total_chars, 'artifact_value', row['artifact_id'])
            linked = associated(row)
            refs = local.get(row['artifact_id'], []) if row['type'] == 'STRING' else []
            reason = ('exact string reference(s): ' + ', '.join(r.reference_id for r in refs) if refs else
                'import symbol at selected external function address' if linked else 'requested binary-level ' + row['type'])
            provenance = Provenance('artifacts', row['artifact_id'], request.binary_id, row['address'], reason,
                                    tuple(dict.fromkeys(r.source_function_id for r in refs)) if refs else
                                    (externals[row['address']],) if linked else ())
            bundle.artifacts.append(ArtifactEvidence(
                ArtifactRecord(row['artifact_id'], request.binary_id, row['type'], row['address'], value),
                reason, 'function-reference' if refs else 'external-address-match' if linked else 'binary', provenance))
            bundle.provenance.append(provenance)

    def _warnings(self, db, request, bundle):
        total = db.execute('SELECT count(*) FROM warnings WHERE binary_id = ?', (request.binary_id,)).fetchone()[0]
        if request.include_warnings:
            rows = db.execute('''SELECT ordinal, warning_text FROM warnings WHERE binary_id = ?
                                 AND (substr(warning_text, 1, 7) = ? OR substr(warning_text, 1, 9) = ?)
                                 ORDER BY ordinal LIMIT ?''',
                              (request.binary_id, 'Import:', 'Analysis:', request.max_warnings))
            for row in rows:
                identity = f'{request.binary_id}:warning:{row["ordinal"]}'
                text = _text_limit(bundle, row['warning_text'], request.max_warning_chars, 'warning_text', identity)
                provenance = Provenance('warnings', identity, request.binary_id, None,
                                        'persisted global loader/analysis diagnostic; no function association')
                bundle.warnings.append(WarningEvidence(text, row['ordinal'], provenance))
                bundle.provenance.append(provenance)
        omitted = total - len(bundle.warnings)
        bundle.metadata['omitted_warning_count'] = omitted
        if omitted:
            bundle.truncations.append(Truncation('warnings',
                'unassociated warnings omitted; global warnings bounded by request',
                request.max_warnings, total, len(bundle.warnings)))
