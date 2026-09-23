"""M5 binary overview policy, layered on M4 without changing targeted selection."""
from dataclasses import replace
from aire.ai.context_builder import ContextBuilder, _edge_key
from aire.knowledge.evidence import Truncation
from aire.knowledge.retrieval import _address_key, _function_key

OVERVIEW_POLICY = ('Binary overview: up to two stored CALL roots first, then internal non-thunk '
                   'functions by distinct callers+callees, address/ID ties; bounded graph context. '
                   'Artifacts have STRING/IMPORT/EXPORT quotas. No semantic relevance is inferred.')
TARGET_POLICY = 'Explicit exact target through M4; bounded direct neighbors and optional forward traversal.'


class OverviewContextBuilder(ContextBuilder):
    """Use M4's one read snapshot, bounds, provenance, warnings and rendering.

    Lightweight graph rows are inspected for ordering, but only bounded seed
    records/bodies are loaded. Roots describe stored CALLs, not executable entry.
    """
    def _graph(self, db, request, target):
        if target is not None:
            return super()._graph(db, request, target)
        rows = db.execute('''
            SELECT f.function_id, f.address,
              (SELECT count(DISTINCT e.caller_function_id) FROM function_edges e
               WHERE e.binary_id=f.binary_id AND e.callee_function_id=f.function_id
                 AND e.edge_type='CALL') AS incoming,
              (SELECT count(DISTINCT e.callee_function_id) FROM function_edges e
               WHERE e.binary_id=f.binary_id AND e.caller_function_id=f.function_id
                 AND e.edge_type='CALL') AS outgoing
            FROM functions f WHERE f.binary_id=? AND f.is_external=0 AND f.is_thunk=0
            ''', (request.binary_id,)).fetchall()
        ranked = sorted(rows, key=lambda r: (-(r['incoming'] + r['outgoing']),
                                               _address_key(r['address']), r['function_id']))
        roots = [r for r in ranked if r['incoming'] == 0][:2]
        ordered = roots + [r for r in ranked if r not in roots]
        # At most half the function budget is reserved for seeds, leaving neighbors room.
        seeds = ordered[:max(1, request.max_functions // 2)]
        functions, edges = {}, {}
        for rank, row in enumerate(seeds):
            record = self.query._resolve(db, request.binary_id, row['function_id'], 'id')
            fs, es = super()._graph(db, replace(request, target=record), record)
            for priority, depth, function, reason in fs:
                candidate = (0 if function.function_id == record.function_id else priority + 1,
                             depth, function, 'overview: ' + reason)
                old = functions.get(function.function_id)
                if old is None or (candidate[0], depth) < (old[0], old[1]):
                    functions[function.function_id] = candidate
            functions[record.function_id] = (0, 0, record, f'overview seed {rank + 1}: stored root/connectivity policy')
            for priority, depth, edge, reason in es:
                edges.setdefault(_edge_key(edge), (priority, depth, edge, 'overview: ' + reason))
        self._overview_counts = (len(rows), len(seeds))
        return (sorted(functions.values(), key=lambda x: (x[0], x[1], _function_key(x[2]))),
                sorted(edges.values(), key=lambda x: (x[0], x[1], _function_key(x[2].caller),
                                                     _address_key(x[2].callsite_address), _function_key(x[2].callee))))

    def _artifacts(self, db, request, bundle):
        if request.target is not None:
            return super()._artifacts(db, request, bundle)
        for i, kind in enumerate(('STRING', 'IMPORT', 'EXPORT')):
            quota = request.max_artifacts // 3 + (i < request.max_artifacts % 3)
            super()._artifacts(db, replace(request, max_artifacts=quota,
                include_strings=kind == 'STRING', include_imports=kind == 'IMPORT',
                include_exports=kind == 'EXPORT'), bundle)
        total, seeds = self._overview_counts
        selected = sum(not f.function.is_external and not f.function.is_thunk for f in bundle.functions)
        if total > selected:
            bundle.truncations.append(Truncation('overview_functions',
                'bounded root/connectivity selection; not complete binary coverage',
                request.max_functions, total, selected))
        bundle.metadata.update(selection_policy=OVERVIEW_POLICY, overview_seed_count=seeds)
