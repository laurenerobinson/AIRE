"""Application-focused M5 overview policy; exact targeted M4 stays separate."""
from dataclasses import replace
from aire.ai.context_builder import ContextBuilder
from aire.knowledge.application_relevance import (
    ApplicationRelevanceService, ELIGIBLE, RELEVANCE_POLICY_VERSION,
)
from aire.knowledge.evidence import Truncation
from aire.knowledge.graph import CallRelationship
from aire.knowledge.models import FunctionRecord
from aire.knowledge.retrieval import _address_key

OVERVIEW_POLICY = (RELEVANCE_POLICY_VERSION + ': deterministic likely application logic; '
    'exact application entries, bounded runtime-bridge traversal and metadata/graph relevance. '
    'Runtime/external/thunk evidence is demoted. Scores are heuristics, not authorship or '
    'behavior proof. Only resolved stored CALLs are emitted as edges. '
    'Artifacts have STRING/IMPORT/EXPORT quotas; only exact stored references link strings to functions.')
TARGET_POLICY = 'Explicit exact target through M4; bounded direct neighbors and optional forward traversal.'


def overview_code_excerpt(text, limit, *, head_fraction=.5):
    """Keep declarations and final operations under the existing text budget."""
    if text is None or len(text) <= limit:
        return text
    marker = '\n/* A.I.R.E. excerpt: middle omitted */\n'
    if limit <= len(marker):
        return text[:limit]
    available = limit - len(marker)
    head = int(available * head_fraction)
    return text[:head] + marker + text[-(available - head):]


class OverviewContextBuilder(ContextBuilder):
    """Rank metadata in one snapshot; load only bounded selected bodies.

    Optional seed hints never override runtime classification. Explicit targeted
    requests continue through the original ContextBuilder without relevance.
    """
    def __init__(self, store, *, seed_functions=()):
        super().__init__(store)
        self.seed_functions = tuple(dict.fromkeys(seed_functions))[:2]

    def _graph(self, db, request, target):
        if target is not None:
            return super()._graph(db, request, target)
        snapshot = ApplicationRelevanceService(self.store)._rank(db, request.binary_id)
        ranked = snapshot.items
        hinted = [r for i in self.seed_functions for r in ranked
                  if r.function['function_id'] == i and r.classification in ELIGIBLE]
        ordered = hinted + [r for r in ranked if r not in hinted]
        selected = ordered[:request.max_functions] if request.include_function else []
        positions = {r.function['function_id']: n for n, r in enumerate(ordered)}
        selected_ids = {r.function['function_id'] for r in selected}
        by_id = {r.function['function_id']: r for r in ranked}
        functions = []
        self._code_truncations = []
        for n, row in enumerate(selected):
            record = self.query._resolve(db, request.binary_id, row.function['function_id'], 'id')
            for field, enabled, limit, head in (
                ('decompiled_text', request.include_decompiled_text, request.max_decompiled_chars_per_function, .5),
                ('assembly', request.include_assembly, request.max_assembly_chars_per_function, .25),
            ):
                text = getattr(record, field)
                if enabled and text and len(text) > limit:
                    self._code_truncations.append(Truncation(field,
                        'overview declaration/tail excerpt; middle omitted', limit,
                        len(text), limit, record.function_id))
                    record = replace(record, **{field: overview_code_excerpt(text, limit, head_fraction=head)})
            reason = f'overview relevance {row.classification}, score {row.score}; see application_relevance metadata'
            functions.append((n, 0, record, reason))
        candidates = [e for e in snapshot.edges if request.max_depth and
            ((request.include_callees and e['caller_function_id'] in selected_ids) or
             (request.include_callers and e['callee_function_id'] in selected_ids))]
        candidates.sort(key=lambda e: (
            0 if e['caller_function_id'] in selected_ids else 1,
            positions[e['caller_function_id']] if e['caller_function_id'] in selected_ids
                else positions[e['callee_function_id']],
            by_id[e['callee_function_id']].classification not in ELIGIBLE,
            positions[e['callee_function_id']], _address_key(e['callsite_address'])))
        def endpoint(identity):
            f = by_id[identity].function
            return FunctionRecord(identity, request.binary_id, f['address'], f['current_name'],
                None, None, None, f['instruction_count'], f['basic_block_count'], f['branch_count'],
                bool(f['is_external']), bool(f['is_thunk']), namespace=f['namespace'])
        edges = [(n, 1, CallRelationship(endpoint(e['caller_function_id']),
                  endpoint(e['callee_function_id']), e['callsite_address'], 'CALL'),
                  'overview selected function; exact stored CALL callsite')
                 for n, e in enumerate(candidates[:request.max_edges])]
        self._overview = (snapshot, selected, len(candidates))
        return functions, edges

    def _artifacts(self, db, request, bundle):
        if request.target is not None:
            return super()._artifacts(db, request, bundle)
        for i, kind in enumerate(('STRING', 'IMPORT', 'EXPORT')):
            quota = request.max_artifacts // 3 + (i < request.max_artifacts % 3)
            super()._artifacts(db, replace(request, max_artifacts=quota,
                include_strings=request.include_strings and kind == 'STRING',
                include_imports=request.include_imports and kind == 'IMPORT',
                include_exports=request.include_exports and kind == 'EXPORT'), bundle)
        snapshot, selected, edge_count = self._overview
        bundle.truncations.extend(self._code_truncations)
        if len(snapshot.items) > len(selected):
            bundle.truncations.append(Truncation('overview_functions',
                'bounded application relevance selection; not complete binary coverage',
                request.max_functions, len(snapshot.items), len(selected)))
        if edge_count > len(bundle.edges):
            bundle.truncations.append(Truncation('edges', 'max_edges', request.max_edges,
                                                  edge_count, len(bundle.edges)))
        bundle.metadata.update(selection_policy=OVERVIEW_POLICY,
            selection_policy_version=RELEVANCE_POLICY_VERSION,
            overview_seed_count=min(2, len(selected)),
            application_relevance=[r.to_dict() for r in selected],
            relevance_diagnostics=snapshot.diagnostics,
            priority_function_ids=[r.function['function_id'] for r in selected[:3]])
