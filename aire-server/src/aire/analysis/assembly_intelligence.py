"""M10 service layer: function facts + context from the read-only store.

Every result carries binary identity, function identity/address, the evidence
source ('ghidra_pcode' or the lower-confidence 'assembly_text' fallback) and
explicit coverage limits (truncation, missing facts). No model is involved.
"""
from aire.analysis.decompiler_crossval import crossvalidate
from aire.analysis import flow_analysis
from aire.analysis.instruction_semantics import FunctionContext, analyze_function, legacy_document
from aire.knowledge.retrieval import ProgramQueryService

DEFAULT_WINDOW = 64
MAX_WINDOW = 400


class AssemblyIntelligence:
    def __init__(self, store, binary_id):
        self.store, self.binary_id = store, binary_id
        self.query = ProgramQueryService(store)
        self._names = None
        self._documents = {}

    def function_names(self):
        if self._names is None:
            self._names = {row[0]: row[1] for row in self.store._db.execute(
                'SELECT address, current_name FROM functions WHERE binary_id=?', (self.binary_id,))}
        return self._names

    def binary_identity(self):
        row = self.store._db.execute('SELECT program_name, sha256, format, architecture FROM binaries WHERE binary_id=?',
                                     (self.binary_id,)).fetchone()
        return {'binary_id': self.binary_id, 'name': row[0], 'sha256': row[1], 'format': row[2],
                'architecture': row[3]} if row else {'binary_id': self.binary_id}

    def resolve(self, selector):
        return self.query.resolve_function(self.binary_id, selector)

    def document(self, record):
        """(document, source). Fallback parses stored assembly text."""
        if record.function_id in self._documents:
            return self._documents[record.function_id]
        document = self.store.load_function_ir(self.binary_id, record.function_id)
        if document is None:
            architecture = self.binary_identity().get('architecture') or ''
            document = legacy_document(record.assembly, architecture)
        self._documents[record.function_id] = document
        return document

    def references(self, record):
        result = {}
        for source, kind, value, target, rtype in self.store._db.execute(
                'SELECT r.source_address, a.type, a.value, r.target_address, r.reference_type '
                'FROM binary_references r LEFT JOIN artifacts a ON a.artifact_id = r.target_artifact_id '
                'WHERE r.binary_id=? AND r.source_function_id=? ORDER BY r.ordinal', (self.binary_id, record.function_id)):
            if kind is not None:
                result.setdefault(source, []).append({'kind': kind, 'value': value, 'target': target,
                                                      'reference_type': rtype})
        return result

    def context(self, record, document):
        names = self.function_names()

        def callee_return(address):
            row = self.store._db.execute('SELECT function_id, is_external FROM functions WHERE binary_id=? AND address=?',
                                         (self.binary_id, address)).fetchone()
            if row is None or row[1]:
                return None
            callee = self.store.load_function_ir(self.binary_id, row[0])
            storage = (callee or {}).get('signature', {}).get('return', {})
            if storage.get('type') in (None, 'void'):
                return None
            return f"{storage['storage']} (Ghidra-recovered {storage['type']}; signature source " \
                   f"{callee['signature'].get('signature_source')})"
        return FunctionContext(names, self.references(record), callee_return, document.get('language') or '')

    def function_header(self, record, document):
        return {
            'binary': self.binary_identity(),
            'function': {'function_id': record.function_id, 'name': record.current_name, 'address': record.address,
                         'signature': record.signature, 'is_thunk': record.is_thunk, 'is_external': record.is_external},
            'evidence_source': 'ghidra_pcode' if document.get('source') == 'ghidra' else 'assembly_text',
            'coverage': {
                'instructions': len(document.get('instructions', [])),
                'instruction_count': record.instruction_count,
                'truncated': document.get('truncated'),
                'blocks': len(document.get('blocks', [])),
                'note': None if document.get('source') == 'ghidra' else
                'Snapshot predates M10 structured facts; explanations are parsed from stored assembly text '
                '(no P-code, no blocks). Re-analyze the binary for full evidence.',
            },
            'signature_storage': document.get('signature') or None,
        }

    def explain(self, selector, start=None, limit=DEFAULT_WINDOW):
        record = self.resolve(selector)
        document = self.document(record)
        limit = max(1, min(int(limit or DEFAULT_WINDOW), MAX_WINDOW))
        records = analyze_function(document, self.context(record, document), start=start, limit=limit)
        total = len(document.get('instructions', []))
        return {**self.function_header(record, document), 'instructions': records,
                'window': {'start': records[0]['address'] if records else None, 'returned': len(records),
                           'total': total, 'more': bool(records) and records[-1]['address'] != (
                               document['instructions'][-1]['a'] if total else None)}}

    def semantics(self, record, document):
        """Whole-function semantic records (cached per function)."""
        key = ('semantics', record.function_id)
        if key not in self._documents:
            self._documents[key] = analyze_function(document, self.context(record, document))
        return self._documents[key]

    def crossvalidate(self, selector):
        from aire.analysis.function_crosscheck import FunctionCrossCheckService
        record = self.resolve(selector)
        document = self.document(record)
        try:
            arithmetic = FunctionCrossCheckService(self.store).analyze_function(self.binary_id, record.function_id)
        except Exception:
            arithmetic = None
        report = crossvalidate(record, document, self.semantics(record, document),
                               self.context(record, document), arithmetic)
        return {**self.function_header(record, document), 'crossvalidation': report}

    # ------------------------------------------------------------ Phase 3
    def _full(self, selector):
        record = self.resolve(selector)
        document = self.document(record)
        return record, document, self.semantics(record, document)

    def cfg(self, selector):
        record, document, semantics = self._full(selector)
        graph = flow_analysis.control_flow_graph(document)
        branches = {r['address']: r for r in semantics if r['category'] == 'branch_conditional'}
        for block in graph['blocks']:
            last = next((r for r in reversed(semantics) if int(block['start'], 16) <= int(r['address'], 16)
                         <= int(block['end'], 16)), None)
            if last is not None and last['address'] in branches:
                relation = (last['branch'].get('relation') or {}).get('text')
                block['branch'] = {'address': last['address'], 'text': last['text'],
                                   'condition': relation or last['branch'].get('predicate')}
        return {**self.function_header(record, document), 'cfg': graph}

    def branch(self, selector, address):
        record, document, semantics = self._full(selector)
        return {**self.function_header(record, document),
                'paths': flow_analysis.branch_paths(document, semantics, address.lower().removeprefix('0x').zfill(8))}

    def trace(self, selector, address, location):
        record, document, semantics = self._full(selector)
        address = address.lower().removeprefix('0x').zfill(8)
        return {**self.function_header(record, document),
                'trace': flow_analysis.trace_value(document, semantics, address, location),
                'limits': f'Intra-procedural reaching definitions over register families and frame-pointer stack '
                          f'slots; depth <= {flow_analysis.MAX_TRACE_DEPTH}; memory through other pointers is not tracked.'}

    def parameters(self, selector):
        record, document, semantics = self._full(selector)
        return {**self.function_header(record, document),
                'parameter_use': flow_analysis.parameter_use(document, semantics),
                'ghidra_signature': document.get('signature')}

    def return_usage(self, selector, limit=12):
        record = self.resolve(selector)
        document = self.document(record)
        callers = []
        rows = self.store._db.execute(
            'SELECT caller_function_id, callsite_address FROM function_edges WHERE binary_id=? AND callee_function_id=? '
            'ORDER BY ordinal', (self.binary_id, record.function_id)).fetchall()
        thunks = [r[0] for r in self.store._db.execute(
            'SELECT thunk_function_id FROM thunk_relations WHERE binary_id=? AND target_function_id=?',
            (self.binary_id, record.function_id))]
        for thunk in thunks:  # calls usually go through a thunk
            rows += self.store._db.execute('SELECT caller_function_id, callsite_address FROM function_edges '
                                           'WHERE binary_id=? AND callee_function_id=? ORDER BY ordinal',
                                           (self.binary_id, thunk)).fetchall()
        for caller_id, callsite in rows[:limit]:
            caller = self.resolve(caller_id)
            caller_doc = self.document(caller)
            usage = flow_analysis.return_usage_at_callsite(caller_doc, self.semantics(caller, caller_doc), callsite)
            callers.append({'caller': caller.current_name, 'caller_address': caller.address, **usage})
        return {**self.function_header(record, document), 'callsites': callers,
                'truncated': len(rows) > limit, 'total_callsites': len(rows),
                'return_storage': (document.get('signature') or {}).get('return')}

    def function_evidence(self, selector):
        """Deterministic summary evidence for 'what does this function do?'."""
        record, document, semantics = self._full(selector)
        graph = flow_analysis.control_flow_graph(document)
        calls = [{'address': r['address'], 'target': r['call']['target'], 'name': r['call']['target_name'],
                  'indirect': bool(r['call'].get('indirect')), 'tail': r['category'] == 'tail_call'}
                 for r in semantics if r['category'] in ('call', 'tail_call')]
        strings = [{'address': r['address'], 'value': ref['value']} for r in semantics for ref in r['references']
                   if ref['kind'] == 'STRING']
        branches = [{'address': r['address'], 'text': r['text'],
                     'condition': (r['branch'].get('relation') or {}).get('text') or r['branch'].get('predicate'),
                     'target': r['branch']['target']} for r in semantics if r['category'] == 'branch_conditional']
        stores = [{'address': r['address'], 'text': r['text'], 'target': r['writes']['memory']}
                  for r in semantics if r['writes']['memory'] and r['writes']['memory'].get('kind') not in ('frame', 'stack')]
        returns = [r['address'] for r in semantics if r['category'] == 'return']
        callers = self.query.callers(self.binary_id, record.function_id, limit=20) \
            if hasattr(self.query, 'callers') else None
        return {**self.function_header(record, document),
                'calls': calls[:40], 'strings': strings[:20], 'conditional_branches': branches[:40],
                'loops': graph['loops'], 'non_stack_memory_writes': stores[:20], 'returns': returns,
                'parameter_use': flow_analysis.parameter_use(document, semantics),
                'block_count': len(graph['blocks']), 'unreachable_blocks': graph['unreachable_blocks']}
