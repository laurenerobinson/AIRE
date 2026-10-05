"""Validated read-only tools; binary scope is supplied by the application."""
from dataclasses import asdict, dataclass, is_dataclass
from copy import deepcopy
import json
import re

from aire.ai.context_builder import ContextBuilder
from aire.ai.evidence_selector import OverviewContextBuilder
from aire.knowledge.evidence import EvidenceRequest
from aire.knowledge.models import _json_safe
from aire.knowledge.retrieval import ProgramQueryService, _record
from aire.security.rule_engine import RuleEngine


def serializable(value):
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        value = {key: serializable(item) for key, item in value.items()}
    elif isinstance(value, (list, tuple)):
        value = [serializable(item) for item in value]
    return _json_safe(value)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict
    execute: object


class ToolRegistry:
    """Only trusted application tools may be registered; no model code runs."""
    def __init__(self):
        self._tools = {}

    def register(self, tool):
        if (not isinstance(tool, Tool) or not isinstance(tool.name, str)
                or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', tool.name) or not callable(tool.execute)):
            raise ValueError('Expected a named callable Tool')
        if type(tool.parameters) is not dict:
            raise ValueError('Tool parameters must be an object')
        for spec in tool.parameters.values():
            if type(spec) is not dict or spec.get('type') not in ('string', 'integer'):
                raise ValueError('Tool parameters support string and bounded integer types')
            if spec['type'] == 'integer' and (type(spec.get('minimum')) is not int
                    or type(spec.get('maximum')) is not int or spec['minimum'] > spec['maximum']):
                raise ValueError('Integer parameters require valid bounds')
        if tool.name in self._tools:
            raise ValueError('Duplicate tool: ' + tool.name)
        self._tools[tool.name] = Tool(tool.name, tool.description, deepcopy(tool.parameters), tool.execute)

    def catalog(self):
        return [{'name': t.name, 'description': t.description, 'parameters': deepcopy(t.parameters)}
                for t in self._tools.values()]

    def run(self, name, arguments):
        if not isinstance(name, str) or name not in self._tools:
            return {'ok': False, 'tool': name if isinstance(name, str) else None,
                    'error': {'code': 'unknown_tool', 'message': 'Unknown tool'}}
        tool = self._tools[name]
        try:
            if type(arguments) is not dict:
                raise ValueError('arguments must be an object')
            if set(arguments) - set(tool.parameters):
                raise ValueError('Unexpected arguments')
            values = {}
            for key, spec in tool.parameters.items():
                if key not in arguments and 'default' not in spec:
                    raise ValueError('Missing argument: ' + key)
                value = arguments.get(key, spec.get('default'))
                kind = {'string': str, 'integer': int}[spec['type']]
                if value is None and spec.get('nullable'):
                    values[key] = value
                    continue
                if type(value) is not kind:
                    raise ValueError(key + ' has invalid type')
                if kind is str and not 0 < len(value) <= 500:
                    raise ValueError(key + ' must contain 1–500 characters')
                if kind is int and not spec['minimum'] <= value <= spec['maximum']:
                    raise ValueError(key + ' is outside allowed bounds')
                if 'enum' in spec and value not in spec['enum']:
                    raise ValueError(key + ' has invalid value')
                values[key] = value
        except (ValueError, TypeError) as exc:
            return {'ok': False, 'tool': name, 'error': {'code': 'invalid_arguments', 'message': str(exc)}}
        try:
            data = serializable(tool.execute(**values))
            if len(json.dumps(data, ensure_ascii=True, allow_nan=False)) > 100000:
                return {'ok': False, 'tool': name, 'error': {'code': 'result_limit',
                        'message': 'Result exceeds serialization budget; request a smaller limit'}}
            return {'ok': True, 'tool': name, 'data': data}
        except Exception as exc:
            return {'ok': False, 'tool': name, 'error': {'code': type(exc).__name__,
                    'message': str(exc)[:500]}}


def _integer(default, maximum, minimum=1):
    return {'type': 'integer', 'default': default, 'minimum': minimum, 'maximum': maximum}


SELECTOR = {'type': 'string'}


class AgentTools:
    """M2/M3 queries, M4/M5 evidence, M7 rules. Never expose store mutations.

    Existing M3 snapshot helpers also let metadata lists avoid loading every body.
    Results retain stored IDs, addresses, callsites, and explicit source tables.
    """
    def __init__(self, store, binary_id):
        self.store, self.binary_id = store, binary_id
        self.query = ProgramQueryService(store)
        self.last_evidence = None
        self.overview_seeds = ()
        self.registry = ToolRegistry()
        entries = [
            ('binary_metadata', 'Stored binary metadata and coverage counts', {}, self.metadata),
            ('list_functions', 'Bounded function metadata, ordered by persisted ordinal',
             {'limit': _integer(20, 100), 'offset': _integer(0, 1000000, 0)}, self.functions),
            ('get_function', 'Exact function ID, name or address lookup; metadata only',
             {'function': SELECTOR}, self.function),
            ('get_callers', 'Stored direct CALL edges into a function',
             {'function': SELECTOR, 'limit': _integer(20, 100)}, self.callers),
            ('get_callees', 'Stored direct CALL edges out of a function',
             {'function': SELECTOR, 'limit': _integer(20, 100)}, self.callees),
            ('find_call_path', 'Shortest stored CALL path within a depth bound',
             {'source': SELECTOR, 'target': SELECTOR, 'max_depth': _integer(3, 8, 0)}, self.path),
            ('rank_functions', 'Connectivity ranking; does not prove behavioral importance',
             {'metric': {'type': 'string', 'default': 'unique_callers', 'enum': [
                 'unique_callers', 'unique_callees', 'incoming_callsites', 'outgoing_callsites']},
              'limit': _integer(10, 100)}, self.rank),
            ('get_artifacts', 'Bounded binary-level artifacts; strings have no function linkage',
             {'kind': {'type': 'string', 'default': 'STRING', 'enum': ['STRING', 'IMPORT', 'EXPORT']},
              'limit': _integer(20, 100)}, self.artifacts),
            ('get_decompiled_text', 'Stored bounded decompiled text with provenance',
             {'function': SELECTOR, 'max_chars': _integer(2000, 8000)}, self.decompiled),
            ('get_assembly', 'Stored bounded assembly with upstream truncation status',
             {'function': SELECTOR, 'max_chars': _integer(2000, 8000)}, self.assembly),
            ('retrieve_evidence', 'M4 targeted or M5 overview evidence with provenance and truncations',
             {'function': {'type': 'string', 'default': None, 'nullable': True},
              'max_chars': _integer(8000, 16000, 1000)}, self.evidence),
            ('security_findings', 'M7 deterministic signals/candidates; not confirmed vulnerabilities',
             {}, self.security),
        ]
        for entry in entries:
            self.registry.register(Tool(*entry))

    def _provenance(self, table, identity, address=None, **extra):
        return {'source_table': table, 'source_id': identity, 'binary_id': self.binary_id,
                'address': address, **extra}

    def _function(self, function):
        data = asdict(function)
        data.pop('decompiled_text')
        data.pop('assembly')
        return {'function': data, 'provenance': self._provenance(
            'functions', function.function_id, function.address)}

    def metadata(self):
        with self.query._snapshot(self.binary_id) as db:
            binary = self.store._binary_record(db.execute('SELECT * FROM binaries WHERE binary_id=?',
                                                         (self.binary_id,)).fetchone())
            counts = {table: db.execute(f'SELECT count(*) FROM {table} WHERE binary_id=?',
                      (self.binary_id,)).fetchone()[0] for table in ('functions', 'function_edges', 'artifacts', 'warnings')}
        return {'binary': serializable(binary), 'counts': counts,
                'provenance': self._provenance('binaries', self.binary_id, binary.image_base)}

    def functions(self, limit=20, offset=0):
        with self.query._snapshot(self.binary_id) as db:
            # Omit text in SQL; _record needs the two fields for the existing record contract.
            from aire.knowledge.models import FunctionRecord
            columns = [k for k in FunctionRecord.__dataclass_fields__ if k not in ('assembly', 'decompiled_text')]
            rows = db.execute('SELECT ' + ','.join(columns) +
                ', NULL AS assembly, NULL AS decompiled_text FROM functions WHERE binary_id=? ORDER BY ordinal LIMIT ? OFFSET ?',
                (self.binary_id, limit + 1, offset)).fetchall()
        return {'items': [self._function(_record(r)) for r in rows[:limit]],
                'has_more': len(rows) > limit, 'offset': offset}

    def function(self, function):
        return self._function(self.query.resolve_function(self.binary_id, function))

    def _edges(self, edges, limit):
        return {'items': [{'caller': self._function(e.caller), 'callee': self._function(e.callee),
                'callsite_address': e.callsite_address, 'edge_type': e.edge_type,
                'provenance': self._provenance('function_edges',
                    f'{e.caller.function_id}->{e.callee.function_id}@{e.callsite_address}', e.callsite_address,
                    caller_function_id=e.caller.function_id, callee_function_id=e.callee.function_id)}
                for e in edges[:limit]], 'truncated': len(edges) > limit,
                'observed_count': len(edges), 'scope': 'stored resolved CALL edges only'}

    def callers(self, function, limit=20):
        return {'selected_function': self.function(function), **self._edges(self.query.get_callers(self.binary_id, function), limit)}

    def callees(self, function, limit=20):
        return {'selected_function': self.function(function), **self._edges(self.query.get_callees(self.binary_id, function), limit)}

    def path(self, source, target, max_depth=3):
        path = self.query.find_call_path(self.binary_id, source, target, max_depth=max_depth)
        return {'found': path is not None, 'max_depth': max_depth,
                'functions': [self._function(f) for f in path.functions] if path else [],
                'edges': self._edges(path.edges, 8) if path else None,
                'scope': 'No path within bound does not prove global unreachability'}

    def rank(self, metric='unique_callers', limit=10):
        rows = self.query.rank_functions(self.binary_id, metric=metric, limit=limit)
        return {'metric': metric, 'scope': 'Connectivity only; not semantic importance',
                'items': [{**{k: v for k, v in asdict(r).items() if k != 'function'},
                           **self._function(r.function)} for r in rows]}

    def artifacts(self, kind='STRING', limit=20):
        bundle = ContextBuilder(self.store).build(EvidenceRequest(self.binary_id,
            include_strings=kind == 'STRING', include_imports=kind == 'IMPORT', include_exports=kind == 'EXPORT',
            max_artifacts=limit, max_functions=0, max_edges=0, max_total_chars=16000))
        return {'items': serializable(bundle.artifacts), 'truncations': serializable(bundle.truncations),
                'scope': 'binary; no function-to-string cross-references are persisted'}

    def _text(self, function, max_chars, field):
        record = self.query.resolve_function(self.binary_id, function)
        text = getattr(record, field)
        return {**self._function(record), 'text': text[:max_chars] if text is not None else None,
                'field': field, 'available': text is not None,
                'truncated': bool(text and len(text) > max_chars),
                'upstream_truncated': record.assembly_truncated if field == 'assembly' else False,
                'observed_chars': len(text) if text is not None else None}

    def decompiled(self, function, max_chars=2000):
        return self._text(function, max_chars, 'decompiled_text')

    def assembly(self, function, max_chars=2000):
        return self._text(function, max_chars, 'assembly')

    def evidence(self, function=None, max_chars=8000):
        seeded = function is None and bool(self.overview_seeds)
        builder = ContextBuilder(self.store) if function is not None else OverviewContextBuilder(
            self.store, seed_functions=self.overview_seeds)
        self.last_evidence = builder.build(EvidenceRequest(self.binary_id, function, max_functions=6,
            max_edges=12, max_artifacts=6, include_exports=True, max_total_chars=max_chars,
            max_decompiled_chars_per_function=800 if seeded else 1600,
            max_assembly_chars_per_function=300 if seeded else 1000))
        return self.last_evidence.to_dict(include_timings=False)

    def security(self):
        result = RuleEngine(self.store).scan_binary(self.binary_id).to_dict()
        result.pop('timing', None)
        return result
