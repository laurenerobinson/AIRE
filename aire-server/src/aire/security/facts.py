"""Immutable, single-binary fact projection. No code text or AI interpretations."""
from dataclasses import dataclass
import json
from aire.knowledge.retrieval import ProgramQueryService, _address_key
from aire.security.findings import SecurityEvidence, EvidenceType, stable_id


@dataclass(frozen=True)
class FunctionFact:
    function_id: str
    address: str
    current_name: str
    is_external: bool
    is_thunk: bool
    namespace: str | None


@dataclass(frozen=True)
class ImportFact:
    artifact_id: str
    address: str | None
    value: str


@dataclass(frozen=True)
class CallFact:
    caller_function_id: str
    callee_function_id: str
    callsite_address: str

    @property
    def source_id(self):
        return json.dumps([self.caller_function_id, self.callee_function_id,
                           self.callsite_address, 'CALL'], separators=(',', ':'))


@dataclass(frozen=True)
class RuleFacts:
    binary_id: str
    functions: tuple[FunctionFact, ...]
    imports: tuple[ImportFact, ...]
    calls: tuple[CallFact, ...]
    coverage_ready: bool
    evidence: tuple[SecurityEvidence, ...]
    warnings: tuple[str, ...]

    def source(self, table, identity):
        return next(e for e in self.evidence if e.source == table and e.source_id == identity)


def load_rule_facts(store, binary_id):
    """One M3 read snapshot; copy lightweight rows into immutable M7 records.

    Deliberately exposes no store handle, decompilation, assembly, strings,
    naming results, chatbot prose, or executable path to rules.
    """
    query = ProgramQueryService(store)
    with query._snapshot(binary_id) as db:
        rows = db.execute('SELECT function_id,address,current_name,is_external,is_thunk,namespace '
                          'FROM functions WHERE binary_id=?', (binary_id,)).fetchall()
        functions = tuple(sorted((FunctionFact(r['function_id'], r['address'], r['current_name'],
            bool(r['is_external']), bool(r['is_thunk']), r['namespace']) for r in rows),
            key=lambda f: (_address_key(f.address), f.function_id)))
        imports = tuple(ImportFact(*r) for r in db.execute(
            "SELECT artifact_id,address,value FROM artifacts WHERE binary_id=? AND type='IMPORT' ORDER BY artifact_id", (binary_id,)))
        calls = tuple(sorted((CallFact(*r) for r in db.execute(
            "SELECT DISTINCT caller_function_id,callee_function_id,callsite_address FROM function_edges WHERE binary_id=? AND edge_type='CALL'", (binary_id,))),
            key=lambda c: (_address_key(c.callsite_address), c.caller_function_id, c.callee_function_id)))
        metadata = {r['key']: json.loads(r['value']) for r in db.execute(
            "SELECT key,value FROM analysis_metadata WHERE binary_id=? AND key IN ('analysis_completed','options')", (binary_id,))}
        warnings = tuple(r[0] for r in db.execute(
            'SELECT warning_text FROM warnings WHERE binary_id=? ORDER BY ordinal', (binary_id,)))
    options = metadata.get('options', {})
    ready = (metadata.get('analysis_completed') is True and isinstance(options, dict)
             and options.get('include_imports') is True and options.get('include_call_edges') is True)
    evidence = []
    def add(kind, table, identity, description, **location):
        evidence.append(SecurityEvidence(stable_id('EVIDENCE', binary_id, kind.value, table, identity),
            binary_id, kind, description, table, identity, **location))
    by_id = {f.function_id: f for f in functions}
    for f in functions:
        add(EvidenceType.FUNCTION, 'functions', f.function_id,
            f'Stored function {json.dumps(f.current_name)} at {f.address}; external={f.is_external}, thunk={f.is_thunk}.',
            function_id=f.function_id, address=f.address)
    for a in imports:
        add(EvidenceType.IMPORT, 'artifacts', a.artifact_id,
            f'Stored IMPORT {json.dumps(a.value)} at {a.address}.', artifact_id=a.artifact_id, address=a.address)
    for c in calls:
        caller, callee = by_id[c.caller_function_id], by_id[c.callee_function_id]
        add(EvidenceType.CALL_EDGE, 'function_edges', c.source_id,
            f'Stored resolved CALL from {json.dumps(caller.current_name)} ({caller.address}) '
            f'to {json.dumps(callee.current_name)} ({callee.address}) at {c.callsite_address}.',
            function_id=caller.function_id, address=callee.address, callsite=c.callsite_address)
    for key in sorted(metadata):
        # Evidence includes only the relevant coverage flags, not arbitrary metadata.
        value = metadata[key] if key != 'options' else {
            name: options.get(name) for name in ('include_imports', 'include_call_edges')} if isinstance(options, dict) else None
        add(EvidenceType.ANALYSIS_METADATA, 'analysis_metadata', key,
            f'Stored {key} coverage fields: {json.dumps(value, sort_keys=True)}.')
    return RuleFacts(binary_id, functions, imports, calls, ready, tuple(evidence), warnings)
