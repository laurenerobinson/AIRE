"""Strict transient M8A contracts; no persistence or executable model actions."""
from dataclasses import asdict, dataclass, field
import json

STOP_MESSAGE = 'Analysis stopped because the configured evidence/step limit was reached.'
TOOLS = ('get_function', 'get_disassembly', 'get_decompilation', 'get_callers',
         'get_callees', 'get_basic_blocks', 'get_artifacts', 'resolve_address')
VERDICTS = ('CONSISTENT', 'PARTIALLY_CONSISTENT', 'POTENTIAL_DISCREPANCY', 'INSUFFICIENT_EVIDENCE')


class AgentError(ValueError):
    """Invalid action, evidence, or final interpretation."""


class EvidenceLimit(AgentError):
    pass


def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise AgentError('Object fields must be exactly: ' + ', '.join(keys))


def string(value, maximum=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise AgentError(f'Expected nonempty string of at most {maximum} characters')
    return value


def strings(value, maximum=32):
    if not isinstance(value, list) or len(value) > maximum:
        raise AgentError('Expected bounded string list')
    for item in value:
        string(item)
    return value


@dataclass(frozen=True)
class AgentLimits:
    max_steps: int = 6
    max_functions: int = 8
    max_depth: int = 2
    max_assembly_instructions_per_function: int = 200
    max_decompiler_chars_per_function: int = 8000
    max_total_context_chars: int = 20000

    def __post_init__(self):
        for key, low, high in (
            ('max_steps', 1, 32), ('max_functions', 1, 32), ('max_depth', 0, 4),
            ('max_assembly_instructions_per_function', 1, 1000),
            ('max_decompiler_chars_per_function', 1, 32000),
            ('max_total_context_chars', 1000, 200000),
        ):
            value = getattr(self, key)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{key} must be an integer from {low} to {high}')


def object_schema(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


TEXT = {'type': 'string', 'minLength': 1, 'maxLength': 4000}
IDS = {'type': 'array', 'items': TEXT, 'maxItems': 32}
CLAIM_SCHEMA = object_schema({'claim': TEXT, 'evidence_ids': IDS})
CLAIMS = {'type': 'array', 'items': CLAIM_SCHEMA, 'maxItems': 32}
COMPARISON_SCHEMA = object_schema({
    'agreement_points': CLAIMS, 'disagreement_points': CLAIMS, 'uncertain_points': CLAIMS,
    'verdict': {'enum': list(VERDICTS)},
})
FINAL_SCHEMA = object_schema({
    'summary': CLAIM_SCHEMA, 'behavior': CLAIMS,
    'instruction_findings': {'type': 'array', 'maxItems': 32, 'items': object_schema({
        'address': TEXT, 'instruction': TEXT, 'interpretation': TEXT, 'evidence_id': TEXT})},
    'control_flow_findings': CLAIMS, 'calls': IDS, 'register_stack_observations': CLAIMS,
    'decompiler_comparison': COMPARISON_SCHEMA, 'uncertainties': IDS, 'limitations': IDS,
})
ARGUMENTS = {name: object_schema({'function': TEXT}) for name in TOOLS}
ARGUMENTS['get_disassembly'] = object_schema({'function': TEXT, 'start': TEXT, 'end': TEXT})
ARGUMENTS['get_disassembly']['required'] = ['function']
ARGUMENTS['get_artifacts'] = object_schema({'type': {'enum': ['IMPORT', 'EXPORT', 'STRING']}})
ARGUMENTS['resolve_address'] = object_schema({'address': TEXT})
ACTION_SCHEMA = {'oneOf': [object_schema({'action': {'const': name}, 'arguments': ARGUMENTS[name],
                                          'reason': TEXT}) for name in TOOLS] + [
    object_schema({'action': {'const': 'final'}, 'analysis': FINAL_SCHEMA})]}


def parse_json(raw):
    if not isinstance(raw, str) or len(raw) > 64000:
        raise AgentError('Model response exceeds 64000 characters or is not text')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AgentError('Duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise AgentError('Non-finite JSON value')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise AgentError('Invalid structured JSON response') from exc


def validate_action(value):
    exact(value, ('action', 'arguments', 'reason'))
    if not isinstance(value['action'], str) or value['action'] not in TOOLS:
        raise AgentError('Unknown read-only tool')
    string(value['reason'])
    args = value['arguments']
    schema = ARGUMENTS[value['action']]
    if (not isinstance(args, dict) or not set(schema['required']) <= set(args)
            or not set(args) <= set(schema['properties'])):
        raise AgentError('Malformed tool arguments')
    for key, val in args.items():
        string(val, 500)
        if 'enum' in schema['properties'][key] and val not in schema['properties'][key]['enum']:
            raise AgentError('Unsupported artifact type')
    return value


@dataclass
class DisassemblyAnalysis:
    binary_id: str
    target_function_id: str
    target_address: str
    current_name: str
    summary: dict = field(default_factory=lambda: {'claim': 'No validated interpretation available.', 'evidence_ids': []})
    behavior: list = field(default_factory=list)
    instruction_findings: list = field(default_factory=list)
    control_flow_findings: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    register_stack_observations: list = field(default_factory=list)
    decompiler_comparison: dict = field(default_factory=lambda: {
        'agreement_points': [], 'disagreement_points': [], 'uncertain_points': [],
        'verdict': 'INSUFFICIENT_EVIDENCE'})
    uncertainties: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    tools_used: list = field(default_factory=list)
    steps_used: int = 0
    context_truncated: bool = False
    context_characters: int = 0
    model: str = ''
    timings: dict = field(default_factory=dict)
    status: str = 'incomplete'

    def to_dict(self, *, include_timings=True):
        result = asdict(self)
        if not include_timings:
            result.pop('timings')
        return result


def validate_final(value, catalog, target_id):
    exact(value, FINAL_SCHEMA['properties'])
    def citations(ids, primary=False, comparison=False):
        strings(ids)
        if not ids or any(identity not in catalog for identity in ids):
            raise AgentError('Missing or nonexistent evidence citation')
        kinds = {catalog[i]['kind'] for i in ids}
        if primary and not kinds & {'INSN', 'CALL'}:
            raise AgentError('Behavior requires instruction or direct-call evidence')
        if comparison and not {'INSN', 'DECOMP'} <= kinds:
            raise AgentError('Comparison requires assembly and decompiler evidence')
        if comparison and any(catalog[i].get('function_id') != target_id for i in ids):
            raise AgentError('Comparison must cite this target function')
    def claim(item, primary=True, comparison=False):
        exact(item, ('claim', 'evidence_ids'))
        string(item['claim'])
        citations(item['evidence_ids'], primary, comparison)
    def claims(items, primary=True, comparison=False):
        if not isinstance(items, list) or len(items) > 32:
            raise AgentError('Expected at most 32 claims')
        for item in items:
            claim(item, primary, comparison)
    claim(value['summary'])
    # Summary must describe evidence for the analyst-selected target.
    if not any(catalog[i].get('function_id') == target_id or
               catalog[i].get('caller_id') == target_id or catalog[i].get('callee_id') == target_id
               for i in value['summary']['evidence_ids']):
        raise AgentError('Summary must cite target evidence')
    for key in ('behavior', 'control_flow_findings', 'register_stack_observations'):
        claims(value[key])
    findings = value['instruction_findings']
    if not isinstance(findings, list) or len(findings) > 32:
        raise AgentError('Expected at most 32 instruction findings')
    for item in findings:
        exact(item, ('address', 'instruction', 'interpretation', 'evidence_id'))
        for field_value in item.values():
            string(field_value)
        fact = catalog.get(item['evidence_id'], {})
        if (fact.get('kind') != 'INSN' or item['address'] != fact['address'] or
                item['instruction'] != (fact['mnemonic'] + ' ' + fact['operands']).rstrip()):
            raise AgentError('Instruction text/address must match cited deterministic evidence')
    strings(value['calls'])
    if any(catalog.get(i, {}).get('kind') != 'CALL' for i in value['calls']):
        raise AgentError('Calls must reference admitted direct edges')
    comparison = value['decompiler_comparison']
    exact(comparison, COMPARISON_SCHEMA['properties'])
    if comparison['verdict'] not in VERDICTS:
        raise AgentError('Invalid decompiler verdict')
    for key in ('agreement_points', 'disagreement_points'):
        claims(comparison[key], comparison=True)
    claims(comparison['uncertain_points'], primary=False)
    if comparison['verdict'] != 'INSUFFICIENT_EVIDENCE' and not (
            comparison['agreement_points'] or comparison['disagreement_points']):
        raise AgentError('Comparison verdict requires a supported comparison point')
    if comparison['verdict'] == 'CONSISTENT' and comparison['disagreement_points']:
        raise AgentError('CONSISTENT cannot contain disagreement points')
    strings(value['uncertainties'])
    strings(value['limitations'])
    return value
