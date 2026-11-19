"""Read-only deterministic probe of the demo store. Usage (repo root):
PYTHONPATH=aire-server/src aire-server/.venv/bin/python docs/defense_assets/fresh_outputs_20261117/deterministic_tool_probe.py demo_artifacts/m10/defense_20261117/demo.sqlite
No model client is constructed; the store opens with mode=ro + query_only; SHA-256 is compared before/after."""
import hashlib, json, sys, time
from pathlib import Path
from aire.security.rule_engine import _ReadOnlyRuleStore
from aire.agent.tools import AgentTools
from aire.analysis.assembly_intelligence import AssemblyIntelligence
from aire.agent import assembly_answers as aa
DB = Path(sys.argv[1]); BIN = 'be852ca8fcb0945498f5e778acaa01cdbc064291cca222e039ebc94cb46b488e'
h = lambda: hashlib.sha256(DB.read_bytes()).hexdigest()
before = h()
with _ReadOnlyRuleStore(DB) as store:
    t = AgentTools(store, BIN)
    names = [c['name'] for c in t.registry.catalog()]
    print('TOOLS', len(names), names)
    for name, args in [('get_function', {'function': 'validate_input'}),
                       ('get_callers', {'function': 'validate_input'}),
                       ('get_callees', {'function': 'validate_input'}),
                       ('find_call_path', {'source': 'main', 'target': 'calculate_checksum', 'max_depth': 4}),
                       ('get_function_strings', {'function': 'validate_input'}),
                       ('get_function', {'function': 'no_such_function'}),
                       ('get_callers', {'function': 'validate_input', 'limit': 5000}),
                       ('run_shell', {})]:
        tick = time.perf_counter(); r = t.registry.run(name, args); ms = (time.perf_counter()-tick)*1000
        s = json.dumps(r)[:600]
        print(f'\n## {name} {args} ok={r["ok"]} {ms:.2f} ms\n{s}')
    ai = AssemblyIntelligence(store, BIN)
    sel = ai.resolve('validate_input').function_id
    for label, fn in [('function', lambda: aa.answer_function(ai, sel)),
                      ('branch', lambda: aa.answer_branch(ai, sel, '004011e1')),
                      ('trace', lambda: aa.answer_trace(ai, sel, '004011dc', '[RBP-0x10]')),
                      ('trace_PITFALL_unbracketed_slot', lambda: aa.answer_trace(ai, sel, '004011dc', 'RBP-0x10')),
                      ('return_usage', lambda: aa.answer_return_usage(ai, sel)),
                      ('crossvalidate', lambda: aa.answer_crossvalidate(ai, sel))]:
        tick = time.perf_counter()
        try:
            answer, tool, cited = fn(); ms = (time.perf_counter()-tick)*1000
            print(f'\n### M10 {label} ({ms:.1f} ms, {len(cited)} cited addresses)\n{answer[:1500]}')
        except Exception as e:
            print(f'\n### M10 {label} ERROR {type(e).__name__}: {e}')
after = h()
print('\nDB_SHA256_BEFORE', before, '\nDB_SHA256_AFTER ', after, '\nUNCHANGED', before == after)
