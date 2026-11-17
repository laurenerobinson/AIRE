"""M10 Phase 2: decompiler cross-validation rules (pure Python, synthetic facts)."""
import dataclasses
import unittest

from aire.analysis.decompiler_crossval import CONSISTENT, DISCREPANCY, INSUFFICIENT, crossvalidate
from aire.analysis.instruction_semantics import FunctionContext, analyze_function
from aire.knowledge.models import FunctionRecord
import test_m10_semantics as t

B = 'b' * 64
CALL = t.ins('00401010', 'CALL', 'CALL 0x00401500', [t.operand('0x00401500', 'ADDR', 'CODE')],
             [t.op('CALL', None, {'k': 'mem', 'sp': 'ram', 'a': '401500', 's': 8})], length=5,
             flow='UNCONDITIONAL_CALL', targets=['00401500'], call=True)
STRING = t.ins('00401008', 'MOV', 'MOV EDI,0x402000', [t.operand('EDI', 'REG'), t.operand('0x402000', 'SCAL')],
               [t.op('COPY', t.reg('EDI'), t.const(0x402000))], length=5)
SET_EAX = t.ins('00401020', 'MOV', 'MOV EAX,0x7', [t.operand('EAX', 'REG'), t.operand('0x7', 'SCAL')],
                [t.op('COPY', t.reg('EAX'), t.const(7))], length=5)
RET = t.ins('00401025', 'RET', 'RET', [], [t.op('RETURN', None, t.reg('RIP', 8))], length=1, flow='TERMINATOR',
            ft=None, term=True)
DOCUMENT = {'source': 'ghidra', 'function_address': '00401000',
            'instructions': [t.MOV_LOAD | {'a': '00401000'}, STRING, CALL, t.CMP | {'a': '00401015'},
                             t.JE | {'a': '00401018', 'ft': '0040101a'}, SET_EAX, RET],
            'blocks': [{'start': '00401000', 'end': '00401019', 'succ': [{'to': '00401200', 'flow': 'CONDITIONAL_JUMP'},
                                                                          {'to': '00401020', 'flow': 'FALL_THROUGH'}]},
                       {'start': '00401020', 'end': '00401025', 'succ': []}],
            'signature': {'return': {'storage': 'EAX:4', 'type': 'int'}}}
CONTEXT = FunctionContext({'00401500': 'helper', '00401600': 'unrelated', '00401000': 'f'},
                          {'00401008': [{'kind': 'STRING', 'value': 'Hello\nWorld', 'target': '00402000',
                                         'reference_type': 'DATA'}]}, lambda a: None, 'x86:LE:64:default')
GOOD = '''
int f(int param_1)

{
  int iVar1;
  puts("Hello\\nWorld");
  helper();
  if (param_1 == 0) {
    return 0;
  }
  return 7;
}
'''


def record(text, thunk=False):
    return FunctionRecord(f'{B}:00401000', B, '00401000', 'f', None, text, None, None, None, None, is_thunk=thunk)


def run(text, thunk=False, document=DOCUMENT):
    semantics = analyze_function(document, CONTEXT)
    return crossvalidate(record(text, thunk), document, semantics, CONTEXT)


def status(report, check):
    return next(f['status'] for f in report['findings'] if f['check'] == check)


class CrossValidationTests(unittest.TestCase):
    def test_consistent_function(self):
        report = run(GOOD)
        self.assertEqual(report['verdict'], CONSISTENT, [f['summary'] for f in report['findings']])
        for check in ('call_targets', 'string_references', 'control_flow', 'return_value'):
            self.assertEqual(status(report, check), CONSISTENT)

    def test_missing_call_is_flagged_with_address(self):
        report = run(GOOD.replace('  helper();\n', ''))
        self.assertEqual(status(report, 'call_targets'), DISCREPANCY)
        self.assertIn('0x00401010', [f for f in report['findings'] if f['check'] == 'call_targets'][0]['summary'])

    def test_tail_call_is_compared_with_decompiled_call(self):
        tail = dict(CALL, m='JMP', t='JMP 0x00401500', ft=None, term=True,
                    flow='CALL_TERMINATOR')
        document = dict(DOCUMENT, instructions=[tail if i is CALL else i for i in DOCUMENT['instructions']])
        self.assertEqual(status(run(GOOD, document=document), 'call_targets'), CONSISTENT)
        missing = run(GOOD.replace('  helper();\n', ''), document=document)
        self.assertEqual(status(missing, 'call_targets'), DISCREPANCY)
        self.assertIn('0x00401010', next(f['summary'] for f in missing['findings'] if f['check']=='call_targets'))
        phantom = GOOD.replace('helper();', 'helper();\n  unrelated();')
        self.assertEqual(status(run(phantom, document=document), 'call_targets'), DISCREPANCY)

    def test_phantom_known_function_is_flagged_but_pseudo_ops_are_not(self):
        self.assertEqual(status(run(GOOD.replace('helper();', 'helper();\n  unrelated();')), 'call_targets'), DISCREPANCY)
        self.assertNotEqual(status(run(GOOD.replace('helper();', 'helper();\n  iVar1 = CONCAT44(1,2);')),
                                   'call_targets'), DISCREPANCY)

    def test_missing_string_and_escaped_match(self):
        self.assertEqual(status(run(GOOD.replace('"Hello\\nWorld"', '"other"')), 'string_references'), DISCREPANCY)

    def test_no_conditionals_is_flagged(self):
        flat = GOOD.replace('  if (param_1 == 0) {\n    return 0;\n  }\n', '')
        self.assertEqual(status(run(flat), 'control_flow'), DISCREPANCY)

    def test_boolean_expression_counts_as_condition(self):
        expression = GOOD.replace('  if (param_1 == 0) {\n    return 0;\n  }\n  return 7;', '  return (param_1 == 0) * 7;')
        self.assertEqual(status(run(expression), 'control_flow'), CONSISTENT)

    def test_benign_rewrites_are_not_flagged(self):
        renamed = GOOD.replace('iVar1', 'count').replace('param_1', 'value')
        self.assertEqual(run(renamed)['verdict'], CONSISTENT)
        self.assertNotEqual(run(GOOD.replace('return 7;', 'return 0x7;'))['verdict'], DISCREPANCY)

    def test_decompiler_warnings_explain_or_downgrade(self):
        injected = '/* WARNING: Function: helper replaced with injection: helper */\n' + GOOD.replace('  helper();\n', '')
        self.assertEqual(status(run(injected), 'call_targets'), CONSISTENT)
        unreachable = '/* WARNING: Removing unreachable block (ram,0x401200) */\n' + GOOD.replace('  helper();\n', '')
        report = run(unreachable)
        self.assertEqual(status(report, 'call_targets'), INSUFFICIENT)
        self.assertTrue(any('Downgraded' in n for f in report['findings'] for n in f['notes']))

    def test_return_value_rules(self):
        # Nothing writes EAX/RAX (the load into EAX, the call and MOV EAX,7 removed).
        no_write = dict(DOCUMENT, instructions=[i for i in DOCUMENT['instructions'][1:] if i is not SET_EAX and i is not CALL])
        report = run(GOOD.replace('  helper();\n', ''), document=no_write)
        self.assertEqual(status(report, 'return_value'), DISCREPANCY)
        self.assertNotEqual(status(run(GOOD), 'return_value'), DISCREPANCY)

    def test_thunks_and_missing_text_are_insufficient(self):
        self.assertEqual(run(GOOD, thunk=True)['verdict'], INSUFFICIENT)
        self.assertEqual(run(None)['verdict'], INSUFFICIENT)


if __name__ == '__main__':
    unittest.main()
