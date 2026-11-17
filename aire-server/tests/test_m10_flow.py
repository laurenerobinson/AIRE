"""M10 Phase 3: CFG, branch paths, reaching definitions, value origins (pure Python)."""
import unittest

from aire.analysis import flow_analysis as fa
from aire.analysis.instruction_semantics import FunctionContext, analyze_function
import test_m10_semantics as t

X64 = FunctionContext({'00401500': 'helper'}, {}, lambda a: 'EAX:4 (Ghidra-recovered int)', 'x86:LE:64:default')


def mov_slot_const(address, disp, value):
    text = f'dword ptr [RBP + -0x{-disp:x}]'
    return t.ins(address, 'MOV', f'MOV {text},0x{value:x}', [t.operand(text, 'ADDR', 'DYN'), t.operand(f'0x{value:x}', 'SCAL')],
                 [t.op('INT_ADD', t.tmp('a'), t.reg('RBP', 8), t.const(disp, 8)),
                  t.op('STORE', None, t.const(0x1b1, 4), t.tmp('a'), t.const(value))], length=7)


def load_slot(address, register, disp):
    text = f'dword ptr [RBP + -0x{-disp:x}]'
    return t.ins(address, 'MOV', f'MOV {register},{text}', [t.operand(register, 'REG'), t.operand(text, 'ADDR', 'DYN')],
                 [t.op('INT_ADD', t.tmp('a'), t.reg('RBP', 8), t.const(disp, 8)),
                  t.op('LOAD', t.tmp('v', 4), t.const(0x1b1, 4), t.tmp('a')), t.op('COPY', t.reg(register), t.tmp('v', 4))])


def store_reg(address, disp, register):
    text = f'dword ptr [RBP + -0x{-disp:x}]'
    return t.ins(address, 'MOV', f'MOV {text},{register}', [t.operand(text, 'ADDR', 'DYN'), t.operand(register, 'REG')],
                 [t.op('INT_ADD', t.tmp('a'), t.reg('RBP', 8), t.const(disp, 8)),
                  t.op('STORE', None, t.const(0x1b1, 4), t.tmp('a'), t.reg(register))], length=3)


ADD_EDI = t.ins('00401010', 'ADD', 'ADD EAX,EDI', [t.operand('EAX', 'REG'), t.operand('EDI', 'REG')],
                [t.op('INT_ADD', t.reg('EAX'), t.reg('EAX'), t.reg('EDI')), t.op('INT_EQUAL', t.reg('ZF', 1), t.reg('EAX'), t.const(0))],
                length=2)
CMP = t.ins('00401016', 'CMP', 'CMP EAX,0x64', [t.operand('EAX', 'REG'), t.operand('0x64', 'SCAL')],
            [t.op('INT_LESS', t.reg('CF', 1), t.reg('EAX'), t.const(100)), t.op('INT_SUB', t.tmp('s', 4), t.reg('EAX'), t.const(100)),
             t.op('INT_EQUAL', t.reg('ZF', 1), t.tmp('s', 4), t.const(0))], length=3)
JC = t.ins('00401019', 'JC', 'JC 0x00401007', [t.operand('0x00401007', 'ADDR', 'CODE')],
           [t.op('CBRANCH', None, {'k': 'mem', 'sp': 'ram', 'a': '401007', 's': 8}, t.reg('CF', 1))],
           length=2, flow='CONDITIONAL_JUMP', targets=['00401007'], jump=True, cond=True)
CALL = t.ins('0040101b', 'CALL', 'CALL 0x00401500', [t.operand('0x00401500', 'ADDR', 'CODE')],
             [t.op('CALL', None, {'k': 'mem', 'sp': 'ram', 'a': '401500', 's': 8})], length=5,
             flow='UNCONDITIONAL_CALL', targets=['00401500'], call=True)
TEST = t.ins('00401020', 'TEST', 'TEST EAX,EAX', [t.operand('EAX', 'REG'), t.operand('EAX', 'REG')],
             [t.op('INT_AND', t.tmp('t', 4), t.reg('EAX'), t.reg('EAX')), t.op('INT_EQUAL', t.reg('ZF', 1), t.tmp('t', 4), t.const(0))],
             length=2)
JZ = t.ins('00401022', 'JZ', 'JZ 0x00401030', [t.operand('0x00401030', 'ADDR', 'CODE')],
           [t.op('CBRANCH', None, {'k': 'mem', 'sp': 'ram', 'a': '401030', 's': 8}, t.reg('ZF', 1))],
           length=2, flow='CONDITIONAL_JUMP', targets=['00401030'], jump=True, cond=True)
RET = t.ins('00401024', 'RET', 'RET', [], [t.op('RETURN', None, t.reg('RIP', 8))], length=1, flow='TERMINATOR', ft=None, term=True)
RET2 = dict(RET, a='00401030', t='RET')
DOC = {'source': 'ghidra', 'function_address': '00401000',
       'instructions': [mov_slot_const('00401000', -4, 0), load_slot('00401007', 'EAX', -4), ADD_EDI,
                        store_reg('00401012', -4, 'EAX'), CMP, JC, CALL, TEST, JZ, RET, RET2],
       'blocks': [{'start': '00401000', 'end': '00401006', 'succ': [{'to': '00401007', 'flow': 'FALL_THROUGH'}]},
                  {'start': '00401007', 'end': '0040101a', 'succ': [{'to': '00401007', 'flow': 'CONDITIONAL_JUMP'},
                                                                    {'to': '0040101b', 'flow': 'FALL_THROUGH'}]},
                  {'start': '0040101b', 'end': '00401023', 'succ': [{'to': '00401500', 'flow': 'UNCONDITIONAL_CALL'},
                                                                    {'to': '00401030', 'flow': 'CONDITIONAL_JUMP'},
                                                                    {'to': '00401024', 'flow': 'FALL_THROUGH'}]},
                  {'start': '00401024', 'end': '00401024', 'succ': []}, {'start': '00401030', 'end': '00401030', 'succ': []}],
       'signature': {'parameters': [{'ordinal': 0, 'name': 'step', 'storage': 'EDI:4', 'type': 'int'}],
                     'return': {'storage': 'EAX:4', 'type': 'int'}}}


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.semantics = analyze_function(DOC, X64)

    def test_cfg_loop_and_edges(self):
        graph = fa.control_flow_graph(DOC)
        self.assertEqual(graph['back_edges'], [{'from': '00401007', 'to': '00401007'}])
        self.assertEqual(graph['loops'][0]['header'], '00401007')
        self.assertEqual(graph['loops'][0]['exits'], ['0040101b'])
        block = next(b for b in graph['blocks'] if b['start'] == '0040101b')
        self.assertEqual(block['leaves_function'], [])  # call edges are not CFG edges
        self.assertEqual(graph['unreachable_blocks'], [])

    def test_branch_paths(self):
        paths = fa.branch_paths(DOC, self.semantics, '00401022')
        self.assertEqual(paths['condition'], 'EAX == 0')
        self.assertEqual(paths['when_true']['outcome'], 'returns at 0x00401030')
        self.assertEqual(paths['when_false']['outcome'], 'returns at 0x00401024')
        self.assertIn('error', fa.branch_paths(DOC, self.semantics, '00401000'))

    def test_self_loop_excludes_preheader(self):
        # A back-edge to the same block repeats only that block. Walking its
        # predecessors would incorrectly absorb initialization into the loop.
        loop = fa.control_flow_graph(DOC)['loops'][0]
        self.assertEqual(loop['header'], loop['back_edge_from'])
        self.assertEqual(loop['blocks'], ['00401007'])
        self.assertEqual(loop['exits'], ['0040101b'])

    def test_value_origins(self):
        trace = fa.trace_value(DOC, self.semantics, '00401016', 'eax')
        origins = {d['origin'] for d in trace['definitions']}
        self.assertEqual(origins, {'computed'})
        inputs = trace['definitions'][0]['inputs']
        self.assertEqual({i['location'] for i in inputs}, {'RAX', 'RDI'})
        param = next(i for i in inputs if i['location'] == 'RDI')['definitions'][0]
        self.assertEqual(param['origin'], 'parameter')
        self.assertEqual(param['parameter']['name'], 'step')
        slot = fa.trace_value(DOC, self.semantics, '00401007', '[rbp - 0x4]')
        kinds = sorted(d['origin'] for d in slot['definitions'])
        self.assertEqual(kinds, ['constant', 'stored_value'])  # initial 0 and the loop update
        self.assertEqual(next(d for d in slot['definitions'] if d['origin'] == 'constant')['value'], 0)
        call = fa.trace_value(DOC, self.semantics, '00401020', 'EAX')['definitions'][0]
        self.assertEqual((call['origin'], call['call']['target_name']), ('call_result', 'helper'))
        # A location not read by the instruction: the value it holds there, explicitly labelled.
        unused = fa.trace_value(DOC, self.semantics, '00401000', 'RBX')
        self.assertIn('not read by this instruction', unused['note'])
        self.assertEqual(unused['definitions'][0]['origin'], 'function_entry')
        at_call = fa.trace_value(DOC, self.semantics, '0040101b', 'EAX')  # value of EAX when the CALL executes
        self.assertEqual(at_call['definitions'][0]['address'], '00401010')

    def test_return_usage_and_parameter_use(self):
        usage = fa.return_usage_at_callsite(DOC, self.semantics, '0040101b')
        self.assertEqual(usage['uses'][0]['use'], 'tested')
        self.assertIn('EAX == 0', usage['uses'][0]['then'])
        used = fa.parameter_use(DOC, self.semantics)
        self.assertEqual([u['location'] for u in used if u['recovered_by_ghidra']], ['RDI'])

    def test_location_canonicalization(self):
        self.assertEqual(fa.canonical_location('eax'), 'RAX')
        self.assertEqual(fa.canonical_location('[rbp - 0x10]'), '[RBP-0x10]')
        self.assertEqual(fa.canonical_location('[RBP+-16]'), '[RBP-0x10]')
        self.assertEqual(fa.family('XMM0_Qa'), 'XMM0')
        self.assertEqual(fa.family('R9D'), 'R9')


if __name__ == '__main__':
    unittest.main()
