"""M10 Phase 1: structured instruction facts and deterministic semantics (pure Python)."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from aire.analysis.instruction_semantics import FunctionContext, analyze_function, analyze_instruction, legacy_document
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, FunctionRecord, ProgramIndex
from aire.pyghidra.instruction_ir import decode, encode, memory_operand, parse_pcode_list


def reg(name, size=4):
    return {'k': 'reg', 'n': name, 's': size}


def const(value, size=4):
    return {'k': 'const', 'v': value & ((1 << 8 * size) - 1), 'sv': value, 's': size}


def tmp(name, size=8):
    return {'k': 'tmp', 'n': name, 's': size}


def op(name, out, *inputs):
    return {'op': name, 'out': out, 'in': list(inputs)}


def ins(address, mnemonic, text, operands, pcode, length=3, flow='FALL_THROUGH', targets=(), ft='next', **flags):
    base = int(address, 16)
    return {'a': address, 'm': mnemonic, 't': text, 'len': length, 'ops': operands, 'flow': flow,
            'call': flags.get('call', False), 'jump': flags.get('jump', False), 'cond': flags.get('cond', False),
            'term': flags.get('term', False), 'computed': flags.get('computed', False), 'targets': list(targets),
            'ft': format(base + length, '08x') if ft == 'next' else ft, 'pcode': pcode}


def operand(text, *kinds):
    entry = {'text': text, 'kinds': list(kinds)}
    if '[' in text:
        entry['mem'] = memory_operand(text)
    return entry


CMP_FLAGS = [op('INT_LESS', reg('CF', 1), reg('EAX'), const(0)), op('INT_SBORROW', reg('OF', 1), reg('EAX'), const(0)),
             op('INT_SUB', tmp('u1', 4), reg('EAX'), const(0)), op('INT_SLESS', reg('SF', 1), tmp('u1', 4), const(0)),
             op('INT_EQUAL', reg('ZF', 1), tmp('u1', 4), const(0))]
MOV_LOAD = ins('00401230', 'MOV', 'MOV EAX,dword ptr [RBP + -0x4]',
               [operand('EAX', 'REG'), operand('dword ptr [RBP + -0x4]', 'ADDR', 'DYN')],
               [op('INT_ADD', tmp('u8f00'), reg('RBP', 8), const(-4, 8)),
                op('LOAD', tmp('u23d00', 4), const(0x1b1, 4), tmp('u8f00')), op('COPY', reg('EAX'), tmp('u23d00', 4))])
CMP = ins('00401233', 'CMP', 'CMP EAX,0x0', [operand('EAX', 'REG'), operand('0x0', 'SCAL')], CMP_FLAGS)
JE = ins('00401236', 'JZ', 'JZ 0x00401200', [operand('0x00401200', 'ADDR', 'CODE')],
         [op('CBRANCH', None, {'k': 'mem', 'sp': 'ram', 'a': '401200', 's': 8}, reg('ZF', 1))],
         length=2, flow='CONDITIONAL_JUMP', targets=['00401200'], jump=True, cond=True)
X64 = FunctionContext({'00401500': 'helper'}, {}, lambda a: 'EAX:4 (Ghidra-recovered int; signature source IMPORTED)',
                      'x86:LE:64:default')


def cbranch(address, mnemonic, ops_before, cond):
    return ins(address, mnemonic, f'{mnemonic} 0x00401200', [operand('0x00401200', 'ADDR', 'CODE')],
               ops_before + [op('CBRANCH', None, {'k': 'mem', 'sp': 'ram', 'a': '401200', 's': 8}, cond)],
               length=2, flow='CONDITIONAL_JUMP', targets=['00401200'], jump=True, cond=True)


class ParserTests(unittest.TestCase):
    def test_memory_operand_forms(self):
        self.assertEqual(memory_operand('dword ptr [RBP + -0x4]')['disp'], -4)
        m = memory_operand('qword ptr [RAX + RDX*0x4 + 0x10]')
        self.assertEqual((m['base'], m['index'], m['scale'], m['disp']), ('RAX', 'RDX', 4, 16))
        self.assertEqual(memory_operand('qword ptr FS:[0x28]')['segment'], 'FS')
        self.assertEqual(memory_operand('qword ptr [0x00404040]')['absolute'], 0x404040)
        self.assertIsNone(memory_operand('RAX'))

    def test_pcode_list_split(self):
        class Ctx:
            def varnode(self, space, offset, size):
                from aire.pyghidra.instruction_ir import _Context
                return _Context.varnode(self, space, offset, size)
            def register(self, offset, size):
                return {0x28: 'RBP', 0x206: 'ZF'}.get(offset, f'r{offset:x}')
        text = ('[(unique, 0x8f00, 8) INT_ADD (register, 0x28, 8) , (const, 0xfffffffffffffffc, 8),  ---  '
                'STORE (const, 0x1b1, 4) , (unique, 0x8f00, 8) , (const, 0x0, 4), (register, 0x206, 1) BOOL_NEGATE (register, 0x206, 1)]')
        ops = parse_pcode_list(Ctx(), text)
        self.assertEqual([o['op'] for o in ops], ['INT_ADD', 'STORE', 'BOOL_NEGATE'])
        self.assertEqual(ops[0]['in'][1]['sv'], -4)
        self.assertEqual(ops[0]['in'][0]['n'], 'RBP')
        self.assertIsNone(ops[1]['out'])
        self.assertEqual(parse_pcode_list(Ctx(), '[]'), [])

    def test_encode_round_trip(self):
        document = {'version': 1, 'instructions': [MOV_LOAD]}
        self.assertEqual(decode(encode(document)), document)


class SemanticsTests(unittest.TestCase):
    def test_spec_example_frame_load(self):
        record = analyze_instruction(MOV_LOAD, X64)
        self.assertEqual(record['category'], 'memory_load')
        self.assertEqual(record['reads']['memory']['kind'], 'frame')
        self.assertEqual(record['writes']['registers'], ['EAX'])
        self.assertIn('Reads a dword (4 bytes) value from memory at RBP - 0x4', record['explanation'])
        self.assertIn('writes it to EAX', record['explanation'])
        self.assertNotIn('adds', record['explanation'])  # address arithmetic is not data arithmetic
        self.assertEqual(record['evidence_source'], 'ghidra_pcode')

    def test_spec_example_compare_and_branch(self):
        compare = analyze_instruction(CMP, X64)
        self.assertEqual(compare['category'], 'compare')
        self.assertEqual(compare['writes']['registers'], [])
        self.assertIn('ZF', compare['writes']['flags'])
        branch = analyze_instruction(JE, X64, previous=[MOV_LOAD, CMP])
        self.assertEqual(branch['branch']['target'], '00401200')
        self.assertEqual(branch['branch']['fallthrough'], '00401238')
        self.assertEqual(branch['branch']['predicate'], 'ZF')
        self.assertEqual(branch['branch']['relation']['text'], 'EAX == 0x0')
        self.assertEqual(branch['branch']['relation']['setter'], '00401233')
        self.assertIn('Jumps to 0x00401200 when', branch['explanation'])
        self.assertIn('otherwise continues at 0x00401238', branch['explanation'])

    def test_condition_relation_table(self):
        neg = lambda flag, name: op('BOOL_NEGATE', tmp(name, 1), reg(flag, 1))
        cases = {
            'JNZ': ([neg('ZF', 'n')], tmp('n', 1), 'EAX != 0x0'),
            'JC': ([], reg('CF', 1), 'EAX < 0x0 (unsigned)'),
            'JBE': ([op('BOOL_OR', tmp('o', 1), reg('CF', 1), reg('ZF', 1))], tmp('o', 1), 'EAX <= 0x0 (unsigned)'),
            'JA': ([neg('CF', 'a'), neg('ZF', 'b'), op('BOOL_AND', tmp('c', 1), tmp('a', 1), tmp('b', 1))], tmp('c', 1),
                   'EAX > 0x0 (unsigned)'),
            'JL': ([op('INT_NOTEQUAL', tmp('l', 1), reg('OF', 1), reg('SF', 1))], tmp('l', 1), 'EAX < 0x0 (signed)'),
            'JGE': ([op('INT_EQUAL', tmp('g', 1), reg('OF', 1), reg('SF', 1))], tmp('g', 1), 'EAX >= 0x0 (signed)'),
            'JLE': ([op('INT_NOTEQUAL', tmp('x', 1), reg('OF', 1), reg('SF', 1)),
                     op('BOOL_OR', tmp('y', 1), reg('ZF', 1), tmp('x', 1))], tmp('y', 1), 'EAX <= 0x0 (signed)'),
            'JG': ([neg('ZF', 'p'), op('INT_EQUAL', tmp('q', 1), reg('OF', 1), reg('SF', 1)),
                    op('BOOL_AND', tmp('r', 1), tmp('p', 1), tmp('q', 1))], tmp('r', 1), 'EAX > 0x0 (signed)'),
        }
        for mnemonic, (ops_before, cond, expected) in cases.items():
            with self.subTest(mnemonic):
                record = analyze_instruction(cbranch('00401236', mnemonic, ops_before, cond), X64, previous=[CMP])
                self.assertEqual(record['branch']['relation']['text'], expected)

    def test_test_instruction_relation(self):
        test = ins('00401300', 'TEST', 'TEST AL,AL', [operand('AL', 'REG'), operand('AL', 'REG')],
                   [op('COPY', reg('CF', 1), const(0, 1)), op('COPY', reg('OF', 1), const(0, 1)),
                    op('INT_AND', tmp('t', 1), reg('AL', 1), reg('AL', 1)),
                    op('INT_SLESS', reg('SF', 1), tmp('t', 1), const(0, 1)), op('INT_EQUAL', reg('ZF', 1), tmp('t', 1), const(0, 1))])
        record = analyze_instruction(test, X64)
        self.assertEqual(record['category'], 'test')
        self.assertIn('Tests AL against itself', record['explanation'])
        branch = analyze_instruction(cbranch('00401302', 'JZ', [], reg('ZF', 1)), X64, previous=[test])
        self.assertEqual(branch['branch']['relation']['text'], 'AL == 0')

    def test_flags_from_predecessor_block_are_not_guessed(self):
        record = analyze_instruction(JE, X64, previous=[MOV_LOAD])
        self.assertIsNone(record['branch']['relation'].get('text'))
        self.assertTrue(any('predecessor block' in n for n in record['notes']))
        self.assertIn('ZF', record['explanation'])

    def test_call_return_and_abi_fallback(self):
        call = ins('00401240', 'CALL', 'CALL 0x00401500', [operand('0x00401500', 'ADDR', 'CODE')],
                   [op('INT_SUB', reg('RSP', 8), reg('RSP', 8), const(8, 8)),
                    op('STORE', None, const(0x1b1, 4), reg('RSP', 8), const(0x401245, 8)),
                    op('CALL', None, {'k': 'mem', 'sp': 'ram', 'a': '401500', 's': 8})],
                   length=5, flow='UNCONDITIONAL_CALL', targets=['00401500'], call=True)
        record = analyze_instruction(call, X64)
        self.assertEqual(record['call']['target_name'], 'helper')
        self.assertIn('Ghidra-recovered int', record['call']['return_storage'])
        no_sig = FunctionContext({}, {}, lambda a: None, 'x86:LE:64:default')
        self.assertIn('ABI convention', analyze_instruction(call, no_sig)['call']['return_storage'])

    def test_lea_pc_relative_and_push_pop(self):
        lea = ins('00401250', 'LEA', 'LEA RAX,[RIP + 0x10]', [operand('RAX', 'REG'), operand('[RIP + 0x10]', 'ADDR', 'DYN')],
                  [op('COPY', reg('RAX', 8), const(0x401267, 8))], length=7)
        record = analyze_instruction(lea, X64)
        self.assertEqual(record['category'], 'address_calculation')
        self.assertIn('0x401267', record['explanation'])
        self.assertIn('no memory is read', record['explanation'])
        push = ins('00401000', 'PUSH', 'PUSH RBP', [operand('RBP', 'REG')],
                   [op('COPY', tmp('u', 8), reg('RBP', 8)), op('INT_SUB', reg('RSP', 8), reg('RSP', 8), const(8, 8)),
                    op('STORE', None, const(0x1b1, 8), reg('RSP', 8), tmp('u', 8))], length=1)
        self.assertEqual(analyze_instruction(push, X64)['category'], 'stack_push')

    def test_strings_are_cited_with_their_value(self):
        mov = ins('004011ea', 'MOV', 'MOV EDI,0x402028', [operand('EDI', 'REG'), operand('0x402028', 'SCAL')],
                  [op('COPY', reg('EDI'), const(0x402028))], length=5)
        context = FunctionContext({}, {'004011ea': [{'kind': 'STRING', 'value': 'Input must contain', 'target': '00402028',
                                                    'reference_type': 'DATA'}]}, None, 'x86:LE:64:default')
        record = analyze_instruction(mov, context)
        self.assertIn('the string "Input must contain"', record['explanation'])
        self.assertEqual(record['constants'], [0x402028])

    def test_non_x86_is_generic_and_says_so(self):
        cmp_arm = ins('00010000', 'cmp', 'cmp r0,#0x0', [operand('r0', 'REG'), operand('#0x0', 'SCAL')],
                      [op('INT_SUB', tmp('t', 4), reg('r0'), const(0)), op('INT_EQUAL', reg('ZF', 1), tmp('t', 4), const(0))])
        branch = cbranch('00010004', 'beq', [], reg('ZF', 1))
        arm = FunctionContext({}, {}, None, 'ARM:LE:32:v8')
        relation = analyze_instruction(branch, arm, previous=[cmp_arm])['branch']['relation']
        self.assertEqual(relation['basis'], 'P-code flag predicate')
        self.assertIn('ZF', relation['text'])

    def test_function_windows_keep_block_history(self):
        document = {'instructions': [MOV_LOAD, CMP, JE],
                    'blocks': [{'start': '00401230', 'end': '00401237', 'succ': []}]}
        records = analyze_function(document, X64, start='00401236', limit=1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['branch']['relation']['text'], 'EAX == 0x0')

    def test_legacy_text_fallback_is_marked_low_confidence(self):
        document = legacy_document('00401000: CMP EAX,0x0\n00401003: JZ 0x00401200\n00401005: RET', 'x86:LE:64:default')
        records = analyze_function(document, FunctionContext(language='x86:LE:64:default'))
        self.assertEqual(document['source'], 'assembly_text')
        self.assertTrue(all(r['confidence'] == 'low' for r in records))
        self.assertEqual(records[1]['branch']['target'], '00401200')
        self.assertEqual(records[2]['category'], 'return')


class PersistenceTests(unittest.TestCase):
    def index(self, with_ir=True):
        b = 'f' * 64
        index = ProgramIndex(BinaryRecord(b, '/x', b, 'ELF', None, '0', None),
                             [FunctionRecord(f'{b}:1000', b, '1000', 'f', None, None, None, None, None, None)])
        if with_ir:
            index.function_ir = {f'{b}:1000': {'version': 1, 'instructions': [MOV_LOAD], 'blocks': []}}
        return index

    def test_ir_excluded_from_digest_and_equality(self):
        a, b = self.index(True), self.index(False)
        self.assertEqual(a, b)
        self.assertEqual(a.to_dict(), b.to_dict())
        self.assertNotIn('function_ir', a.to_dict())

    def test_table_created_lazily_and_loaded_per_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a.sqlite'
            with BinaryKnowledgeStore(path) as store:
                store.save_program_index(self.index(False))
                tables = {r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertNotIn('function_ir', tables)  # untouched without facts
                self.assertIsNone(store.load_function_ir('f' * 64, 'f' * 64 + ':1000'))
                store.save_program_index(self.index(True))
                self.assertEqual(store.load_function_ir('f' * 64, 'f' * 64 + ':1000')['instructions'][0]['a'], '00401230')
                store.save_program_index(self.index(False))  # replacement removes stale facts
                self.assertIsNone(store.load_function_ir('f' * 64, 'f' * 64 + ':1000'))
                self.assertTrue(store.delete_binary('f' * 64))


if __name__ == '__main__':
    unittest.main()


class ObjdumpTruthTests(unittest.TestCase):
    """The independent oracle itself (parsing + textbook relations)."""

    def test_memory_and_oracle(self):
        from aire.evaluation.objdump_truth import branch_oracle, memory_operand as om, normalize_mnemonic
        self.assertEqual(om('rcx,[rdi*8+0x8]'), {'base': None, 'disp': 8})
        self.assertEqual(om('eax,DWORD PTR [rbp-0x4]'), {'base': 'RBP', 'disp': -4})
        self.assertEqual(normalize_mnemonic('je'), 'jz')
        stream = [{'a': '1', 'm': 'cmp', 'ops': 'eax,0x1f', 'target': None},
                  {'a': '2', 'm': 'jbe', 'ops': '10', 'target': '00000010'},
                  {'a': '3', 'm': 'test', 'ops': 'al,al', 'target': None},
                  {'a': '4', 'm': 'mov', 'ops': 'eax,ebx', 'target': None},
                  {'a': '5', 'm': 'jle', 'ops': '10', 'target': '00000010'},
                  {'a': '6', 'm': 'call', 'ops': '20', 'target': '00000020'},
                  {'a': '7', 'm': 'jz', 'ops': '10', 'target': '00000010'}]
        oracle = branch_oracle(stream)
        self.assertEqual(oracle['2'], {'setter': '1', 'kind': 'cmp', 'operator': '<=', 'signedness': 'unsigned'})
        self.assertEqual(oracle['5']['operator'], '<=')
        self.assertEqual(oracle['5']['signedness'], 'signed')
        self.assertNotIn('7', oracle)  # a call intervenes: the oracle refuses to guess


class EvaluationFindingRegressionTests(unittest.TestCase):
    """Regressions for defects found by the Phase 6 evaluation."""

    def test_multibyte_nop_is_no_operation(self):
        nop = ins('00401100', 'NOP', 'NOP dword ptr [RAX + RAX*0x1]', [operand('dword ptr [RAX + RAX*0x1]', 'ADDR', 'DYN')], [], length=5)
        self.assertEqual(analyze_instruction(nop, X64)['category'], 'no_operation')

    def test_thunk_jump_is_tail_call(self):
        jmp = ins('00401030', 'JMP', 'JMP qword ptr [0x00404000]', [operand('qword ptr [0x00404000]', 'ADDR', 'DYN')],
                  [op('LOAD', tmp('t', 8), const(0x1b1, 4), const(0x404000, 8)), op('CALLIND', None, tmp('t', 8))],
                  length=6, flow='COMPUTED_CALL_TERMINATOR', targets=['EXTERNAL:00000001'], ft=None, call=True,
                  computed=True, term=True)
        record = analyze_instruction(jmp, X64)
        self.assertEqual(record['category'], 'tail_call')
        self.assertIn('tail jump', record['explanation'])
        self.assertNotIn('resumes', record['explanation'])

    def test_direct_ram_varnode_is_a_memory_read(self):
        mov = ins('00401200', 'MOV', 'MOV RAX,qword ptr [0x00420028]', [operand('RAX', 'REG'), operand('qword ptr [0x00420028]', 'ADDR', 'DYN')],
                  [op('COPY', reg('RAX', 8), {'k': 'mem', 'sp': 'ram', 'a': '420028', 's': 8})], length=8)
        record = analyze_instruction(mov, X64)
        self.assertEqual(record['category'], 'memory_load')
        self.assertEqual(record['reads']['memory']['kind'], 'global')

    def test_alu_with_memory_source_names_both_operands(self):
        orr = ins('00401300', 'OR', 'OR RAX,qword ptr [RBP + -0x8]', [operand('RAX', 'REG'), operand('qword ptr [RBP + -0x8]', 'ADDR', 'DYN')],
                  [op('INT_ADD', tmp('a'), reg('RBP', 8), const(-8, 8)), op('LOAD', tmp('v', 8), const(0x1b1, 4), tmp('a')),
                   op('INT_OR', reg('RAX', 8), reg('RAX', 8), tmp('v', 8)), op('INT_EQUAL', reg('ZF', 1), reg('RAX', 8), const(0, 8))])
        record = analyze_instruction(orr, X64)
        self.assertEqual(record['category'], 'memory_load')
        self.assertTrue(record['explanation'].startswith('Bitwise-ORs RAX with the qword (8 bytes) at RBP - 0x8'))

    def test_zeroing_is_not_a_read_in_data_flow(self):
        from aire.analysis import flow_analysis as fa
        xor = ins('00401400', 'XOR', 'XOR ECX,ECX', [operand('ECX', 'REG'), operand('ECX', 'REG')],
                  [op('INT_XOR', reg('ECX'), reg('ECX'), reg('ECX')), op('INT_EQUAL', reg('ZF', 1), reg('ECX'), const(0))], length=2)
        record = analyze_instruction(xor, X64)
        self.assertEqual(record['category'], 'zeroing')
        defs, uses = fa._defs_uses(record)
        self.assertEqual(uses, set())
        self.assertIn('RCX', defs)
