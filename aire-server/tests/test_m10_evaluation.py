"""Keep M10 evaluation strict while recognizing stored tail-call/data evidence."""
import importlib
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
try:
    evaluation = importlib.import_module('evaluate_m10_full')
finally:
    sys.path.pop(0)


class EvaluationTests(unittest.TestCase):
    def test_stripped_value_origin_is_compared_by_ground_truth_address(self):
        symbols = {'00401000': 'secret_operation', '00402000': 'add_values',
                   '00403000': 'calculate_checksum'}
        call = {'category': 'call', 'address': '00401010',
                'call': {'target': '00402000', 'target_name': 'FUN_00402000'}}
        source = {'origin': 'call_result', 'call': {'target': '00403000', 'target_name': 'FUN_00403000'}}
        ai = SimpleNamespace(explain=lambda *_, **__: {'instructions': [call]},
                             trace=lambda *_: {'trace': {'definitions': [source]}})
        functions = [('f', '00401000', 'FUN_00401000', False)]
        result = evaluation.origin_checks(ai, functions, symbols)
        self.assertEqual(result[1]['outcome'], 'correct')
        source['call'] = {'target': '00404000', 'target_name': 'FUN_00404000'}
        self.assertEqual(evaluation.origin_checks(ai, functions, symbols)[1]['outcome'], 'incorrect_or_missing')

    def test_cfg_tail_target_is_checked_without_an_internal_successor(self):
        instruction = {'a': '00401000', 'm': 'jmp', 'target': '00402000'}
        document = {'instructions': [instruction]}
        record = SimpleNamespace(function_id='f')
        graph = {'blocks': [{'start': '00401000', 'end': '00401000',
                             'successors': [], 'leaves_function': []}]}
        tail = {'address': '00401000', 'category': 'tail_call', 'call': {'target': '00402000'}}
        ai = SimpleNamespace(cfg=lambda _: {'cfg': graph}, resolve=lambda _: record,
                             document=lambda _: document, semantics=lambda *_: [tail])
        with patch.object(evaluation, 'disassemble', return_value={'f': document}):
            result = evaluation.cfg_checks(ai, Path('unused'), [('f', '00401000', 'f', False)])
            self.assertEqual(result['jump_rate'], 1.0)
            self.assertEqual(result['mismatches'], [])
            # A tail-call label must never excuse the wrong destination.
            tail['call']['target'] = '00403000'
            result = evaluation.cfg_checks(ai, Path('unused'), [('f', '00401000', 'f', False)])
            self.assertEqual(result['jump_rate'], 0.0)
            self.assertEqual(len(result['mismatches']), 1)

    def test_citation_oracle_accepts_stored_data_reference_but_rejects_invention(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript('''
                CREATE TABLE functions(binary_id TEXT,address TEXT);
                CREATE TABLE artifacts(binary_id TEXT,address TEXT);
                CREATE TABLE binary_references(binary_id TEXT,target_address TEXT);
                INSERT INTO functions VALUES('binary','00401000');
                INSERT INTO binary_references VALUES('binary','00404030');
            ''')
            literal = {'category': 'data_move', 'constants': [0x404050],
                       'reads': {'memory': None}, 'writes': {'memory': None}}
            ai = SimpleNamespace(resolve=lambda _: None,
                                 document=lambda _: {'instructions': [{'a': '00401000'}]},
                                 explain=lambda *_, **__: {'instructions': [literal]})
            with patch.object(evaluation.aa, 'answer_function', return_value=(
                    'Stored global 0x00404030; immediate 0x404050; invented 0xdeadbeef', None, set())), \
                 patch.object(evaluation.aa, 'answer_crossvalidate', return_value=('', None, set())):
                result = evaluation.citation_checks(ai, SimpleNamespace(_db=db),
                    SimpleNamespace(binary_id='binary'), [('f', '00401000', 'f', False)])
            self.assertEqual(result['citations'], 3)
            self.assertEqual(result.get('valid', 0), 2)
            self.assertEqual(result['literal_occurrences'], 1)
            self.assertEqual(result['invalid_examples'], [('f', 'deadbeef')])


if __name__ == '__main__':
    unittest.main()
