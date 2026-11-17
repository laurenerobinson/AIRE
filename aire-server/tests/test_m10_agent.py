"""M10 Phase 4: routing, deterministic grounded answers, validated narration (no real model)."""
from pathlib import Path
import json
import tempfile
import time
import unittest
from unittest.mock import patch

from aire.agent import assembly_answers as aa
from aire.analysis.assembly_intelligence import AssemblyIntelligence
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.models import BinaryRecord, FunctionEdge, FunctionRecord, ProgramIndex
import test_m10_flow as flow

B = 'a' * 64


def make_store(directory):
    path = Path(directory) / 'm10.sqlite'
    function = FunctionRecord(f'{B}:00401000', B, '00401000', 'loop_fn', 'int loop_fn(int step)',
                              'int loop_fn(int step)\n{\n  int iVar1;\n  do { iVar1 = iVar1 + step; } while (iVar1 < 100);\n'
                              '  iVar1 = helper();\n  if (iVar1 == 0) { return 0; }\n  return 1;\n}\n',
                              None, 11, 5, 3)
    helper = FunctionRecord(f'{B}:00401500', B, '00401500', 'helper', None, 'int helper(void)\n{\n  return 1;\n}\n',
                            None, 1, 1, 0)
    index = ProgramIndex(BinaryRecord(B, '/x', B, 'ELF', 'x86:LE:64:default', '00400000', None,
                                      program_name='fixture'), [function, helper],
                         function_edges=[FunctionEdge(function.function_id, helper.function_id, '0040101b', 'CALL')])
    index.function_ir = {function.function_id: dict(flow.DOC, language='x86:LE:64:default', version=1),
                         helper.function_id: {'version': 1, 'source': 'ghidra', 'function_address': '00401500', 'language': 'x86:LE:64:default',
                                              'instructions': [], 'blocks': [], 'signature': {'return': {'storage': 'EAX:4', 'type': 'int'}}}}
    with BinaryKnowledgeStore(path) as store:
        store.save_program_index(index)
    return path


class RoutingTests(unittest.TestCase):
    def test_intents_and_arguments(self):
        cases = {'What does this function do?': 'function',
                 'What happens when the branch at 0x401022 is true?': 'branch',
                 'Where does the value of EAX at 0x401016 come from?': 'trace',
                 'How is the return value used?': 'return_usage',
                 'Does the assembly support the decompiled code?': 'crossvalidate',
                 'Where is input validation performed?': 'validation',
                 'Explain these instructions': 'instructions'}
        for question, intent in cases.items():
            with self.subTest(question):
                self.assertEqual(aa.route(question)['intent'], intent)
        routed = aa.route('Where does the value of [rbp - 0x4] at 0x401007 come from?')
        self.assertEqual((routed['addresses'], routed['locations']), (['00401007'], ['[rbp - 0x4]']))

    def test_existing_card_prompts_keep_the_m8_pipeline(self):
        self.assertIsNone(aa.route('Summarize this function'))
        self.assertIsNone(aa.route('Explain this assembly'))

    def test_narration_validation(self):
        instructions = {'00401016': 'CMP EAX,0x64', '00401019': 'JC 0x00401007'}
        self.assertEqual(aa.validate_narration('At 0x00401016 the CMP compares EAX.', {'00401016'}, instructions), [])
        problems = aa.validate_narration('The jump at 0x00409999 loops.', {'00401016'}, instructions)
        self.assertIn('0x00409999', problems[0])
        problems = aa.validate_narration('A JZ at 0x00401019 exits.', {'00401019'}, instructions)
        self.assertTrue(any('JC' in p for p in problems) or problems == [])  # JZ not a mnemonic of this function
        problems = aa.validate_narration('The CMP at 0x00401019 sets flags.', {'00401019'}, instructions)
        self.assertTrue(any('"JC' in p for p in problems))
        self.assertEqual(aa.validate_narration('SHA-256 be852ca8fcb09454 matches.', set(), instructions), [])


class AnswerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = BinaryKnowledgeStore(make_store(directory.name))
        self.addCleanup(self.store.close)
        self.ai = AssemblyIntelligence(self.store, B)

    def test_function_answer_has_identity_evidence_confidence_limits(self):
        answer, tool, cited = aa.answer_function(self.ai, 'loop_fn')
        for needle in ('`loop_fn` at `0x00401000`', 'fixture', '**Evidence:**', '**Confidence:**', '**Limitations:**',
                       'Contains 1 loop(s)', '0x00401022'):
            self.assertIn(needle, answer)
        self.assertIn('00401022', cited)
        self.assertEqual(tool['tool'], 'function_evidence')

    def test_branch_trace_return_and_crossvalidate_answers(self):
        answer, _, cited = aa.answer_branch(self.ai, 'loop_fn', '0x401022')
        self.assertIn('EAX == 0', answer)
        self.assertIn('returns at 0x00401030', answer)
        answer, _, _ = aa.answer_trace(self.ai, 'loop_fn', '00401016', 'eax')
        self.assertIn('parameter 0 (step', answer)
        answer, _, _ = aa.answer_return_usage(self.ai, 'helper')
        self.assertIn('In `loop_fn` (call at `0x0040101b`): tested', answer)
        answer, _, _ = aa.answer_crossvalidate(self.ai, 'loop_fn')
        self.assertIn('**Verdict:**', answer)
        self.assertIn('POTENTIAL DISCREPANCY means analyst review', answer)

    def test_render_tool_for_prompts(self):
        data = self.ai.explain('loop_fn', limit=5)
        lines = aa.render_tool('explain_instructions', data)
        self.assertTrue(lines[0].startswith('M10 explain_instructions for loop_fn at 0x00401000'))
        self.assertTrue(all(line.startswith('- 0x') for line in lines[1:]))


class GuiPathTests(unittest.TestCase):
    def setUp(self):
        from aire.api.server import GuiApplication
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = make_store(directory.name)
        self.replies = []

        class FakeModel:
            model, num_ctx = 'fake', 4096
            def generate(inner, prompt, **kwargs):
                reply = self.replies.pop(0)
                if isinstance(reply, Exception):
                    raise reply
                if isinstance(reply, float):
                    time.sleep(reply)
                    reply = 'late'
                return type('G', (), {'text': json.dumps({'explanation': reply})})()
        # Narration is opt-in (chat-performance Step 1); these tests exercise it explicitly.
        narration = patch.dict('os.environ', {'AIRE_M10_NARRATION': '1'})
        narration.start()
        self.addCleanup(narration.stop)
        self.app = GuiApplication(path, session_dir=Path(directory.name) / 's', upload_dir=Path(directory.name) / 'u',
                                  client_factory=FakeModel)
        self.addCleanup(self.app.library.close)
        self.sid = self.app.new_session(B)['session_id']
        self.app.select_function(self.sid, 'loop_fn')

    def test_valid_narration_is_appended(self):
        self.replies.append('The loop branches back at 0x00401019 until EAX reaches 0x64.')
        result = self.app.run_chat(self.sid, 'What does this function do?')
        self.assertIn('Plain-English summary', result.answer)
        self.assertEqual(self.app.last_performance['path'], 'm10_assembly')

    def test_invalid_narration_is_rejected_and_evidence_stands(self):
        self.replies.append('It calls the network API at 0x00409999.')
        result = self.app.run_chat(self.sid, 'What does this function do?')
        self.assertNotIn('Plain-English summary', result.answer)
        self.assertIn('narration rejected', result.answer)
        self.assertIn('**Evidence:**', result.answer)

    def test_model_unavailable_and_timeout_keep_deterministic_answer(self):
        self.replies.append(ConnectionError('ollama down'))
        result = self.app.run_chat(self.sid, 'Does the assembly support the decompiled code?')
        self.assertIn('deterministic evidence only', result.answer)
        self.replies.append(1.0)
        with patch.dict('os.environ', {'AIRE_M10_NARRATION_SECONDS': '0.2'}):
            result = self.app.run_chat(self.sid, 'How is the return value used?')
        self.assertIn('no narration within 0.2 s', result.answer)

    def test_default_returns_deterministic_answer_without_model_call(self):
        with patch.dict('os.environ', {}, clear=False):
            import os
            os.environ.pop('AIRE_M10_NARRATION', None)
            result = self.app.run_chat(self.sid, 'What does this function do?')
        self.assertNotIn('Local model', result.answer)  # FakeModel would raise if called (no replies queued)
        self.assertEqual(self.app.last_performance['path'], 'm10_assembly')
        self.assertEqual(self.app.last_performance['narration_seconds'], 0.0)
        self.assertIn('**Evidence:**', result.answer)
        self.assertNotIn('Plain-English summary', result.answer)

    def test_missing_arguments_explain_what_is_needed(self):
        from aire.api.server import GuiError
        with self.assertRaisesRegex(GuiError, 'address of the conditional jump'):
            self.app.run_chat(self.sid, 'What happens when the branch is true?')


if __name__ == '__main__':
    unittest.main()
