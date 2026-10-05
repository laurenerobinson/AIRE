from pathlib import Path
import tempfile
import unittest
from aire.agent.session import AgentSession


class SessionTests(unittest.TestCase):
    def test_pronoun_and_missing_selection(self):
        session = AgentSession('b')
        with self.assertRaises(ValueError):
            session.resolve_selector('it')
        session.current_function_id = 'b:a'
        self.assertEqual(session.resolve_selector('it'), 'b:a')
        self.assertEqual(session.resolve_selector('this function'), 'b:a')
        self.assertEqual(session.resolve_selector('named'), 'named')

    def test_bounds_persistence_and_isolation(self):
        session = AgentSession('b', 'b:a')
        for _ in range(30):
            session.remember('x' * 3000, 'answer', [{'binary_id': 'b', 'source_id': 'b:a'}])
        self.assertEqual(len(session.history), 8)
        self.assertEqual(len(session.history[0]['text']), 2000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.json'
            session.save(path)
            self.assertEqual(AgentSession.load(path, 'b').to_dict(), session.to_dict())
            with self.assertRaises(ValueError):
                AgentSession.load(path, 'other')
