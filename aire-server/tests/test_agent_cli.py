from pathlib import Path
import tempfile
import unittest

from aire.agent.cli import main, render_event
from aire.agent.events import AgentEvent
from aire.knowledge.database import BinaryKnowledgeStore
from test_agent_runner import AgentModel, tool
from test_retrieval import fixture


class CliTests(unittest.TestCase):
    def test_interactive_activity_and_persisted_follow_up(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'analysis.sqlite'
            session = Path(directory) / 'session.json'
            with BinaryKnowledgeStore(database) as store:
                index, _ = fixture()
                store.save_program_index(index)
            before = database.read_bytes()
            output = []
            model = AgentModel([tool('get_function', function='start')])
            status = main(['chat', 'b', '--database', str(database), '--session', str(session),
                           '--question', 'Explain start'], client=model, output=output.append)
            self.assertEqual(status, 0)
            self.assertLess(next(i for i, v in enumerate(output) if '[TOOL]' in v),
                            next(i for i, v in enumerate(output) if 'A.I.R.E.:' in v))
            model = AgentModel([tool('get_callers', function='it')])
            self.assertEqual(main(['chat', 'b', '--database', str(database), '--session', str(session),
                                   '--question', 'What calls it?'], client=model, output=output.append), 0)
            self.assertEqual(database.read_bytes(), before)

    def test_missing_database_and_bad_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'missing.sqlite'
            self.assertEqual(main(['chat', 'b', '--database', str(database)],
                                   client=AgentModel(), output=lambda _: None), 1)
            self.assertFalse(database.exists())

    def test_renderer_escapes_controls(self):
        event = AgentEvent('function_selected', '2026-10-04T00:00:00+00:00', 'Selected',
                           function_id='b:a', function_name='evil\x1b[2J')
        self.assertNotIn('\x1b', render_event(event))
