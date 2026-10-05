import json
import unittest
from aire.agent.events import AgentEvent, EventStream


class EventTests(unittest.TestCase):
    def test_serialization_and_immediate_delivery(self):
        received = []
        stream = EventStream(received.append, lambda: '2026-10-04T00:00:00+00:00')
        event = stream.emit('tool_started', 'Executing tool', tool_name='get_function',
                            function={'function_id': 'b:a', 'current_name': 'start', 'address': '2'})
        self.assertEqual(received, [event])
        self.assertEqual(json.loads(json.dumps(event.to_dict()))['function_id'], 'b:a')

    def test_private_metadata_rejected(self):
        with self.assertRaises(ValueError):
            AgentEvent('progress', '2026-10-04T00:00:00+00:00', 'Progress', metadata={'reasoning': 'secret'})
        with self.assertRaises(ValueError):
            AgentEvent('thought', '2026-10-04T00:00:00+00:00', 'Private')
