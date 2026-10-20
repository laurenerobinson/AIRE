"""Static-only validation against the existing small ELF fixtures."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from aire.analysis.cache import analyze_binary
from aire.agent.tools import AgentTools
from aire.ai.context_builder import ContextBuilder
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.evidence import EvidenceRequest
from aire.security.rule_engine import _ReadOnlyRuleStore

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class InvestigationIntegrationTests(unittest.TestCase):
    def test_existing_debug_and_stripped_elf_static_evidence(self):
        for name in ('aire_test_binary', 'aire_test_binary_stripped'):
            target = ROOT / 'tests/fixtures/simple_elf' / name
            before = hashlib.sha256(target.read_bytes()).hexdigest()
            with self.subTest(binary=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'facts.sqlite'
                with BinaryKnowledgeStore(path) as store:
                    fresh = analyze_binary(target, store, force=True)
                    index = fresh.program_index
                    string_ids = {a.artifact_id for a in index.artifacts if a.type == 'STRING'}
                    reference = next(r for r in index.references if r.source_function_id and r.target_artifact_id in string_ids)
                    function = reference.source_function_id
                    cached = analyze_binary(target, store)
                    self.assertTrue(cached.cache_hit)
                    self.assertEqual(cached.program_index, index)
                with _ReadOnlyRuleStore(path) as store:
                    tools = AgentTools(store, index.binary.binary_id)
                    result = tools.registry.run('get_function_strings', {'function': function, 'limit': 100})
                    self.assertTrue(result['ok'], result)
                    self.assertTrue(any(i['reference']['reference_id'] == reference.reference_id for i in result['data']['items']))
                    bundle = ContextBuilder(store).build(EvidenceRequest(index.binary.binary_id, function, max_total_chars=16000))
                    self.assertTrue(bundle.references)
                    self.assertTrue(any(a.scope == 'function-reference' for a in bundle.artifacts))
                    self.assertEqual(store.load_program_index(index.binary.binary_id), index)
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)
