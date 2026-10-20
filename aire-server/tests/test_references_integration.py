"""One real Program lifecycle, reference persistence, and offline demo consumers."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
from aire.knowledge.retrieval import ProgramQueryService
from aire.knowledge.investigation import InvestigationService
from aire.ai.context_builder import ContextBuilder
from aire.knowledge.evidence import EvidenceRequest
from aire.agent.tools import AgentTools
from aire.api.workspace import BinaryWorkspace
from aire.profiling import AnalysisProfile
from aire.pyghidra.references import extract_references

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('AIRE_RUN_GHIDRA_TESTS') == '1', 'Opt-in Ghidra integration')
class ReferenceIntegrationTests(unittest.TestCase):
    def test_same_analyzed_program_pe_and_elf_with_one_import_each(self):
        import pyghidra
        samples = [
            ('professor_samples/function_overloading/original/FunctionOverloading.exe',
             'demoL_function_overloading.py'),
            ('professor_samples/function_overloading_elf/original/FunctionOverloading',
             'demo_function_overloading.py'),
        ]
        for relative, demo_name in samples:
            path = ROOT / relative
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.subTest(binary=relative), tempfile.TemporaryDirectory() as directory:
                with BinaryKnowledgeStore(Path(directory) / 'analysis.sqlite') as store:
                    with patch('pyghidra.analyze', wraps=pyghidra.analyze) as analyze:
                        with patch('pyghidra.open_project', wraps=pyghidra.open_project) as project:
                            with patch('pyghidra.program_loader', wraps=pyghidra.program_loader) as loader:
                                with patch('aire.pyghidra.indexer.extract_references', wraps=extract_references) as extract:
                                    with AnalysisProfile() as profile:
                                        fresh = analyze_binary(path, store, force=True)
                    self.assertEqual(project.call_count, 1)
                    self.assertEqual(loader.call_count, 1)
                    self.assertEqual(analyze.call_count, 1)
                    self.assertIs(extract.call_args.args[0], analyze.call_args.args[0])
                    for counter in ('projects_created', 'executable_imports', 'analyze_calls', 'xref_collection_calls'):
                        self.assertEqual(profile.counts[counter], 1)
                    index = fresh.program_index
                    self.assertTrue(index.references)
                    self.assertTrue(index.program_info)
                    self.assertEqual(profile.counts['decompile_attempts'],
                                     sum(not function.is_external for function in index.functions))
                    self.assertEqual(profile.to_dict()['repeated_decompilations'], {})
                    query = ProgramQueryService(store)
                    for edge in index.function_edges[:10]:
                        self.assertTrue(any(item.callsite_address == edge.callsite_address for item in
                                            query.get_callees(index.binary.binary_id, edge.caller_function_id)))
                        self.assertTrue(any(item.callsite_address == edge.callsite_address for item in
                                            query.get_callers(index.binary.binary_id, edge.callee_function_id)))
                    with patch('aire.analysis.cache.index_binary', side_effect=AssertionError('Cache indexed')):
                        cached = analyze_binary(path, store)
                    self.assertTrue(cached.cache_hit)
                    self.assertEqual(cached.program_index, index)
                    spec = importlib.util.spec_from_file_location('reference_demo', ROOT / 'scripts' / demo_name)
                    demo = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(demo)
                    with patch('pyghidra.open_project', side_effect=AssertionError('Demo opened project')):
                        with patch('pyghidra.analyze', side_effect=AssertionError('Demo analyzed')):
                            strings, thunks, info, constants = demo.collect_xrefs(cached.program_index)
                    for value in demo.STRINGS[:2]:
                        matches = [string for string in strings if string['value'] == value]
                        self.assertEqual(len(matches), 1)
                        self.assertTrue(matches[0]['xrefs'])
                        self.assertEqual(len({ref['function'] for ref in matches[0]['xrefs'] if ref['function']}), 1)
                    if demo_name == 'demoL_function_overloading.py':
                        self.assertEqual(constants.hex(), '0000000000001e40')
                        self.assertTrue(any(thunk['target'] == '00412620' for thunk in thunks))
                        self.assertTrue(any(thunk['target'] == '004126c0' for thunk in thunks))
                        investigation = InvestigationService(store)
                        agent_tools = AgentTools(store, index.binary.binary_id)
                        bid = index.binary.binary_id
                        for owner, source, destination in (
                            ('00412620', '00412653', '00419b38'),
                            ('004126c0', '004126fc', '00419b50'),
                            ('00412790', '00412857', '00419b68'),
                        ):
                            local = investigation.references(bid, owner, strings_only=True, limit=100)
                            self.assertTrue(any(r['reference']['source_address'] == source and
                                                r['reference']['target_address'] == destination for r in local['items']))
                            bundle = ContextBuilder(store).build(EvidenceRequest(bid, owner, max_total_chars=16000))
                            self.assertTrue(any(r.reference.source_address == source for r in bundle.references))
                            self.assertTrue(any(a.artifact.address == destination and a.scope == 'function-reference'
                                                for a in bundle.artifacts))
                            tool_result = agent_tools.registry.run('retrieve_evidence', {'function': owner})
                            self.assertTrue(tool_result['ok'], tool_result)
                            self.assertTrue(tool_result['data']['references'])
                        overview = agent_tools.registry.run('retrieve_evidence', {})
                        self.assertTrue(overview['ok'], overview)
                        workspace = BinaryWorkspace(store, bid)
                        cached_tools = workspace.tools(store)
                        for owner in ('00412620', None):
                            gui_evidence = cached_tools.registry.run('retrieve_evidence', {'function': owner})
                            self.assertTrue(gui_evidence['ok'], gui_evidence)
                        calls = query.get_callees(bid, '00412790')
                        for site, thunk, body in (('004127ba', '00411028', '00412620'),
                                                  ('00412802', '004110cd', '004126c0')):
                            self.assertTrue(any(c.callsite_address == site and c.callee.address == thunk for c in calls))
                            self.assertFalse(any(c.callee.address == body for c in calls))
                            chain = investigation.thunk_chain(bid, thunk)
                            self.assertEqual(chain['hops'][0]['binding']['target_address'], body)
                            self.assertEqual(chain['hops'][0]['relationship'], 'VERIFIED_DIRECT_JUMP')
                    else:
                        self.assertEqual(info['ELF DF_1_PIE'], 'true')
                        self.assertTrue(info['ELF interpreter'])
                        self.assertTrue(any(read['raw'].hex() == '0000000000001e40'
                                            for reads in constants.values() for read in reads))
                    self.assertFalse(any('Reference from' in warning or 'References at' in warning
                                         for warning in index.warnings), index.warnings)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
