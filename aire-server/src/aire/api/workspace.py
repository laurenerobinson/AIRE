"""Bounded, binary-scoped memoization over the existing read-only AgentTools.

No SQLite connections cross threads. A workspace stores values, not a second
analysis engine. The application replaces workspaces when DB/WAL stamps change.
"""
from collections import OrderedDict
from copy import deepcopy
import json
import threading
import time

from aire.agent.tools import AgentTools, Tool, ToolRegistry, serializable
from aire.ai.context_builder import ContextBuilder
from aire.ai.evidence_selector import OverviewContextBuilder
from aire.knowledge.evidence import EvidenceRequest
from aire.knowledge.application_relevance import RELEVANCE_POLICY_VERSION, ELIGIBLE
from aire.analysis.function_crosscheck import CROSSCHECK_POLICY_VERSION


class WorkspaceOverviewBuilder(OverviewContextBuilder):
    """GUI uses the same relevance policy and bounded selection as CLI."""


class BinaryWorkspace:
    MAX_ENTRIES = 128
    MAX_BYTES = 4_000_000

    def __init__(self, store, binary_id):
        self.binary_id = binary_id
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.lock = threading.RLock()
        self.hits = self.misses = 0
        self.overview_answers = OrderedDict()
        tools = self.tools(store)
        self.metadata = tools.registry.run('binary_metadata', {})['data']
        self.sha256 = self.metadata['binary']['sha256']
        self.preloaded = []
        for name, args in (
            ('list_functions', {'limit': 100}),
            ('rank_functions', {'metric': 'unique_callees', 'limit': 10}),
            ('rank_application_functions', {'limit': 10}),
            ('get_artifacts', {'kind': 'IMPORT', 'limit': 20}),
            ('get_artifacts', {'kind': 'STRING', 'limit': 20}),
            ('get_artifacts', {'kind': 'EXPORT', 'limit': 10}),
            ('security_findings', {}),
        ):
            self.preloaded.append(tools.registry.run(name, args))
        self.seed_ids = []
        ranking = next(r for r in self.preloaded if r['tool'] == 'rank_application_functions')
        if ranking['ok']:
            for row in ranking['data']['items']:
                f = row['function']
                if row['classification'] in ELIGIBLE and f['function_id'] not in self.seed_ids:
                    self.seed_ids.append(f['function_id'])
                if len(self.seed_ids) >= 2:
                    break
        tools.overview_seeds = tuple(self.seed_ids)
        if self.seed_ids:
            self.preloaded.append(tools.registry.run('get_callees', {'function': self.seed_ids[0], 'limit': 12}))
        # Prepare bounded code for overview seeds only; never all function bodies.
        tools.registry.run('retrieve_evidence', {'max_chars': 8000})

    def tools(self, store, *, assembly=False):
        return CachedAgentTools(store, self, assembly=assembly)

    def overview_preview(self):
        """Immediate useful structure while model interpretation is generated."""
        name = self.metadata['binary'].get('program_name') or 'Selected binary'
        lines = [f"{name}: {self.metadata['counts']['functions']} stored functions."]
        graph = next((r for r in self.preloaded if r['tool'] == 'get_callees' and r['ok']), None)
        if graph:
            caller = graph['data']['selected_function']['function']['current_name']
            callees = list(dict.fromkeys(e['callee']['function']['current_name'] for e in graph['data']['items']))
            lines.append(f"Stored CALL graph: {caller} calls {', '.join(callees[:8])}.")
        lines.append('Preparing a behavioral interpretation from bounded static code and relationships…')
        return '\n'.join(lines)

    def memo(self, key, producer):
        with self.lock:
            if key in self.cache:
                self.hits += 1
                self.cache.move_to_end(key)
                return deepcopy(self.cache[key][0])
            self.misses += 1
            value = producer()
            size = len(json.dumps(value[0], ensure_ascii=True))
            if size <= self.MAX_BYTES and value[0].get('ok'):
                while self.cache and (len(self.cache) >= self.MAX_ENTRIES or self.cache_bytes + size > self.MAX_BYTES):
                    _, (_, old_size) = self.cache.popitem(last=False)
                    self.cache_bytes -= old_size
                self.cache[key] = (deepcopy(value), size)
                self.cache_bytes += size
            return value


class CachedAgentTools(AgentTools):
    """Wrap validated tool executions; cache keys use validated default arguments."""
    def __init__(self, store, workspace, *, assembly=False):
        super().__init__(store, workspace.binary_id)
        self.workspace = workspace
        self.assembly_requested = assembly
        self.overview_seeds = tuple(getattr(workspace, 'seed_ids', ()))
        self.retrieval_seconds = self.evidence_seconds = 0.0
        original = self.registry
        self.registry = ToolRegistry()
        for name, tool in original._tools.items():
            def execute(_name=name, **values):
                tick = time.perf_counter()
                if _name == 'crosscheck_function':
                    # Equivalent exact selectors share a stable function identity.
                    selected = self.registry.run('get_function', {'function': values['function']})
                    if not selected['ok']:
                        # Preserve the normal query exception type at the registry boundary.
                        self.query.resolve_function(self.binary_id, values['function'])
                    values['function'] = selected['data']['function']['function_id']
                key = json.dumps([workspace.binary_id, RELEVANCE_POLICY_VERSION, CROSSCHECK_POLICY_VERSION, _name, values,
                    self.overview_seeds if _name == 'retrieve_evidence' else (),
                    self.crosscheck_selectors if _name == 'retrieve_evidence' else (),
                    self.assembly_requested if _name == 'retrieve_evidence' else False],
                    sort_keys=True, separators=(',', ':'))
                def produce():
                    data = serializable(original._tools[_name].execute(**values))
                    result = {'ok': True, 'tool': _name, 'data': data}
                    if len(json.dumps(data, ensure_ascii=True)) > 100000:
                        return {'ok': False, 'tool': _name, 'error': {
                            'code': 'result_limit', 'message': 'Result exceeds serialization budget'}}, None
                    return result, self.last_evidence if _name == 'retrieve_evidence' else None
                result, bundle = workspace.memo(key, produce)
                elapsed = time.perf_counter() - tick
                if _name == 'retrieve_evidence':
                    self.last_evidence = bundle
                    self.evidence_seconds += elapsed
                else:
                    self.retrieval_seconds += elapsed
                if not result['ok']:
                    # Registry preserves safe tool failures rather than caching them.
                    raise ValueError(result['error']['message'])
                return result['data']
            self.registry.register(Tool(name, tool.description, tool.parameters, execute))

    def evidence(self, function=None, max_chars=8000):
        tick = time.perf_counter()
        builder = ContextBuilder(self.store) if function else WorkspaceOverviewBuilder(
            self.store, seed_functions=self.overview_seeds)
        # M4's audit renderer is verbose. Give it room to retain bounded source
        # bodies; the compact model prompt has its own smaller admission budget.
        request = EvidenceRequest(self.binary_id, function,
            max_functions=6, max_edges=12 if function else 20,
            max_references=8, max_thunks=4,
            max_artifacts=12, include_exports=True, max_total_chars=60000,
            max_decompiled_chars_per_function=2400 if function else 900,
            include_assembly=self.assembly_requested,
            max_assembly_chars_per_function=1800 if self.assembly_requested else 0)
        data = self._build_evidence(builder, request, prompt_chars=min(max_chars, 5000), omit_rendered_text=True)
        self.last_evidence.metadata['workspace_build_seconds'] = time.perf_counter() - tick
        data['metadata']['workspace_build_seconds'] = self.last_evidence.metadata['workspace_build_seconds']
        # The legacy rendered audit text duplicates structured records and can
        # exceed the registry's 100 KB limit. It remains in the final response's
        # EvidenceBundle; retrieval returns the full structured source records.
        return data
