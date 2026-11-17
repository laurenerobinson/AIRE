"""Local static-analysis web application for the A.I.R.E. binary analysis agent.

The HTTP boundary deliberately stays in the Python standard library. Analysis
facts are investigated through the same read-only M8 AgentTools/AgentRunner used
by the CLI. Validated intake uses a separate serialized index worker. GUI
conversation files and uploaded binaries live separately from analysis facts.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from collections import OrderedDict
from copy import deepcopy
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
import logging
from http.cookies import CookieError, SimpleCookie
from urllib.parse import parse_qs, urlparse
from uuid import uuid4
import webbrowser

from aire.agent.binary_scope import resolve_binary
from aire.agent.runner import AgentLimits, AgentResult, AgentRunner
from aire.agent.session import AgentSession
from aire.agent.tools import AgentTools, serializable
from aire.ai.ollama_client import OllamaClient
from aire.security.rule_engine import _ReadOnlyRuleStore
from aire.api.workspace import BinaryWorkspace
from aire.api.chat_presentation import present
from aire.agent.events import EventStream
from aire.agent.runner import _binary_overview
from aire.knowledge.application_relevance import RELEVANCE_POLICY_VERSION
from aire.analysis.function_crosscheck import CROSSCHECK_POLICY_VERSION
from aire.security.crypto_evidence import EVIDENCE_VERSION as CRYPTO_EVIDENCE_VERSION
from aire.api.binary_library import BinaryLibrary, MAX_UPLOAD, redact_paths
from aire.knowledge.database import KnowledgeStoreError

_LOG = logging.getLogger('aire.performance')

_STATIC_DIR = Path(__file__).with_name('static')
_SESSION_RE = re.compile(r'^[0-9a-f]{32}$')
_MAX_BODY = 1_000_000
_MAX_TRANSCRIPT_MESSAGES = 80
_MAX_TRANSCRIPT_TEXT = 60_000
_SOCKET_TIMEOUT = 60  # seconds; a stalled client must not hold a handler thread forever
_ERROR_LOG = logging.getLogger('aire.gui')
_MAX_CONCURRENT_CHATS = 4  # expensive model/agent work; excess requests get 429, not a queued thread
# Exact Host/Origin authorities: no other loopback spellings, no DNS names.
_AUTHORITY_RE = re.compile(r'^(localhost|127\.0\.0\.1)(?::([0-9]{1,5}))?$', re.IGNORECASE)
_TOKEN_QUERY_RE = re.compile(r'(token=)[^&\s"]+')
_TOKEN_HEADER = 'X-AIRE-Token'


def _public_error(exc):
    """(name, message) safe to return to a client. Application errors keep their
    curated message; OS errors drop file paths; anything else is generic and logged."""
    if isinstance(exc, (GuiError, ValueError, KnowledgeStoreError)):
        return type(exc).__name__, redact_paths(str(exc))[:500] or type(exc).__name__
    if isinstance(exc, OSError):
        return type(exc).__name__, exc.strerror or 'Operating system error'
    _ERROR_LOG.error('Unhandled GUI request error', exc_info=exc)
    return 'InternalError', 'Internal server error; details were written to the server log'


class GuiError(RuntimeError):
    """Safe local-GUI request error."""


@dataclass(frozen=True)
class GuiModelConfig:
    host: str | None = None
    model: str | None = None
    num_ctx: int | None = None
    # Set only from the CLI flag / environment at launch; no request can change it.
    allow_remote_host: bool = False


class GuiSessionStore:
    """Persist agent state and UI transcript outside the analysis database."""

    def __init__(self, directory):
        self.directory = Path(directory).expanduser().resolve()
        # Transcripts can contain analyst questions: owner-only on creation.
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._guard = threading.RLock()
        self._session_locks = {}
        self._agents = OrderedDict()

    def _validate_id(self, session_id):
        if not isinstance(session_id, str) or not _SESSION_RE.fullmatch(session_id):
            raise GuiError('Invalid session id')
        return session_id

    def _agent_path(self, session_id):
        return self.directory / (self._validate_id(session_id) + '.agent.json')

    def _transcript_path(self, session_id):
        return self.directory / (self._validate_id(session_id) + '.transcript.json')

    @contextmanager
    def lock(self, session_id):
        self._validate_id(session_id)
        with self._guard:
            lock = self._session_locks.setdefault(session_id, threading.RLock())
        with lock:
            yield

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _atomic_json(path, data):
        encoded = json.dumps(data, ensure_ascii=True, allow_nan=False)
        temporary = path.with_name(path.name + '.tmp')
        temporary.unlink(missing_ok=True)
        # Transcripts hold analyst questions and model answers: owner-only regardless of umask.
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as out:
            out.write(encoded)
        temporary.replace(path)

    def create(self, binary_id):
        if not isinstance(binary_id, str) or not binary_id:
            raise GuiError('Session requires a binary id')
        session_id = uuid4().hex
        now = self._now()
        AgentSession(binary_id).save(self._agent_path(session_id))
        self._atomic_json(self._transcript_path(session_id), {
            'session_id': session_id,
            'binary_id': binary_id,
            'created_at': now,
            'updated_at': now,
            'messages': [],
        })
        return session_id

    def load_agent(self, session_id, binary_id=None):
        path = self._agent_path(session_id)
        if not path.exists():
            raise GuiError('Session not found')
        if path.stat().st_size > 100_000:
            raise GuiError('Session state exceeds size limit')
        stamp = (path.stat().st_mtime_ns, path.stat().st_size)
        with self._guard:
            cached = self._agents.get(session_id)
            if cached and cached[0] == stamp:
                if binary_id:
                    cached[1].require_binary(binary_id)
                self._agents.move_to_end(session_id)
                return deepcopy(cached[1])
        if binary_id is None:
            payload = json.loads(path.read_text(encoding='utf-8'))
            binary_id = payload.get('binary_id')
        agent = AgentSession.load(path, binary_id)
        with self._guard:
            self._agents[session_id] = (stamp, deepcopy(agent))
            while len(self._agents) > 128:
                self._agents.popitem(last=False)
        return agent

    def save_agent(self, session_id, session):
        session.save(self._agent_path(session_id))
        path = self._agent_path(session_id)
        with self._guard:
            self._agents[session_id] = ((path.stat().st_mtime_ns, path.stat().st_size), deepcopy(session))
            while len(self._agents) > 128:
                self._agents.popitem(last=False)

    def _load_transcript(self, session_id):
        path = self._transcript_path(session_id)
        if not path.exists():
            raise GuiError('Session transcript not found')
        if path.stat().st_size > 5_000_000:
            raise GuiError('Session transcript exceeds size limit')
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('session_id') != session_id or not isinstance(data.get('messages'), list):
            raise GuiError('Invalid session transcript')
        return data

    def append_exchange(self, session_id, question, answer, status, presentation=None):
        data = self._load_transcript(session_id)
        now = self._now()
        data['messages'].extend([
            {'role': 'user', 'text': str(question)[:_MAX_TRANSCRIPT_TEXT], 'timestamp': now},
            {'role': 'assistant', 'text': str(answer)[:_MAX_TRANSCRIPT_TEXT],
             'timestamp': now, 'status': str(status)[:64]},
        ])
        if presentation:
            data['messages'][-1]['presentation'] = presentation
        data['messages'] = data['messages'][-_MAX_TRANSCRIPT_MESSAGES:]
        while len(data['messages']) > 2 and len(json.dumps(data, ensure_ascii=True)) > 4_000_000:
            data['messages'] = data['messages'][2:]
        data['updated_at'] = now
        self._atomic_json(self._transcript_path(session_id), data)
        return data

    def get(self, session_id):
        data = self._load_transcript(session_id)
        agent = self.load_agent(session_id, data['binary_id'])
        data['current_function_id'] = agent.current_function_id
        return data

    def list(self, binary_id=None):
        rows = []
        for path in self.directory.glob('*.transcript.json'):
            session_id = path.name.split('.', 1)[0]
            if not _SESSION_RE.fullmatch(session_id):
                continue
            try:
                data = self._load_transcript(session_id)
            except (OSError, ValueError, GuiError):
                continue
            if binary_id and data.get('binary_id') != binary_id:
                continue
            messages = [m for m in data.get('messages', [])
                        if isinstance(m, dict) and m.get('role') in ('user', 'assistant')
                        and isinstance(m.get('text'), str)]
            if not messages:
                continue
            first = next((m['text'] for m in messages if m['role'] == 'user'), 'Analysis chat')
            last = messages[-1]['text'] if messages else ''
            rows.append({
                'session_id': session_id,
                'binary_id': data.get('binary_id'),
                'title': first.strip().replace('\n', ' ')[:80] or 'Analysis chat',
                'preview': last.strip().replace('\n', ' ')[:140],
                'updated_at': data.get('updated_at'),
            })
        rows.sort(key=lambda row: row.get('updated_at') or '', reverse=True)
        return rows


class GuiApplication:
    """Application boundary used by HTTP handlers and unit tests."""

    def __init__(self, database, *, initial_binary=None, session_dir=None,
                 model_config=None, limits=None, client_factory=None, upload_dir=None,
                 repository=None):
        self.database = Path(database).expanduser().resolve()
        if not self.database.is_file():
            raise GuiError(f'Analysis database not found: {self.database}')
        self.sessions = GuiSessionStore(session_dir or Path.home() / '.aire' / 'gui-sessions')
        self.model_config = model_config or GuiModelConfig()
        self.limits = limits or AgentLimits()
        self.client_factory = client_factory
        self._shared_client = None
        self._workspace_lock = threading.RLock()
        self._workspaces = OrderedDict()
        self._database_stamp = None
        self.last_performance = {}  # Development instrumentation, never a UI footer.
        self.library = BinaryLibrary(self.database, directory=upload_dir, repository=repository)
        if os.environ.get('AIRE_GUI_PERFORMANCE') == '1':
            _LOG.setLevel(logging.INFO)
            if not _LOG.handlers:
                _LOG.addHandler(logging.StreamHandler())
            _LOG.propagate = False
        with self.store() as store:
            binaries = store.list_binaries()
            selected = resolve_binary(store, initial_binary) if initial_binary else (binaries[0] if binaries else None)
            self.initial_binary_id = selected.binary_id if selected else None

    @contextmanager
    def store(self):
        with _ReadOnlyRuleStore(self.database) as store:
            yield store

    def _client(self):
        with self._workspace_lock:
            if self._shared_client is None:
                self._shared_client = (self.client_factory() if self.client_factory else
                    OllamaClient(host=self.model_config.host, model=self.model_config.model,
                                 num_ctx=self.model_config.num_ctx,
                                 allow_remote_host=self.model_config.allow_remote_host is True))
            return self._shared_client

    def database_stamp(self):
        # WAL mutations may not touch the main DB. Include replacement identity,
        # sizes and nanosecond mtime/ctime; connections are reopened per request.
        stamps = []
        for path in (self.database, Path(str(self.database) + '-wal')):
            try:
                s = path.stat()
                stamps.append((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
            except FileNotFoundError:
                stamps.append(None)
        return tuple(stamps)

    def workspace(self, binary_id, store):
        with self._workspace_lock:
            stamp = self.database_stamp()
            if stamp != self._database_stamp:
                self._workspaces.clear()
                self._database_stamp = stamp
            if binary_id not in self._workspaces:
                workspace = BinaryWorkspace(store, binary_id)
                if self.database_stamp() != stamp:
                    raise GuiError('Analysis database changed during workspace load; retry the request')
                workspace.database_stamp = stamp
                self._workspaces[binary_id] = workspace
                while len(self._workspaces) > 4:
                    self._workspaces.popitem(last=False)
            self._workspaces.move_to_end(binary_id)
            return self._workspaces[binary_id]

    def _check_database(self, stamp):
        if self.database_stamp() != stamp:
            with self._workspace_lock:
                self._workspaces.clear()
            raise GuiError('Analysis database changed during the request; retry against the refreshed workspace')

    def list_binaries(self):
        with self.store() as store:
            return [serializable(binary) for binary in store.list_binaries()]

    def binary_metadata(self, binary_id):
        with self.store() as store:
            # HTTP selectors are IDs or stored names only; never filesystem paths.
            binary_id = resolve_binary(store, binary_id, allow_paths=False).binary_id
            stamp = self.database_stamp()
            data = AgentTools(store, binary_id).registry.run('binary_metadata', {})['data']
            self._check_database(stamp)
            return data

    def bootstrap(self, requested_binary=None):
        binaries = self.list_binaries()
        selected_id = requested_binary or self.initial_binary_id
        if selected_id is None and binaries:
            selected_id = binaries[0]['binary_id']
        if selected_id and selected_id not in {b['binary_id'] for b in binaries}:
            with self.store() as store:
                selected_id = resolve_binary(store, selected_id, allow_paths=False).binary_id
        return {
            'product': 'A.I.R.E.',
            'subtitle': 'Artificial Intelligence Reverse Engineering Assistant',
            'database': self.database.name,
            'selected_binary_id': selected_id,
            'binary_metadata': self.binary_metadata(selected_id) if selected_id else None,
            'binaries': binaries,
            'model': self.model_config.model or os.environ.get('AIRE_OLLAMA_MODEL'),
            'sessions': self.sessions.list(selected_id),
            'tool_names': [entry['name'] for entry in self.tool_catalog(selected_id)] if selected_id else [],
        }

    def tool_catalog(self, binary_id):
        with self.store() as store:
            return AgentTools(store, binary_id).registry.catalog()

    def new_session(self, binary_id):
        self.binary_metadata(binary_id)  # validate binary scope
        session_id = self.sessions.create(binary_id)
        return self.sessions.get(session_id)

    def session(self, session_id):
        data = self.sessions.get(session_id)
        self.binary_metadata(data['binary_id'])
        return data

    def select_function(self, session_id, selector):
        with self.sessions.lock(session_id):
            session = self.sessions.load_agent(session_id)
            with self.store() as store:
                workspace = self.workspace(session.binary_id, store)
                stamp = workspace.database_stamp
                result = workspace.tools(store).registry.run(
                    'get_function', {'function': selector})
                self._check_database(stamp)
            if not result['ok']:
                raise GuiError(result['error']['message'])
            function = result['data']['function']
            session.current_function_id = function['function_id']
            self.sessions.save_agent(session_id, session)
            return {'selected_function': function}

    def run_tool(self, session_id, name, arguments):
        if not isinstance(arguments, dict):
            raise GuiError('Tool arguments must be an object')
        with self.sessions.lock(session_id):
            session = self.sessions.load_agent(session_id)
            resolved = dict(arguments)
            for key in ('function', 'source', 'target'):
                if key in resolved:
                    resolved[key] = session.resolve_selector(resolved[key])
            with self.store() as store:
                workspace = self.workspace(session.binary_id, store)
                tools = workspace.tools(store)
                stamp = workspace.database_stamp
                result = tools.registry.run(name, resolved)
                self._check_database(stamp)
            if result['ok'] and name in ('get_function', 'get_decompiled_text', 'get_assembly', 'crosscheck_function'):
                function = result['data'].get('function')
                if function:
                    session.current_function_id = function['function_id']
                    self.sessions.save_agent(session_id, session)
            return result

    def run_chat(self, session_id, question, on_event=None, cancelled=None, on_text=None, on_context=None):
        if not isinstance(question, str) or not question.strip():
            raise GuiError('Question must not be empty')
        started = time.perf_counter()
        with self.sessions.lock(session_id):
            session = self.sessions.load_agent(session_id)
            resolution = time.perf_counter() - started
            with self.store() as store:
                tick = time.perf_counter()
                workspace = self.workspace(session.binary_id, store)
                workspace_resolution = time.perf_counter() - tick
                stamp = workspace.database_stamp
                facts = self._fact_answer(store, workspace, session, question, on_event)
                if facts is not None:
                    self._check_database(stamp)
                    self.sessions.save_agent(session_id, session)
                    self.sessions.append_exchange(session_id, question.strip(), facts.answer, facts.status,
                                                  facts.presentation)
                    self.last_performance = {'total_seconds': time.perf_counter() - started,
                                             'path': 'deterministic_facts', 'model_requests': 0,
                                             'session_resolution_seconds': resolution,
                                             'workspace_resolution_seconds': workspace_resolution,
                                             **facts.presentation.get('timing', {})}
                    _LOG.info('chat_performance %s', json.dumps(self.last_performance, sort_keys=True))
                    return facts
                client = self._client()
                m10 = self._assembly_answer(store, session, question, client, on_event)
                if m10 is not None:
                    self._structure_banner(m10, self._structure(workspace))
                    self._check_database(stamp)
                    self.sessions.save_agent(session_id, session)
                    self.sessions.append_exchange(session_id, question.strip(), m10.answer, m10.status, m10.presentation)
                    self.last_performance = {'total_seconds': time.perf_counter() - started, 'path': 'm10_assembly',
                                             **m10.presentation.get('timing', {})}
                    return m10
                key = (RELEVANCE_POLICY_VERSION, CROSSCHECK_POLICY_VERSION, CRYPTO_EVIDENCE_VERSION, question.strip().lower(), getattr(client, 'model', None),
                       getattr(client, 'num_ctx', None), self.limits.evidence_chars)
                overview = _binary_overview(question)
                if overview or any(s in question.lower() for s in ('suspicious behavior', 'crypto or hashing')):
                    workspace.prepare_overview(store)
                tools = workspace.tools(store, assembly='assembly' in question.lower())
                first_visible = None
                first_summary = None
                model_performance = {'model_seconds': 0.0, 'model_requests': 0}
                def preview(text):
                    nonlocal first_visible, first_summary
                    if text and first_summary is None:
                        first_summary = time.perf_counter() - started
                    if text and first_visible is None:
                        first_visible = time.perf_counter() - started
                    if on_text:
                        on_text(text)
                with workspace.lock:
                    cached = deepcopy(workspace.overview_answers.get(key)) if overview else None
                if cached and not (cancelled and cancelled()):
                    stream = EventStream(on_event)
                    stream.emit('agent_started', 'A.I.R.E. agent started')
                    stream.emit('progress', 'Reusing grounded binary overview')
                    result = cached
                    result.events = stream.events
                    preview(result.response.summary.claim)
                    session.remember(question, result.response.summary.claim,
                        [vars(p) for p in result.response.evidence_bundle.provenance], result.tool_results)
                    stream.emit('answer_completed', 'Grounded answer completed')
                    stream.emit('agent_finished', 'Agent finished', metadata={'status': result.status, 'tool_calls': 0})
                else:
                    if overview:
                        first_visible = time.perf_counter() - started
                        if on_context:
                            on_context(workspace.overview_preview())
                    actions = self._prepared_actions(workspace, session, question, tools)
                    runner = AgentRunner(store, client, limits=self.limits)
                    result = runner.run(session, question.strip(), on_event=on_event, cancelled=cancelled,
                        tools=tools, prepared_actions=actions, compact=True, on_text=preview,
                        deterministic='suspicious behavior' in question.lower() or 'call relationships' in question.lower(),
                        performance=model_performance)
                    tick = time.perf_counter()
                    present(result)
                    self._structure_banner(result, self._structure(workspace))
                    formatting = time.perf_counter() - tick
                    if overview and result.status == 'completed' and result.response:
                        with workspace.lock:
                            workspace.overview_answers[key] = deepcopy(result)
                            while len(workspace.overview_answers) > 4:
                                workspace.overview_answers.popitem(last=False)
                self._check_database(stamp)
            self.sessions.save_agent(session_id, session)
            self.sessions.append_exchange(session_id, question.strip(), result.answer, result.status, result.presentation)
            model_timing = result.response.timing if result.response and not cached else {}
            if first_visible is None and result.status == 'completed':
                first_visible = time.perf_counter() - started
            self.last_performance = {'total_seconds': time.perf_counter() - started,
                'session_resolution_seconds': resolution, 'tool_retrieval_seconds': tools.retrieval_seconds,
                'workspace_resolution_seconds': workspace_resolution,
                'evidence_build_seconds': tools.evidence_seconds, 'response_formatting_seconds': 0 if cached else formatting,
                'first_visible_seconds': first_visible, 'overview_cache_hit': bool(cached),
                'first_summary_seconds': first_summary,
                'cache_hits': workspace.hits, 'cache_misses': workspace.misses, **model_timing, **model_performance}
            _LOG.info('chat_performance %s', json.dumps(self.last_performance, sort_keys=True))
            return result

    def _fact_answer(self, store, workspace, session, question, on_event=None):
        """Deterministic answers for supported factual crypto/API/call-graph questions.

        No model request is made. Returns None for unsupported question forms so the
        M10 and model-backed paths run unchanged.
        """
        from aire.agent import fact_answers
        tick = time.perf_counter()
        routed = fact_answers.classify(question)
        structure = self._structure(workspace)
        if routed is None and _binary_overview(question) and structure['status'] in ('partial', 'none'):
            # Structural validation is authoritative: no whole-program model interpretation of a damaged file.
            routed = {**fact_answers.classify('What is this file?'), 'overview': True}
        if routed is None:
            return None
        stream = EventStream(on_event)
        stream.emit('agent_started', 'A.I.R.E. deterministic evidence lookup started')
        tools = workspace.tools(store)
        try:
            fact = fact_answers.FactAnswerer(tools, session, workspace.metadata.get('binary'), structure).answer(routed)
        except fact_answers.FactQuestionError as exc:
            raise GuiError(str(exc)) from exc
        evidence_seconds = time.perf_counter() - tick
        for result in fact.tool_results:
            stream.emit('tool_completed', 'Tool completed' if result['ok'] else 'Tool failed',
                        tool_name=result['tool'], metadata={'ok': result['ok']})
        stream.emit('evidence_found', 'Retrieved stored evidence with provenance',
                    metadata={'count': len(fact.evidence) + len(fact.relationships)})
        if fact.selected:
            session.current_function_id = fact.selected['function_id']
            stream.emit('function_selected', 'Selected stored function', function=fact.selected)
        stream.emit('answer_completed', 'Deterministic answer completed (no model inference)')
        stream.emit('agent_finished', 'Agent finished',
                    metadata={'status': 'completed', 'tool_calls': len(fact.tool_results)})
        session.remember(question, fact.summary, [e['provenance'] for e in fact.evidence[:32]],
                         fact.tool_results)
        sources = len({e['evidence_id'] for e in fact.evidence}) + len(fact.relationships)
        presentation = {'footer': f'Static analysis only · {sources} cited evidence sources · No target execution',
                        'interpretation': False, 'verified': True, 'evidence': fact.evidence,
                        'relationships': fact.relationships, 'security': [], 'limitations': fact.limitations,
                        'tool_facts': fact.tool_facts, 'facts': fact.facts,
                        'raw': {'answer': fact.answer, 'response': None,
                                'tool_results': fact.tool_results, 'intent': fact.intent},
                        'timing': {'evidence_seconds': evidence_seconds}}
        return AgentResult('completed', fact.answer, stream.events, fact.tool_results, None, presentation)

    @staticmethod
    def _structure(workspace):
        """Cached authoritative structural condition of the workspace binary (re-validated original file)."""
        from aire.analysis.file_structure import assess
        with workspace.lock:
            if getattr(workspace, 'structure', None) is None:
                workspace.structure = assess(workspace.metadata.get('binary') or {})
            return workspace.structure

    @staticmethod
    def _structure_banner(result, structure):
        """Prefix non-deterministic answers about a damaged or unverified file with its condition."""
        if structure['status'] == 'full' or not result.answer:
            return result
        from aire.agent.fact_answers import STRUCTURE_LABEL
        codes = ', '.join(dict.fromkeys(i['code'] for i in structure['issues'] if i['severity'] != 'info'))
        banner = (f"**Structural condition:** {STRUCTURE_LABEL[structure['status']]}" + (f' ({codes})' if codes else '') +
                  '. This file is damaged or could not be re-validated, so evidence may be missing or misattributed; '
                  'treat any interpretation below as unverified. Ask "Is this file corrupted?" for details.\n\n')
        result.answer = banner + result.answer
        if result.presentation is not None:
            result.presentation['structure'] = {k: structure.get(k) for k in ('status', 'summary', 'reason')}
        return result

    def _assembly_answer(self, store, session, question, client, on_event=None):
        """M10: deterministic, evidence-grounded assembly answers (model narration optional and validated)."""
        from aire.agent import assembly_answers as aa
        from aire.analysis.assembly_intelligence import AssemblyIntelligence
        routed = aa.route(question)
        if routed is None:
            return None
        ai = AssemblyIntelligence(store, session.binary_id)
        selector = session.current_function_id
        if routed['intent'] != 'validation' and not selector:
            for token in [*routed['addresses'], *re.findall(r'[A-Za-z_][A-Za-z0-9_]{2,}', question)]:
                try:
                    selector = ai.resolve(token).function_id
                    break
                except Exception:
                    continue
            if not selector:
                raise GuiError('Select a function from Functions (or name it / give its address) for this question.')
        stream = EventStream(on_event)
        stream.emit('agent_started', 'A.I.R.E. assembly analysis started')
        tick = time.perf_counter()
        intent, addresses, locations = routed['intent'], routed['addresses'], routed['locations']
        try:
            if intent == 'function':
                answer, tool, cited = aa.answer_function(ai, selector)
            elif intent == 'instructions':
                answer, tool, cited = aa.answer_instructions(ai, selector, start=addresses[0] if addresses else None)
            elif intent == 'branch':
                if not addresses:
                    raise GuiError('Give the address of the conditional jump, e.g. "what happens when the branch at 0x4011e1 is true?"')
                answer, tool, cited = aa.answer_branch(ai, selector, addresses[0])
            elif intent == 'trace':
                if not addresses or not locations:
                    raise GuiError('Give an instruction address and a register or stack slot, e.g. "where does the value of '
                                   'EAX at 0x4011dc come from?"')
                answer, tool, cited = aa.answer_trace(ai, selector, addresses[0], locations[0])
            elif intent == 'return_usage':
                answer, tool, cited = aa.answer_return_usage(ai, selector)
            elif intent == 'crossvalidate':
                answer, tool, cited = aa.answer_crossvalidate(ai, selector)
            elif intent == 'validation':
                answer, tool, cited = aa.answer_validation(ai)
            else:  # callers: existing graph path handles it
                return None
        except (KeyError, ValueError) as exc:
            raise GuiError(str(exc)) from exc
        evidence_seconds = time.perf_counter() - tick
        stream.emit('progress', 'Deterministic evidence retrieved')
        narration_note, narration_seconds = None, 0.0
        # Narration is opt-in until it can stream after the deterministic answer
        # (chat-performance Step 2); a blocking local-model call must not delay it.
        if os.environ.get('AIRE_M10_NARRATION', '0') == '1' and client is not None and tool is not None:
            tick = time.perf_counter()
            instructions = {}
            if selector:
                record = ai.resolve(selector)
                instructions = {i['a']: i['t'] for i in ai.document(record).get('instructions', [])}
            budget = float(os.environ.get('AIRE_M10_NARRATION_SECONDS', '60'))
            from aire.agent.assembly_answers import CITED
            # The deterministic answer is the evidence: anything it displays may be cited.
            cited = set(cited) | {m.group(1).lower().zfill(8)[-8:] for m in CITED.finditer(answer)}
            if selector:
                cited.add(ai.resolve(selector).address)
            box = {}
            def narrate():
                try:
                    box['result'] = client.generate(
                    'Explain the verified evidence below to a reverse engineer in 3-5 sentences. Use only facts in the '
                    'evidence; cite instruction addresses exactly as written (0x...). Do not speculate about source-level '
                    'names or intent beyond the evidence.\n\n' + answer[:12000],
                    system='You narrate deterministic static-analysis evidence. Never add facts.',
                    response_schema={'type': 'object', 'properties': {'explanation': {'type': 'string'}},
                                     'required': ['explanation']})
                except Exception as exc:  # reported below
                    box['error'] = exc
            worker = threading.Thread(target=narrate, daemon=True)
            worker.start()
            worker.join(budget)
            try:
                if worker.is_alive():
                    raise TimeoutError(f'no narration within {budget:g} s')
                if 'error' in box:
                    raise box['error']
                text = json.loads(box['result'].text)['explanation'].strip()
                problems = aa.validate_narration(text, cited, instructions)
                if problems:
                    narration_note = ('Local-model narration rejected (unsupported claims: ' + '; '.join(problems[:3]) +
                                      '). The deterministic evidence above is the answer.')
                else:
                    answer += '\n\n### Plain-English summary (local model; every cited address validated against the evidence)\n\n' + text
            except Exception as exc:
                narration_note = (f'Local model unavailable or failed ({type(exc).__name__}: {str(exc)[:120]}); '
                                  'deterministic evidence only.')
            narration_seconds = time.perf_counter() - tick
        if narration_note:
            answer += '\n\n*' + narration_note + '*'
        stream.emit('answer_completed', 'Grounded answer completed')
        stream.emit('agent_finished', 'Agent finished', metadata={'status': 'completed', 'tool_calls': 1})
        tool_results = [{'ok': True, 'tool': tool['tool'], 'data': tool['data']}] if tool else []
        summary = answer.split('\n')[0].lstrip('# ').strip()
        session.remember(question, summary, [], tool_results)
        evidence = [{'label': f'instruction @ 0x{a}', 'evidence_id': f'{session.binary_id}:{a}',
                     'provenance': {'source_table': 'function_ir', 'source_id': selector, 'address': a,
                                    'binary_id': session.binary_id}} for a in sorted(cited)[:60]]
        presentation = {'footer': f'Static analysis only · {len(cited)} cited instruction addresses · No target execution'
                                  ' · Deterministic evidence (M10)', 'interpretation': False, 'evidence': evidence,
                        'relationships': [], 'security': [],
                        'raw': {'answer': answer, 'response': None, 'tool_results': tool_results},
                        'timing': {'evidence_seconds': evidence_seconds, 'narration_seconds': narration_seconds}}
        return AgentResult('completed', answer, stream.events, tool_results, None, presentation)

    @staticmethod
    def _prepared_actions(workspace, session, question, tools):
        lower = question.lower()
        if not session.current_function_id and any(s in lower for s in (
                'this function', 'this assembly', 'current function', 'what calls it', 'who calls it')):
            raise GuiError('Select a function from Functions, or name a stored function in your question.')
        if _binary_overview(question) or any(s in lower for s in ('suspicious behavior', 'crypto or hashing')):
            actions = [('binary_metadata', {}), ('rank_application_functions', {'limit': 10})]
            if workspace.seed_ids:
                actions.append(('get_callees', {'function': workspace.seed_ids[0], 'limit': 12}))
            actions += [('get_artifacts', {'kind': 'IMPORT', 'limit': 20}),
                        ('get_artifacts', {'kind': 'STRING', 'limit': 20}), ('security_findings', {})]
            if 'crypto or hashing' in lower:
                actions.append(('crypto_evidence', {'limit': 20}))
                actions.append(('list_functions', {'limit': 100}))
                # Prefer functions with exact crypto API callsite evidence
                # (works for stripped binaries); names are only a fallback.
                try:
                    evidence = tools.crypto(limit=20)['functions']
                except Exception:
                    evidence = []
                candidates = [row['function_id'] for row in evidence if row['primary_operations']]
                candidates = candidates or [r['function']['function_id'] for r in workspace.preloaded[0]['data'].get('items', [])
                              if re.search(r'(?:crypto|hash|sha[0-9]*|md5|aes|encrypt|decrypt|checksum)',
                                           r['function']['current_name'], re.IGNORECASE)
                              and not r['function']['is_external'] and not r['function']['is_thunk']]
                if candidates:
                    # Name matches guide retrieval only; code must support any
                    # cryptographic interpretation in the final validated prompt.
                    tools.overview_seeds = tuple(candidates[:2])
            return actions
        if 'important functions' in lower:
            return [('rank_functions', {'metric': 'unique_callers', 'limit': 10})]
        if any(s in lower for s in ('what calls', 'who calls', 'callers of', 'call relationships', 'what does it call')):
            if not session.current_function_id:
                return []
            names = ('get_callers', 'get_callees') if 'call relationships' in lower else (
                ('get_callees',) if 'what does it call' in lower else ('get_callers',))
            return [(n, {'function': session.current_function_id, 'limit': 20}) for n in names]
        # Exact lookup still occurs inside AgentRunner. Recognized explanations
        # need evidence retrieval, not a model decision to retrieve that evidence.
        if re.search(r'\b(?:explain|summarize|summarise)\b', lower):
            if session.current_function_id or any(
                    tools.query.find_functions(session.binary_id, word)
                    for word in dict.fromkeys(re.findall(r'[A-Za-z0-9_:.]+', question))):
                return []
        return None


class AireHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler, application, *, token=None, public_ports=()):
        self.application = application
        self.token = token
        super().__init__(server_address, handler)
        port = self.server_address[1]
        # Host/Origin ports accepted: the guest port plus any host-side forwarded port.
        self.allowed_ports = frozenset({port, *public_ports})
        self.cookie_name = f'aire_token_{port}'
        self.chat_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_CHATS)


class AireRequestHandler(SimpleHTTPRequestHandler):
    """Static frontend plus small JSON/NDJSON API. No CORS is enabled."""

    protocol_version = 'HTTP/1.1'
    server_version = 'AIRELocal/1.0'
    timeout = _SOCKET_TIMEOUT

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(_STATIC_DIR), **kwargs)

    def log_message(self, format, *args):
        # Keep normal server logging concise, avoid reflecting request bodies,
        # and never write the access token (from /?token=...) to the log.
        args = tuple(_TOKEN_QUERY_RE.sub(r'\1<redacted>', a) if isinstance(a, str) else a for a in args)
        super().log_message(format, *args)

    @property
    def app(self):
        return self.server.application

    def _authority(self, value):
        """Normalized 'host:port' when value is exactly localhost/127.0.0.1 on an allowed port, else None.

        DNS rebinding sends the attacker's hostname as Host; other loopback
        spellings (127.0.0.2, [::1], 0x7f000001) and unexpected ports are refused.
        """
        match = _AUTHORITY_RE.fullmatch(value or '')
        if not match:
            return None
        port = int(match.group(2) or 80)
        if port not in self.server.allowed_ports:
            return None
        return f'{match.group(1).lower()}:{port}'

    def _header_token_ok(self):
        token = self.server.token
        supplied = self.headers.get(_TOKEN_HEADER)
        return bool(token and supplied) and hmac.compare_digest(supplied.encode(), token.encode())

    def _cookie_token_ok(self):
        token = self.server.token
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
        except CookieError:
            return False
        morsel = cookie.get(self.server.cookie_name)
        return bool(token and morsel and morsel.value) and hmac.compare_digest(morsel.value.encode(), token.encode())

    def _authorized(self):
        """Per-launch token (Jupyter-style). Servers created without a token (tests) skip this."""
        return self.server.token is None or self._header_token_ok() or self._cookie_token_ok()

    def _trusted_request(self):
        host = self._authority(self.headers.get('Host', ''))
        if host is None:
            return False
        # Fetch metadata (Firefox/Chrome): only same-origin subrequests or direct navigation.
        fetch_site = self.headers.get('Sec-Fetch-Site')
        if fetch_site is not None and fetch_site not in ('same-origin', 'none'):
            return False
        origin = self.headers.get('Origin')
        if origin is not None:
            # Same origin only: another web page (other site or other local port)
            # must not drive uploads, analysis jobs, chats or sessions.
            if not origin[:7].lower() == 'http://' or self._authority(origin[7:]) != host:
                return False
        elif self.command not in ('GET', 'HEAD') and not self._header_token_ok():
            # Browsers always send Origin on POST. A missing Origin is accepted only
            # from a non-browser client presenting the token in a custom header
            # (which a cross-site page cannot send without a failing preflight).
            return False
        return True

    def _reject(self, status, error, message):
        self.close_connection = True  # never parse an unread request body as the next request
        return self._json(status, {'error': error, 'message': message})

    def _forbidden(self):
        return self._reject(403, 'Forbidden', 'A.I.R.E. GUI accepts same-origin requests to localhost only')

    def _unauthorized(self):
        return self._reject(401, 'Unauthorized', 'Missing or invalid A.I.R.E. access token. Open the tokenized URL '
                            'printed in the terminal where the GUI was started.')

    def _token_login(self):
        """GET /?token=...: exchange the printed token for an HttpOnly SameSite=Strict cookie."""
        supplied = parse_qs(urlparse(self.path).query).get('token', [''])[0]
        if not (self.server.token and supplied and hmac.compare_digest(supplied.encode(), self.server.token.encode())):
            return self._unauthorized()
        self.send_response(303)
        self.send_header('Location', '/')
        self.send_header('Set-Cookie', f'{self.server.cookie_name}={self.server.token}; Path=/; HttpOnly; SameSite=Strict')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy',
                         "default-src 'self'; style-src 'self'; script-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                         "base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def _security_headers(self, content_type, length=None):
        self.send_header('Content-Type', content_type)
        if length is not None:
            self.send_header('Content-Length', str(length))

    def _json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode('utf-8')
        self.send_response(status)
        self._security_headers('application/json; charset=utf-8', len(raw))
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, status, exc):
        # A rejected POST may still have unread bytes. Do not parse those bytes
        # as another HTTP request on a persistent connection.
        if self.command == 'POST':
            self.close_connection = True
        name, message = _public_error(exc)
        payload = {'error': name, 'message': message}
        report = getattr(exc, 'report', None)
        if isinstance(report, dict):
            payload['validation'] = report  # structured PE/ELF intake issues
        self._json(status, payload)

    def _body(self):
        if self.headers.get_content_type() != 'application/json':
            raise GuiError('Expected application/json')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise GuiError('Invalid request length') from exc
        if not 0 < length <= _MAX_BODY:
            raise GuiError('Request body is empty or exceeds size limit')
        try:
            value = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise GuiError('Malformed JSON request') from exc
        if not isinstance(value, dict):
            raise GuiError('JSON request must be an object')
        return value

    def _api_path(self):
        return urlparse(self.path).path

    def _session_route(self, suffix=''):
        pattern = r'^/api/sessions/([0-9a-f]{32})' + re.escape(suffix) + r'$'
        match = re.match(pattern, self._api_path())
        return match.group(1) if match else None

    def do_HEAD(self):
        if not self._trusted_request():
            return self._forbidden()
        if self._api_path().startswith('/api/'):
            return self._reject(405, 'MethodNotAllowed', 'Use GET for API requests')
        return super().do_HEAD()

    def do_GET(self):
        if not self._trusted_request():
            return self._forbidden()
        path = self._api_path()
        if path == '/' and 'token' in parse_qs(urlparse(self.path).query):
            return self._token_login()
        if path.startswith('/api/') and not self._authorized():
            return self._unauthorized()
        try:
            if path == '/api/bootstrap':
                selected = parse_qs(urlparse(self.path).query).get('binary_id', [None])[0]
                return self._json(200, self.app.bootstrap(selected))
            if path == '/api/binaries':
                return self._json(200, {'binaries': self.app.list_binaries()})
            if path == '/api/library':
                return self._json(200, {'fixtures': self.app.library.list(), 'max_upload_bytes': MAX_UPLOAD,
                                        'analyzer': self.app.library.analyzer_status()})
            if re.fullmatch(r'/api/analysis/[0-9a-f]{32}', path):
                return self._json(200, self.app.library.job(path.rsplit('/', 1)[-1]))
            if path == '/api/sessions':
                binary_id = parse_qs(urlparse(self.path).query).get('binary_id', [None])[0]
                return self._json(200, {'sessions': self.app.sessions.list(binary_id)})
            session_id = self._session_route()
            if session_id:
                return self._json(200, self.app.session(session_id))
            if path == '/api/health':
                client = self.app._client()
                try:
                    health = client.health()
                    return self._json(200, {'ok': True, **health, 'selected_model': client.model})
                except Exception as exc:
                    return self._json(200, {'ok': False, 'selected_model': getattr(client, 'model', None),
                                            'message': str(exc)[:500]})
            if path == '/':
                self.path = '/index.html'
            return super().do_GET()
        except GuiError as exc:
            return self._error(400, exc)
        except (OSError, ValueError) as exc:
            return self._error(400, exc)
        except Exception as exc:
            return self._error(500, exc)

    def do_POST(self):
        if not self._trusted_request():
            return self._forbidden()
        if not self._authorized():
            return self._unauthorized()
        path = self._api_path()
        try:
            if path == '/api/uploads':
                if self.headers.get_content_type() != 'application/octet-stream':
                    raise GuiError('Expected application/octet-stream')
                if self.headers.get('Transfer-Encoding'):
                    raise GuiError('Chunked uploads are not supported')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_UPLOAD:
                    self.close_connection = True
                    raise GuiError('Upload must be between 1 byte and 32 MiB')
                self.connection.settimeout(30)
                filename = parse_qs(urlparse(self.path).query).get('filename', ['binary'])[0]
                return self._json(201, self.app.library.upload(self.rfile, length, filename))
            body = self._body()
            if path == '/api/analysis':
                return self._json(202, self.app.library.start(
                    upload_id=body.get('upload_id'), fixture_id=body.get('fixture_id')))
            if path == '/api/sessions':
                return self._json(201, self.app.new_session(body.get('binary_id')))
            session_id = self._session_route('/select-function')
            if session_id:
                return self._json(200, self.app.select_function(session_id, body.get('function')))
            if path == '/api/tool':
                result = self.app.run_tool(body.get('session_id'), body.get('tool'), body.get('arguments', {}))
                return self._json(200 if result.get('ok') else 400, result)
            if path == '/api/chat':
                if not self.server.chat_slots.acquire(blocking=False):
                    return self._reject(429, 'Busy', f'At most {_MAX_CONCURRENT_CHATS} chat requests run at once; '
                                        'wait for one to finish')
                try:
                    return self._chat(body)
                finally:
                    self.server.chat_slots.release()
            return self._json(404, {'error': 'NotFound', 'message': 'Unknown API endpoint'})
        except GuiError as exc:
            return self._error(400, exc)
        except (OSError, ValueError, TypeError) as exc:
            return self._error(400, exc)
        except Exception as exc:
            return self._error(500, exc)

    def _chat(self, body):
        session_id = body.get('session_id')
        question = body.get('question')
        disconnected = False
        self.send_response(200)
        self._security_headers('application/x-ndjson; charset=utf-8')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

        def emit(kind, payload):
            nonlocal disconnected
            if disconnected:
                return
            try:
                line = json.dumps({'type': kind, 'data': payload}, ensure_ascii=True,
                                  allow_nan=False).encode('utf-8') + b'\n'
                self.wfile.write(line)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                disconnected = True

        try:
            result = self.app.run_chat(session_id, question,
                on_event=lambda event: emit('event', event.to_dict()),
                on_text=lambda text: emit('text', {'text': text, 'provisional': True}),
                on_context=lambda text: emit('context', {'text': text}),
                cancelled=lambda: disconnected)
            emit('result', result.to_dict())
        except Exception as exc:
            name, message = _public_error(exc)
            emit('error', {'error': name, 'message': message})


def _validate_bind_host(host, allow_non_loopback=False):
    """Loopback by default. A single private IPv4 interface address (e.g. the VirtualBox
    NAT address 10.0.2.15) only with an explicit opt-in; never a wildcard address."""
    if host == 'localhost':
        return '127.0.0.1'
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise GuiError('GUI host must be localhost or an IP address literal') from exc
    if address.is_loopback:
        return host
    if not allow_non_loopback:
        raise GuiError('GUI host must be loopback; remote binding is disabled '
                       '(see --allow-non-loopback-bind for a VirtualBox NAT address)')
    if (address.version != 4 or address.is_unspecified or address.is_multicast or address.is_link_local
            or not address.is_private or address == ipaddress.ip_address('255.255.255.255')):
        raise GuiError('Non-loopback GUI binding requires one private IPv4 interface address '
                       '(for example the VirtualBox NAT address 10.0.2.15); wildcard, public, '
                       'link-local, multicast and IPv6 addresses are refused')
    return host


def _validate_port(port, label='Port'):
    if type(port) is not int or not 0 <= port <= 65535:
        raise GuiError(f'{label} must be between 0 and 65535')
    return port


def create_server(application, host='127.0.0.1', port=8765, *, token=None, public_ports=(),
                  allow_non_loopback=False):
    host = _validate_bind_host(host, allow_non_loopback)
    _validate_port(port)
    public_ports = tuple(_validate_port(p, 'Public port') for p in public_ports)
    if token is not None and (not isinstance(token, str) or len(token) < 32):
        raise GuiError('Access token must be a string of at least 32 characters')
    if not ipaddress.ip_address(host).is_loopback and token is None:
        raise GuiError('Non-loopback GUI binding requires the per-launch access token')
    return AireHttpServer((host, port), AireRequestHandler, application, token=token, public_ports=public_ports)


def serve(application, *, host='127.0.0.1', port=8765, open_browser=True, output=print,
          allow_non_loopback=False, public_port=None):
    token = secrets.token_urlsafe(32)  # per launch; required on every API request
    server = create_server(application, host, port, token=token,
                           public_ports=(public_port,) if public_port else (),
                           allow_non_loopback=allow_non_loopback)
    actual_host, actual_port = server.server_address[:2]
    loopback = ipaddress.ip_address(actual_host).is_loopback
    output('A.I.R.E. GUI')
    if not loopback:
        warning = (f'WARNING: listening on non-loopback address {actual_host}:{actual_port} (explicit opt-in). '
                   'Only Host localhost/127.0.0.1 on ports ' + ', '.join(map(str, sorted(server.allowed_ports))) +
                   ' and the access token are accepted. Keep the VirtualBox port forward bound to host IP 127.0.0.1.')
        _ERROR_LOG.warning(warning)
        output(warning)
    url = f'http://127.0.0.1:{actual_port}/?token={token}'
    if loopback:
        output('Local URL: ' + url)
    if public_port:
        output(f'Host-side URL (VirtualBox forward 127.0.0.1:{public_port}): '
               f'http://127.0.0.1:{public_port}/?token={token}')
    output('Treat the token like a password. It changes every launch.')
    output('Analysis database: ' + str(application.database))
    output('Press Ctrl-C to stop.')
    if open_browser and loopback:
        threading.Timer(0.25, partial(webbrowser.open, url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
        return 0
    except KeyboardInterrupt:
        output('\nA.I.R.E. GUI stopped.')
        return 130
    finally:
        server.server_close()
        application.library.close()
