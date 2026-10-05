"""Local read-only web application for the A.I.R.E. binary analysis agent.

The HTTP boundary deliberately stays in the Python standard library. Analysis
facts are read from the existing SQLite knowledge store through the same M8
AgentTools/AgentRunner used by the CLI. GUI conversation files live separately
from the immutable analysis database.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import parse_qs, urlparse
from uuid import uuid4
import webbrowser

from aire.agent.binary_scope import resolve_binary
from aire.agent.runner import AgentLimits, AgentRunner
from aire.agent.session import AgentSession
from aire.agent.tools import AgentTools, serializable
from aire.ai.ollama_client import OllamaClient
from aire.security.rule_engine import _ReadOnlyRuleStore

_STATIC_DIR = Path(__file__).with_name('static')
_SESSION_RE = re.compile(r'^[0-9a-f]{32}$')
_MAX_BODY = 1_000_000
_MAX_TRANSCRIPT_MESSAGES = 80
_MAX_TRANSCRIPT_TEXT = 60_000


class GuiError(RuntimeError):
    """Safe local-GUI request error."""


@dataclass(frozen=True)
class GuiModelConfig:
    host: str | None = None
    model: str | None = None
    num_ctx: int | None = None


class GuiSessionStore:
    """Persist agent state and UI transcript outside the analysis database."""

    def __init__(self, directory):
        self.directory = Path(directory).expanduser().resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._guard = threading.RLock()
        self._session_locks = {}

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
        temporary.write_text(encoded, encoding='utf-8')
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
        if binary_id is None:
            payload = json.loads(path.read_text(encoding='utf-8'))
            binary_id = payload.get('binary_id')
        return AgentSession.load(path, binary_id)

    def save_agent(self, session_id, session):
        session.save(self._agent_path(session_id))

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

    def append_exchange(self, session_id, question, answer, status):
        data = self._load_transcript(session_id)
        now = self._now()
        data['messages'].extend([
            {'role': 'user', 'text': str(question)[:_MAX_TRANSCRIPT_TEXT], 'timestamp': now},
            {'role': 'assistant', 'text': str(answer)[:_MAX_TRANSCRIPT_TEXT],
             'timestamp': now, 'status': str(status)[:64]},
        ])
        data['messages'] = data['messages'][-_MAX_TRANSCRIPT_MESSAGES:]
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
                 model_config=None, limits=None, client_factory=None):
        self.database = Path(database).expanduser().resolve()
        if not self.database.is_file():
            raise GuiError(f'Analysis database not found: {self.database}')
        self.sessions = GuiSessionStore(session_dir or Path.home() / '.aire' / 'gui-sessions')
        self.model_config = model_config or GuiModelConfig()
        self.limits = limits or AgentLimits()
        self.client_factory = client_factory
        with self.store() as store:
            binaries = store.list_binaries()
            if not binaries:
                raise GuiError('Analysis database contains no indexed binaries')
            selected = resolve_binary(store, initial_binary) if initial_binary else binaries[0]
            self.initial_binary_id = selected.binary_id

    @contextmanager
    def store(self):
        with _ReadOnlyRuleStore(self.database) as store:
            yield store

    def _client(self):
        if self.client_factory:
            return self.client_factory()
        return OllamaClient(host=self.model_config.host, model=self.model_config.model,
                            num_ctx=self.model_config.num_ctx)

    def list_binaries(self):
        with self.store() as store:
            return [serializable(binary) for binary in store.list_binaries()]

    def binary_metadata(self, binary_id):
        with self.store() as store:
            resolve_binary(store, binary_id)
            return AgentTools(store, binary_id).metadata()

    def bootstrap(self, requested_binary=None):
        binaries = self.list_binaries()
        selected_id = requested_binary or self.initial_binary_id
        if selected_id not in {b['binary_id'] for b in binaries}:
            with self.store() as store:
                selected_id = resolve_binary(store, selected_id).binary_id
        return {
            'product': 'A.I.R.E.',
            'subtitle': 'Artificial Intelligence Reverse Engineering Assistant',
            'database': self.database.name,
            'selected_binary_id': selected_id,
            'binary_metadata': self.binary_metadata(selected_id),
            'binaries': binaries,
            'model': self.model_config.model or os.environ.get('AIRE_OLLAMA_MODEL'),
            'sessions': self.sessions.list(selected_id),
            'tool_names': [entry['name'] for entry in self.tool_catalog(selected_id)],
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
                result = AgentTools(store, session.binary_id).registry.run(
                    'get_function', {'function': selector})
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
                tools = AgentTools(store, session.binary_id)
                result = tools.registry.run(name, resolved)
            if result['ok'] and name in ('get_function', 'get_decompiled_text', 'get_assembly'):
                function = result['data'].get('function')
                if function:
                    session.current_function_id = function['function_id']
                    self.sessions.save_agent(session_id, session)
            return result

    def run_chat(self, session_id, question, on_event=None, cancelled=None):
        if not isinstance(question, str) or not question.strip():
            raise GuiError('Question must not be empty')
        with self.sessions.lock(session_id):
            session = self.sessions.load_agent(session_id)
            with self.store() as store:
                runner = AgentRunner(store, self._client(), limits=self.limits)
                result = runner.run(session, question.strip(), on_event=on_event, cancelled=cancelled)
            self.sessions.save_agent(session_id, session)
            self.sessions.append_exchange(session_id, question.strip(), result.answer, result.status)
            return result


class AireHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler, application):
        self.application = application
        super().__init__(server_address, handler)


class AireRequestHandler(SimpleHTTPRequestHandler):
    """Static frontend plus small JSON/NDJSON API. No CORS is enabled."""

    protocol_version = 'HTTP/1.1'
    server_version = 'AIRELocal/1.0'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(_STATIC_DIR), **kwargs)

    def log_message(self, format, *args):
        # Keep normal server logging concise and avoid reflecting request bodies.
        super().log_message(format, *args)

    @property
    def app(self):
        return self.server.application

    def _loopback_host(self, value):
        try:
            hostname = urlparse('//' + value).hostname
        except ValueError:
            return False
        if hostname == 'localhost':
            return True
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except (ValueError, TypeError):
            return False

    def _trusted_request(self):
        host = self.headers.get('Host', '')
        if not self._loopback_host(host):
            return False
        origin = self.headers.get('Origin')
        if origin:
            try:
                parsed = urlparse(origin)
                if parsed.scheme not in ('http', 'https') or not self._loopback_host(parsed.netloc):
                    return False
            except ValueError:
                return False
        return True

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
        message = str(exc)[:500] or type(exc).__name__
        self._json(status, {'error': type(exc).__name__, 'message': message})

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
        except (ValueError, UnicodeError) as exc:
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

    def do_GET(self):
        if not self._trusted_request():
            return self._json(403, {'error': 'Forbidden', 'message': 'A.I.R.E. GUI accepts loopback requests only'})
        path = self._api_path()
        try:
            if path == '/api/bootstrap':
                selected = parse_qs(urlparse(self.path).query).get('binary_id', [None])[0]
                return self._json(200, self.app.bootstrap(selected))
            if path == '/api/binaries':
                return self._json(200, {'binaries': self.app.list_binaries()})
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
            return self._json(403, {'error': 'Forbidden', 'message': 'A.I.R.E. GUI accepts loopback requests only'})
        path = self._api_path()
        try:
            body = self._body()
            if path == '/api/sessions':
                return self._json(201, self.app.new_session(body.get('binary_id')))
            session_id = self._session_route('/select-function')
            if session_id:
                return self._json(200, self.app.select_function(session_id, body.get('function')))
            if path == '/api/tool':
                result = self.app.run_tool(body.get('session_id'), body.get('tool'), body.get('arguments', {}))
                return self._json(200 if result.get('ok') else 400, result)
            if path == '/api/chat':
                return self._chat(body)
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
                cancelled=lambda: disconnected)
            emit('result', result.to_dict())
        except Exception as exc:
            emit('error', {'error': type(exc).__name__, 'message': str(exc)[:500]})


def _validate_bind_host(host):
    if host == 'localhost':
        return '127.0.0.1'
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise GuiError('GUI host must be localhost or a loopback IP address') from exc
    if not address.is_loopback:
        raise GuiError('GUI host must be loopback; remote binding is disabled')
    return host


def create_server(application, host='127.0.0.1', port=8765):
    host = _validate_bind_host(host)
    if type(port) is not int or not 0 <= port <= 65535:
        raise GuiError('Port must be between 0 and 65535')
    return AireHttpServer((host, port), AireRequestHandler, application)


def serve(application, *, host='127.0.0.1', port=8765, open_browser=True, output=print):
    server = create_server(application, host, port)
    actual_host, actual_port = server.server_address[:2]
    url = f'http://{actual_host}:{actual_port}/'
    output('A.I.R.E. GUI')
    output('Local URL: ' + url)
    output('Analysis database: ' + str(application.database))
    output('Press Ctrl-C to stop.')
    if open_browser:
        threading.Timer(0.25, partial(webbrowser.open, url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
        return 0
    except KeyboardInterrupt:
        output('\nA.I.R.E. GUI stopped.')
        return 130
    finally:
        server.server_close()
