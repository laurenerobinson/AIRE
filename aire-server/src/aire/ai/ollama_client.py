"""Bounded non-streaming Ollama transport. No retrieval or tool execution."""
from dataclasses import dataclass, field
from http.client import HTTPException
import ipaddress
import json
import math
import os
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class OllamaError(RuntimeError):
    """Transport, model availability, or protocol failure."""


class OllamaConnectionError(OllamaError):
    pass


class OllamaTimeoutError(OllamaError):
    pass


class OllamaModelError(OllamaError):
    pass


class OllamaProtocolError(OllamaError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OllamaProtocolError('Ollama redirects are disabled; evidence was not forwarded')


@dataclass(frozen=True)
class GenerationResult:
    text: str
    model: str
    seconds: float
    prompt_eval_count: int | None = None
    eval_count: int | None = None
    timing: dict = field(default_factory=dict)


class OllamaClient:
    supports_streaming = True
    """Loopback literals/localhost only unless remote access is explicitly enabled.

    localhost is pinned to 127.0.0.1, avoiding DNS changes. Other hostnames are
    rejected without DNS lookup unless remote access is authorized. Environment
    proxies and redirects are disabled, including with opt-in. The timeout is
    a socket-operation timeout, not a total wall-clock deadline.
    """
    def __init__(self, host=None, model=None, timeout_seconds=240, temperature=0.1,
                 allow_remote_host=False, *, num_ctx=None, keep_alive='10m'):
        host = host if host is not None else os.environ.get('AIRE_OLLAMA_HOST', 'http://127.0.0.1:11434')
        self.model = model if model is not None else os.environ.get('AIRE_OLLAMA_MODEL')
        if num_ctx is None:
            value = os.environ.get('AIRE_OLLAMA_NUM_CTX', '32768')
            if not value.isascii() or not value.isdecimal():
                raise ValueError('AIRE_OLLAMA_NUM_CTX must be a positive decimal integer')
            try:
                num_ctx = int(value)
            except ValueError as exc:
                raise ValueError('AIRE_OLLAMA_NUM_CTX must be a positive decimal integer') from exc
        if type(num_ctx) is not int or num_ctx <= 0:
            raise ValueError('num_ctx / AIRE_OLLAMA_NUM_CTX must be a positive integer')
        self.num_ctx = num_ctx
        if self.model is not None and (not isinstance(self.model, str) or not self.model.strip()
                                       or len(self.model) > 200):
            raise ValueError('model must be a nonempty name of at most 200 characters')
        if type(allow_remote_host) is not bool:
            raise ValueError('allow_remote_host must be bool')
        for label, value, lower, upper in [('timeout_seconds', timeout_seconds, 0.1, 600),
                                           ('temperature', temperature, 0, 1)]:
            if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
                raise ValueError(f'{label} must be between {lower} and {upper}')
        if not isinstance(host, str) or any(ch.isspace() or ord(ch) < 32 for ch in host):
            raise ValueError('Invalid Ollama host')
        try:
            parts = urlsplit(host)
            port = parts.port
            if (parts.scheme not in ('http', 'https') or not parts.hostname
                    or parts.username is not None or parts.password is not None
                    or parts.path not in ('', '/') or parts.query or parts.fragment):
                raise ValueError('Use an HTTP(S) origin without credentials, path, query, or fragment')
            hostname = parts.hostname
            if hostname == 'localhost':
                hostname = '127.0.0.1'
            try:
                address = ipaddress.ip_address(hostname)
                # Keep the default allowlist independent of Python's changing
                # IPv4-mapped IPv6 loopback classification. Remote opt-in still
                # permits these origins deliberately.
                mapped = isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
                local = address.is_loopback and not mapped and '%' not in hostname
            except ValueError:
                local = False
            if not local and not allow_remote_host:
                raise ValueError('Non-loopback Ollama host rejected; set allow_remote_host=True explicitly')
            authority = f'[{hostname}]' if ':' in hostname else hostname
            self.host = f'{parts.scheme}://{authority}' + (f':{port}' if port is not None else '')
        except ValueError as exc:
            raise ValueError(f'Invalid Ollama endpoint: {exc}') from exc
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature
        if not isinstance(keep_alive, str) or keep_alive not in ('5m', '10m', '30m'):
            raise ValueError('keep_alive must be 5m, 10m, or 30m')
        self.keep_alive = keep_alive
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, route, payload=None, *, timeout=None):
        data = None if payload is None else json.dumps(payload, allow_nan=False).encode('utf-8')
        request = Request(self.host + route, data=data, headers={'Content-Type': 'application/json'})
        try:
            with self._opener.open(request, timeout=timeout or self.timeout_seconds) as response:
                raw = response.read(1_000_001)
        except HTTPError as exc:
            with exc:
                detail = exc.read(4096).decode('utf-8', errors='replace')
            if exc.code == 404 and route == '/api/generate':
                raise OllamaModelError(f'Model {self.model!r} unavailable at {self.host}: {detail}') from exc
            raise OllamaError(f'Ollama HTTP {exc.code}: {detail}') from exc
        except (TimeoutError, socket.timeout) as exc:
            raise OllamaTimeoutError(f'Ollama timed out at {self.host}') from exc
        except URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise OllamaTimeoutError(f'Ollama timed out at {self.host}') from exc
            raise OllamaConnectionError(f'Cannot connect to Ollama at {self.host}: {exc.reason}') from exc
        except OSError as exc:
            raise OllamaConnectionError(f'Ollama connection failed at {self.host}: {exc}') from exc
        except HTTPException as exc:
            raise OllamaProtocolError(f'Ollama HTTP response was incomplete: {exc}') from exc
        if len(raw) > 1_000_000:
            raise OllamaProtocolError('Ollama response exceeds 1,000,000 bytes')
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise OllamaProtocolError('Ollama returned malformed JSON') from exc
        if not isinstance(result, dict):
            raise OllamaProtocolError('Ollama response must be a JSON object')
        if 'error' in result:
            raise OllamaModelError(f'Ollama model {self.model!r} error: {str(result["error"])[:4096]}')
        return result

    def list_models(self):
        """Connectivity check via /api/tags with a short timeout."""
        result = self._request('/api/tags', timeout=min(3, self.timeout_seconds))
        models = result.get('models')
        if not isinstance(models, list) or any(not isinstance(m, dict) or
                not isinstance(m.get('name'), str) or not m['name'] for m in models):
            raise OllamaProtocolError('Ollama tags response has invalid models')
        return sorted({m['name'] for m in models})

    def health(self):
        return {'host': self.host, 'models': self.list_models()}

    def warm(self):
        """Optional explicit local model load, without binary evidence."""
        if not self.model:
            raise OllamaModelError('No model selected')
        return self._request('/api/generate', {'model': self.model, 'prompt': '',
            'stream': False, 'keep_alive': self.keep_alive,
            'options': {'num_ctx': self.num_ctx}})

    def _stream(self, payload, on_chunk):
        tick = time.perf_counter()
        request = Request(self.host + '/api/generate',
            data=json.dumps(payload, allow_nan=False).encode('utf-8'),
            headers={'Content-Type': 'application/json'})
        pieces, total, first = [], 0, None
        startup = None
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                startup = time.perf_counter() - tick
                while True:
                    if time.perf_counter() - tick >= self.timeout_seconds:
                        raise OllamaTimeoutError('Ollama generation deadline exceeded')
                    line = response.readline(1_000_001)
                    if not line:
                        raise OllamaProtocolError('Ollama stream ended without completion')
                    total += len(line)
                    if total > 1_000_000:
                        raise OllamaProtocolError('Ollama response exceeds 1,000,000 bytes')
                    try:
                        item = json.loads(line)
                    except (ValueError, UnicodeError) as exc:
                        raise OllamaProtocolError('Ollama returned malformed streaming JSON') from exc
                    if not isinstance(item, dict) or type(item.get('response', '')) is not str:
                        raise OllamaProtocolError('Invalid Ollama stream record')
                    if 'error' in item:
                        raise OllamaModelError(str(item['error'])[:4096])
                    chunk = item.get('response', '')
                    if chunk:
                        first = first if first is not None else time.perf_counter() - tick
                        pieces.append(chunk)
                        on_chunk(chunk)
                    if item.get('done') is True:
                        item['response'] = ''.join(pieces)
                        return item, {'request_startup_seconds': startup,
                                      'first_output_seconds': first,
                                      'generation_seconds': time.perf_counter() - tick - (first or 0)}
        except HTTPError as exc:
            with exc:
                detail = exc.read(4096).decode('utf-8', errors='replace')
            if exc.code == 404:
                raise OllamaModelError(detail) from exc
            raise OllamaError(f'Ollama HTTP {exc.code}: {detail}') from exc
        except (TimeoutError, socket.timeout) as exc:
            raise OllamaTimeoutError('Ollama stream timed out') from exc
        except URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise OllamaTimeoutError('Ollama stream timed out') from exc
            raise OllamaConnectionError(str(exc.reason)) from exc
        except OSError as exc:
            raise OllamaConnectionError('Ollama stream connection failed') from exc
        except HTTPException as exc:
            raise OllamaProtocolError('Ollama stream was incomplete') from exc

    def generate(self, prompt, *, system='', response_schema=None, on_chunk=None):
        if not self.model:
            raise OllamaModelError('No model selected; set AIRE_OLLAMA_MODEL or model=. Use list_models() to discover installed models')
        if not isinstance(prompt, str) or not 0 < len(prompt) <= 250_000:
            raise ValueError('prompt must contain 1–250000 characters')
        tick = time.perf_counter()
        payload = {
            'model': self.model, 'prompt': prompt, 'system': system, 'stream': on_chunk is not None,
            'keep_alive': self.keep_alive,
            'format': response_schema or 'json',
            'options': {'temperature': self.temperature, 'seed': 0, 'num_predict': 2048,
                        'num_ctx': self.num_ctx},
        }
        if on_chunk is not None:
            result, timing = self._stream(payload, on_chunk)
        else:
            result, timing = self._request('/api/generate', payload), {}
        if not isinstance(result.get('response'), str) or not result['response'].strip():
            raise OllamaProtocolError('Ollama response field is missing, empty, or not text')
        if result.get('done') is not True or result.get('done_reason') == 'length':
            raise OllamaProtocolError('Ollama generation was incomplete or output-token limited')
        if not isinstance(result.get('model'), str) or not result['model']:
            raise OllamaProtocolError('Ollama response has no model name')
        for name in ('load_duration', 'prompt_eval_duration', 'eval_duration'):
            value = result.get(name)
            if type(value) is int and value >= 0:
                timing[name + '_seconds'] = value / 1_000_000_000
        return GenerationResult(result['response'], result['model'], time.perf_counter() - tick,
                                result.get('prompt_eval_count'), result.get('eval_count'), timing)
