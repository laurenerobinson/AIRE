"""Ollama transport tests without a service, network sockets, or Ghidra."""
import io
from http.client import IncompleteRead
import json
import os
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from aire.ai.ollama_client import (OllamaClient, OllamaError, OllamaConnectionError,
    OllamaTimeoutError, OllamaModelError, OllamaProtocolError, _NoRedirect)


class OllamaClientTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = OllamaClient(model='installed:small')
        self.client._opener = MagicMock()

    def reply(self, value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.client._opener.open.return_value.__enter__.return_value.read.return_value = raw

    def success(self):
        self.reply({'response': ' {} ', 'model': 'installed:small', 'done': True, 'prompt_eval_count': 5})

    def test_success_and_request(self):
        self.success()
        result = self.client.generate('evidence', system='rules', response_schema={'type': 'object'})
        self.assertEqual(result.text, ' {} ')
        self.assertEqual(result.model, 'installed:small')
        request = self.client._opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'http://127.0.0.1:11434/api/generate')
        body = json.loads(request.data)
        self.assertEqual(body['system'], 'rules')
        self.assertFalse(body['stream'])
        self.assertEqual(body['options']['temperature'], 0.1)
        self.assertEqual(body['options']['num_ctx'], 32768)
        self.assertEqual(body['options']['num_predict'], 2048)
        self.assertEqual(body['model'], 'installed:small')
        self.assertEqual(body['format'], {'type': 'object'})
        self.assertEqual(self.client._opener.open.call_args.kwargs['timeout'], 240)
        self.assertEqual(body['keep_alive'], '10m')

    def stream_reply(self, records):
        lines = [json.dumps(r).encode() + b'\n' for r in records]
        response = self.client._opener.open.return_value.__enter__.return_value
        response.readline.side_effect = lines + [b'']

    def test_streaming_preserves_schema_and_records_timings(self):
        self.stream_reply([{'response': '{', 'done': False},
                           {'response': '}', 'done': False},
                           {'response': '', 'model': 'm', 'done': True, 'eval_duration': 25000000}])
        chunks = []
        result = self.client.generate('evidence', response_schema={'type': 'object'}, on_chunk=chunks.append)
        self.assertEqual(result.text, '{}')
        self.assertEqual(chunks, ['{', '}'])
        self.assertIn('first_output_seconds', result.timing)
        self.assertEqual(result.timing['eval_duration_seconds'], .025)
        body = json.loads(self.client._opener.open.call_args.args[0].data)
        self.assertTrue(body['stream'])
        self.assertEqual(body['format'], {'type': 'object'})

    def test_stream_rejects_invalid_and_incomplete_records(self):
        for records in ([{'response': '{}', 'done': False}],
                        [{'response': '{}', 'model': 'm', 'done': True, 'done_reason': 'length'}],
                        [{'response': 42, 'done': True}],
                        [{'response': '{}', 'done': True}]):
            self.stream_reply(records)
            with self.assertRaises(OllamaProtocolError):
                self.client.generate('evidence', on_chunk=lambda s: None)

    def test_stream_rejects_malformed_oversized_and_model_errors(self):
        response = self.client._opener.open.return_value.__enter__.return_value
        for line in (b'not json\n', b'[]\n', b'x' * 1000001):
            response.readline.side_effect = [line]
            with self.assertRaises(OllamaProtocolError):
                self.client.generate('evidence', on_chunk=lambda s: None)
        self.stream_reply([{'error': 'model unavailable'}])
        with self.assertRaises(OllamaModelError):
            self.client.generate('evidence', on_chunk=lambda s: None)

    def test_explicit_warmup_has_no_binary_evidence_and_keeps_model_loaded(self):
        self.reply({'done': True})
        self.client.warm()
        body = json.loads(self.client._opener.open.call_args.args[0].data)
        self.assertEqual(body['prompt'], '')
        self.assertEqual(body['keep_alive'], '10m')
        self.assertNotIn('system', body)

    def test_num_ctx_default(self):
        self.assertEqual(OllamaClient().num_ctx, 32768)

    def test_num_ctx_environment_reaches_request(self):
        with patch.dict(os.environ, {'AIRE_OLLAMA_NUM_CTX': '4096',
                'AIRE_OLLAMA_HOST': 'http://localhost:1234', 'AIRE_OLLAMA_MODEL': 'local:v2'}):
            self.client = OllamaClient(temperature=0.25)
        self.client._opener = MagicMock()
        self.success()
        self.client.generate('evidence')
        request = self.client._opener.open.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(self.client.num_ctx, 4096)
        self.assertEqual(request.full_url, 'http://127.0.0.1:1234/api/generate')
        self.assertEqual(body['model'], 'local:v2')
        self.assertEqual(body['options'], {
            'temperature': 0.25, 'seed': 0, 'num_predict': 2048, 'num_ctx': 4096})

    def test_num_ctx_invalid_environment_string(self):
        for value in ('', 'invalid', '4096.0', '4_096', '+4096', ' 4096', '４０９６'):
            with self.subTest(value=value), patch.dict(os.environ, {'AIRE_OLLAMA_NUM_CTX': value}):
                with self.assertRaisesRegex(ValueError, 'AIRE_OLLAMA_NUM_CTX.*positive'):
                    OllamaClient()

    def test_num_ctx_zero_environment_rejected(self):
        with patch.dict(os.environ, {'AIRE_OLLAMA_NUM_CTX': '0'}):
            with self.assertRaisesRegex(ValueError, 'AIRE_OLLAMA_NUM_CTX.*positive'):
                OllamaClient()

    def test_num_ctx_negative_environment_rejected(self):
        with patch.dict(os.environ, {'AIRE_OLLAMA_NUM_CTX': '-2048'}):
            with self.assertRaisesRegex(ValueError, 'AIRE_OLLAMA_NUM_CTX.*positive'):
                OllamaClient()

    def test_num_ctx_explicit_override(self):
        with patch.dict(os.environ, {'AIRE_OLLAMA_NUM_CTX': 'invalid'}):
            self.client = OllamaClient(model='explicit', num_ctx=2048)
        self.client._opener = MagicMock()
        self.success()
        self.client.generate('evidence')
        self.assertEqual(json.loads(self.client._opener.open.call_args.args[0].data)['options']['num_ctx'], 2048)

    def test_num_ctx_explicit_invalid(self):
        for value in (0, -1, True, 4096.0, '4096'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'num_ctx.*positive'):
                OllamaClient(num_ctx=value)

    def test_connection_failure(self):
        self.client._opener.open.side_effect = URLError(ConnectionRefusedError('refused'))
        with self.assertRaisesRegex(OllamaConnectionError, '127.0.0.1'):
            self.client.generate('x')
        self.assertEqual(self.client._opener.open.call_count, 1)

    def test_timeout(self):
        for error in (TimeoutError(), URLError(TimeoutError())):
            self.client._opener.open.side_effect = error
            with self.assertRaises(OllamaTimeoutError):
                self.client.generate('x')

    def test_malformed_json(self):
        for value in (b'not json', b'\xff', b'[]'):
            self.reply(value)
            with self.assertRaises(OllamaProtocolError):
                self.client.generate('x')

    def test_incomplete_http_body(self):
        response = self.client._opener.open.return_value.__enter__.return_value
        response.read.side_effect = IncompleteRead(b'{', 20)
        with self.assertRaises(OllamaProtocolError):
            self.client.generate('x')

    def test_missing_or_invalid_response_field(self):
        for value in (None, 0, '', '   '):
            self.reply({'response': value, 'done': True, 'model': 'm'})
            with self.assertRaises(OllamaProtocolError):
                self.client.generate('x')

    def test_incomplete_response(self):
        for extra in ({'done': False}, {'done': True, 'done_reason': 'length'}, {'done': True}):
            self.reply({'response': '{}', **extra})
            with self.assertRaises(OllamaProtocolError):
                self.client.generate('x')

    def test_model_error(self):
        self.reply({'error': 'model not found'})
        with self.assertRaisesRegex(OllamaModelError, 'installed:small'):
            self.client.generate('x')

    def test_http_missing_model(self):
        self.client._opener.open.side_effect = HTTPError('url', 404, 'missing', {}, io.BytesIO(b'model not found'))
        with self.assertRaisesRegex(OllamaModelError, 'installed:small'):
            self.client.generate('x')

    def test_http_server_error(self):
        self.client._opener.open.side_effect = HTTPError('url', 500, 'failed', {}, io.BytesIO(b'failure'))
        with self.assertRaisesRegex(OllamaError, 'HTTP 500'):
            self.client.generate('x')

    def test_configurable_host_model(self):
        with patch.dict(os.environ, {'AIRE_OLLAMA_HOST': 'http://localhost:1234', 'AIRE_OLLAMA_MODEL': 'local:v2'}):
            client = OllamaClient()
            self.assertEqual((client.host, client.model), ('http://127.0.0.1:1234', 'local:v2'))
            self.assertEqual(OllamaClient(model='explicit').model, 'explicit')

    def test_no_default_model_or_automatic_requests(self):
        client = OllamaClient()
        client._opener = MagicMock()
        with self.assertRaisesRegex(OllamaModelError, 'No model selected'):
            client.generate('x')
        client._opener.open.assert_not_called()

    def test_health_and_discovery(self):
        self.reply({'models': [{'name': 'z'}, {'name': 'a'}, {'name': 'a'}]})
        self.assertEqual(self.client.health()['models'], ['a', 'z'])
        self.assertTrue(self.client._opener.open.call_args.args[0].full_url.endswith('/api/tags'))
        self.assertEqual(self.client._opener.open.call_args.kwargs['timeout'], 3)

    def test_empty_and_malformed_model_lists(self):
        self.reply({'models': []})
        self.assertEqual(self.client.list_models(), [])
        for value in ({}, {'models': [None]}, {'models': [{'name': ''}]}):
            self.reply(value)
            with self.assertRaises(OllamaProtocolError):
                self.client.list_models()

    def test_remote_hosts_rejected_without_dns(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            for host in ('http://example.com', 'http://192.168.1.1:11434', 'http://0.0.0.0',
                         'http://localhost.evil', 'http://2130706433', 'http://127.1', 'http://[::ffff:127.0.0.1]'):
                with self.subTest(host=host), self.assertRaises(ValueError):
                    OllamaClient(host=host)

    def test_explicit_remote_opt_in(self):
        client = OllamaClient(host='http://192.0.2.1:11434', allow_remote_host=True)
        self.assertEqual(client.host, 'http://192.0.2.1:11434')

    def test_loopback_ipv6(self):
        self.assertEqual(OllamaClient(host='http://[::1]:11434').host, 'http://[::1]:11434')

    def test_mapped_ipv6_policy_independent_of_python_loopback_classification(self):
        from unittest.mock import PropertyMock
        # Some Python versions classify mapped loopback differently. Honor the
        # same narrow default allowlist on both, without performing a request.
        with patch('ipaddress.IPv6Address.is_loopback', new_callable=PropertyMock, return_value=True):
            for host in ('http://[::ffff:127.0.0.1]', 'http://[::ffff:7f00:1]'):
                with self.subTest(host=host), self.assertRaises(ValueError):
                    OllamaClient(host=host)
            client = OllamaClient(host='http://[::ffff:127.0.0.1]', allow_remote_host=True)
            self.assertEqual(client.host, 'http://[::ffff:127.0.0.1]')

    def test_unsafe_url_shapes(self):
        for host in ('file:///tmp/a', 'http://user:pass@localhost', 'http://localhost/path',
                     'http://localhost?x=y', 'http://localhost/#x', 'http://localhost:99999',
                     'http://local\nhost', 'http://[::1%eth0]'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                OllamaClient(host=host)

    def test_proxies_disabled(self):
        with patch('aire.ai.ollama_client.build_opener') as build:
            OllamaClient()
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], _NoRedirect)

    def test_redirect_disabled(self):
        with self.assertRaises(OllamaProtocolError):
            _NoRedirect().redirect_request(None, None, 302, '', {}, 'http://remote/')

    def test_limits(self):
        for options in ({'timeout_seconds': 0}, {'timeout_seconds': float('nan')},
                        {'temperature': True}, {'temperature': 2}, {'model': ''}, {'allow_remote_host': 1}):
            with self.assertRaises(ValueError):
                OllamaClient(**options)
        self.reply(b'x' * 1_000_001)
        with self.assertRaises(OllamaProtocolError):
            self.client.generate('x')
        with self.assertRaises(ValueError):
            self.client.generate('x' * 250001)


if __name__ == '__main__':
    unittest.main()
