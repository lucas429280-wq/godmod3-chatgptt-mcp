"""Public MCP boundary tests with synthetic backend credentials; no paid calls."""
import functools
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4

import httpx
from starlette.testclient import TestClient

BASE = 'https://bridge.example.invalid'
KEY = 'synthetic-private-backend-fixture'


class PublicMCPTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {
            'PUBLIC_URL': BASE,
            'GODMOD3_BASE_URL': 'https://backend.example.invalid',
            'GODMOD3_API_KEY': KEY,
        })
        self.environment.start()
        os.environ.pop('OAUTH_ADMIN_PASSWORD', None)
        os.environ.pop('MCP_ACCESS_TOKEN', None)
        name = 'public_bridge_' + uuid4().hex
        path = Path(__file__).resolve().parents[1] / 'server (1).py'
        spec = importlib.util.spec_from_file_location(name, path)
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.module
        spec.loader.exec_module(self.module)
        self.context = TestClient(self.module.app, base_url=BASE)
        self.client = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.addCleanup(self.environment.stop)
        self.addCleanup(sys.modules.pop, name, None)

    def rpc(self, method, params=None, extra_headers=None):
        return self.client.post('/mcp', json={
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {},
        }, headers={'Accept': 'application/json, text/event-stream', **(extra_headers or {})})

    def test_initialize_without_any_client_credential(self):
        response = self.rpc('initialize', {
            'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': 'public-test', 'version': '1'},
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('serverInfo', response.json()['result'])
        self.assertNotIn('WWW-Authenticate', response.headers)

    def test_tool_listing_without_any_client_credential(self):
        response = self.rpc('tools/list')
        self.assertEqual(response.status_code, 200)
        self.assertEqual({x['name'] for x in response.json()['result']['tools']},
                         {'godmod3_models', 'godmod3_chat'})

    def test_old_oauth_endpoints_no_longer_request_login(self):
        for path in ('/login', '/authorize', '/token', '/register',
                     '/.well-known/oauth-authorization-server',
                     '/.well-known/oauth-protected-resource/mcp'):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
                self.assertEqual(self.client.post(path, data={}).status_code, 404)

    def test_invalid_legacy_bearer_does_not_trigger_oauth(self):
        response = self.rpc('tools/list', extra_headers={'Authorization': 'Bearer expired-legacy-fixture'})
        self.assertEqual(response.status_code, 200)

    def test_host_and_origin_protection_remain_enabled(self):
        self.assertEqual(self.rpc('tools/list', extra_headers={'Host': 'untrusted.example.invalid'}).status_code, 421)
        self.assertEqual(self.rpc('tools/list', extra_headers={'Origin': 'https://untrusted.example.invalid'}).status_code, 403)
        self.assertEqual(self.rpc('tools/list', extra_headers={'Origin': 'https://chatgpt.com'}).status_code, 200)

    def test_health_reports_no_auth_without_exposing_secrets(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['auth'], 'none')
        self.assertNotIn(KEY, response.text)

    def test_public_tools_still_authenticate_to_private_backend(self):
        requests = []
        def backend(request):
            requests.append(request)
            self.assertEqual(request.url.host, 'backend.example.invalid')
            self.assertEqual(request.headers['Authorization'], 'Bearer ' + KEY)
            if request.url.path == '/v1/models':
                return httpx.Response(200, json={'data': [{'id': 'fixture-model'}]})
            self.assertEqual(request.url.path, '/v1/chat/completions')
            body = json.loads(request.content)
            self.assertEqual(body['model'], 'fixture-model')
            self.assertFalse(body['stream'])
            self.assertFalse(body['contribute_to_dataset'])
            return httpx.Response(200, json={'choices': [{'message': {'content': 'OK'}}]})
        original_client = httpx.AsyncClient
        with patch.object(self.module.httpx, 'AsyncClient',
                          functools.partial(original_client, transport=httpx.MockTransport(backend))):
            for tool, arguments in [('godmod3_models', {}),
                                    ('godmod3_chat', {'prompt': 'Reply OK', 'model': 'fixture-model'})]:
                with self.subTest(tool=tool):
                    response = self.rpc('tools/call', {'name': tool, 'arguments': arguments})
                    self.assertEqual(response.status_code, 200)
                    self.assertFalse(response.json()['result'].get('isError', False))
                    self.assertNotIn(KEY, response.text)
        self.assertEqual(len(requests), 2)


if __name__ == '__main__':
    unittest.main()
