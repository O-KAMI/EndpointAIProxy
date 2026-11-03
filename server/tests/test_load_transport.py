import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from controlserver.security import sign_policy
from controlserver.transport import open_envelope, seal
from tools.load_transport import (FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID,
                                  SyntheticTransport, loopback_port)


@pytest.mark.parametrize('origin', [
    'http://localhost:1234', 'http://192.168.1.1:1234', 'https://127.0.0.1:1234',
    'http://127.0.0.1:1234/path', 'http://user@127.0.0.1:1234',
    'http://127.0.0.1:1234/?query=1', 'http://127.0.0.1',
])
def test_rejects_nonfixture_origins(origin):
    with pytest.raises(ValueError):
        loopback_port(origin)


@pytest.fixture
def fixture_server():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            env = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            inner = open_envelope(FIXTURE_KEY, FIXTURE_KEY_ID, env, 'request')
            assert inner['token'] == FIXTURE_ENROLLMENT_TOKEN
            body = b'{"policyVersion":1}' if inner['path'] == '/api/v1/policy' else b'{"ok":true}'
            headers = {'X-SF-Policy-Signature': sign_policy(body, FIXTURE_KEY)}
            if self.server.bad_signature:
                headers['X-SF-Policy-Signature'] = 'invalid'
            result = dict(status=200, body=base64.b64encode(body).decode(), headers=headers)
            wire = json.dumps(seal(FIXTURE_KEY, FIXTURE_KEY_ID, env['requestId'], result, 'response')).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.bad_signature = False
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_synthetic_encrypted_transport_requires_proof(fixture_server):
    client = SyntheticTransport(f'http://127.0.0.1:{fixture_server.server_port}')
    with pytest.raises(RuntimeError):
        client.request('GET', '/api/v1/policy', FIXTURE_ENROLLMENT_TOKEN)
    client.verify()
    result = client.request('POST', '/api/v1/heartbeat', FIXTURE_ENROLLMENT_TOKEN, {'synthetic': True})
    assert result['status'] == 200
    assert json.loads(result['body']) == {'ok': True}
    client.close()


def test_rejects_untrusted_endpoint_before_dispatch(fixture_server):
    fixture_server.bad_signature = True
    client = SyntheticTransport(f'http://127.0.0.1:{fixture_server.server_port}')
    with pytest.raises(RuntimeError):
        client.verify()
    with pytest.raises(RuntimeError):
        client.request('POST', '/api/v1/heartbeat', FIXTURE_ENROLLMENT_TOKEN, {})


def test_synthetic_transport_interoperates_with_control_app(config):
    from werkzeug.serving import make_server
    from app import create_app
    from controlserver.validation import seed_policy

    config.CLIENT_TOKEN = FIXTURE_ENROLLMENT_TOKEN
    config.TRANSPORT_KEY_ID = FIXTURE_KEY_ID
    config.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    config.HMAC_TEXT = config.TRANSPORT_KEY_TEXT
    config.validate()

    class Store:
        def claim_transport(self, envelope):
            return True

        def policy(self):
            return seed_policy(config)

    server = make_server('127.0.0.1', 0, create_app(config, Store(), check_database=False), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = SyntheticTransport(f'http://127.0.0.1:{server.server_port}')
    try:
        client.verify()
        result = client.request('GET', '/api/v1/policy', FIXTURE_ENROLLMENT_TOKEN)
        assert result['status'] == 200
        assert json.loads(result['body'])['policyVersion'] == 1
    finally:
        client.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
