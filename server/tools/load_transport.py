"""Transport foundation for a synthetic loopback-only control-plane load harness.

This module is not a capacity test. It deliberately accepts only a fixed public
fixture key, token and loopback HTTP origin; never configure these on production.
"""
import base64
import hmac
import http.client
import json
from urllib.parse import urlsplit
from uuid import uuid4

from controlserver.security import sign_policy
from controlserver.transport import open_envelope, seal

FIXTURE_KEY = bytes(range(32))
FIXTURE_KEY_ID = 'isolated-load-fixture-v1'
FIXTURE_ENROLLMENT_TOKEN = 'isolated-load-enrollment-token'
MAX_RESPONSE = 56_000_000


def loopback_port(origin):
    u = urlsplit(origin)
    if (u.scheme != 'http' or u.hostname != '127.0.0.1' or u.username is not None
            or u.password is not None or u.path not in ('', '/') or u.query or u.fragment
            or not u.port or u.netloc != f'127.0.0.1:{u.port}'):
        raise ValueError('Only an explicit IPv4 loopback HTTP origin is permitted')
    return u.port


class SyntheticTransport:
    def __init__(self, origin, timeout=10):
        self.port = loopback_port(origin)
        self.timeout = timeout
        self.connection = None
        self.verified = False

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def request(self, method, path, token, body=None, query=''):
        if not self.verified:
            raise RuntimeError('Verify the synthetic endpoint before dispatch')
        return self._request(method, path, token, body, query)

    def _request(self, method, path, token, body=None, query=''):
        if method not in ('GET', 'POST') or not path.startswith('/api/v'):
            raise ValueError('Invalid synthetic request')
        payload = b'' if body is None else json.dumps(body, separators=(',', ':')).encode('utf-8')
        request_id = str(uuid4())
        inner = dict(method=method, path=path, query=query, token=token,
                     body=base64.b64encode(payload).decode('ascii'))
        wire = json.dumps(seal(FIXTURE_KEY, FIXTURE_KEY_ID, request_id, inner, 'request'),
                          separators=(',', ':')).encode('utf-8')
        if self.connection is None:
            self.connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        try:
            self.connection.request('POST', '/api/transport/v1', wire, {'Content-Type': 'application/json'})
            response = self.connection.getresponse()
            data = response.read(MAX_RESPONSE + 1)
            if response.status != 200 or len(data) > MAX_RESPONSE:
                raise RuntimeError('Synthetic transport request rejected')
            result = open_envelope(FIXTURE_KEY, FIXTURE_KEY_ID, json.loads(data), 'response', request_id)
            if not isinstance(result, dict) or set(result) != {'status', 'body', 'headers'}:
                raise ValueError('Invalid synthetic response')
            result['body'] = base64.b64decode(result['body'], validate=True)
            return result
        except Exception:
            self.close()
            raise

    def verify(self):
        self.verified = False
        result = self._request('GET', '/api/v1/policy', FIXTURE_ENROLLMENT_TOKEN)
        signature = result['headers'].get('X-SF-Policy-Signature', '')
        if result['status'] != 200 or not hmac.compare_digest(signature, sign_policy(result['body'], FIXTURE_KEY)):
            self.close()
            raise RuntimeError('Endpoint did not prove the synthetic fixture configuration')
        self.verified = True
