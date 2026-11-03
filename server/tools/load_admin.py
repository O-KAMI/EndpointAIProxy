"""Synthetic policy publisher for a loopback-only isolated load environment."""
import http.client
import json
import ssl
import threading
import time
from urllib.parse import urlsplit
from uuid import UUID

from tools.load_transport import SyntheticTransport, loopback_port

FIXTURE_ADMIN_TOKEN = 'isolated-load-admin-token'
FIXTURE_ADMIN_USERNAME = 'synthetic-load-admin'
FIXTURE_ADMIN_PASSWORD = 'synthetic-load-admin-password-only'


def local_admin_port(admin_origin):
    url = urlsplit(admin_origin)
    if (url.scheme != 'https' or url.hostname != '127.0.0.1' or not url.port
            or url.netloc != f'127.0.0.1:{url.port}' or url.path not in ('', '/')
            or url.query or url.fragment):
        raise ValueError('Only explicit IPv4 loopback HTTPS admin origins are permitted')
    return url.port


class SyntheticAdmin:
    def __init__(self, origin, timeout=10):
        self.port = loopback_port(origin)
        self.timeout = timeout
        proof = SyntheticTransport(origin, timeout)
        try:
            proof.verify()
        finally:
            proof.close()

    def _request(self, method, body=None, path='/admin/v1/policy', expected_status=200):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        try:
            raw = None if body is None else json.dumps(body, separators=(',', ':')).encode()
            connection.request(method, path, raw, {
                'Authorization': 'Bearer ' + FIXTURE_ADMIN_TOKEN,
                'X-SF-Admin-Actor': 'synthetic-load', 'Content-Type': 'application/json',
            })
            response = connection.getresponse()
            data = response.read(1_000_001)
            if response.status != expected_status or len(data) > 1_000_000:
                raise RuntimeError('Synthetic admin request rejected')
            return json.loads(data)
        finally:
            connection.close()

    def publish_toggle(self):
        current = self._request('GET')
        if type(current.get('policyVersion')) is not int or type(current.get('enabled')) is not bool:
            raise ValueError('Invalid synthetic policy')
        fields = ('routeMode', 'gatewayOrigin', 'allowInsecureGateway', 'pollIntervalSeconds',
                  'heartbeatIntervalSeconds', 'allowlistedBaseUrls', 'allowlistedDomains', 'routingRules')
        update = {key: current[key] for key in fields if key in current}
        update.update(expectedVersion=current['policyVersion'], enabled=not current['enabled'])
        started = time.monotonic()
        result = self._request('PUT', update)
        completed = time.monotonic()
        if type(result.get('policyVersion')) is not int or result['policyVersion'] <= current['policyVersion']:
            raise RuntimeError('Synthetic policy publication did not advance')
        return dict(version=result['policyVersion'], started=started, completed=completed)

    def create_command(self, device, command_type):
        if str(UUID(device)) != device or command_type not in ('enableProxy', 'disableProxy'):
            raise ValueError('Invalid synthetic command target')
        started = time.monotonic()
        result = self._request('POST', dict(type=command_type, reason='synthetic load test', expiresInMinutes=10),
                               f'/admin/v1/devices/{device}/commands', expected_status=202)
        completed = time.monotonic()
        command_id = result.get('commandId')
        if not isinstance(command_id, str) or str(UUID(command_id)) != command_id or result.get('deviceId') != device:
            raise ValueError('Invalid synthetic command response')
        return dict(commandId=command_id, deviceId=device, started=started, completed=completed)

    def query_devices(self):
        started = time.monotonic()
        result = self._request('GET', path='/admin/v1/devices?skip=0&take=25')
        elapsed = time.monotonic() - started
        if not isinstance(result, list) or len(result) > 25:
            raise ValueError('Invalid synthetic device page')
        return elapsed


class LocalSyntheticAdmin(SyntheticAdmin):
    """Local-account path using a verified test CA and a fixed public fixture account."""
    def __init__(self, origin, admin_origin, ca_file, timeout=10):
        admin_port = local_admin_port(admin_origin)
        super().__init__(origin, timeout)
        self.admin_port = admin_port
        self.tls_context = ssl.create_default_context(cafile=str(ca_file))
        self.session = None
        self.login_lock = threading.Lock()
        self._login()

    def _login(self):
        status, login = self._send('POST', dict(username=FIXTURE_ADMIN_USERNAME, password=FIXTURE_ADMIN_PASSWORD),
                                   '/auth/login', None)
        if (status != 200 or login.get('username') != FIXTURE_ADMIN_USERNAME or login.get('role') != 'admin'
                or not isinstance(login.get('token'), str) or not login['token']):
            raise RuntimeError('Synthetic local administrator login failed')
        self.session = login['token']

    def _send(self, method, body, path, token):
        connection = http.client.HTTPSConnection('127.0.0.1', self.admin_port, timeout=self.timeout,
                                               context=self.tls_context)
        try:
            raw = None if body is None else json.dumps(body, separators=(',', ':')).encode()
            headers = {'Content-Type': 'application/json'}
            if token is not None:
                headers['Authorization'] = 'Bearer ' + token
            connection.request(method, path, raw, headers)
            response = connection.getresponse()
            data = response.read(1_000_001)
            if len(data) > 1_000_000:
                raise RuntimeError('Synthetic local administrator request rejected')
            return response.status, json.loads(data) if data else {}
        finally:
            connection.close()

    def _request(self, method, body=None, path='/admin/v1/policy', expected_status=200):
        token = self.session
        status, data = self._send(method, body, path, token)
        if status == 401:
            with self.login_lock:
                if self.session == token:
                    self._login()
                token = self.session
            status, data = self._send(method, body, path, token)
        if status != expected_status:
            raise RuntimeError('Synthetic local administrator request rejected')
        return data

    def create_rollout(self, devices, max_per_second=20):
        if (not 1 <= len(devices) <= 150_000 or not 1 <= max_per_second <= 5000
                or len(set(devices)) != len(devices)
                or any(not isinstance(device, str) or str(UUID(device)) != device for device in devices)):
            raise ValueError('Invalid synthetic rollout targets')
        result = self._request('POST', dict(type='disableProxy', reason='synthetic load test',
            expiresInMinutes=60, maxPerSecond=max_per_second, deviceIds=devices, confirmCount=len(devices)),
            '/admin/v1/rollouts', expected_status=201)
        batch = result.get('batchId')
        if (not isinstance(batch, str) or str(UUID(batch)) != batch or result.get('status') != 'paused'
                or result.get('totalTargets') != len(devices)):
            raise ValueError('Invalid synthetic rollout response')
        return batch

    def change_rollout(self, batch, action):
        if str(UUID(batch)) != batch or action not in ('pause', 'resume'):
            raise ValueError('Invalid synthetic rollout action')
        return self._request('POST', dict(reason='synthetic load test'), f'/admin/v1/rollouts/{batch}/{action}')

    def rollout_details(self, batch):
        if str(UUID(batch)) != batch:
            raise ValueError('Invalid synthetic rollout identifier')
        return self._request('GET', path=f'/admin/v1/rollouts/{batch}?skip=0&take=1')

    def rollout_targets(self, batch):
        if str(UUID(batch)) != batch:
            raise ValueError('Invalid synthetic rollout identifier')
        after = ''
        count = 0
        while True:
            page = self._request('GET', path=f'/admin/v1/rollouts/{batch}/targets?take=500&after={after}')
            rows, next_after = page.get('targets'), page.get('nextAfter')
            if page.get('batchId') != batch or not isinstance(rows, list) or len(rows) > 500:
                raise ValueError('Invalid synthetic rollout target page')
            for row in rows:
                device = row.get('deviceId')
                command = row.get('commandId')
                if (not isinstance(device, str) or str(UUID(device)) != device or device <= after
                        or (command is not None and (not isinstance(command, str) or str(UUID(command)) != command))):
                    raise ValueError('Invalid synthetic rollout target')
                after = device
                count += 1
                if count > 150_000:
                    raise ValueError('Too many synthetic rollout targets')
                yield row
            if next_after is None:
                break
            if not rows or next_after != after:
                raise ValueError('Invalid synthetic rollout cursor')
