import base64
import copy
import json
from pathlib import Path
from uuid import uuid4
import pytest

from app import create_app
from controlserver.device_transport import (device_for_key_id, device_key_id, device_master,
    device_v2_key_id, device_v2_for_key_id, device_v2_master)
from controlserver.security import hash_token
from controlserver.transport import seal, open_envelope, b64
from controlserver.validation import seed_policy

FIXTURE = json.loads((Path(__file__).parent / 'fixtures' / 'dotnet-v0.1.19.json').read_text(encoding='utf-8'))
DEVICE = '11111111-2222-4333-8444-555555555555'
OTHER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
TOKEN = 'synthetic-device-token-1234567890'


def test_derivation_vector_and_invalid_identifiers():
    key_id = device_key_id(DEVICE)
    assert key_id == 'dv1_11111111222243338444555555555555'
    assert device_for_key_id(key_id) == DEVICE
    assert device_master(hash_token(TOKEN), DEVICE).hex() == '4b70d6d084f7b137a74034ff407c481d0bbbd14a1fef24a6017d18b82d78b894'
    assert device_master(hash_token(TOKEN), DEVICE) != device_master(hash_token(TOKEN), OTHER)
    assert device_master(hash_token(TOKEN), DEVICE) != device_master(hash_token('synthetic-new-token-1234567890'), DEVICE)
    for bad in ('dv1_' + '0' * 32, key_id.upper(), key_id + '0', 'shared'):
        assert device_for_key_id(bad) is None
    with pytest.raises(ValueError): device_master('bad', DEVICE)


def test_device_transport_namespace_cannot_collide_with_shared_keys(config):
    config.DEVICE_TRANSPORT = True
    config.TRANSPORT_KEY_ID = device_key_id(DEVICE)
    with pytest.raises(ValueError, match='namespace'):
        config.validate()


def test_production_device_transport_requires_loopback_tls_proxy(config):
    config.APP_ENV = 'prd'
    config.DEVICE_TRANSPORT = True
    with pytest.raises(ValueError, match='loopback listener'):
        config.validate()
    config.HTTP_HOST = '127.0.0.1'
    config.TRUST_PROXY = True
    assert config.validate().DEVICE_TRANSPORT is True


def test_bound_envelopes_require_tls_active_credential_and_exact_device(config):
    config.DEVICE_TRANSPORT = True
    class Store:
        def __init__(self):
            self.verifiers = {DEVICE: hash_token(TOKEN), OTHER: hash_token('another-synthetic-token-123456')}
            self.replays = set()
        def device_transport_verifier(self, device): return self.verifiers.get(device)
        def claim_transport(self, envelope):
            key = (envelope['keyId'], envelope['requestId'])
            if key in self.replays: return False
            self.replays.add(key); return True
        def authenticate(self, device, token): return self.verifiers.get(str(device)) == hash_token(token)
        def policy(self, *args, **kwargs): return seed_policy(config)
        def heartbeat(self, *args, **kwargs): pass
        def lease(self, device): return None
    store = Store()
    client = create_app(config, store, check_database=False).test_client()
    kid = device_key_id(DEVICE)
    master = device_master(hash_token(TOKEN), DEVICE)
    def make(key, name, path, token, body=None, method=None):
        return seal(key, name, str(uuid4()), dict(method=method or ('GET' if body is None else 'POST'),
            path=path, query='', token=token, body=b64(b'' if body is None else json.dumps(body).encode())), 'request')
    def send(wire, secure=True):
        return client.post('/api/transport/v1', json=wire, base_url='https://localhost' if secure else 'http://localhost')
    def inner(response, wire, key=master, name=kid):
        return open_envelope(key, name, response.json, 'response', wire['requestId'])
    policy = f'/api/v2/devices/{DEVICE}/policy'
    wire = make(master, kid, policy, TOKEN)
    assert TOKEN not in json.dumps(wire) and master.hex() not in json.dumps(wire)
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        open_envelope(config.TRANSPORT_KEY, kid, wire, 'request')
    assert send(wire, secure=False).status_code == 400
    response = send(wire)
    assert response.status_code == 200 and inner(response, wire)['status'] == 200
    assert send(wire).status_code == 400
    assert send(make(master, kid, f'/api/v2/devices/{OTHER}/policy', TOKEN)).status_code == 400
    assert send(make(master, kid, policy, 'another-synthetic-token-123456')).status_code == 400
    assert send(make(master, kid, '/api/v2/enroll', TOKEN, FIXTURE['enrollment'])).status_code == 400
    beat = copy.deepcopy(FIXTURE['heartbeat']); beat['device']['deviceId'] = OTHER
    # Even a duplicated verifier cannot escape the envelope's device binding.
    store.verifiers[OTHER] = hash_token(TOKEN)
    assert store.authenticate(OTHER, TOKEN)
    cross = make(master, kid, '/api/v2/heartbeat', TOKEN, beat)
    result = send(cross)
    assert result.status_code == 200 and inner(result, cross)['status'] == 401
    beat['device']['deviceId'] = DEVICE
    legacy_policy = make(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, '/api/v1/policy', config.CLIENT_TOKEN)
    legacy_response = send(legacy_policy, secure=False)
    assert inner(legacy_response, legacy_policy, config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID)['status'] == 200
    legacy = make(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, '/api/v2/heartbeat', TOKEN, beat)
    result = send(legacy)
    body = inner(result, legacy, config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID)
    assert json.loads(base64.b64decode(body['body']))['deviceTransport'] is True
    legacy_http = make(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, '/api/v2/heartbeat', TOKEN, beat)
    result = send(legacy_http, secure=False)
    body = inner(result, legacy_http, config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID)
    assert 'deviceTransport' not in json.loads(base64.b64decode(body['body']))
    del store.verifiers[DEVICE]
    assert send(make(master, kid, policy, TOKEN)).status_code == 400


def test_mysql_device_transport_rotation_and_replay(mysql_store):
    cfg = mysql_store.cfg
    cfg.DEVICE_TRANSPORT = True
    client = create_app(cfg, mysql_store).test_client()
    def exchange(master, key_id, method, path, token, body=None):
        wire = seal(master, key_id, str(uuid4()), dict(method=method, path=path, query='', token=token,
            body=b64(b'' if body is None else json.dumps(body).encode())), 'request')
        response = client.post('/api/transport/v1', json=wire, base_url='https://localhost')
        if response.status_code != 200:
            return response.status_code, None, wire
        value = open_envelope(master, key_id, response.json, 'response', wire['requestId'])
        return response.status_code, value, wire
    status, value, _ = exchange(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, 'POST', '/api/v2/enroll',
                                 cfg.CLIENT_TOKEN, FIXTURE['enrollment'])
    assert status == 200 and value['status'] == 200
    credential = json.loads(base64.b64decode(value['body']))
    device, token = credential['deviceId'], credential['deviceToken']
    beat = copy.deepcopy(FIXTURE['heartbeat'])
    status, value, _ = exchange(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, 'POST', '/api/v2/heartbeat', token, beat)
    assert status == 200 and json.loads(base64.b64decode(value['body']))['deviceTransport'] is True
    kid, master = device_key_id(device), device_master(hash_token(token), device)
    route = f'/api/v2/devices/{device}/policy'
    status, value, wire = exchange(master, kid, 'GET', route, token)
    assert status == 200 and value['status'] == 200
    assert client.post('/api/transport/v1', json=wire, base_url='https://localhost').status_code == 400
    recovered = mysql_store.recover_device_credential(device, beat['device']['hostname'], 'synthetic rotation', 'fixture-admin')
    new_token = recovered['deviceToken']
    assert exchange(master, kid, 'GET', route, token)[0] == 400
    new_master = device_master(hash_token(new_token), device)
    status, value, _ = exchange(new_master, kid, 'GET', route, new_token)
    assert status == 200 and value['status'] == 200
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET revoked=1 WHERE device_id=%s', (device,))
    assert exchange(new_master, kid, 'GET', route, new_token)[0] == 400


@pytest.mark.parametrize("use_v2", [False, True])
def test_go_client_and_python_server_device_transport_over_pinned_https(mysql_store, tmp_path, use_v2):
    import ipaddress
    import os
    import subprocess
    from datetime import datetime, timedelta, timezone
    from threading import Thread
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from werkzeug.serving import make_server

    go = os.environ.get('ENDPOINTAI_TEST_GO')
    if not go:
        pytest.skip('Set ENDPOINTAI_TEST_GO to the local toolchain for loopback interop')
    cfg = mysql_store.cfg
    cfg.DEVICE_TRANSPORT = not use_v2
    cfg.DEVICE_TRANSPORT_V2 = use_v2
    if use_v2:
        # Stage generation 2 as an overlap key, then promote after first use.
        cfg.DEVICE_KEY_ID = '1'
        cfg.DEVICE_KEY_TEXT = base64.b64encode(b'\x77' * 32).decode()
        cfg.DEVICE_PREVIOUS_KEY_ID = '2'
        cfg.DEVICE_PREVIOUS_KEY_TEXT = base64.b64encode(b'\x55' * 32).decode()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(hours=1)).add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
        .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'fixture-cert.pem', tmp_path / 'fixture-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256()); digest.update(public)
    pin = base64.b64encode(digest.finalize()).decode('ascii')
    app1 = create_app(cfg, mysql_store)
    routed = []
    if use_v2:
        # Emulate staggered worker configuration: both accept both keys,
        # but worker 2 advertises generation 2 while worker 1 advertises 1.
        cfg2 = copy.copy(cfg)
        cfg2.DEVICE_KEY_ID, cfg2.DEVICE_KEY_TEXT = cfg.DEVICE_PREVIOUS_KEY_ID, cfg.DEVICE_PREVIOUS_KEY_TEXT
        cfg2.DEVICE_PREVIOUS_KEY_ID, cfg2.DEVICE_PREVIOUS_KEY_TEXT = cfg.DEVICE_KEY_ID, cfg.DEVICE_KEY_TEXT
        app2 = create_app(cfg2, mysql_store)
        def application(environ, start_response):
            chosen = 2 if len(routed) == 3 else 1
            routed.append(chosen)
            return (app2 if chosen == 2 else app1)(environ, start_response)
    else:
        application = app1
    server = make_server('127.0.0.1', 0, application, threaded=True,
                         ssl_context=(str(cert_path), str(key_path)))
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    device = str(uuid4())
    repo = Path(__file__).resolve().parents[2]
    environment = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', CGO_ENABLED='0')
    try:
        process = subprocess.run([go, 'run', '-mod=vendor', './internal/control/testdata/device_binding_probe.go',
            '-origin', f'https://127.0.0.1:{server.server_port}', '-pin', pin, '-device', device,
            '-fixture', str(Path(__file__).parent / 'fixtures' / 'dotnet-v0.1.19.json')] + (['-v2', '-rotate'] if use_v2 else []),
            cwd=repo / 'go-client', env=environment, capture_output=True, encoding='utf-8', timeout=120)
        assert process.returncode == 0, process.stderr
        assert 'synthetic device-bound interop passed' in process.stdout
        if use_v2:
            assert routed == [1, 1, 1, 2, 1, 1]
        with mysql_store.transaction() as cur:
            cur.execute('SELECT COUNT(*) AS n FROM transport_replay WHERE key_id=%s', (device_v2_key_id(device, '2') if use_v2 else device_key_id(device),))
            assert cur.fetchone()['n'] == 2
            if use_v2:
                cur.execute('SELECT COUNT(*) AS n FROM transport_replay WHERE key_id=%s', (device_v2_key_id(device, '1'),))
                assert cur.fetchone()['n'] == 2
        detail = mysql_store.details(device)
        assert detail['device']['employeeIds'] and detail['agents'] and detail['endpoints']
    finally:
        server.shutdown(); thread.join(timeout=5); server.server_close()


def test_forwarded_tls_is_trusted_only_from_loopback(config):
    config.APP_ENV = 'prd'
    config.DEVICE_TRANSPORT = True
    config.HTTP_HOST = '127.0.0.1'
    config.TRUST_PROXY = True
    class Store:
        def device_transport_verifier(self, device): return hash_token(TOKEN) if device == DEVICE else None
        def claim_transport(self, envelope): return True
        def authenticate(self, device, token): return str(device) == DEVICE and token == TOKEN
        def policy(self, *args, **kwargs): return seed_policy(config)
    client = create_app(config, Store(), check_database=False).test_client()
    kid = device_key_id(DEVICE)
    master = device_master(hash_token(TOKEN), DEVICE)
    def request(remote):
        wire = seal(master, kid, str(uuid4()), dict(method='GET', path=f'/api/v2/devices/{DEVICE}/policy',
                    query='', token=TOKEN, body=b64(b'')), 'request')
        response = client.post('/api/transport/v1', json=wire, headers={'X-Forwarded-Proto':'https'},
                               environ_overrides={'REMOTE_ADDR':remote}, base_url='http://localhost')
        return response, wire
    response, wire = request('127.0.0.1')
    assert response.status_code == 200
    assert open_envelope(master, kid, response.json, 'response', wire['requestId'])['status'] == 200
    assert request('192.0.2.1')[0].status_code == 400


def test_device_verifier_failure_is_unavailable_and_never_dispatches(config):
    config.DEVICE_TRANSPORT = True
    class Store:
        def device_transport_verifier(self, device): raise RuntimeError('sensitive fixture database error')
        def claim_transport(self, envelope): pytest.fail('replay claim must not occur')
    client = create_app(config, Store(), check_database=False).test_client()
    kid = device_key_id(DEVICE)
    key = device_master(hash_token(TOKEN), DEVICE)
    wire = seal(key, kid, str(uuid4()), dict(method='GET', path=f'/api/v2/devices/{DEVICE}/policy',
        query='', token=TOKEN, body=b64(b'')), 'request')
    response = client.post('/api/transport/v1', json=wire, base_url='https://localhost')
    assert response.status_code == 503
    assert b'sensitive' not in response.data and TOKEN.encode() not in response.data


def test_v2_configuration_requires_distinct_secrets_and_valid_generations(config):
    config.DEVICE_TRANSPORT_V2 = True
    with pytest.raises(ValueError, match='supplied together'): config.validate()
    config.DEVICE_KEY_ID = '2'
    config.DEVICE_KEY_TEXT = base64.b64encode(b'\x55' * 32).decode()
    config.DEVICE_PREVIOUS_KEY_ID = '1'
    config.DEVICE_PREVIOUS_KEY_TEXT = base64.b64encode(b'\x77' * 32).decode()
    assert set(config.validate().DEVICE_TRANSPORT_V2_KEYS) == {'1', '2'}
    config.DEVICE_PREVIOUS_KEY_TEXT = config.DEVICE_KEY_TEXT
    with pytest.raises(ValueError, match='distinct'): config.validate()
    config.DEVICE_PREVIOUS_KEY_TEXT = base64.b64encode(b'\x77' * 32).decode()
    config.DEVICE_KEY_ID = '02'
    with pytest.raises(ValueError, match='generation'): config.validate()
    config.DEVICE_KEY_ID = '2'
    config.DEVICE_KEY_TEXT = config.TRANSPORT_KEY_TEXT
    with pytest.raises(ValueError, match='distinct'): config.validate()


def test_v2_derived_keys_require_server_secret_and_support_overlap(config):
    config.DEVICE_TRANSPORT = True
    config.DEVICE_TRANSPORT_V2 = True
    config.DEVICE_KEY_ID = '2'
    config.DEVICE_KEY_TEXT = base64.b64encode(b'\x55' * 32).decode()
    config.DEVICE_PREVIOUS_KEY_ID = '1'
    config.DEVICE_PREVIOUS_KEY_TEXT = base64.b64encode(b'\x77' * 32).decode()
    config.validate()
    verifier = hash_token(TOKEN)
    current = device_v2_master(config.DEVICE_TRANSPORT_V2_KEYS['2'], verifier, DEVICE)
    previous = device_v2_master(config.DEVICE_TRANSPORT_V2_KEYS['1'], verifier, DEVICE)
    assert current != previous and current != device_master(verifier, DEVICE)
    assert current != device_v2_master(b'\x11' * 32, verifier, DEVICE)
    assert current != device_v2_master(config.DEVICE_TRANSPORT_V2_KEYS['2'], verifier, OTHER)
    assert device_v2_for_key_id(device_v2_key_id(DEVICE, '2')) == (DEVICE, '2')
    assert device_v2_for_key_id('dv2_02_' + DEVICE.replace('-', '')) is None
    class Store:
        def device_transport_verifier(self, device): return verifier if device == DEVICE else None
        def claim_transport(self, envelope): return True
        def authenticate(self, device, token): return str(device) == DEVICE and token == TOKEN
        def policy(self, *args, **kwargs): return seed_policy(config)
        def heartbeat(self, *args, **kwargs): pass
        def lease(self, device): return None
    client = create_app(config, Store(), check_database=False).test_client()
    beat = copy.deepcopy(FIXTURE['heartbeat']); beat['device']['deviceId'] = DEVICE
    beat['deviceTransportV2'] = True
    def send(key, kid, body, path='/api/v2/heartbeat'):
        wire = seal(key, kid, str(uuid4()), dict(method='POST', path=path, query='', token=TOKEN,
            body=b64(json.dumps(body).encode())), 'request')
        response = client.post('/api/transport/v1', json=wire, base_url='https://localhost')
        if response.status_code != 200: return response.status_code, None
        return 200, open_envelope(key, kid, response.json, 'response', wire['requestId'])
    def shared_heartbeat(token, secure):
        wire = seal(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, str(uuid4()), dict(method='POST',
            path='/api/v2/heartbeat', query='', token=token, body=b64(json.dumps(beat).encode())), 'request')
        result = client.post('/api/transport/v1', json=wire, base_url='https://localhost' if secure else 'http://localhost')
        assert result.headers['Cache-Control'] == 'no-store'
        return open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json, 'response', wire['requestId'])
    plain_http = shared_heartbeat(TOKEN, False)
    assert 'deviceTransportV2' not in json.loads(base64.b64decode(plain_http['body']))
    del beat['deviceTransportV2']
    legacy_https = shared_heartbeat(TOKEN, True)
    assert 'deviceTransportV2' not in json.loads(base64.b64decode(legacy_https['body']))
    beat['deviceTransportV2'] = True
    unauthorized = shared_heartbeat('incorrect-synthetic-token', True)
    assert unauthorized['status'] == 401 and 'deviceTransportV2' not in base64.b64decode(unauthorized['body']).decode()
    for generation, key in [('1', previous), ('2', current)]:
        status, inner = send(key, device_v2_key_id(DEVICE, generation), beat)
        assert status == 200 and inner['status'] == 200
        capability = json.loads(base64.b64decode(inner['body']))
        assert capability['deviceTransport'] is True
        assert capability['deviceTransportV2']['keyId'] == device_v2_key_id(DEVICE, '2')
        assert base64.b64decode(capability['deviceTransportV2']['key']) == current
        assert capability['deviceTransportV2']['key'] != config.DEVICE_KEY_TEXT
    compact = dict(beat, inventoryUnchanged=True, compactInventory=True, users=[], agents=[], endpoints=[])
    assert send(current, device_v2_key_id(DEVICE, '2'), compact, '/api/v2/heartbeat/light-compact')[1]['status'] == 200
    assert send(current, device_v2_key_id(OTHER, '2'), beat)[0] == 400
    assert send(current, device_v2_key_id(DEVICE, '3'), beat)[0] == 400
    del config.DEVICE_TRANSPORT_V2_KEYS['1']
    assert send(previous, device_v2_key_id(DEVICE, '1'), beat)[0] == 400
