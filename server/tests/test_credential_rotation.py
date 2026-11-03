"""Synthetic renewal state, real MySQL transactions and authenticated envelopes."""
import base64
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from app import create_app
from controlserver import credential_rotation as rotation
from controlserver.database import dbtime
from controlserver.device_transport import device_v2_key_id, device_v2_master, device_key_id, device_master
from controlserver.models import DeviceEnrollmentRequest, HeartbeatV2Request
from controlserver.security import hash_token, utcnow
from controlserver.transport import b64, open_envelope, seal
from controlserver.validation import ApiProblem

OLD = base64.b64encode(b'o' * 32).decode()
NEXT = base64.b64encode(b'n' * 32).decode()
OTHER = base64.b64encode(b'x' * 32).decode()
FIXTURE = json.loads((Path(__file__).parent / 'fixtures/dotnet-v0.1.19.json').read_text(encoding='utf-8'))


@pytest.fixture
def renewal(mysql_store):
    cfg = mysql_store.cfg
    cfg.DEVICE_TRANSPORT_V2 = True
    cfg.DEVICE_KEY_ID = '1'
    cfg.DEVICE_KEY_TEXT = base64.b64encode(b'k' * 32).decode()
    cfg.CREDENTIAL_ROTATION = True
    cfg.validate()
    with pytest.raises(RuntimeError, match='storage is missing'):
        mysql_store.check_schema()
    rotation.ensure_table(mysql_store)
    mysql_store.check_schema()
    device = str(uuid4())
    mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=device,
        hostname='synthetic-renewal', serviceVersion='synthetic', initialDeviceToken=OLD))
    body = copy.deepcopy(FIXTURE['heartbeat'])
    body['device'].update(deviceId=device, hostname='synthetic-renewal')
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET enrolled_at_utc=%s WHERE device_id=%s',
                    (dbtime(utcnow() - timedelta(days=31)), device))
    return mysql_store, device, str(uuid4()), body


def expire(store, device):
    with store.transaction() as cur:
        cur.execute('UPDATE device_credential_rotations SET expires_at_utc=%s WHERE device_id=%s',
                    (dbtime(utcnow() - timedelta(seconds=1)), device))


def test_renewal_defaults_off_and_requires_v2(config):
    assert not config.CREDENTIAL_ROTATION
    config.CREDENTIAL_ROTATION = True
    with pytest.raises(ValueError, match='requires device transport V2'):
        config.validate()


def test_response_loss_retry_overlap_and_drain_after_disable(renewal):
    store, device, ident, _ = renewal
    first = rotation.prepare(store, device, ident, OLD, NEXT)
    assert first == rotation.prepare(store, device, ident, OLD, NEXT)
    assert store.authenticate(device, OLD) and store.authenticate(device, NEXT)
    with pytest.raises(ApiProblem) as problem:
        rotation.commit(store, device, ident, OLD)
    assert problem.value.status == 409
    store.cfg.CREDENTIAL_ROTATION = False
    assert first == rotation.prepare(store, device, ident, OLD, NEXT)
    with pytest.raises(ApiProblem) as problem:
        rotation.prepare(store, device, str(uuid4()), OLD, OTHER)
    assert problem.value.status == 503
    active = rotation.commit(store, device, ident, NEXT)
    assert active == rotation.commit(store, device, ident, NEXT)
    assert store.authenticate(device, OLD) and store.authenticate(device, NEXT)
    with pytest.raises(ApiProblem) as problem:
        rotation.prepare(store, device, str(uuid4()), NEXT, OTHER)
    assert problem.value.status == 503
    audit = store.audits(device, 0, 20)
    assert sum(a['action'] == 'DEVICE_CREDENTIAL_ROTATION_PREPARED' for a in audit) == 1
    assert sum(a['action'] == 'DEVICE_CREDENTIAL_ROTATION_COMMITTED' for a in audit) == 1
    assert all(value not in json.dumps(audit) for value in (OLD, NEXT, hash_token(OLD), hash_token(NEXT)))


def test_expired_preparation_can_resume_and_expired_overlap_cannot_authenticate(renewal):
    store, device, ident, _ = renewal
    rotation.prepare(store, device, ident, OLD, NEXT)
    expire(store, device)
    assert store.authenticate(device, OLD) and not store.authenticate(device, NEXT)
    with pytest.raises(ApiProblem):
        rotation.commit(store, device, ident, NEXT)
    rotation.prepare(store, device, ident, OLD, NEXT)
    rotation.commit(store, device, ident, NEXT)
    expire(store, device)
    assert not store.authenticate(device, OLD) and store.authenticate(device, NEXT)
    assert rotation.cleanup(store) == 1
    assert rotation.commit(store, device, ident, NEXT)['state'] == 'active'
    assert not store.authenticate(device, OLD)


def test_rotation_identity_and_primary_proof_cannot_be_replaced(renewal):
    store, device, ident, _ = renewal
    rotation.prepare(store, device, ident, OLD, NEXT)
    for identity, token, target in [(ident, OLD, OTHER), (str(uuid4()), OLD, OTHER), (str(uuid4()), NEXT, OTHER)]:
        with pytest.raises(ApiProblem):
            rotation.prepare(store, device, identity, token, target)
    with pytest.raises(ApiProblem):
        rotation.commit(store, device, str(uuid4()), NEXT)
    rotation.commit(store, device, ident, NEXT)
    with pytest.raises(ApiProblem):
        rotation.prepare(store, device, str(uuid4()), OLD, OTHER)
    with pytest.raises(ApiProblem):
        rotation.prepare(store, device, str(uuid4()), NEXT, OTHER)


def test_minimum_age_and_invalid_credential(renewal):
    store, device, ident, _ = renewal
    with store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET enrolled_at_utc=%s WHERE device_id=%s', (dbtime(utcnow()), device))
    for candidate in (NEXT, 'not-base64', base64.b64encode(b'a' * 31).decode()):
        with pytest.raises(ApiProblem):
            rotation.prepare(store, device, ident, OLD, candidate)
    assert not store.authenticate(device, NEXT)


@pytest.mark.parametrize('committed', [False, True])
def test_recovery_and_revocation_invalidate_all_renewal_credentials(renewal, committed):
    store, device, ident, _ = renewal
    rotation.prepare(store, device, ident, OLD, NEXT)
    if committed:
        rotation.commit(store, device, ident, NEXT)
    with store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET revoked=1 WHERE device_id=%s', (device,))
    assert not store.authenticate(device, OLD) and not store.authenticate(device, NEXT)
    assert store.device_transport_verifiers(device) == ()
    recovered = store.recover_device_credential(device, 'synthetic-renewal', 'synthetic recovery', 'admin')
    assert store.authenticate(device, recovered['deviceToken'])
    assert not store.authenticate(device, OLD) and not store.authenticate(device, NEXT)
    with store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS n FROM device_credential_rotations WHERE device_id=%s', (device,))
        assert cur.fetchone()['n'] == 0


def test_legacy_credential_replacement_clears_prepared_state(renewal):
    store, device, ident, _ = renewal
    rotation.prepare(store, device, ident, OLD, NEXT)
    request = DeviceEnrollmentRequest(schemaVersion=2, deviceId=device, hostname='synthetic-renewal',
        serviceVersion='synthetic', initialDeviceToken=OTHER, previousDeviceToken=OLD)
    assert store.enroll(request)['deviceToken'] == OTHER
    assert store.authenticate(device, OTHER)
    assert not store.authenticate(device, OLD) and not store.authenticate(device, NEXT)


def test_concurrent_prepare_and_idempotent_commit(renewal):
    store, device, _, _ = renewal
    attempts = [(str(uuid4()), NEXT), (str(uuid4()), OTHER)]
    def prepare(item):
        ident, token = item
        try:
            rotation.prepare(store, device, ident, OLD, token)
            return item
        except ApiProblem as exc:
            assert exc.status == 409
    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = [value for value in pool.map(prepare, attempts) if value is not None]
    assert len(winners) == 1
    ident, token = winners[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: rotation.commit(store, device, ident, token), range(2)))
    assert results[0] == results[1]
    assert store.authenticate(device, OLD) and store.authenticate(device, token)


def test_prepare_and_commit_rollback_preserve_the_previous_state(renewal, monkeypatch):
    store, device, ident, _ = renewal
    audit = store._audit
    def fail(*_): raise RuntimeError('synthetic audit failure')
    monkeypatch.setattr(store, '_audit', fail)
    with pytest.raises(RuntimeError): rotation.prepare(store, device, ident, OLD, NEXT)
    assert not store.authenticate(device, NEXT) and store.authenticate(device, OLD)
    monkeypatch.setattr(store, '_audit', audit)
    rotation.prepare(store, device, ident, OLD, NEXT)
    monkeypatch.setattr(store, '_audit', fail)
    with pytest.raises(RuntimeError): rotation.commit(store, device, ident, NEXT)
    with store.transaction() as cur:
        cur.execute('SELECT token_hash FROM device_credentials WHERE device_id=%s', (device,))
        assert cur.fetchone()['token_hash'] == hash_token(OLD)
    monkeypatch.setattr(store, '_audit', audit)
    assert rotation.commit(store, device, ident, NEXT)['state'] == 'active'


def test_storage_constraints_checked_even_when_new_preparations_disabled(renewal):
    store, _, _, _ = renewal
    store.cfg.CREDENTIAL_ROTATION = False
    with store.transaction() as cur:
        cur.execute('ALTER TABLE device_credential_rotations DROP INDEX ix_credential_rotation_expires')
    with pytest.raises(RuntimeError, match='indexes'):
        store.check_schema()


def test_schema6_marker_blocks_old_server_and_schema_reverts(renewal):
    store, _, _, _ = renewal
    from controlserver.database import SCHEMA_VERSION, schema_checksum
    with store.transaction() as cur:
        cur.execute('SELECT version,checksum FROM schema_migrations')
        marker = cur.fetchall()
    assert marker == [rotation.schema_identity()]
    assert marker != [{'version': SCHEMA_VERSION, 'checksum': schema_checksum()}]
    for revert in (store.revert_unused_rollout_schema, store.revert_unused_policy_rollout_schema):
        with pytest.raises(RuntimeError): revert()
    assert store.migrate() == 'already_migrated'
    store.check_schema()


def test_interrupted_empty_storage_creation_can_resume(mysql_store):
    with mysql_store.transaction() as cur:
        cur.execute(rotation.DDL)
    mysql_store.check_schema()
    assert not mysql_store._credential_rotation_table
    rotation.ensure_table(mysql_store)
    mysql_store.check_schema()
    assert mysql_store._credential_rotation_table


def test_nontransactional_rotation_storage_is_rejected(renewal):
    store, _, _, _ = renewal
    with store.transaction() as cur:
        cur.execute('ALTER TABLE device_credential_rotations ENGINE=MyISAM')
    with pytest.raises(RuntimeError, match='InnoDB'):
        store.check_schema()


def test_cleanup_has_a_fixed_budget_and_retains_active_preparation(renewal):
    store, device, ident, _ = renewal
    rotation.prepare(store, device, ident, OLD, NEXT)
    expired = dbtime(utcnow() - timedelta(days=2))
    with store.transaction() as cur:
        cur.executemany('INSERT INTO device_credential_rotations VALUES (%s,%s,%s,NULL,%s,NULL,%s)',
            [(str(uuid4()), str(uuid4()), hash_token(OTHER), expired, expired) for _ in range(1005)])
    assert rotation.cleanup(store) == 1000
    assert rotation.cleanup(store) == 5
    assert rotation.cleanup(store) == 0
    assert store.authenticate(device, NEXT)


def test_http_two_phase_keys_binding_and_replay(renewal):
    store, device, ident, body = renewal
    store.cfg.DEVICE_TRANSPORT = True
    store.cfg.validate()
    client = create_app(store.cfg, store).test_client()
    kid = device_v2_key_id(device, '1')
    def key(token): return device_v2_master(store.cfg.DEVICE_TRANSPORT_V2_KEYS['1'], hash_token(token), device)
    def send(path, token, body=None, *, envelope_token=None, name=kid, master=None):
        master = master or key(token)
        envelope = seal(master, name, str(uuid4()), dict(method='GET' if body is None else 'POST',
            path=path, query='', token=envelope_token or token,
            body=b64(b'' if body is None else json.dumps(body).encode())), 'request')
        result = client.post('/api/transport/v1', json=envelope, base_url='https://localhost')
        if result.status_code != 200: return result.status_code, None, envelope
        inner = open_envelope(master, name, result.json, 'response', envelope['requestId'])
        return inner['status'], json.loads(base64.b64decode(inner['body'])) if inner['body'] else None, envelope
    prepare = f'/api/v2/devices/{device}/credential/prepare'
    commit = f'/api/v2/devices/{device}/credential/commit'
    payload = dict(rotationId=ident, nextDeviceToken=NEXT)
    assert send(prepare, OLD, payload, name=store.cfg.TRANSPORT_KEY_ID, master=store.cfg.TRANSPORT_KEY)[0] == 403
    assert send(prepare, OLD, payload, name=device_key_id(device), master=device_master(hash_token(OLD), device))[0] == 403
    status, result, _ = send(prepare, OLD, payload)
    assert status == 200 and result['state'] == 'prepared'
    assert base64.b64decode(result['deviceTransportV2']['key']) == key(NEXT)
    assert send(f'/api/v2/devices/{device}/policy', OLD, envelope_token=NEXT)[0] == 400
    status, active, wire = send(commit, NEXT, dict(rotationId=ident))
    assert status == 200 and active['state'] == 'active'
    assert client.post('/api/transport/v1', json=wire, base_url='https://localhost').status_code == 400
    for token in (OLD, NEXT):
        assert send(f'/api/v2/devices/{device}/policy', token)[0] == 200
    assert send(prepare.replace(device, str(uuid4())), OLD, payload)[0] == 400
    expire(store, device)
    assert send(f'/api/v2/devices/{device}/policy', OLD)[0] == 400
    assert send(f'/api/v2/devices/{device}/policy', NEXT)[0] == 200
    body.update(deviceTransportV2=True, credentialRotationV1=True)
    assert send('/api/v2/heartbeat', NEXT, body)[1]['credentialRotationV1']['minAgeSeconds'] == 30 * 86400
    store.cfg.CREDENTIAL_ROTATION = False
    assert 'credentialRotationV1' not in send('/api/v2/heartbeat', NEXT, body)[1]
