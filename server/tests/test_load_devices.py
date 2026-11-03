import base64
from threading import Thread
import pytest

from controlserver.models import DeviceEnrollmentRequest, EventBatchRequest, HeartbeatRequest, HeartbeatV2Request
from controlserver.validation import validate_heartbeat
from tools.load_devices import enrollment, event_batch, heartbeat, synthetic_id, register_v2, seed_devices


@pytest.mark.parametrize('version,light', [(1, False), (2, False), (2, True)])
def test_synthetic_heartbeats_match_production_contract(version, light):
    raw = heartbeat(7, version, light)
    parsed = (HeartbeatRequest if version == 1 else HeartbeatV2Request).model_validate(raw)
    validate_heartbeat(parsed, version)
    assert str(parsed.device.deviceId) == enrollment(7)['deviceId']
    if version == 2:
        assert parsed.inventoryUnchanged is light
        assert len(parsed.endpoints) == (0 if light else 1)
        assert len(parsed.activity) == 1


def test_device_ids_and_enrollments_are_stable_and_distinct():
    one, two = enrollment(0), enrollment(1)
    DeviceEnrollmentRequest.model_validate(one)
    assert one == enrollment(0)
    assert one['deviceId'] != two['deviceId']
    assert synthetic_id('device', 0) != synthetic_id('asset', 0)
    assert EventBatchRequest.model_validate(event_batch(0)).deviceId == DeviceEnrollmentRequest.model_validate(one).deviceId
    with pytest.raises(ValueError):
        synthetic_id('device', 300_000)
    with pytest.raises(ValueError):
        heartbeat(0, 1, light=True)


def test_registration_does_not_use_lightweight_mode_after_failed_baseline():
    class FailedBaseline:
        def __init__(self):
            self.paths = []

        def request(self, method, path, token, body):
            self.paths.append(path)
            if path.endswith('/enroll'):
                import json
                return dict(status=200, body=json.dumps(dict(deviceId=body['deviceId'],
                    deviceToken='synthetic-device-token-123456')).encode())
            return dict(status=503, body=b'{}')

    transport = FailedBaseline()
    with pytest.raises(RuntimeError, match='initial heartbeat'):
        register_v2(transport, 0)
    assert transport.paths == ['/api/v2/enroll', '/api/v2/heartbeat']


def test_registration_full_then_light_over_actual_http(config):
    from app import create_app
    from controlserver.validation import seed_policy
    from tools.load_admin import FIXTURE_ADMIN_TOKEN
    from tools.load_transport import (FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID,
                                      SyntheticTransport)
    from werkzeug.serving import make_server

    config.CLIENT_TOKEN = FIXTURE_ENROLLMENT_TOKEN
    config.ADMIN_TOKEN = FIXTURE_ADMIN_TOKEN
    config.TRANSPORT_KEY_ID = FIXTURE_KEY_ID
    config.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    config.HMAC_TEXT = config.TRANSPORT_KEY_TEXT
    config.validate()

    class Store:
        def __init__(self):
            self.devices = {}
            self.modes = []
            self.seen = []
            self.current = seed_policy(config)

        def claim_transport(self, envelope):
            return True

        def policy(self, device=None, **kwargs):
            return self.current.copy()

        def update_policy(self, update, actor):
            self.current['enabled'] = update.enabled
            self.current['policyVersion'] += 1
            return self.current.copy()

        def analytics_page(self, *args, **kwargs):
            return [], {}, 0

        def enroll(self, request):
            token = 'synthetic-device-token-123456'
            self.devices[str(request.deviceId)] = token
            return dict(deviceId=str(request.deviceId), deviceToken=token, enrolledAtUtc='2026-01-01T00:00:00Z')

        def authenticate(self, device, token):
            return self.devices.get(str(device)) == token

        def heartbeat(self, request, interval, peer):
            self.modes.append(getattr(request, 'inventoryUnchanged', False))
            self.seen.append(str(request.device.deviceId))

        def lease(self, device):
            return None

    store = Store()
    server = make_server('127.0.0.1', 0, create_app(config, store, check_database=False), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    transport = SyntheticTransport(f'http://127.0.0.1:{server.server_port}')
    try:
        transport.verify()
        token = register_v2(transport, 7)
        response = transport.request('POST', '/api/v2/heartbeat/light', token, heartbeat(7, 2, light=True))
        assert response['status'] == 200
        assert store.modes == [False, True]
        tokens = seed_devices(f'http://127.0.0.1:{server.server_port}', 6, 2, workers=2)
        assert len(tokens) == 6
        assert tokens[:2] == [FIXTURE_ENROLLMENT_TOKEN] * 2
        assert all(token == 'synthetic-device-token-123456' for token in tokens[2:])
        assert len(store.devices) == 5
        from tools.load_run import run_heartbeats
        report = run_heartbeats(f'http://127.0.0.1:{server.server_port}', tokens, 2,
                                seconds=2.8, interval=1, workers=3, publish_after=0.2,
                                admin_query_interval=1, outage_after=0.4,
                                outage_seconds=0.8, reconnect_spread=0.2)
        assert report['counts'].get('transport_error', 0) == 0
        assert report['counts'].get('business_error', 0) == 0
        assert report['counts']['v1-full'] >= 2
        assert report['counts']['v2-light'] >= 4
        assert report['counts']['admin_query_success'] == 3
        assert report['offlineSuppressedEvents'] > 0
        assert report['simulatedConvergence']['observedDevices'] == 6
        tokens = seed_devices(f'http://127.0.0.1:{server.server_port}', 3, 1, workers=2, ordinal_start=100)
        before = len(store.seen)
        report = run_heartbeats(f'http://127.0.0.1:{server.server_port}', tokens, 1,
                                seconds=0.7, interval=60, workers=2, startup_spread=0,
                                ordinal_start=100)
        assert report['counts'].get('business_error', 0) == report['counts'].get('transport_error', 0) == 0
        assert set(store.seen[before:]) == {synthetic_id('device', i) for i in range(100, 103)}
        from concurrent.futures import ThreadPoolExecutor
        from tools.load_publication import identity, read_event, write_event
        origin = f'http://127.0.0.1:{server.server_port}'
        publisher_tokens = seed_devices(origin, 2, 0, workers=1, ordinal_start=110)
        follower_tokens = seed_devices(origin, 2, 0, workers=1, ordinal_start=120)
        config.DATA_ROOT.mkdir(exist_ok=True)
        event_path = config.DATA_ROOT / 'synthetic-event.json'
        from datetime import datetime, timezone
        event_start = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        event_identity = identity('b63ddd38-45d2-4da4-9032-d5e01a650d6f', 'a' * 64, event_start)
        with ThreadPoolExecutor(max_workers=2) as pool:
            publisher = pool.submit(run_heartbeats, origin, publisher_tokens, 0, 3.1, interval=1, workers=2,
                startup_spread=0, ordinal_start=110, publish_after=0.2,
                publication_sink=lambda value: write_event(event_path, event_identity, value))
            follower = pool.submit(run_heartbeats, origin, follower_tokens, 0, 3.1, interval=1, workers=2,
                startup_spread=0, ordinal_start=120,
                publication_observer=lambda: read_event(event_path, event_identity))
            publisher_report, follower_report = publisher.result(), follower.result()
        assert publisher_report['publicationFailed'] is follower_report['publicationFailed'] is False
        assert publisher_report['publicationEvidence'] == follower_report['publicationEvidence']
        assert publisher_report['simulatedConvergence']['observedDevices'] == 2
        assert follower_report['simulatedConvergence']['observedDevices'] == 2
        assert follower_report['simulatedConvergence']['timingOrigin'].endswith('external_clock_unverified')
    finally:
        transport.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_batch_seed_does_not_retry_failed_enrollment():
    class BrokenTransport:
        requests = []

        def __init__(self, origin):
            pass

        def verify(self):
            pass

        def request(self, method, path, token, body):
            self.requests.append(path)
            return dict(status=409, body=b'{}')

        def close(self):
            pass

    with pytest.raises(RuntimeError, match='enrollment failed'):
        seed_devices('http://127.0.0.1:1234', 1, 0, workers=1, transport_factory=BrokenTransport)
    assert BrokenTransport.requests == ['/api/v2/enroll']


def test_batch_seed_emits_bounded_progress_without_tokens():
    class Client:
        def __init__(self, origin):
            pass
        def verify(self):
            pass
        def request(self, method, path, token, body):
            return {'status': 200}
        def close(self):
            pass

    progress = []
    tokens = seed_devices('unused', 5, 5, workers=2, transport_factory=Client,
                          progress_callback=progress.append, progress_every=2)
    assert len(tokens) == 5
    assert [item['completedDevices'] for item in progress] == [2, 4, 5]
    assert all(item['totalDevices'] == 5 for item in progress)


def test_batch_seed_against_isolated_mysql(mysql_store):
    from app import create_app
    from tools.load_admin import FIXTURE_ADMIN_TOKEN, SyntheticAdmin
    from tools.load_commands import simulate_command
    from tools.load_transport import FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID, SyntheticTransport
    from werkzeug.serving import make_server
    import json

    cfg = mysql_store.cfg
    cfg.CLIENT_TOKEN = FIXTURE_ENROLLMENT_TOKEN
    cfg.ADMIN_TOKEN = FIXTURE_ADMIN_TOKEN
    cfg.TRANSPORT_KEY_ID = FIXTURE_KEY_ID
    cfg.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    cfg.HMAC_TEXT = cfg.TRANSPORT_KEY_TEXT
    cfg.validate()
    server = make_server('127.0.0.1', 0, create_app(cfg, mysql_store), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    try:
        tokens = seed_devices(origin, 6, 2, workers=2)
        assert len(tokens) == 6
        from tools.load_run import run_heartbeats
        compact_tokens = seed_devices(origin, 3, 0, workers=2, ordinal_start=20, compact_v2=True)
        compact_report = run_heartbeats(origin, compact_tokens, 0, 1.1, interval=1, workers=3,
                                        ordinal_start=20, compact_v2=True)
        assert compact_report['counts'].get('compact_success', 0) > 0
        assert not compact_report['counts'].get('compact_error', 0)
        assert mysql_store.details(synthetic_id('device', 20))['device']['employeeIds']
        client = SyntheticTransport(origin)
        try:
            client.verify()
            device = synthetic_id('device', 2)
            admin = SyntheticAdmin(origin)
            assert admin.query_devices() >= 0
            command = admin.create_command(device, 'disableProxy')
            response = client.request('POST', '/api/v2/heartbeat/light', tokens[2], heartbeat(2, 2, light=True))
            assert response['status'] == 200
            received = json.loads(response['body'])['command']
            assert received['payload']['commandId'] == command['commandId']
            assert simulate_command(client, tokens[2], device, received, set()) == 'disabled'
            assert mysql_store.commands(device)[0]['status'] == 'succeeded'
            assert len(mysql_store.details(device)['endpoints']) == 1
            batch = event_batch(2)
            first = client.request('POST', '/api/v2/events/batch', tokens[2], batch)
            second = client.request('POST', '/api/v2/events/batch', tokens[2], batch)
            assert json.loads(first['body'])['accepted'] == 1
            assert json.loads(second['body'])['duplicates'] == 1
        finally:
            client.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_disjoint_seed_ranges_keep_local_client_mix_and_tokens():
    import json
    from threading import Lock
    calls, lock = [], Lock()
    class Transport:
        def __init__(self, origin): pass
        def verify(self): pass
        def close(self): pass
        def request(self, method, path, token, body):
            with lock: calls.append((path, body))
            if path.endswith('/enroll'):
                return dict(status=200, body=json.dumps(dict(deviceId=body['deviceId'], deviceToken='synthetic-device-token-123456')).encode())
            return dict(status=200, body=b'{"lightweightInventory":true,"statelessPolicyVersions":true}')
    left = seed_devices('unused', 3, 1, workers=2, full_v2_count=1, transport_factory=Transport)
    right = seed_devices('unused', 3, 1, workers=2, full_v2_count=1, transport_factory=Transport, ordinal_start=3)
    assert left == right and len(left) == 3
    enrolled = [body['deviceId'] for path, body in calls if path.endswith('/enroll')]
    legacy = [body['device']['deviceId'] for path, body in calls if path == '/api/v1/heartbeat']
    assert set(enrolled) == {synthetic_id('device', i) for i in (1, 2, 4, 5)}
    assert set(legacy) == {synthetic_id('device', i) for i in (0, 3)}
    for start, count in ((-1, 1), (149999, 2), (True, 1), (150000, 1)):
        with pytest.raises(ValueError):
            seed_devices('unused', count, 0, transport_factory=Transport, ordinal_start=start)


def test_compact_synthetic_heartbeat_requires_light_mode_and_omits_inventory():
    raw = heartbeat(7, 2, light=True, compact=True)
    parsed = HeartbeatV2Request.model_validate(raw)
    validate_heartbeat(parsed, 2)
    assert parsed.compactInventory and parsed.inventoryUnchanged
    assert parsed.users == parsed.agents == parsed.endpoints == [] and parsed.activity
    with pytest.raises(ValueError): heartbeat(7, 2, compact=True)
    with pytest.raises(ValueError): heartbeat(7, 1, light=True, compact=True)


def test_compact_synthetic_registration_requires_advertised_capability():
    import json
    class Transport:
        compact = False
        def request(self, method, path, token, body):
            if path.endswith('/enroll'):
                return dict(status=200, body=json.dumps(dict(deviceId=body['deviceId'], deviceToken='synthetic-device-token-123')).encode())
            return dict(status=200, body=json.dumps(dict(lightweightInventory=True,statelessPolicyVersions=True,compactInventory=self.compact)).encode())
    t = Transport()
    with pytest.raises(RuntimeError, match='compact'): register_v2(t, 7, compact=True)
    t.compact = True
    assert register_v2(t, 7, compact=True) == 'synthetic-device-token-123'
