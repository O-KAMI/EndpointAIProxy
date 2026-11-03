import json
import time
import pytest

from controlserver.security import sign_policy
from tools.load_run import rephase_receipts, run_heartbeats
from tools.load_transport import FIXTURE_KEY


class SyntheticClient:
    calls = []
    closed = 0

    def __init__(self, origin):
        self.verified = False

    def verify(self):
        self.verified = True

    def request(self, method, path, token, body=None, query=''):
        assert self.verified
        self.calls.append((path, body.get('inventoryUnchanged', False) if body else False))
        if method == 'GET':
            policy = json.dumps({'policyVersion': 1}).encode()
            return {'status': 200, 'body': policy, 'headers': {'X-SF-Policy-Signature': sign_policy(policy, FIXTURE_KEY)}}
        return {'status': 200, 'body': b'{"acceptedPolicyVersion":1}'}

    def close(self):
        type(self).closed += 1


def test_outage_rephases_queued_and_overdue_receipts_without_losing_them():
    import heapq
    import random
    queued = [(9.0, 1), (10.5, 2), (11.5, 3), (14.0, 4)]
    rephase_receipts(queued, recovery=12.0, spread=1.0, rng=random.Random(1))
    ordered = [heapq.heappop(queued) for _ in range(4)]
    assert {ordinal for _, ordinal in ordered} == {1, 2, 3, 4}
    assert all(12.0 <= due < 13.0 for due, ordinal in ordered if ordinal != 4)
    assert next(due for due, ordinal in ordered if ordinal == 4) == 14.0


def test_outage_defers_policy_receipt_already_queued():
    class ChangedPolicy(SyntheticClient):
        calls_at = []

        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                policy = b'{"policyVersion":2}'
                return {'status': 200, 'body': policy, 'headers': {'X-SF-Policy-Signature': sign_policy(policy, FIXTURE_KEY)}}
            self.calls_at.append(time.monotonic())
            return {'status': 200, 'body': b'{"acceptedPolicyVersion":2}'}

    started = time.monotonic()
    report = run_heartbeats('unused', ['synthetic'], legacy_count=0, seconds=2.4,
                            interval=60, startup_spread=0, workers=1, seed=0,
                            outage_after=0.3, outage_seconds=1.5, reconnect_spread=0,
                            transport_factory=ChangedPolicy)
    assert report['receiptHeartbeatsScheduled'] == 1
    assert (report['counts'].get('receipt_heartbeat_dispatched', 0)
            + report['counts'].get('receipt_heartbeat_missed_busy', 0)
            + report['receiptHeartbeatsMissing']) == 1
    assert all(not (started + 0.4 < when < started + 1.7) for when in ChangedPolicy.calls_at)
    assert len(ChangedPolicy.calls_at) >= 2


def test_mixed_heartbeat_runner_counts_planned_events_and_closes_clients():
    SyntheticClient.calls = []
    SyntheticClient.closed = 0
    report = run_heartbeats('unused', ['synthetic'] * 10, legacy_count=3,
                            seconds=1.1, interval=1, workers=3, full_every=2,
                            seed=4, transport_factory=SyntheticClient)
    assert report['expectedEvents'] >= 10
    assert report['dispatchedEvents'] + report['missingEvents'] + report['counts'].get('missed_busy', 0) == report['expectedEvents']
    assert report['counts']['business_success'] + report['counts']['periodic_policy_success'] == len(SyntheticClient.calls)
    assert report['counts']['v1-full'] >= 3
    assert report['counts']['v2-light'] >= 7
    assert all(not light for path, light in SyntheticClient.calls if path == '/api/v1/heartbeat')
    assert SyntheticClient.closed > 0
    assert report['counts']['periodic_policy_success'] >= 3
    assert report['expectedPolicyPolls'] == report['dispatchedPolicyPolls'] + report['missingPolicyPolls'] + report['counts'].get('policy_missed_busy', 0)
    assert report['kind'] == 'heartbeat-policy'


def test_overloaded_generator_reports_missed_or_delayed_events():
    class SlowClient(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            time.sleep(0.12)
            return super().request(method, path, token, body, query)

    report = run_heartbeats('unused', ['synthetic'] * 20, legacy_count=0,
                            seconds=1.1, interval=1, workers=1,
                            transport_factory=SlowClient)
    assert report['expectedEvents'] >= 20
    assert report['missingEvents'] > 0 or report['counts'].get('missed_busy', 0) > 0
    assert report['elapsedSeconds'] >= 1.1


def test_v2_pulls_new_signed_policy_and_reports_applied_version():
    class ChangedPolicy(SyntheticClient):
        versions = []
        pulls = 0

        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                type(self).pulls += 1
                policy = b'{"policyVersion":2}'
                return {'status': 200, 'body': policy, 'headers': {'X-SF-Policy-Signature': sign_policy(policy, FIXTURE_KEY)}}
            type(self).versions.append(body['policy']['appliedVersion'])
            return {'status': 200, 'body': b'{"acceptedPolicyVersion":2}'}

    report = run_heartbeats('unused', ['synthetic'], legacy_count=0, seconds=1.4,
                            interval=1, workers=1, seed=1, transport_factory=ChangedPolicy)
    assert ChangedPolicy.versions == [1, 2]
    assert ChangedPolicy.pulls == 1
    assert report['counts']['policy_success'] == 1


def test_invalid_policy_signature_never_updates_applied_version():
    class BadPolicy(SyntheticClient):
        versions = []

        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                return {'status': 200, 'body': b'{"policyVersion":2}', 'headers': {'X-SF-Policy-Signature': 'bad'}}
            type(self).versions.append(body['policy']['appliedVersion'])
            return {'status': 200, 'body': b'{"acceptedPolicyVersion":2}'}

    report = run_heartbeats('unused', ['synthetic'], legacy_count=0, seconds=1.4,
                            interval=1, workers=1, seed=1, transport_factory=BadPolicy)
    assert BadPolicy.versions == [1, 1]
    assert report['counts']['policy_error'] == 2


def test_policy_publication_measures_only_subsequent_simulated_heartbeat():
    class State:
        version = 1

    class DynamicClient(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                raw = json.dumps({'policyVersion': State.version}).encode()
                return {'status': 200, 'body': raw, 'headers': {'X-SF-Policy-Signature': sign_policy(raw, FIXTURE_KEY)}}
            return {'status': 200, 'body': json.dumps({'acceptedPolicyVersion': State.version}).encode()}

    class Publisher:
        def __init__(self, origin):
            pass

        def publish_toggle(self):
            started = time.monotonic()
            time.sleep(0.3)
            State.version = 2
            return {'version': 2, 'started': started, 'completed': time.monotonic()}

    report = run_heartbeats('unused', ['synthetic'] * 3, legacy_count=1, seconds=2.8,
                            interval=1, workers=2, seed=1, transport_factory=DynamicClient,
                            publish_after=0.2, admin_factory=Publisher)
    convergence = report['simulatedConvergence']
    assert not report['publicationFailed']
    assert convergence['policyVersion'] == 2
    assert convergence['targetDevices'] == convergence['observedDevices'] == 3
    assert convergence['within120Seconds'] == 3
    assert convergence['timingOrigin'] == 'publication_request_started'
    assert convergence['p99ObservedSeconds'] >= convergence['publicationLatencySeconds'] >= 0.3
    assert 'not real client reconciliation' in convergence['scope']


def test_new_v2_policy_change_adds_bounded_receipt_heartbeat():
    class State:
        version = 1
        applied = []

    class DynamicClient(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                raw = json.dumps({'policyVersion': State.version}).encode()
                return {'status': 200, 'body': raw, 'headers': {'X-SF-Policy-Signature': sign_policy(raw, FIXTURE_KEY)}}
            State.applied.append(body['policy']['appliedVersion'])
            return {'status': 200, 'body': json.dumps({'acceptedPolicyVersion': State.version}).encode()}

    class Publisher:
        def __init__(self, origin):
            pass
        def publish_toggle(self):
            started = time.monotonic()
            State.version = 2
            return {'version': 2, 'started': started, 'completed': time.monotonic()}

    report = run_heartbeats('unused', ['synthetic'], legacy_count=0, seconds=2.5, interval=60,
                            startup_spread=1.5, workers=1, seed=10, transport_factory=DynamicClient,
                            publish_after=0.1, admin_factory=Publisher)
    assert State.applied == [1, 2]
    assert report['receiptHeartbeatsScheduled'] == 1
    assert report['receiptDevicesAtPublishedVersion'] == 1
    assert report['counts']['receipt_heartbeat_dispatched'] == 1
    assert report['expectedEvents'] == report['dispatchedEvents'] == 2
    assert report['simulatedConvergence']['within120Seconds'] == 1


def test_heartbeat_runner_acknowledges_simulated_command_and_reports_disabled():
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from controlserver.security import sign_command
    from tools.load_devices import synthetic_id

    now = datetime.now(timezone.utc)
    command = dict(schemaVersion=1, commandId=str(uuid4()), deviceId=synthetic_id('device', 0),
                   type='disableProxy', issuedAtUtc=(now - timedelta(seconds=1)).isoformat(),
                   expiresAtUtc=(now + timedelta(minutes=1)).isoformat())

    class CommandClient(SyntheticClient):
        statuses = []
        operation_states = []

        def request(self, method, path, token, body=None, query=''):
            if '/commands/' in path:
                type(self).statuses.append(body['status'])
                return {'status': 202}
            type(self).operation_states.append(body['runtime']['operationState'])
            return {'status': 200, 'body': json.dumps({'acceptedPolicyVersion': 1,
                'command': {'payload': command, 'signature': sign_command(command, FIXTURE_KEY)}}).encode()}

    report = run_heartbeats('unused', ['synthetic'], 0, seconds=1.4, interval=1,
                            workers=1, seed=1, transport_factory=CommandClient)
    assert CommandClient.statuses == ['executing', 'succeeded']
    assert CommandClient.operation_states == ['enabled', 'disabled']
    assert report['counts']['command_success'] == 1
    assert report['counts']['command_duplicate_ignored'] == 1


def test_command_time_is_measured_from_creation_request_to_simulated_receipt():
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from controlserver.security import sign_command
    from tools.load_devices import synthetic_id

    now = datetime.now(timezone.utc)
    payload = dict(schemaVersion=1, commandId=str(uuid4()), deviceId=synthetic_id('device', 0),
                   type='disableProxy', issuedAtUtc=(now - timedelta(seconds=1)).isoformat(),
                   expiresAtUtc=(now + timedelta(minutes=1)).isoformat())

    class Shared:
        ready = False

    class Publisher:
        def __init__(self, origin):
            pass

        def create_command(self, device, command_type):
            started = time.monotonic()
            Shared.ready = True
            return dict(commandId=payload['commandId'], deviceId=device, started=started, completed=time.monotonic())

    class CommandClient(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            if '/commands/' in path:
                return {'status': 202}
            command = {'payload': payload, 'signature': sign_command(payload, FIXTURE_KEY)} if Shared.ready else None
            return {'status': 200, 'body': json.dumps({'acceptedPolicyVersion': 1, 'command': command}).encode()}

    report = run_heartbeats('unused', ['synthetic'], 0, seconds=1.5, interval=1,
                            workers=1, seed=1, transport_factory=CommandClient,
                            command_after=0.2, admin_factory=Publisher)
    assert not report['commandCreationFailed']
    assert report['simulatedCommand']['receiptObserved']
    assert report['simulatedCommand']['within120Seconds']
    assert report['simulatedCommand']['completedAfterSeconds'] >= 0
    assert 'no real configuration change' in report['simulatedCommand']['scope']


def test_receipts_after_deadline_do_not_count_as_in_window():
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from controlserver.security import sign_command
    from tools.load_devices import synthetic_id

    now = datetime.now(timezone.utc)
    payload = dict(schemaVersion=1, commandId=str(uuid4()), deviceId=synthetic_id('device', 0),
                   type='disableProxy', issuedAtUtc=(now - timedelta(seconds=1)).isoformat(),
                   expiresAtUtc=(now + timedelta(minutes=1)).isoformat())
    class Admin:
        def __init__(self, origin):
            pass
        def create_command(self, device, command_type):
            stamp = time.monotonic()
            return dict(commandId=payload['commandId'], deviceId=device, started=stamp, completed=stamp)
    class LateClient(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            if '/commands/' in path:
                return {'status': 202}
            time.sleep(0.35)
            return {'status': 200, 'body': json.dumps({'acceptedPolicyVersion': 1,
                'command': {'payload': payload, 'signature': sign_command(payload, FIXTURE_KEY)}}).encode()}
    report = run_heartbeats('unused', ['synthetic'], 0, seconds=0.2, interval=1,
                            workers=1, startup_spread=0, transport_factory=LateClient,
                            command_after=0, admin_factory=Admin)
    assert report['counts']['heartbeat_completed_after_deadline'] == 1
    assert report['simulatedCommand']['receiptObserved'] is False
    assert report['simulatedCommand']['receiptAfterDeadline'] is True


def test_management_queries_overlap_with_synthetic_heartbeats():
    class Admin:
        def __init__(self, origin):
            pass

        def query_devices(self):
            time.sleep(0.03)
            return 0.03

    report = run_heartbeats('unused', ['synthetic'] * 4, legacy_count=1, seconds=1.2,
                            interval=1, workers=2, transport_factory=SyntheticClient,
                            admin_factory=Admin, admin_query_interval=1)
    assert report['counts']['admin_query_success'] == 2
    assert report['counts']['business_success'] >= 4
    assert sum(report['adminLatencyMilliseconds'].values()) == 2
    assert report['counts'].get('admin_query_error', 0) == 0


def test_management_query_overload_is_not_hidden():
    class SlowAdmin:
        def __init__(self, origin):
            pass

        def query_devices(self):
            time.sleep(1.3)
            return 1.3

    report = run_heartbeats('unused', ['synthetic'], 0, seconds=1.2,
                            interval=1, workers=1, transport_factory=SyntheticClient,
                            admin_factory=SlowAdmin, admin_query_interval=1)
    assert report['counts']['admin_query_success'] == 1
    assert report['counts']['admin_query_missed'] == 1


def test_outage_counts_suppressed_events_and_reopens_connections_after_recovery():
    class ReconnectingClient(SyntheticClient):
        verified_count = 0

        def verify(self):
            super().verify()
            type(self).verified_count += 1

    report = run_heartbeats('unused', ['synthetic'] * 10, 2, seconds=2.5,
                            interval=1, workers=2, seed=9,
                            outage_after=0.3, outage_seconds=1, reconnect_spread=0.2,
                            transport_factory=ReconnectingClient)
    assert report['offlineSuppressedEvents'] == 10
    assert report['dispatchedEvents'] + report['missingEvents'] + report['counts'].get('missed_busy', 0) == report['expectedEvents']
    assert report['counts']['business_success'] >= 10
    assert ReconnectingClient.verified_count >= 2
    assert any('does not inject a real network failure' in item for item in report['limitations'])


def test_runner_attaches_resource_sampling_without_claiming_acceptance():
    class Monitor:
        started = False

        def start(self):
            self.started = True

        def stop(self):
            assert self.started
            return {'complete': True, 'samples': [{'errors': []}]}

    report = run_heartbeats('unused', ['synthetic'], 0, seconds=0.2, interval=1,
                            workers=1, transport_factory=SyntheticClient, resource_monitor=Monitor())
    assert report['resources']['complete'] is True
    assert report['resources']['samples'][0]['errors'] == []


def test_progress_checkpoints_report_counts_without_credentials():
    checkpoints = []
    run_heartbeats('unused', ['sensitive-fixture'] * 3, 0, seconds=0.35, interval=1,
                   workers=1, transport_factory=SyntheticClient,
                   progress_callback=checkpoints.append, progress_seconds=0.1)
    assert len(checkpoints) >= 2
    assert checkpoints[0]['elapsedSeconds'] >= 0.1
    assert checkpoints[0]['expectedEvents'] >= 0
    assert 'sensitive-fixture' not in json.dumps(checkpoints)


def test_v1_and_v2_synthetic_events_are_counted():
    class EventClient(SyntheticClient):
        event_paths = []

        def request(self, method, path, token, body=None, query=''):
            if path.endswith('/events/batch'):
                type(self).event_paths.append(path)
                return {'status': 202, 'body': b'{"accepted":1,"duplicates":0,"rejected":0,"errors":[]}'}
            return super().request(method, path, token, body, query)

    report = run_heartbeats('unused', ['synthetic'] * 4, 2, seconds=1.1, interval=1,
                            workers=2, seed=4, event_devices=4, event_every=60,
                            transport_factory=EventClient)
    assert report['counts']['event_success'] == 4
    assert EventClient.event_paths.count('/api/v1/events/batch') == 2
    assert EventClient.event_paths.count('/api/v2/events/batch') == 2
    assert sum(report['eventLatencyMilliseconds'].values()) == 4


def test_old_v2_clients_send_full_inventory_and_poll_v1_policy():
    class Client(SyntheticClient):
        old_bodies = []
        queries = []

        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                self.queries.append((path, query))
            elif path == '/api/v2/heartbeat':
                self.old_bodies.append(body)
            return super().request(method, path, token, body, query)

    report = run_heartbeats('unused', ['synthetic'] * 4, 1, seconds=1.1, interval=1,
                            workers=2, seed=4, full_v2_count=2, transport_factory=Client)
    assert report['counts']['v1-full'] == 1
    assert report['counts']['v2-legacy-full'] == 2
    assert report['counts']['v2-light'] == 1
    assert all(len(body['endpoints']) == 1 and 'statelessPolicyVersions' not in body for body in Client.old_bodies)
    assert sum(query == 'policySchemaVersion=1' for _, query in Client.queries) == 2


def test_concentrated_startup_uses_full_v2_inventory_and_initial_policy():
    report = run_heartbeats('unused', ['synthetic'] * 8, 2, seconds=0.7, interval=1,
                            workers=4, full_v2_count=2, startup_spread=0, startup_full=True,
                            transport_factory=SyntheticClient)
    assert report['startupSpreadSeconds'] == 0 and report['startupFullV2'] is True
    assert report['counts']['v1-full'] == 2
    assert report['counts']['v2-legacy-full'] == 2
    assert report['counts']['v2-full'] == 4
    assert report['counts']['startup_policy_success'] == 4
    assert report['counts']['periodic_policy_success'] == 4
    assert report['missingEvents'] == report['missingPolicyPolls'] == 0


@pytest.mark.parametrize('wrong_command,expected', [(False, 2), (True, 1)])
def test_local_rollout_reports_target_receipts_and_server_counts(wrong_command, expected):
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from controlserver.security import sign_command
    from tools.load_devices import synthetic_id

    now = datetime.now(timezone.utc)
    devices = [synthetic_id('device', i) for i in (2, 3)]
    commands = {device: dict(schemaVersion=1, commandId=str(uuid4()), deviceId=device, type='disableProxy',
        issuedAtUtc=(now - timedelta(seconds=1)).isoformat(), expiresAtUtc=(now + timedelta(minutes=1)).isoformat())
        for device in devices}

    class State:
        running = False

    class Admin:
        def __init__(self, origin):
            pass
        def create_rollout(self, targets, rate):
            assert targets == devices and rate == 20
            return str(uuid4())
        def change_rollout(self, batch, action):
            State.running = True
            return {'status': 'running'}
        def rollout_details(self, batch):
            return {'status': 'dispatchComplete', 'counts': {'succeeded': 2}}
        def rollout_targets(self, batch):
            return [dict(deviceId=device, commandId=str(uuid4()) if wrong_command and index == 0 else commands[device]['commandId'])
                    for index, device in enumerate(devices)]

    class Client(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            if '/commands/' in path:
                return {'status': 202}
            if method == 'GET':
                return super().request(method, path, token, body, query)
            payload = commands.get(body['device']['deviceId']) if State.running else None
            command = {'payload': payload, 'signature': sign_command(payload, FIXTURE_KEY)} if payload else None
            return {'status': 200, 'body': json.dumps({'acceptedPolicyVersion': 1, 'command': command}).encode()}

    report = run_heartbeats('unused', ['synthetic'] * 4, 1, seconds=1.8, interval=1, workers=2,
                            rollout_after=0.1, rollout_targets=2, transport_factory=Client, admin_factory=Admin)
    assert not report['rolloutCreationFailed']
    assert report['simulatedRollout']['observedDevices'] == expected
    assert report['simulatedRollout']['serverCounts'] == {'succeeded': 2}
    assert report['simulatedRollout']['timingOrigin'] == 'batch_creation_request_started'
    assert report['simulatedRollout']['observationSeconds'] > 0
    assert 'matched against server batch command IDs' in report['simulatedRollout']['scope']


def test_partition_uses_global_ids_for_heartbeats_events_and_policy():
    from tools.load_devices import synthetic_id
    class Client(SyntheticClient):
        heartbeats, events, policy_paths = [], [], []
        def request(self, method, path, token, body=None, query=''):
            if path.endswith('/events/batch'):
                self.events.append(body['deviceId'])
                return {'status': 202, 'body': b'{"accepted":1,"duplicates":0,"rejected":0}'}
            if method == 'GET':
                self.policy_paths.append(path)
            else:
                self.heartbeats.append(body['device']['deviceId'])
            return super().request(method, path, token, body, query)
    report = run_heartbeats('unused', ['token'] * 3, legacy_count=1, full_v2_count=1,
                            seconds=0.5, interval=60, startup_spread=0, startup_full=True,
                            workers=2, event_devices=3, ordinal_start=100, transport_factory=Client)
    ids = {synthetic_id('device', i) for i in range(100, 103)}
    assert set(Client.heartbeats) == set(Client.events) == ids
    assert any(synthetic_id('device', 101) in path for path in Client.policy_paths)
    assert any(synthetic_id('device', 102) in path for path in Client.policy_paths)
    assert report['ordinalStart'] == 100 and report['devices'] == 3
    with pytest.raises(ValueError):
        run_heartbeats('unused', ['token'] * 2, 0, seconds=1, ordinal_start=149999)


def test_scheduled_start_waits_until_due_and_rejects_late_seed():
    from tools.load_test import wait_for_start
    now = [10.0]
    sleeps = []
    def sleep(delay):
        sleeps.append(delay)
        now[0] += delay
    assert wait_for_start(11.25, clock=lambda: now[0], sleeper=sleep) == 11.25
    assert sleeps == [0.5, 0.5, 0.25]
    with pytest.raises(ValueError, match='passed'):
        wait_for_start(11.25, clock=lambda: now[0], sleeper=sleep)


def test_cli_records_partition_and_coordinated_start_without_tokens(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from tools import load_test
    target = datetime(2026, 11, 1, 12, tzinfo=timezone.utc).timestamp()
    captured = {}
    def seed(origin, devices, legacy, **kwargs):
        captured['seed'] = (devices, legacy, kwargs['ordinal_start'])
        return ['secret-fixture-token'] * devices
    def run(origin, tokens, legacy, seconds, **kwargs):
        captured['run'] = (len(tokens), legacy, kwargs['ordinal_start'])
        return {'elapsedSeconds': seconds, 'latencyMilliseconds': {}, 'policyLatencyMilliseconds': {},
                'eventLatencyMilliseconds': {}, 'adminLatencyMilliseconds': {}}
    monkeypatch.setattr(load_test, 'seed_devices', seed)
    monkeypatch.setattr(load_test, 'run_heartbeats', run)
    monkeypatch.setattr(load_test.time, 'time', lambda: target - 60)
    monkeypatch.setattr(load_test, 'wait_for_start', lambda scheduled: scheduled + 0.125)
    artifact = tmp_path / 'candidate'
    artifact.write_text('fixture', encoding='utf-8')
    output = tmp_path / 'report.jsonl'
    assert load_test.main(['--confirm-isolated', '--origin', 'http://127.0.0.1:18080',
                           '--devices', '3', '--online', '2', '--legacy', '1', '--ordinal-start', '100',
                           '--seconds', '1', '--start-at', '2026-11-01T12:00:00Z',
                           '--server-artifact', str(artifact), '--output', str(output)]) == 0
    raw = output.read_text(encoding='utf-8')
    records = [json.loads(line) for line in raw.splitlines()]
    assert [r['status'] for r in records] == ['running', 'ready', 'finished']
    assert records[0]['parameters']['ordinalStart'] == 100
    assert records[1]['scheduledStartUtc'] == '2026-11-01T12:00:00Z'
    assert records[-1]['startSkewSeconds'] == 0.125
    assert captured == {'seed': (3, 1, 100), 'run': (2, 1, 100)}
    assert 'secret-fixture-token' not in raw


def test_follower_backfills_receipts_seen_before_publication_event():
    class Changed(SyntheticClient):
        def request(self, method, path, token, body=None, query=''):
            if method == 'GET':
                payload = b'{"policyVersion":2}'
                return {'status': 200, 'body': payload, 'headers': {'X-SF-Policy-Signature': sign_policy(payload, FIXTURE_KEY)}}
            return {'status': 200, 'body': b'{"acceptedPolicyVersion":2}'}
    started = time.monotonic()
    def observer():
        if time.monotonic() < started + 1.4:
            return None
        return {'version': 2, 'started': started + 0.05, 'completed': started + 0.1, 'evidence': {'fixture': True}}
    report = run_heartbeats('unused', ['token'], 0, seconds=2.1, interval=1, startup_spread=0,
                            workers=1, transport_factory=Changed, publication_observer=observer)
    assert report['simulatedConvergence']['observedDevices'] == 1
    assert report['simulatedConvergence']['within120Seconds'] == 1
    assert report['publicationEvidence'] == {'fixture': True}


def test_follower_missing_publication_never_claims_convergence():
    report = run_heartbeats('unused', ['token'], 0, seconds=0.2, startup_spread=0,
                            transport_factory=SyntheticClient, publication_observer=lambda: None)
    assert report['publicationFailed'] is True
    assert report['simulatedConvergence'] is None


def test_publication_sink_failure_does_not_claim_success():
    class Admin:
        def __init__(self, origin): pass
        def publish_toggle(self):
            now = time.monotonic()
            return {'version': 2, 'started': now, 'completed': now}
    def fail(_):
        raise OSError('fixture shared storage failure')
    report = run_heartbeats('unused', ['token'], 0, seconds=0.3, startup_spread=0,
                            transport_factory=SyntheticClient, admin_factory=Admin,
                            publish_after=0, publication_sink=fail)
    assert report['publicationFailed'] is True
    assert report['publicationEvidence'] is None
    assert report['simulatedConvergence'] is None


def test_compact_workload_uses_dedicated_route_and_records_mode():
    class CompactClient(SyntheticClient):
        compact_seen = []
        def request(self, method, path, token, body=None, query=''):
            if path == '/api/v2/heartbeat/light-compact':
                self.compact_seen.append(body)
                assert body['compactInventory'] is True and body['inventoryUnchanged'] is True
                assert body['users'] == body['agents'] == body['endpoints'] == []
            return super().request(method, path, token, body, query)
    report = run_heartbeats('unused', ['synthetic'] * 3, legacy_count=0, seconds=1.1,
                            interval=1, workers=2, compact_v2=True, transport_factory=CompactClient)
    assert report['compactV2'] is True and report['counts']['v2-compact'] >= 3
    assert report['counts']['compact_success'] == report['counts']['v2-compact']
    assert CompactClient.compact_seen
    assert report['dispatchedEvents'] + report['missingEvents'] + report['counts'].get('missed_busy', 0) == report['expectedEvents']
