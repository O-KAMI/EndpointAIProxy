import json

import pytest
from tools import load_test


def test_percentiles_are_nearest_rank_with_empty_histogram():
    assert load_test.percentile({}, 95) is None
    assert load_test.percentile({'1': 95, '20': 5}, 95) == 1
    assert load_test.percentile({'1': 95, '20': 5}, 99) == 20


def test_fixture_probe_reports_its_limited_scope(capsys):
    from tools.load_fixture_probe import main
    main(['--requests', '5'])
    report = json.loads(capsys.readouterr().out)
    assert report['requests'] == 5 and report['requestsPerSecond'] > 0
    assert 'no HTTP' in report['scope']


def test_report_is_exclusive_redacted_and_never_claims_capacity(tmp_path, monkeypatch):
    artifact = tmp_path / 'candidate.bin'
    artifact.write_bytes(b'synthetic candidate')
    output = tmp_path / 'report.jsonl'
    monkeypatch.setattr(load_test, 'seed_devices', lambda *args, **kwargs: ['secret-fixture-token'] * 3)
    def fake_run(origin, tokens, legacy, seconds, **kwargs):
        assert len(tokens) == 2 and legacy == 1
        return dict(elapsedSeconds=seconds, latencyMilliseconds={1: 19, 30: 1},
                    policyLatencyMilliseconds={}, eventLatencyMilliseconds={}, adminLatencyMilliseconds={})
    monkeypatch.setattr(load_test, 'run_heartbeats', fake_run)
    args = ['--confirm-isolated', '--origin', 'http://127.0.0.1:1234', '--devices', '3',
            '--online', '2', '--legacy', '1', '--seconds', '1', '--server-artifact', str(artifact),
            '--output', str(output)]
    assert load_test.main(args) == 0
    text = output.read_text(encoding='utf-8')
    assert 'secret-fixture-token' not in text
    start, end = map(json.loads, text.splitlines())
    assert start['runningArtifactBinding'] == 'operator verification required'
    assert end['capacityAcceptance'] == 'not evaluated'
    assert not end['duration8hCompleted']
    assert end['report']['heartbeatP95BucketMs'] == 1
    assert end['report']['heartbeatP99BucketMs'] == 30
    with pytest.raises(FileExistsError):
        load_test.main(args)


def test_invalid_scenario_is_rejected_before_seeding(tmp_path, monkeypatch):
    artifact = tmp_path / 'candidate.bin'
    artifact.write_bytes(b'synthetic')
    monkeypatch.setattr(load_test, 'seed_devices', lambda *args, **kwargs: pytest.fail('seed should not run'))
    with pytest.raises(SystemExit):
        load_test.main(['--confirm-isolated', '--origin', 'http://127.0.0.1:1234', '--devices', '2',
            '--online', '2', '--seconds', '1', '--outage-after', '0.5', '--outage-seconds', '2',
            '--server-artifact', str(artifact), '--output', str(tmp_path / 'never-created.jsonl')])
    assert not (tmp_path / 'never-created.jsonl').exists()


def test_generator_pid_can_be_included_in_resource_monitor(tmp_path, monkeypatch):
    import os
    artifact = tmp_path / 'candidate.bin'
    artifact.write_bytes(b'synthetic')
    output = tmp_path / 'report.jsonl'
    class Monitor:
        def __init__(self, pids, disk):
            assert pids == [os.getpid()] and disk == tmp_path
    monkeypatch.setattr(load_test, 'ResourceMonitor', Monitor)
    monkeypatch.setattr(load_test, 'seed_devices', lambda *args, **kwargs: ['fixture'])
    def run(*args, **kwargs):
        assert isinstance(kwargs['resource_monitor'], Monitor)
        return dict(elapsedSeconds=1, latencyMilliseconds={}, policyLatencyMilliseconds={},
                    eventLatencyMilliseconds={}, adminLatencyMilliseconds={})
    monkeypatch.setattr(load_test, 'run_heartbeats', run)
    assert load_test.main(['--confirm-isolated', '--origin', 'http://127.0.0.1:1234',
        '--devices', '1', '--online', '1', '--seconds', '1', '--server-artifact', str(artifact),
        '--monitor-generator', '--disk-path', str(tmp_path), '--output', str(output)]) == 0
    first = json.loads(output.read_text(encoding='utf-8').splitlines()[0])
    assert first['parameters']['generatorPid'] == os.getpid()


def test_progress_is_appended_without_claiming_completion(tmp_path, monkeypatch):
    artifact = tmp_path / 'candidate.bin'
    artifact.write_bytes(b'synthetic')
    output = tmp_path / 'report.jsonl'
    monkeypatch.setattr(load_test, 'seed_devices', lambda *args, **kwargs: ['fixture'])
    def run(*args, **kwargs):
        kwargs['progress_callback']({'elapsedSeconds': 10, 'expectedEvents': 1, 'counts': {}})
        return dict(elapsedSeconds=1, latencyMilliseconds={}, policyLatencyMilliseconds={},
                    eventLatencyMilliseconds={}, adminLatencyMilliseconds={})
    monkeypatch.setattr(load_test, 'run_heartbeats', run)
    assert load_test.main(['--confirm-isolated', '--origin', 'http://127.0.0.1:1234',
        '--devices', '1', '--online', '1', '--seconds', '1', '--server-artifact', str(artifact),
        '--output', str(output)]) == 0
    records = [json.loads(line) for line in output.read_text(encoding='utf-8').splitlines()]
    assert [record['status'] for record in records] == ['running', 'progress', 'finished']
    assert records[1]['snapshot']['expectedEvents'] == 1
    assert not records[-1]['duration8hCompleted']


def test_small_complete_entrypoint_with_isolated_mysql(mysql_store, tmp_path):
    import base64
    from threading import Thread
    from werkzeug.serving import make_server
    from app import create_app
    from tools.load_admin import FIXTURE_ADMIN_TOKEN
    from tools.load_transport import FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID

    cfg = mysql_store.cfg
    cfg.CLIENT_TOKEN, cfg.ADMIN_TOKEN, cfg.TRANSPORT_KEY_ID = FIXTURE_ENROLLMENT_TOKEN, FIXTURE_ADMIN_TOKEN, FIXTURE_KEY_ID
    cfg.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    cfg.HMAC_TEXT = cfg.TRANSPORT_KEY_TEXT
    cfg.validate()
    server = make_server('127.0.0.1', 0, create_app(cfg, mysql_store), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    artifact = tmp_path / 'synthetic-release.bin'
    artifact.write_bytes(b'synthetic release')
    output = tmp_path / 'result.jsonl'
    try:
        result = load_test.main(['--confirm-isolated', '--origin', f'http://127.0.0.1:{server.server_port}',
            '--devices', '6', '--online', '6', '--legacy', '2', '--full-v2', '2', '--seconds', '4.5',
            '--heartbeat-seconds', '1', '--workers', '3', '--publish-after', '0.2',
            '--startup-spread', '0', '--startup-full',
            '--event-devices', '6', '--event-every', '2',
            '--command-after', '0.4', '--admin-query-seconds', '1', '--outage-after', '1.5',
            '--outage-seconds', '0.4', '--reconnect-spread', '0.2',
            '--server-artifact', str(artifact), '--output', str(output)])
        assert result == 0
        records = [json.loads(line) for line in output.read_text(encoding='utf-8').splitlines()]
        start, final = records[0], records[-1]
        assert start['status'] == 'running' and final['status'] == 'finished'
        assert any(record['status'] == 'seeding' for record in records)
        report = final['report']
        assert not final['duration8hCompleted'] and final['capacityAcceptance'] == 'not evaluated'
        assert report['counts'].get('transport_error', 0) == 0
        assert report['counts'].get('business_error', 0) == 0
        assert report['counts']['admin_query_success'] > 0
        assert report['counts']['event_success'] >= 6
        assert report['counts']['v2-legacy-full'] >= 2
        assert report['counts']['startup_policy_success'] == 2
        assert report['simulatedConvergence']['observedDevices'] == 6
        assert report['simulatedCommand']['receiptObserved']
        assert FIXTURE_ENROLLMENT_TOKEN not in output.read_text(encoding='utf-8')
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.parametrize('rate', [20, 40])
def test_local_https_rollout_entrypoint_with_isolated_mysql(mysql_store, tmp_path, rate):
    import base64
    from threading import Event, Thread
    from werkzeug.serving import make_server
    from app import create_app
    from controlserver import rollout
    from test_load_admin import make_tls_fixtures
    from tools.load_transport import FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID

    cert, key, accounts = make_tls_fixtures(tmp_path)
    cfg = mysql_store.cfg
    cfg.ROLLOUT_MAX_RATE = rate
    cfg.CLIENT_TOKEN, cfg.TRANSPORT_KEY_ID = FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY_ID
    cfg.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    cfg.HMAC_TEXT = cfg.TRANSPORT_KEY_TEXT
    cfg.ADMIN_AUTH_MODE, cfg.ADMIN_ACCOUNTS_PATH = 'local', str(accounts)
    cfg.ADMIN_SESSION_KEY_TEXT = base64.b64encode(b's' * 32).decode()
    cfg.validate()
    app = create_app(cfg, mysql_store)
    plain = make_server('127.0.0.1', 0, app, threaded=True)
    secure = make_server('127.0.0.1', 0, app, threaded=True, ssl_context=(str(cert), str(key)))
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (plain, secure)]
    stop = Event()
    failures = []
    def dispatch():
        while not stop.is_set():
            try:
                rollout.dispatch_one(mysql_store)
            except Exception as error:
                failures.append(type(error).__name__)
                return
            stop.wait(0.05)
    worker = Thread(target=dispatch, daemon=True)
    for thread in threads:
        thread.start()
    worker.start()
    artifact = tmp_path / 'synthetic-release.bin'
    artifact.write_bytes(b'synthetic release')
    output = tmp_path / 'rollout-result.jsonl'
    try:
        result = load_test.main(['--confirm-isolated', '--origin', f'http://127.0.0.1:{plain.server_port}',
            '--admin-origin', f'https://127.0.0.1:{secure.server_port}', '--admin-ca', str(cert),
            '--devices', '6', '--online', '6', '--legacy', '2', '--seconds', '4.5',
            '--heartbeat-seconds', '1', '--workers', '3', '--rollout-after', '0.2',
            '--rollout-targets', '3', '--rollout-rate', str(rate), '--admin-query-seconds', '1',
            '--server-artifact', str(artifact), '--output', str(output)])
        assert result == 0 and not failures
        records = [json.loads(line) for line in output.read_text(encoding='utf-8').splitlines()]
        start, final = records[0], records[-1]
        assert any(record['status'] == 'seeding' for record in records)
        report = final['report']
        assert start['parameters']['adminAuthMode'] == 'local-https'
        assert not report['rolloutCreationFailed']
        assert report['simulatedRollout']['serverCounts']['succeeded'] == 3
        assert report['simulatedRollout']['observedDevices'] == 3
        assert final['capacityAcceptance'] == 'not evaluated'
    finally:
        stop.set()
        worker.join(timeout=5)
        for server in (plain, secure):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
