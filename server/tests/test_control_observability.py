"""Synthetic local requests: no MySQL, real credential files or network calls."""
import logging
from uuid import uuid4
import pytest

from app import create_app
from controlserver.transport import b64, open_envelope, seal


def test_replay_maintenance_reports_deleted_and_oldest_expired(monkeypatch):
    from types import SimpleNamespace
    import app as application

    class StopLoop(BaseException):
        pass

    class Thread:
        def __init__(self, target, **kwargs):
            self.target = target
        def start(self):
            self.target()

    class Store:
        def cleanup_transport(self):
            return 3
        def replay_expired_age_seconds(self):
            return 12

    calls = []
    sleeps = iter((None, StopLoop()))
    def sleep(_seconds):
        result = next(sleeps)
        if result:
            raise result
    times = iter((0, 61, 61))
    monkeypatch.setattr(application, 'threading', SimpleNamespace(Thread=Thread))
    monkeypatch.setattr(application, 'time', SimpleNamespace(sleep=sleep, monotonic=lambda: next(times)))
    logger = SimpleNamespace(info=lambda message, *args: calls.append((message, args)),
                             error=lambda *args: pytest.fail('unexpected metrics error'))
    with pytest.raises(StopLoop):
        application.start_replay_maintenance(SimpleNamespace(extensions={'control_store': Store()}, logger=logger))
    assert len(calls) == 1
    assert 'oldestExpiredSeconds=%s' in calls[0][0]
    assert calls[0][1][-2:] == (3, 12)


class ReplayStore:
    def __init__(self):
        self.claims = set()

    def claim_transport(self, envelope):
        if envelope["requestId"] in self.claims:
            return False
        self.claims.add(envelope["requestId"])
        return True


def test_split_service_roles_restrict_routes_and_database_budget(config):
    from controlserver.database import ControlStore
    config.SERVICE_ROLE = "admin"
    with pytest.raises(ValueError, match="loopback"):
        config.validate()
    config.HTTP_HOST = "127.0.0.1"
    assert ControlStore(config)._pool_limit == 2
    admin = create_app(config, ReplayStore(), check_database=False).test_client()
    assert admin.post("/api/transport/v1", json={}).status_code == 404
    assert admin.get("/auth/mode").status_code == 200
    config.SERVICE_ROLE = "client"
    assert ControlStore(config)._pool_limit == 8
    client = create_app(config, ReplayStore(), check_database=False).test_client()
    assert client.get("/auth/mode").status_code == 404
    assert client.get("/admin/v1/policy").status_code == 404
    assert client.post("/api/transport/v1", json={}).status_code == 400


def test_admin_ingress_allows_maximum_policy_batch_targets():
    import json
    import re
    from pathlib import Path
    from uuid import UUID
    from controlserver.models import CreatePolicyRolloutRequest
    from controlserver.validation import validate_policy
    template = (Path(__file__).resolve().parents[1] / 'deploy/nginx-local-admin.conf.example').read_text(encoding='utf-8')
    match = re.search(r'location\s+\^~\s+/admin/v1/policy-rollouts\s*\{([^}]*)\}', template)
    assert match
    block = match.group(1)
    assert 'client_max_body_size 30m;' in block
    assert 'proxy_pass http://127.0.0.1:18081;' in block
    assert 'proxy_set_header X-Forwarded-Proto https;' in block
    assert 'proxy_set_header X-Forwarded-For $remote_addr;' in block
    ids = [str(UUID(int=i + 1)) for i in range(150000)]
    url = 'https://example.test/' + '汉' * 1900
    request = {'deviceIds':ids, 'confirmCount':len(ids), 'reason':'synthetic', 'maxPerSecond':20,
               'policy':{'expectedVersion':1, 'enabled':True, 'routeMode':'fixedGateway',
                         'gatewayOrigin':'https://gateway.example', 'allowInsecureGateway':False,
                         'pollIntervalSeconds':60, 'heartbeatIntervalSeconds':60,
                         'allowlistedBaseUrls':[url] * 256}}
    body = json.dumps(request, separators=(',', ':')).encode()
    assert 8 * 1024 * 1024 < len(body) < 30_000_000
    validated = CreatePolicyRolloutRequest.model_validate(request)
    validate_policy(validated.policy)


def test_client_ingress_allows_the_app_transport_wire_limit():
    import re
    from pathlib import Path
    from controlserver.transport import MAX_PLAIN, MAX_WIRE
    template = (Path(__file__).resolve().parents[1] / 'deploy/nginx-local-admin.conf.example').read_text(encoding='utf-8')
    locations = re.findall(r'location\s+=\s+/api/transport/v1\s*\{([^}]*)\}', template)
    assert len(locations) == 2
    for block, scheme in zip(locations, ('http', 'https')):
        limit = re.search(r'client_max_body_size\s+(\d+)m;', block)
        assert limit and int(limit.group(1)) * 1024 * 1024 >= MAX_WIRE
        assert 'proxy_pass http://127.0.0.1:18080;' in block
        assert f'proxy_set_header X-Forwarded-Proto {scheme};' in block
    double_base64 = ((MAX_PLAIN + 2) // 3 * 4 + 2) // 3 * 4
    assert 41 * 1024 * 1024 < double_base64 < MAX_WIRE


def wire(config, path="/api/v2/missing", token="synthetic-secret-token"):
    return seal(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, str(uuid4()),
                dict(method="GET", path=path, query="secret=synthetic-secret-query", token=token,
                     body=b64(b"synthetic-secret-body")), "request")


def test_transport_logs_authenticated_ids_without_payloads(config, caplog):
    app = create_app(config, ReplayStore(), check_database=False)
    caplog.set_level(logging.INFO, logger=app.logger.name)
    request = wire(config)
    result = app.test_client().post("/api/transport/v1", json=request)
    assert result.status_code == 200
    value = open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                          "response", request["requestId"])
    assert value["status"] == 404
    business = value["headers"]["X-Request-ID"]
    logs = [r.getMessage() for r in caplog.records if "controlEnvelopeId=" in r.getMessage()]
    assert len(logs) == 2
    assert all(f"controlEnvelopeId={request['requestId']}" in line for line in logs)
    assert all(f"businessRequestId={business}" in line for line in logs)
    assert "stage=business" in logs[0] and "stage=transport_complete" in logs[1]
    assert all("durationMilliseconds=" in line for line in logs)
    assert result.headers["X-Request-ID"] == business
    assert "synthetic-secret" not in "\n".join(logs)


def test_successful_control_requests_are_aggregated_without_losing_errors(config, caplog, monkeypatch):
    app = create_app(config, ReplayStore(), check_database=False)
    @app.get("/api/v2/probe")
    def probe():
        return {"ok": True}
    caplog.set_level(logging.INFO, logger=app.logger.name)
    now = [1_800_000_000]
    monkeypatch.setattr("app.time.time", lambda: now[0])
    client = app.test_client()
    def send(request_id):
        request = seal(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, request_id,
                       dict(method="GET", path="/api/v2/probe", query="", token="synthetic-token", body=b64(b"")), "request")
        return client.post("/api/transport/v1", json=request)
    assert send("00000000-0000-0000-0000-000000000001").status_code == 200
    assert not any("controlEnvelopeId=" in record.getMessage() for record in caplog.records)
    now[0] += 61
    assert send("00000000-0000-0000-0000-000000000002").status_code == 200
    lines = [record.getMessage() for record in caplog.records]
    assert sum("CONTROL_SUCCESS_AGGREGATE" in line for line in lines) == 2
    assert all("le200=" in line and "le1000=" in line for line in lines if "CONTROL_SUCCESS_AGGREGATE" in line)
    assert not any("synthetic-token" in line for line in lines)


def test_idle_worker_flushes_completed_success_metrics_once(config, caplog, monkeypatch):
    app = create_app(config, ReplayStore(), check_database=False)
    @app.get('/api/v2/probe')
    def probe(): return {'ok': True}
    caplog.set_level(logging.INFO, logger=app.logger.name)
    now = [1_800_000_000]
    monkeypatch.setattr('app.time.time', lambda: now[0])
    envelope = seal(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, '00000000-0000-0000-0000-000000000001',
                    dict(method='GET', path='/api/v2/probe', query='', token='synthetic-token', body=b64(b'')), 'request')
    assert app.test_client().post('/api/transport/v1', json=envelope).status_code == 200
    app.extensions['flush_control_success']()
    assert not any('CONTROL_SUCCESS_AGGREGATE' in record.getMessage() for record in caplog.records)
    now[0] += 61
    app.extensions['flush_control_success']()
    app.extensions['flush_control_success']()
    lines = [record.getMessage() for record in caplog.records if 'CONTROL_SUCCESS_AGGREGATE' in record.getMessage()]
    assert len(lines) == 2 and all('count=1' in line for line in lines)
    assert not any('synthetic-token' in line for line in lines)


def test_control_failure_burst_preserves_counts_and_bounded_examples(config, caplog, monkeypatch):
    app = create_app(config, ReplayStore(), check_database=False)
    caplog.set_level(logging.INFO, logger=app.logger.name)
    now = [1_800_000_000]
    monkeypatch.setattr('app.time.time', lambda: now[0])
    client = app.test_client()
    for _ in range(8):
        envelope = wire(config)
        result = client.post('/api/transport/v1', json=envelope)
        assert result.status_code == 200
        assert open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                             'response', envelope['requestId'])['status'] == 404
    examples = [r.getMessage() for r in caplog.records if 'controlEnvelopeId=' in r.getMessage()]
    assert len(examples) == 10  # Five business and five outer-envelope examples.
    now[0] += 61
    app.extensions['flush_control_success']()
    app.extensions['flush_control_success']()
    summaries = [r.getMessage() for r in caplog.records if 'CONTROL_FAILURE_AGGREGATE' in r.getMessage()]
    assert len(summaries) == 2 and all('count=8' in line for line in summaries)
    assert not any('synthetic-secret' in line for line in examples + summaries)


def test_control_failure_codes_are_separate_and_unknown_codes_are_redacted(config, caplog, monkeypatch):
    from controlserver.validation import ApiProblem
    app = create_app(config, ReplayStore(), check_database=False)
    codes = iter(['DEVICE_ENROLLMENT_CONFLICT'] * 6 + ['POLICY_SCHEMA_UNSUPPORTED', 'synthetic-secret'])
    @app.get('/api/v2/probe')
    def probe(): raise ApiProblem(next(codes), 'synthetic-secret-message', 409)
    caplog.set_level(logging.INFO, logger=app.logger.name)
    now = [1_800_000_000]
    monkeypatch.setattr('app.time.time', lambda: now[0])
    client = app.test_client()
    for _ in range(8):
        result = client.post('/api/transport/v1', json=wire(config, '/api/v2/probe'))
        assert result.status_code == 200
    now[0] += 61
    app.extensions['flush_control_success']()
    summaries = [r.getMessage() for r in caplog.records if 'CONTROL_FAILURE_AGGREGATE' in r.getMessage()]
    assert len(summaries) == 6
    assert sum('errorCode=DEVICE_ENROLLMENT_CONFLICT count=6' in line for line in summaries) == 2
    assert sum('errorCode=POLICY_SCHEMA_UNSUPPORTED count=1' in line for line in summaries) == 2
    assert sum('errorCode=OTHER count=1' in line for line in summaries) == 2
    assert not any('synthetic-secret' in r.getMessage() for r in caplog.records)


def test_pool_reporter_runs_idle_success_flush(monkeypatch):
    from types import SimpleNamespace
    import app as application
    class StopLoop(BaseException): pass
    class Thread:
        def __init__(self, target, **kwargs): self.target = target
        def start(self): self.target()
    calls = []
    sleeps = iter((None, StopLoop()))
    def sleep(_):
        result = next(sleeps)
        if result: raise result
    metrics = SimpleNamespace(snapshot=lambda: dict(inUse=0, attempts=0, exhausted=0,
        waitMilliseconds=0.0, maxWaitMilliseconds=0.0))
    fake = SimpleNamespace(extensions={'flush_control_success': lambda: calls.append('flush'),
        'control_store': SimpleNamespace(pool_metrics=metrics, _pool_limit=8),
        'control_config': SimpleNamespace(SERVICE_ROLE='client')},
        logger=SimpleNamespace(info=lambda *args: None, warning=lambda *args: None))
    monkeypatch.setattr(application, 'threading', SimpleNamespace(Thread=Thread))
    monkeypatch.setattr(application, 'time', SimpleNamespace(sleep=sleep))
    with pytest.raises(StopLoop): application.start_pool_metrics(fake)
    assert calls == ['flush']


def test_overloaded_replay_store_returns_authenticated_retry_without_dispatch(config):
    from controlserver.database import PoolExhausted
    class BusyStore:
        def claim_transport(self, envelope):
            raise PoolExhausted()
    app = create_app(config, BusyStore(), check_database=False)
    called = []
    @app.get("/api/v2/probe")
    def probe():
        called.append(True)
        return {"ok": True}
    request = wire(config, "/api/v2/probe")
    result = app.test_client().post("/api/transport/v1", json=request)
    assert result.status_code == 200
    value = open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                          "response", request["requestId"])
    assert value["status"] == 503 and value["headers"]["Retry-After"] == "5"
    assert not called


def test_unauthenticated_envelope_id_not_logged(config, caplog):
    app = create_app(config, ReplayStore(), check_database=False)
    caplog.set_level(logging.INFO, logger=app.logger.name)
    request = wire(config)
    request["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    result = app.test_client().post("/api/transport/v1", json=request)
    assert result.status_code == 400
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert request["requestId"] not in text
    assert "stage=transport_validate" in text


def test_error_logs_do_not_include_exception_messages(config, caplog):
    app = create_app(config, ReplayStore(), check_database=False)
    @app.get("/api/v2/crash")
    def crash():
        raise RuntimeError("synthetic-secret-error")
    caplog.set_level(logging.INFO, logger=app.logger.name)
    request = wire(config, "/api/v2/crash")
    result = app.test_client().post("/api/transport/v1", json=request)
    value = open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                          "response", request["requestId"])
    assert value["status"] == 500
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "errorClass=INTERNAL_ERROR" in text and "synthetic-secret" not in text


def test_control_exception_burst_has_bounded_examples_and_complete_count(config, caplog, monkeypatch):
    app = create_app(config, ReplayStore(), check_database=False)
    @app.get('/api/v2/crash')
    def crash(): raise RuntimeError('synthetic-secret-exception')
    caplog.set_level(logging.INFO, logger=app.logger.name)
    now = [1_800_000_000]
    monkeypatch.setattr('app.time.time', lambda: now[0])
    client = app.test_client()
    for _ in range(8):
        envelope = wire(config, '/api/v2/crash')
        result = client.post('/api/transport/v1', json=envelope)
        assert open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                             'response', envelope['requestId'])['status'] == 500
    errors = [r.getMessage() for r in caplog.records if 'Unhandled request exception' in r.getMessage()]
    assert len(errors) == 5
    now[0] += 61
    app.extensions['flush_control_success']()
    app.extensions['flush_control_success']()
    summaries = [r.getMessage() for r in caplog.records if 'CONTROL_EXCEPTION_AGGREGATE' in r.getMessage()]
    assert len(summaries) == 1 and 'errorType=RuntimeError' in summaries[0] and 'count=8' in summaries[0]
    assert not any('synthetic-secret' in r.getMessage() for r in caplog.records)


def test_control_exception_aggregate_limits_distinct_groups(config, caplog, monkeypatch):
    import re
    from controlserver.transport import INTERNAL
    app = create_app(config, ReplayStore(), check_database=False)
    @app.get('/api/v2/crash')
    def crash(): raise RuntimeError('synthetic')
    numbers = iter(range(260))
    monkeypatch.setattr('app.safe_exception', lambda exc: ('RuntimeError', next(numbers), '', ''))
    now = [1_800_000_000]
    monkeypatch.setattr('app.time.time', lambda: now[0])
    caplog.set_level(logging.ERROR, logger=app.logger.name)
    client = app.test_client()
    for _ in range(260):
        assert client.get('/api/v2/crash', environ_overrides={'endpointai.transport': INTERNAL}).status_code == 500
    now[0] += 61
    app.extensions['flush_control_success']()
    summaries = [r.getMessage() for r in caplog.records if 'CONTROL_EXCEPTION_AGGREGATE' in r.getMessage()]
    assert len(summaries) == 256
    assert sum(int(re.search(r'count=(\d+)', line).group(1)) for line in summaries) == 260
    assert any('stage=other errorType=OTHER' in line and 'count=5' in line for line in summaries)


@pytest.mark.parametrize("version", ["0.1.23", "0.1.24"])
def test_rotation_template_covers_upgrade_layout_and_distinguishes_open_console(version):
    from pathlib import Path
    from fnmatch import fnmatch
    import re
    template = (Path(__file__).resolve().parents[1] / "deploy/logrotate-appdeploy.conf").read_text()
    rules = dict(re.findall(r"(?m)^(/[^\n ]+)\s*\{([^}]+)\}", template))
    app_rule = next(body for path, body in rules.items()
                    if fnmatch(f"/app/EndpointAIDLP-Server-{version}/logs/app.log", path))
    console_rule = next(body for path, body in rules.items()
                        if fnmatch(f"/app/EndpointAIDLP-Server-{version}/console.log", path))
    assert "su appdeploy appdeploy" in app_rule and "create 0640 appdeploy appdeploy" in app_rule
    assert "copytruncate" not in app_rule
    assert "copytruncate" in console_rule and "su appdeploy appdeploy" in console_rule
    assert "maxsize 20M" in app_rule and "maxsize 20M" in console_rule


def test_exception_metadata_is_bounded_and_does_not_accept_free_text():
    from controlserver.observability import safe_exception
    import pymysql
    error = pymysql.OperationalError(2003, "synthetic-secret-connection")
    error.sqlstate = "08001"
    assert safe_exception(error)[:3] == ("OperationalError", 2003, "08001")
    error.sqlstate = "synthetic-secret-state"
    assert safe_exception(error)[2] == ""
    assert "synthetic-secret" not in str(safe_exception(error))
    assert safe_exception(RuntimeError("synthetic-secret"))[1] == 0
def test_pool_metrics_tracks_success_exhaustion_and_release():
    from controlserver.observability import PoolMetrics
    metrics = PoolMetrics()
    metrics.acquired(0.125, True)
    metrics.acquired(5, False)
    assert metrics.snapshot() == {"attempts": 2, "exhausted": 1, "inUse": 1,
                                  "waitMilliseconds": 5125.0, "maxWaitMilliseconds": 5000.0}
    metrics.released()
    assert metrics.snapshot()["inUse"] == 0


def test_pool_metrics_release_after_connection_failure(monkeypatch):
    from types import SimpleNamespace
    import pytest
    from controlserver.database import ControlStore
    store = ControlStore(SimpleNamespace(SERVICE_ROLE="client"))
    def fail_connect():
        raise RuntimeError("synthetic connection failure")
    monkeypatch.setattr(store, "connect", fail_connect)
    with pytest.raises(RuntimeError):
        with store.transaction():
            pass
    snapshot = store.pool_metrics.snapshot()
    assert snapshot["attempts"] == 1 and snapshot["inUse"] == 0
    assert snapshot["exhausted"] == 0


@pytest.mark.parametrize('failure', ['database', 'rollback'])
def test_pool_discards_uncertain_connection_and_preserves_error(monkeypatch, failure):
    from types import SimpleNamespace
    import pymysql
    from controlserver.database import ControlStore
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *args): return False
    class Connection:
        open = True
        committed = False
        def cursor(self): return Cursor()
        def rollback(self):
            if failure == 'rollback': raise OSError('synthetic rollback failure')
        def close(self): self.open = False
        def commit(self): self.committed = True
    connection, replacement = Connection(), Connection()
    available = iter([connection, replacement])
    store = ControlStore(SimpleNamespace(SERVICE_ROLE='client'))
    monkeypatch.setattr(store, 'connect', lambda: next(available))
    error = pymysql.err.OperationalError(1205, 'synthetic database failure') if failure == 'database' else RuntimeError('synthetic original failure')
    with pytest.raises(type(error)) as raised:
        with store.transaction():
            raise error
    assert raised.value is error
    assert not connection.open and store._pool_idle.empty()
    assert store.pool_metrics.snapshot()['inUse'] == 0
    with store.transaction():
        pass
    assert replacement.committed and store._pool_idle.get_nowait() is replacement
