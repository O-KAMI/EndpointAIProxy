import copy
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time
from uuid import uuid4

import pytest

from controlserver import rollout
from controlserver.models import CreateRemoteCommandRequest, CreateRolloutRequest, HeartbeatV2Request
from controlserver.validation import ApiProblem


def devices(store, count):
    fixture = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    ids = []
    for index in range(count):
        body = copy.deepcopy(fixture)
        body["device"]["deviceId"] = str(uuid4())
        body["device"]["hostname"] = "synthetic-" + str(index)
        store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
        ids.append(body["device"]["deviceId"])
    return sorted(ids)


def request(ids):
    return CreateRolloutRequest(type="disableProxy", reason="synthetic test", expiresInMinutes=60,
                                maxPerSecond=20, deviceIds=ids, confirmCount=len(ids))


def test_batch_snapshot_pause_failure_retry_and_unknown(mysql_store):
    ids = devices(mysql_store, 4)
    active = mysql_store.create_command(ids[1], CreateRemoteCommandRequest(type="disableProxy", reason="existing", expiresInMinutes=60), "operator")
    created = rollout.create(mysql_store, request(ids), "operator")
    batch = created["batchId"]
    assert created["status"] == "paused" and not rollout.dispatch_one(mysql_store)
    rollout.change(mysql_store, batch, "resume", "approved", "operator")
    assert rollout.dispatch_one(mysql_store)
    rollout.change(mysql_store, batch, "pause", "inspect", "operator")
    assert not rollout.dispatch_one(mysql_store)
    first = rollout.details(mysql_store, batch, 0, 10)
    assert first["counts"] == {"pendingCommand": 1, "pending": 3}
    rollout.change(mysql_store, batch, "resume", "continue", "operator")
    for _ in range(3):
        with mysql_store.transaction() as cur:
            cur.execute("UPDATE rollout_batches SET next_dispatch_at_utc=UTC_TIMESTAMP(6) WHERE batch_id=%s", (batch,))
        assert rollout.dispatch_one(mysql_store)
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE rollout_batches SET next_dispatch_at_utc=UTC_TIMESTAMP(6) WHERE batch_id=%s", (batch,))
    assert rollout.dispatch_one(mysql_store)
    snapshot = rollout.details(mysql_store, batch, 0, 10)
    assert snapshot["status"] == "dispatchComplete"
    assert snapshot["counts"] == {"pendingCommand": 3, "dispatchFailed": 1}
    failed_dispatch = rollout.details(mysql_store, batch, 0, 10, "dispatchFailed")
    assert failed_dispatch["filteredTargets"] == 1 and failed_dispatch["targets"][0]["deviceId"] == ids[1]
    issued = [item for item in snapshot["targets"] if item["commandId"]]
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE remote_commands SET status='failed',result_code='TEST_FAILED' WHERE command_id=%s", (issued[0]["commandId"],))
        cur.execute("UPDATE remote_commands SET status='resultUnknown' WHERE command_id=%s", (issued[1]["commandId"],))
        cur.execute("UPDATE remote_commands SET status='executing' WHERE command_id=%s", (issued[2]["commandId"],))
    result = rollout.change(mysql_store, batch, "retry", "verified", "operator")
    assert result["retriedTargets"] == 2 and result["status"] == "paused"
    snapshot = rollout.details(mysql_store, batch, 0, 10)
    assert snapshot["counts"] == {"pending": 2, "resultUnknown": 1, "executing": 1}
    unknown = rollout.details(mysql_store, batch, 0, 10, "resultUnknown")
    assert unknown["filteredTargets"] == 1 and unknown["targets"][0]["commandId"] == issued[1]["commandId"]
    assert not rollout.dispatch_one(mysql_store)
    assert mysql_store.cancel(active["commandId"], "operator")
    audit = mysql_store.audits(None, 0, 100)
    assert {"ROLLOUT_CREATED", "ROLLOUT_RESUME", "ROLLOUT_PAUSE", "ROLLOUT_RETRY"} <= {item["action"] for item in audit}


def test_batch_rejects_duplicate_or_unknown_snapshot(mysql_store):
    ids = devices(mysql_store, 1)
    with pytest.raises(ApiProblem, match="ROLLOUT_INVALID"):
        rollout.create(mysql_store, request(ids + ids), "operator")
    with pytest.raises(ApiProblem, match="ROLLOUT_DEVICE_NOT_FOUND"):
        rollout.create(mysql_store, request(ids + [str(uuid4())]), "operator")
    assert rollout.list_batches(mysql_store, 0, 10)["batches"] == []


@pytest.mark.parametrize('rate', [20, 40])
def test_expired_delivered_and_executing_block_batch_until_review(mysql_store, rate):
    ids = devices(mysql_store, 2)
    old = [mysql_store.create_command(device, CreateRemoteCommandRequest(
        type='disableProxy', reason='existing', expiresInMinutes=60), 'operator') for device in ids]
    for device in ids:
        assert mysql_store.lease(device)['status'] == 'delivered'
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE remote_commands SET status='executing' WHERE command_id=%s", (old[1]['commandId'],))
        cur.execute('UPDATE remote_commands SET expires_at_utc=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE command_id IN (%s,%s)',
                    (old[0]['commandId'], old[1]['commandId']))
    mysql_store.cfg.ROLLOUT_MAX_RATE = rate
    body = request(ids); body.maxPerSecond = rate
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    def finish_dispatch():
        for _ in range(4):
            with mysql_store.transaction() as cur:
                cur.execute('UPDATE rollout_batches SET next_dispatch_at_utc=UTC_TIMESTAMP(6) WHERE batch_id=%s', (batch,))
            assert rollout.dispatch_one(mysql_store)
            if rollout.details(mysql_store, batch, 0, 10)['status'] == 'dispatchComplete': return
        pytest.fail('batch did not complete dispatch')
    finish_dispatch()
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result['counts'] == {'dispatchFailed': 2}
    assert all(target['errorCode'] == 'DEVICE_COMMAND_ALREADY_ACTIVE' for target in result['targets'])
    assert all(len(mysql_store.commands(device)) == 1 and mysql_store.lease(device) is None for device in ids)
    assert mysql_store.resolve_unknown(old[0]['commandId'], 'operator', 'manually verified')
    assert rollout.change(mysql_store, batch, 'retry', 'retry after review', 'operator')['retriedTargets'] == 2
    rollout.change(mysql_store, batch, 'resume', 'continue', 'operator')
    finish_dispatch()
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result['counts'] == {'pendingCommand': 1, 'dispatchFailed': 1}
    assert len(mysql_store.commands(ids[0])) == 2 and len(mysql_store.commands(ids[1])) == 1
    assert mysql_store.commands(ids[1])[0]['status'] == 'executing'


def test_batch_detail_counts_and_page_share_snapshot(mysql_store, monkeypatch):
    from contextlib import contextmanager
    ids = devices(mysql_store, 1)
    batch = rollout.create(mysql_store, request(ids), 'operator')['batchId']
    original = mysql_store.transaction
    statements, changed = [], False

    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            nonlocal changed
            statements.append(sql)
            result = self.cur.execute(sql, args)
            if not changed and 'GROUP BY state' in sql:
                changed = True
                with original() as writer:
                    writer.execute("UPDATE rollout_targets SET status='dispatchFailed',error_code='TEST' WHERE batch_id=%s", (batch,))
            return result

    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)

    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    result = rollout.details(mysql_store, batch, 0, 10, 'pending')
    assert changed and result['counts'] == {'pending': 1}
    assert result['filteredTargets'] == 1 and result['targets'][0]['state'] == 'pending'
    assert not any(sql.startswith('SELECT COUNT(*) AS count FROM rollout_targets') for sql in statements)
    newer = rollout.details(mysql_store, batch, 0, 10, 'dispatchFailed')
    assert newer['filteredTargets'] == 1 and newer['targets'][0]['state'] == 'dispatchFailed'


def test_target_cursor_pages_match_snapshot_and_validate_input(mysql_store):
    from app import create_app
    ids = devices(mysql_store, 5)
    batch = rollout.create(mysql_store, request(ids), 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    assert rollout.dispatch_one(mysql_store)
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    headers = {'Authorization': 'Bearer ' + mysql_store.cfg.ADMIN_TOKEN}
    path = f'/admin/v1/rollouts/{batch}/targets'
    first = client.get(path + '?take=2', headers=headers)
    assert first.status_code == 200 and len(first.json['targets']) == 2
    second = client.get(path + '?take=2&after=' + first.json['nextAfter'], headers=headers)
    third = client.get(path + '?take=2&after=' + second.json['nextAfter'], headers=headers)
    rows = first.json['targets'] + second.json['targets'] + third.json['targets']
    assert [row['deviceId'] for row in rows] == sorted(ids)
    assert third.json['nextAfter'] is None
    original = rollout.details(mysql_store, batch, 0, 10)['targets']
    assert [(r['deviceId'], r['commandId'], r['state']) for r in rows] == [
        (r['deviceId'], r['commandId'], r['state']) for r in original]
    assert client.get(path + '?take=501', headers=headers).status_code == 400
    assert client.get(path + '?after=not-a-uuid', headers=headers).status_code == 400


def test_schema_rollback_only_before_any_batch_data(mysql_store):
    from controlserver.database import SCHEMA_3_CHECKSUM
    assert mysql_store.revert_unused_rollout_schema() == "reverted_to_schema_3"
    with mysql_store.transaction() as cur:
        cur.execute("SELECT version,checksum FROM schema_migrations")
        assert cur.fetchall() == [{"version": 3, "checksum": SCHEMA_3_CHECKSUM}]
    assert mysql_store.migrate() == "migrated"
    rollout.create(mysql_store, request(devices(mysql_store, 1)), "operator")
    with pytest.raises(RuntimeError, match="rollout data exists"):
        mysql_store.revert_unused_rollout_schema()
    mysql_store.check_schema()


def test_dispatch_rolls_back_target_and_command_together(mysql_store, monkeypatch):
    ids = devices(mysql_store, 1)
    batch = rollout.create(mysql_store, request(ids), "operator")["batchId"]
    rollout.change(mysql_store, batch, "resume", "test", "operator")
    original = mysql_store._audit
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic failure before commit")
    monkeypatch.setattr(mysql_store, "_audit", fail)
    with pytest.raises(RuntimeError, match="before commit"):
        rollout.dispatch_one(mysql_store)
    assert rollout.details(mysql_store, batch, 0, 10)["counts"] == {"pending": 1}
    assert mysql_store.commands(ids[0]) == []
    monkeypatch.setattr(mysql_store, "_audit", original)
    assert rollout.dispatch_one(mysql_store)
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result["counts"] == {"pendingCommand": 1}
    assert result["targets"][0]["attempts"] == 1


def test_batch_creation_rolls_back_batched_targets_if_audit_fails(mysql_store, monkeypatch):
    ids = devices(mysql_store, 3)
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic audit failure')
    monkeypatch.setattr(mysql_store, '_audit', fail)
    with pytest.raises(RuntimeError, match='synthetic audit failure'):
        rollout.create(mysql_store, request(ids), 'operator')
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS n FROM rollout_batches')
        assert cur.fetchone()['n'] == 0
        cur.execute('SELECT COUNT(*) AS n FROM rollout_targets')
        assert cur.fetchone()['n'] == 0


def test_concurrent_dispatch_preserves_rate_and_exactly_once(mysql_store):
    ids = devices(mysql_store, 10)
    batch = rollout.create(mysql_store, request(ids), "operator")["batchId"]
    rollout.change(mysql_store, batch, "resume", "test", "operator")
    def worker():
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rollout.dispatch_one(mysql_store)
            time.sleep(0.01)
            if rollout.details(mysql_store, batch, 0, 1)["status"] == "dispatchComplete":
                return
        raise AssertionError("Batch did not finish dispatching")
    with ThreadPoolExecutor(max_workers=3) as executor:
        list(executor.map(lambda _: worker(), range(3)))
    result = rollout.details(mysql_store, batch, 0, 20)
    assert result["counts"] == {"pendingCommand": 10}
    assert len({item["commandId"] for item in result["targets"]}) == 10
    assert all(item["attempts"] == 1 for item in result["targets"])
    with mysql_store.transaction() as cur:
        cur.execute("SELECT created_at_utc FROM remote_commands ORDER BY created_at_utc")
        times = [row["created_at_utc"] for row in cur.fetchall()]
    assert all((b-a).total_seconds() >= 0.045 for a, b in zip(times, times[1:]))


def test_slow_dispatch_does_not_consume_the_next_rate_interval(mysql_store, monkeypatch):
    ids = devices(mysql_store, 2)
    body = request(ids)
    body.maxPerSecond = 1
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    original = mysql_store._audit
    def slow_audit(cur, actor, action, *args, **kwargs):
        if action == 'REMOTE_COMMAND_CREATED':
            time.sleep(1.15)
        return original(cur, actor, action, *args, **kwargs)
    monkeypatch.setattr(mysql_store, '_audit', slow_audit)
    assert rollout.dispatch_one(mysql_store)
    assert not rollout.dispatch_one(mysql_store)
    assert rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pendingCommand': 1, 'pending': 1}


def test_pause_resume_preserves_next_dispatch_time(mysql_store):
    body = request(devices(mysql_store, 2))
    body.maxPerSecond = 1
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    assert rollout.dispatch_one(mysql_store)
    rollout.change(mysql_store, batch, 'pause', 'test', 'operator')
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    assert not rollout.dispatch_one(mysql_store)
    assert rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pendingCommand': 1, 'pending': 1}


def test_schema_three_migration_preserves_existing_device_and_policy(mysql_store):
    from controlserver.database import SCHEMA_3_CHECKSUM
    ids = devices(mysql_store, 1)
    policy = mysql_store.policy()
    with mysql_store.transaction() as cur:
        cur.execute("DROP TABLE rollout_targets")
        cur.execute("DROP TABLE rollout_batches")
        cur.execute("UPDATE schema_migrations SET version=3,checksum=%s", (SCHEMA_3_CHECKSUM,))
    assert mysql_store.migrate() == "migrated"
    assert mysql_store.migrate() == "already_migrated"
    assert mysql_store.policy() == policy
    assert mysql_store.details(ids[0])["device"]["deviceId"] == ids[0]
    assert rollout.list_batches(mysql_store, 0, 10)["total"] == 0


def test_high_rate_requires_explicit_server_limit_and_suspends_after_reduction(mysql_store):
    ids = devices(mysql_store, 3)
    body = request(ids); body.maxPerSecond = 40
    with pytest.raises(ApiProblem, match='ROLLOUT_RATE_EXCEEDS_LIMIT'):
        rollout.create(mysql_store, body, 'operator')
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    mysql_store.cfg.ROLLOUT_MAX_RATE = 20
    assert rollout.dispatch_one(mysql_store)
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result['status'] == 'paused' and result['counts'] == {'pending': 3}
    with pytest.raises(ApiProblem, match='ROLLOUT_RATE_EXCEEDS_LIMIT'):
        rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM admin_audit_log WHERE action='ROLLOUT_RATE_SUSPENDED'")
        assert cur.fetchone()['n'] == 1


def test_high_rate_chunk_preserves_failures_expiry_and_per_device_audit(mysql_store, monkeypatch):
    ids = devices(mysql_store, 6)
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    body = request(ids); body.maxPerSecond = 40
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    # One active command must block a new one; another target disappears.
    mysql_store.create_command(ids[0], CreateRemoteCommandRequest(type='disableProxy', reason='existing', expiresInMinutes=60), 'operator')
    expired = mysql_store.create_command(ids[2], CreateRemoteCommandRequest(type='disableProxy', reason='expired', expiresInMinutes=60), 'operator')
    orphan = mysql_store.create_command(ids[1], CreateRemoteCommandRequest(type='disableProxy', reason='orphan', expiresInMinutes=60), 'operator')
    with mysql_store.transaction() as cur:
        cur.execute('DELETE FROM device_heartbeats WHERE device_id=%s', (ids[1],))
        cur.execute('UPDATE remote_commands SET expires_at_utc=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE command_id IN (%s,%s)', (expired['commandId'], orphan['commandId']))
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    from contextlib import contextmanager
    from pymysql.cursors import RE_INSERT_VALUES
    original = mysql_store.transaction
    commands_sql = []
    class CursorProxy:
        def __init__(self, cursor): self.cursor = cursor
        def __getattr__(self, name): return getattr(self.cursor, name)
        def executemany(self, sql, values):
            if 'INSERT INTO remote_commands' in sql: commands_sql.append(sql)
            return self.cursor.executemany(sql, values)
    @contextmanager
    def wrapped():
        with original() as cur: yield CursorProxy(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    for _ in range(5):
        with mysql_store.transaction() as cur:
            cur.execute('UPDATE rollout_batches SET next_dispatch_at_utc=UTC_TIMESTAMP(6) WHERE batch_id=%s', (batch,))
        assert rollout.dispatch_one(mysql_store)
        if rollout.details(mysql_store, batch, 0, 10)['status'] == 'dispatchComplete': break
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result['status'] == 'dispatchComplete'
    assert commands_sql and all(RE_INSERT_VALUES.match(sql) for sql in commands_sql)
    assert result['counts'] == {'dispatchFailed': 2, 'pendingCommand': 4}
    assert all(t['attempts'] == 1 for t in result['targets'])
    assert {t['errorCode'] for t in result['targets'] if t['state']=='dispatchFailed'} == {'DEVICE_NOT_FOUND','DEVICE_COMMAND_ALREADY_ACTIVE'}
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM admin_audit_log WHERE action='REMOTE_COMMAND_CREATED' AND summary LIKE %s", ('rollout='+batch+';%',))
        assert cur.fetchone()['n'] == 4

    assert {c['status'] for c in mysql_store.commands(ids[2])} == {'expired', 'pending'}
    assert mysql_store.commands(ids[1])[0]['status'] == 'pending'  # Missing device: preserve the original lease semantics.


def test_high_rate_chunk_rolls_back_commands_targets_and_audits(mysql_store, monkeypatch):
    ids = devices(mysql_store, 4)
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    body = request(ids); body.maxPerSecond = 40
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    original = rollout._audit_batch
    def fail(*args):
        original(*args)
        raise RuntimeError('synthetic batch failure')
    monkeypatch.setattr(rollout, '_audit_batch', fail)
    with pytest.raises(RuntimeError, match='synthetic batch failure'):
        rollout.dispatch_one(mysql_store)
    assert rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pending': 4}
    assert all(mysql_store.commands(device) == [] for device in ids)
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM admin_audit_log WHERE action='REMOTE_COMMAND_CREATED' AND summary LIKE %s", ('rollout='+batch+';%',))
        assert cur.fetchone()['n'] == 0
    monkeypatch.setattr(rollout, '_audit_batch', original)
    assert rollout.dispatch_one(mysql_store)
    assert rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pendingCommand': 2, 'pending': 2}


def test_overlapping_high_rate_batches_issue_at_most_one_active_command_per_device(mysql_store):
    ids = devices(mysql_store, 10)
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    body = request(ids); body.maxPerSecond = 40
    batches = [rollout.create(mysql_store, body, 'operator')['batchId'] for _ in range(2)]
    for batch in batches: rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    def worker():
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            rollout.dispatch_one(mysql_store)
            if all(rollout.details(mysql_store, b, 0, 1)['status'] == 'dispatchComplete' for b in batches): return
            time.sleep(.01)
        raise AssertionError('batches did not finish')
    with ThreadPoolExecutor(max_workers=2) as pool: list(pool.map(lambda _: worker(), range(2)))
    for device in ids: assert len(mysql_store.commands(device)) == 1
    outcomes = [rollout.details(mysql_store, b, 0, 20) for b in batches]
    assert sum(x['counts'].get('pendingCommand',0) for x in outcomes) == 10
    assert sum(x['counts'].get('dispatchFailed',0) for x in outcomes) == 10
    assert all(t['attempts'] == 1 for x in outcomes for t in x['targets'])


def test_pause_waits_for_current_high_rate_chunk_and_stops_later_chunks(mysql_store, monkeypatch):
    from threading import Event
    ids = devices(mysql_store, 6)
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    body = request(ids); body.maxPerSecond = 40
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    entered, release = Event(), Event()
    original = rollout._audit_batch
    def hold(*args):
        original(*args)
        entered.set()
        if not release.wait(5): raise RuntimeError('synthetic hold timeout')
    monkeypatch.setattr(rollout, '_audit_batch', hold)
    with ThreadPoolExecutor(max_workers=2) as pool:
        issued = pool.submit(rollout.dispatch_one, mysql_store)
        try:
            assert entered.wait(5)
            paused = pool.submit(rollout.change, mysql_store, batch, 'pause', 'test', 'operator')
            time.sleep(.1)
            assert not paused.done()
        finally:
            release.set()
        assert issued.result(timeout=5)
        assert paused.result(timeout=5)['status'] == 'paused'
    assert not rollout.dispatch_one(mysql_store)
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result['counts'] == {'pendingCommand': 2, 'pending': 4}


def test_rollout_rate_configuration_defaults_to_twenty_and_is_bounded(config):
    assert config.ROLLOUT_MAX_RATE == 20
    for value in (0, -1, 5001):
        config.ROLLOUT_MAX_RATE = value
        with pytest.raises(ValueError, match='rollout rate limit'):
            config.validate()
    config.ROLLOUT_MAX_RATE = 5000
    assert config.validate().ROLLOUT_MAX_RATE == 5000



def test_highest_rate_limits_chunk_to_250_and_pause_stops_next_chunk(mysql_store):
    from controlserver.security import utcnow
    from controlserver.database import dbtime
    ids = [str(uuid4()) for _ in range(252)]
    now = dbtime(utcnow())
    body_json = json.dumps({'schemaVersion': 1, 'users': [], 'agents': []})
    with mysql_store.transaction() as cur:
        cur.executemany('INSERT INTO device_heartbeats VALUES (%s,%s,%s,%s,%s,%s,%s)',
                        [(device, now, 'synthetic', 'synthetic', 0, 'listening', body_json) for device in ids])
    mysql_store.cfg.ROLLOUT_MAX_RATE = 5000
    body = request(ids); body.maxPerSecond = 5000
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    assert rollout.dispatch_one(mysql_store)
    result = rollout.details(mysql_store, batch, 0, 10)
    assert result['counts'] == {'pendingCommand': 250, 'pending': 2}
    rollout.change(mysql_store, batch, 'pause', 'test', 'operator')
    assert not rollout.dispatch_one(mysql_store)


def test_high_rate_slow_chunk_does_not_accumulate_dispatch_credit(mysql_store, monkeypatch):
    ids = devices(mysql_store, 4)
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    body = request(ids); body.maxPerSecond = 40
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    original = rollout._audit_batch
    def slow(*args):
        original(*args)
        time.sleep(.2)
    monkeypatch.setattr(rollout, '_audit_batch', slow)
    assert rollout.dispatch_one(mysql_store)
    assert not rollout.dispatch_one(mysql_store)
    assert rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pendingCommand': 2, 'pending': 2}


def test_high_rate_requires_complete_visible_pending_index(mysql_store):
    mysql_store.cfg.ROLLOUT_MAX_RATE = 40
    mysql_store.check_schema()
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE rollout_targets ALTER INDEX ix_rollout_pending INVISIBLE')
    with pytest.raises(RuntimeError, match='complete visible pending index'):
        mysql_store.check_schema()
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE rollout_targets ALTER INDEX ix_rollout_pending VISIBLE')
        cur.execute('ALTER TABLE rollout_targets DROP INDEX ix_rollout_pending')
    with pytest.raises(RuntimeError, match='complete visible pending index'):
        mysql_store.check_schema()
    mysql_store.cfg.ROLLOUT_MAX_RATE = 20
    mysql_store.check_schema()  # Legacy low-rate behavior remains usable.


def test_high_rate_chunk_and_heartbeats_serialize_without_losing_updates(mysql_store, monkeypatch):
    from threading import Event
    from controlserver.database import dbtime
    from controlserver.security import utcnow
    fixture = json.loads((Path(__file__).parent / 'fixtures' / 'dotnet-v0.1.19.json').read_text())['heartbeat']
    ids = sorted(str(uuid4()) for _ in range(80))
    body_json = json.dumps({'schemaVersion': 1, 'users': [], 'agents': []})
    now = dbtime(utcnow())
    with mysql_store.transaction() as cur:
        cur.executemany('INSERT INTO device_heartbeats VALUES (%s,%s,%s,%s,%s,%s,%s)',
                        [(device, now, 'synthetic', 'synthetic', 0, 'listening', body_json) for device in ids])
    mysql_store.cfg.ROLLOUT_MAX_RATE = 5000
    body = request(ids); body.maxPerSecond = 5000
    batch = rollout.create(mysql_store, body, 'operator')['batchId']
    rollout.change(mysql_store, batch, 'resume', 'test', 'operator')
    locked, release = Event(), Event()
    original = rollout._audit_batch
    def hold(*args):
        original(*args)
        locked.set()
        if not release.wait(10): raise RuntimeError('synthetic hold timeout')
    monkeypatch.setattr(rollout, '_audit_batch', hold)
    def report(device):
        item = copy.deepcopy(fixture)
        item['device']['deviceId'] = device
        item['device']['hostname'] = 'updated-synthetic'
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(item), 60, '127.0.0.1')
    with ThreadPoolExecutor(max_workers=9) as pool:
        dispatch = pool.submit(rollout.dispatch_one, mysql_store)
        try:
            assert locked.wait(8)
            reports = [pool.submit(report, device) for device in ids[:8]]
            time.sleep(.1)
            assert any(not future.done() for future in reports)
        finally:
            release.set()
        assert dispatch.result(timeout=10)
        for future in reports: future.result(timeout=10)
    result = rollout.details(mysql_store, batch, 0, 100)
    assert result['counts'] == {'pendingCommand': 80}
    assert all(mysql_store.details(device)['device']['hostname'] == 'updated-synthetic' for device in ids[:8])
    assert all(len(mysql_store.commands(device)) == 1 for device in ids)
