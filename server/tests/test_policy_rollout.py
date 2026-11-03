import copy
import json
from pathlib import Path
from uuid import uuid4
import pytest
from concurrent.futures import ThreadPoolExecutor
from controlserver import policy_rollout
from controlserver.models import (CreatePolicyRolloutRequest, ExtendPolicyRolloutRequest, DeviceEnrollmentRequest,
    HeartbeatV2Request, PolicyUpdateRequest, DevicePolicyUpdateRequest)
from controlserver.validation import ApiProblem

FIXTURE = json.loads((Path(__file__).parent / 'fixtures/dotnet-v0.1.19.json').read_text(encoding='utf-8'))['heartbeat']


def devices(store, count):
    result = []
    for i in range(count):
        ident = uuid4()
        store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=ident, hostname=f'fixture-{i}', serviceVersion='test'))
        body = copy.deepcopy(FIXTURE)
        body['device'].update(deviceId=str(ident), hostname=f'fixture-{i}')
        store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
        result.append(str(ident))
    store.ensure_scale_indexes()
    return sorted(result)


def request(store, ids):
    base = store.policy()
    candidate = PolicyUpdateRequest(expectedVersion=base['policyVersion'],
        **{k:v for k,v in base.items() if k in PolicyUpdateRequest.model_fields})
    candidate.gatewayOrigin = 'https://new-gateway.example'
    return CreatePolicyRolloutRequest(policy=candidate, reason='synthetic', maxPerSecond=20,
                                      deviceIds=ids, confirmCount=len(ids))


def due(store, batch):
    with store.transaction() as cur:
        cur.execute('UPDATE policy_rollout_batches SET next_dispatch_at_utc=UTC_TIMESTAMP(6) WHERE batch_id=%s', (batch,))


def test_staged_versions_pause_extend_promote_and_overrides(mysql_store):
    ids = devices(mysql_store, 3)
    base = mysql_store.policy()
    override = DevicePolicyUpdateRequest(expectedVersion=base['policyVersion'], overrides={'allowlistedBaseUrls': []})
    before = mysql_store.device_policy(ids[0], override, 'test')['effectivePolicy']
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids[:2]), 'admin')['batchId']
    assert not policy_rollout.dispatch_one(mysql_store)
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_ACTIVE'):
        mysql_store.update_policy(request(mysql_store, ids).policy)
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_ACTIVE'):
        mysql_store.device_policy(ids[1], DevicePolicyUpdateRequest(expectedVersion=base['policyVersion'], overrides={}), 'admin')
    # Other clients can negotiate and allocate versions while the batch is paused.
    negotiated = mysql_store.policy(ids[2], schema_version=2)
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    first = mysql_store.policy(ids[0])
    assert first['gatewayOrigin'] == 'https://new-gateway.example' and first['allowlistedBaseUrls'] == []
    assert first['policyVersion'] > max(before['policyVersion'], negotiated['policyVersion'])
    schema2 = mysql_store.policy(ids[0], schema_version=2)
    assert schema2['gatewayOrigin'] == first['gatewayOrigin'] and schema2['policyVersion'] > first['policyVersion']
    assert policy_rollout.details(mysql_store, batch, 0, 10)['targets'][0]['assignedVersion'] == schema2['policyVersion']
    policy_rollout.change(mysql_store, batch, 'pause', 'check', 'admin')
    assert not policy_rollout.dispatch_one(mysql_store)
    assert mysql_store.policy(ids[1])['gatewayOrigin'] == base['gatewayOrigin']
    policy_rollout.change(mysql_store, batch, 'resume', 'continue', 'admin')
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'assigned': 2}
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INCOMPLETE'):
        policy_rollout.change(mysql_store, batch, 'promote', 'all', 'admin')
    extra = ExtendPolicyRolloutRequest(reason='expand', deviceIds=ids[2:], confirmCount=1)
    policy_rollout.extend(mysql_store, batch, extra, 'admin')
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    last = mysql_store.policy(ids[2])['policyVersion']
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    policy_rollout.change(mysql_store, batch, 'promote', 'all assigned', 'admin')
    promoted = mysql_store.policy()
    assert promoted['policyVersion'] > last and promoted['gatewayOrigin'] == 'https://new-gateway.example'
    assert mysql_store.policy(ids[0])['allowlistedBaseUrls'] == []
    assert mysql_store.policy(ids[0])['policyVersion'] == promoted['policyVersion']
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert detail['appliedTargets'] is None and all(t['applied'] is None for t in detail['targets'])


def test_abort_advances_version_and_restores_original_policy(mysql_store):
    ids = devices(mysql_store, 2)
    base = mysql_store.policy()
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    staged = mysql_store.policy(ids[0])
    policy_rollout.change(mysql_store, batch, 'abort', 'revert', 'admin')
    after = mysql_store.policy(ids[0])
    assert after['policyVersion'] > staged['policyVersion']
    assert after['gatewayOrigin'] == base['gatewayOrigin']
    assert mysql_store.policy(ids[1])['gatewayOrigin'] == base['gatewayOrigin']
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert detail['status'] == 'aborted' and detail['appliedTargets'] is None


def test_historical_batch_does_not_scan_for_live_applied_count(mysql_store, monkeypatch):
    from contextlib import contextmanager
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    original, statements = mysql_store.transaction, []

    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            statements.append(sql)
            return self.cur.execute(sql, args)

    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)

    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['appliedTargets'] == 0
    assert any('AS applied' in sql for sql in statements)
    policy_rollout.change(mysql_store, batch, 'abort', 'test', 'operator')
    statements.clear()
    result = policy_rollout.details(mysql_store, batch, 0, 10)
    assert result['appliedTargets'] is None
    assert all(target['applicationState'] == 'historical' for target in result['targets'])
    assert not any('AS applied' in sql for sql in statements)


def test_policy_batch_detail_uses_one_snapshot_during_update(mysql_store, monkeypatch):
    from contextlib import contextmanager
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    original, changed = mysql_store.transaction, False

    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            nonlocal changed
            result = self.cur.execute(sql, args)
            if not changed and sql.startswith('SELECT status,COUNT(*) AS count FROM policy_rollout_targets'):
                changed = True
                with original() as writer:
                    writer.execute("UPDATE policy_rollout_targets SET status='dispatchFailed',error_code='TEST' WHERE batch_id=%s", (batch,))
            return result

    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)

    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    result = policy_rollout.details(mysql_store, batch, 0, 10, 'pending')
    assert changed and result['counts'] == {'pending': 1} and result['filteredTargets'] == 1
    assert result['targets'][0]['state'] == 'pending'
    result = policy_rollout.details(mysql_store, batch, 0, 10, 'dispatchFailed')
    assert result['filteredTargets'] == 1 and result['targets'][0]['state'] == 'dispatchFailed'


def test_revoked_target_failure_retry_and_no_false_applied(mysql_store):
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET revoked=1 WHERE device_id=%s', (ids[0],))
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert detail['counts'] == {'dispatchFailed': 1} and not detail['targets'][0]['applied']
    assert policy_rollout.details(mysql_store, batch, 0, 10, 'dispatchFailed')['filteredTargets'] == 1
    assert policy_rollout.details(mysql_store, batch, 0, 10, 'pending')['filteredTargets'] == 0
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_QUERY_INVALID'):
        policy_rollout.details(mysql_store, batch, 0, 10, 'invalid')
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INCOMPLETE'):
        policy_rollout.change(mysql_store, batch, 'promote', 'go', 'admin')
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET revoked=0 WHERE device_id=%s', (ids[0],))
    policy_rollout.change(mysql_store, batch, 'retry', 'recovered', 'admin')
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    assert not policy_rollout.details(mysql_store, batch, 0, 10)['targets'][0]['applied']


def test_concurrent_dispatchers_preserve_unique_versions(mysql_store):
    ids = devices(mysql_store, 6)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    for _ in ids:
        due(mysql_store, batch)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: policy_rollout.dispatch_one(mysql_store), range(2)))
        assert sum(results) == 1
    versions = [v['assignedVersion'] for v in policy_rollout.details(mysql_store, batch, 0, 20)['targets']]
    assert len(set(versions)) == len(ids)
    assert min(versions) > mysql_store.policy()['policyVersion']


def test_slow_policy_dispatch_does_not_consume_next_rate_interval(mysql_store, monkeypatch):
    import time
    ids = devices(mysql_store, 2)
    body = request(mysql_store, ids)
    body.maxPerSecond = 1
    batch = policy_rollout.create(mysql_store, body, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    original = mysql_store._validate_effective_policy
    def slow_validation(value):
        time.sleep(1.15)
        return original(value)
    monkeypatch.setattr(mysql_store, '_validate_effective_policy', slow_validation)
    assert policy_rollout.dispatch_one(mysql_store)
    assert not policy_rollout.dispatch_one(mysql_store)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'assigned': 1, 'pending': 1}


def test_policy_pause_resume_preserves_next_dispatch_time(mysql_store):
    body = request(mysql_store, devices(mysql_store, 2))
    body.maxPerSecond = 1
    batch = policy_rollout.create(mysql_store, body, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    policy_rollout.change(mysql_store, batch, 'pause', 'test', 'admin')
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert not policy_rollout.dispatch_one(mysql_store)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'assigned': 1, 'pending': 1}


def test_dispatch_failure_rolls_back_target_and_device_policy(mysql_store, monkeypatch):
    ids = devices(mysql_store, 1)
    base = mysql_store.policy(ids[0])
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    original = mysql_store._validate_effective_policy
    def fail(_):
        raise RuntimeError('synthetic dispatch interruption')
    monkeypatch.setattr(mysql_store, '_validate_effective_policy', fail)
    with pytest.raises(RuntimeError, match='synthetic dispatch interruption'):
        policy_rollout.dispatch_one(mysql_store)
    assert mysql_store.policy(ids[0]) == base
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pending': 1}
    monkeypatch.setattr(mysql_store, '_validate_effective_policy', original)
    assert policy_rollout.dispatch_one(mysql_store)


def test_policy_batch_creation_rolls_back_batched_targets_if_audit_fails(mysql_store, monkeypatch):
    ids = devices(mysql_store, 3)
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic audit failure')
    monkeypatch.setattr(mysql_store, '_audit', fail)
    with pytest.raises(RuntimeError, match='synthetic audit failure'):
        policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS n FROM policy_rollout_batches')
        assert cur.fetchone()['n'] == 0
        cur.execute('SELECT COUNT(*) AS n FROM policy_rollout_targets')
        assert cur.fetchone()['n'] == 0


def test_applied_requires_version_schema_and_success(mysql_store):
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    version = policy_rollout.details(mysql_store, batch, 0, 10)['targets'][0]['assignedVersion']
    body = copy.deepcopy(FIXTURE)
    body['device']['deviceId'] = ids[0]
    body['policy']['appliedVersion'] = version
    body['policy']['appliedSchemaVersion'] = 2
    body['runtime']['lastReconcileResult'] = 'completed'
    body['runtime']['lastReconcileErrorCode'] = None
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert detail['targets'][0]['applied'] and detail['appliedTargets'] == 1
    assert policy_rollout.details(mysql_store, batch, 0, 10, 'unsupported')['filteredTargets'] == 0
    body['runtime']['lastReconcileResult'] = 'failed'
    body['runtime']['lastReconcileErrorCode'] = 'PROFILE_DISCOVERY_FAILED'
    body['runtime']['supportedPolicySchemaVersion'] = 2
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS count FROM agent_endpoint_assets WHERE device_id=%s', (ids[0],))
        assets_before = cur.fetchone()['count']
    assert assets_before > 0
    body['inventoryUnchanged'] = True
    body['endpoints'] = []
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert not detail['targets'][0]['applied'] and detail['appliedTargets'] == 0
    assert detail['targets'][0]['applicationState'] == 'applyFailed'
    assert detail['targets'][0]['errorCode'] == 'PROFILE_DISCOVERY_FAILED'
    assert policy_rollout.details(mysql_store, batch, 0, 10, 'applyFailed')['filteredTargets'] == 1
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS count FROM agent_endpoint_assets WHERE device_id=%s', (ids[0],))
        assert cur.fetchone()['count'] == assets_before
    body['runtime'].update(lastReconcileResult='completed', lastReconcileErrorCode=None)
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    assert policy_rollout.details(mysql_store, batch, 0, 10)['targets'][0]['applicationState'] == 'applied'


def test_v1_device_blocks_promotion_and_is_not_a_valid_target(mysql_store):
    from controlserver.models import HeartbeatRequest
    ids = devices(mysql_store, 1)
    legacy = copy.deepcopy(FIXTURE)
    legacy['device']['deviceId'] = str(uuid4())
    legacy['schemaVersion'] = 1
    for field in ('runtime', 'endpoints', 'activity'):
        legacy.pop(field)
    mysql_store.heartbeat(HeartbeatRequest.model_validate(legacy), 60, '127.0.0.1')
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_TARGET_INVALID'):
        policy_rollout.create(mysql_store, request(mysql_store, [legacy['device']['deviceId']]), 'admin')
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INCOMPLETE'):
        policy_rollout.change(mysql_store, batch, 'promote', 'verify', 'admin')


def test_schema4_migration_and_nonempty_rollback_guard(mysql_store):
    from controlserver.database import SCHEMA_4_CHECKSUM
    ids = devices(mysql_store, 1)
    with mysql_store.transaction() as cur:
        cur.execute('DROP TABLE policy_rollout_targets')
        cur.execute('DROP TABLE policy_rollout_batches')
        cur.execute('UPDATE schema_migrations SET version=4,checksum=%s', (SCHEMA_4_CHECKSUM,))
    assert mysql_store.migrate() == 'migrated'
    assert mysql_store.details(ids[0]) is not None
    policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')
    with pytest.raises(RuntimeError, match='rollout data exists'):
        mysql_store.revert_unused_rollout_schema()


def test_schema5_to_4_rollback_preserves_command_batches_and_rejects_policy_history(mysql_store):
    from controlserver import rollout
    from controlserver.models import CreateRolloutRequest
    from controlserver.database import SCHEMA_4_CHECKSUM
    ids = devices(mysql_store, 1)
    request_value = CreateRolloutRequest(type='disableProxy', reason='test', expiresInMinutes=60,
                                         maxPerSecond=2, deviceIds=ids, confirmCount=1)
    command_batch = rollout.create(mysql_store, request_value, 'admin')['batchId']
    assert mysql_store.revert_unused_policy_rollout_schema() == 'reverted_to_schema_4'
    with mysql_store.transaction() as cur:
        cur.execute('SELECT version,checksum FROM schema_migrations')
        assert cur.fetchall() == [{'version':4, 'checksum':SCHEMA_4_CHECKSUM}]
    assert mysql_store.migrate() == 'migrated'
    assert rollout.details(mysql_store, command_batch, 0, 10)['totalTargets'] == 1
    policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')
    with pytest.raises(RuntimeError, match='policy rollout data exists'):
        mysql_store.revert_unused_policy_rollout_schema()


def test_new_enrollment_without_heartbeat_blocks_promotion(mysql_store):
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    due(mysql_store, batch); assert policy_rollout.dispatch_one(mysql_store)
    mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=uuid4(), hostname='no-heartbeat', serviceVersion='test'))
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INCOMPLETE'):
        policy_rollout.change(mysql_store, batch, 'promote', 'verify', 'admin')


def test_missing_version_index_blocks_rollout(mysql_store):
    ids = devices(mysql_store, 1)
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE device_policy_state DROP INDEX idx_effective_policy_version')
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INDEX_REQUIRED'):
        policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')
    assert policy_rollout.list_batches(mysql_store, 0, 10)['total'] == 0


def test_invisible_version_index_blocks_rollout_and_maintenance(mysql_store):
    ids = devices(mysql_store, 1)
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE device_policy_state ALTER INDEX idx_effective_policy_version INVISIBLE')
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INDEX_REQUIRED'):
        policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')
    with pytest.raises(RuntimeError, match='Conflicting policy version index'):
        mysql_store.ensure_scale_indexes()
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE device_policy_state ALTER INDEX idx_effective_policy_version VISIBLE')
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE device_policy_state ALTER INDEX idx_effective_policy_version INVISIBLE')
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_INDEX_REQUIRED'):
        policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE device_policy_state ALTER INDEX idx_effective_policy_version VISIBLE')
    assert policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')['status'] == 'running'


def test_visible_alternate_version_index_is_accepted(mysql_store):
    ids = devices(mysql_store, 1)
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE device_policy_state ALTER INDEX idx_effective_policy_version INVISIBLE')
        cur.execute('ALTER TABLE device_policy_state ADD INDEX alternate_version_index (effective_policy_version)')
    assert policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['status'] == 'paused'


def test_high_rate_policy_chunk_preserves_versions_failures_and_abort(mysql_store):
    ids = devices(mysql_store, 8)
    base = mysql_store.policy()
    before = mysql_store.device_policy(ids[0], DevicePolicyUpdateRequest(
        expectedVersion=base['policyVersion'], overrides={'allowlistedBaseUrls': []}), 'test')['effectivePolicy']
    payload = request(mysql_store, ids).model_dump(mode='json')
    payload['maxPerSecond'] = 1000
    high = CreatePolicyRolloutRequest.model_validate(payload)
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_RATE_EXCEEDS_LIMIT'):
        policy_rollout.create(mysql_store, high, 'admin')
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    mysql_store.check_schema()
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET revoked=1 WHERE device_id=%s', (ids[1],))
        cur.execute("UPDATE device_heartbeats SET heartbeat_json=JSON_SET(heartbeat_json,'$.schemaVersion',1) WHERE device_id=%s", (ids[2],))
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    detail = policy_rollout.details(mysql_store, batch, 0, 20)
    assert detail['counts'] == {'assigned': 6, 'dispatchFailed': 2}
    versions = [item['assignedVersion'] for item in detail['targets'] if item['assignedVersion'] is not None]
    assert len(set(versions)) == 6 and min(versions) > before['policyVersion']
    errors = {item['deviceId']: item['errorCode'] for item in detail['targets'] if item['state'] == 'dispatchFailed'}
    assert errors == {ids[1]: 'DEVICE_CREDENTIAL_INACTIVE', ids[2]: 'DEVICE_PROTOCOL_UNSUPPORTED'}
    effective = mysql_store.policy(ids[0])
    assert effective['gatewayOrigin'] == 'https://new-gateway.example' and effective['allowlistedBaseUrls'] == []
    policy_rollout.change(mysql_store, batch, 'abort', 'test rollback', 'admin')
    after = mysql_store.policy(ids[0])
    assert after['policyVersion'] > max(versions) and after['gatewayOrigin'] == base['gatewayOrigin']


def test_policy_version_allocator_reads_current_watermark_after_old_snapshot(mysql_store):
    from controlserver.database import decode
    ids = devices(mysql_store, 1)
    base = mysql_store.policy()
    with mysql_store.transaction() as stale:
        stale.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        stale.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT')
        stale.execute('SELECT COUNT(*) AS n FROM device_policy_state')
        assert stale.fetchone()['n'] == 0
        new = mysql_store.device_policy(ids[0], DevicePolicyUpdateRequest(
            expectedVersion=base['policyVersion'], overrides={'allowlistedBaseUrls': []}), 'test')['effectivePolicy']
        stale.execute('SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE')
        locked_base = decode(stale.fetchone()['policy_json'])
        assert mysql_store._next_policy_version(stale, locked_base) > new['policyVersion']


def test_policy_watermark_across_reset_recovery_publication_and_abort(mysql_store):
    ids = devices(mysql_store, 2)
    initial_global = mysql_store.policy()
    initial = mysql_store.policy(ids[0], schema_version=2)
    changed = mysql_store.device_policy(ids[0], DevicePolicyUpdateRequest(
        expectedVersion=initial['policyVersion'], overrides={'allowlistedBaseUrls': []}), 'admin')['effectivePolicy']
    reset = mysql_store.device_policy(ids[0], DevicePolicyUpdateRequest(
        expectedVersion=changed['policyVersion'], overrides={}), 'admin', reset=True)['effectivePolicy']
    assert initial['policyVersion'] < changed['policyVersion'] < reset['policyVersion']
    hostname = mysql_store.details(ids[0])['device']['hostname']
    assert mysql_store.recover_device_credential(ids[0], hostname, 'synthetic', 'admin')['deviceId'] == ids[0]
    assert mysql_store.policy(ids[0])['policyVersion'] == reset['policyVersion']
    update = PolicyUpdateRequest(expectedVersion=initial_global['policyVersion'],
        **{key: value for key, value in initial_global.items() if key in PolicyUpdateRequest.model_fields})
    published = mysql_store.update_policy(update)
    assert published['policyVersion'] > reset['policyVersion']
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 40
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids).model_copy(update={'maxPerSecond': 40}), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    assigned = [row['assignedVersion'] for row in policy_rollout.details(mysql_store, batch, 0, 10)['targets']]
    assert len(set(assigned)) == 2 and min(assigned) > published['policyVersion']
    policy_rollout.change(mysql_store, batch, 'abort', 'synthetic', 'admin')
    restored = mysql_store.policy(ids[0])
    assert restored['policyVersion'] > max(assigned)


def test_high_rate_policy_chunk_rolls_back_and_suspends_on_reduced_limit(mysql_store, monkeypatch):
    from contextlib import contextmanager
    ids = devices(mysql_store, 4)
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 1000})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    original = mysql_store.transaction
    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            if sql.startswith('UPDATE policy_rollout_targets t JOIN JSON_TABLE'):
                raise RuntimeError('synthetic failure')
            return self.cur.execute(sql, args)
    @contextmanager
    def failed():
        with original() as cur: yield Cursor(cur)
    monkeypatch.setattr(mysql_store, 'transaction', failed)
    with pytest.raises(RuntimeError, match='synthetic failure'):
        policy_rollout.dispatch_one(mysql_store)
    monkeypatch.setattr(mysql_store, 'transaction', original)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pending': 4}
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS n FROM device_policy_state')
        assert cur.fetchone()['n'] == 0
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 20
    assert policy_rollout.dispatch_one(mysql_store)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['status'] == 'paused'
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_RATE_EXCEEDS_LIMIT'):
        policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert any(item['action'] == 'POLICY_ROLLOUT_RATE_SUSPENDED' for item in mysql_store.audits(None, 0, 100))


def test_high_rate_policy_requires_visible_pending_index(mysql_store):
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    with mysql_store.transaction() as cur:
        cur.execute('ALTER TABLE policy_rollout_targets ALTER INDEX ix_policy_rollout_pending INVISIBLE')
    with pytest.raises(RuntimeError, match='High-rate policy rollout requires'):
        mysql_store.check_schema()


def test_high_rate_policy_pause_waits_for_atomic_chunk(mysql_store, monkeypatch):
    from contextlib import contextmanager
    from threading import Event
    ids = devices(mysql_store, 4)
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 40
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 40})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    original, entered, release = mysql_store.transaction, Event(), Event()
    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            result = self.cur.execute(sql, args)
            if sql.startswith('UPDATE policy_rollout_targets t JOIN JSON_TABLE'):
                entered.set()
                if not release.wait(10): raise RuntimeError('test timed out')
            return result
    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    with ThreadPoolExecutor(max_workers=2) as executor:
        dispatch = executor.submit(policy_rollout.dispatch_one, mysql_store)
        assert entered.wait(10)
        pause = executor.submit(policy_rollout.change, mysql_store, batch, 'pause', 'test', 'admin')
        try:
            import time
            time.sleep(.2)
            assert not pause.done()
        finally:
            release.set()
        assert dispatch.result(timeout=10) and pause.result(timeout=10)['status'] == 'paused'
    monkeypatch.setattr(mysql_store, 'transaction', original)
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert detail['counts'] == {'assigned': 2, 'pending': 2}
    assert not policy_rollout.dispatch_one(mysql_store)


def test_high_rate_policy_uses_driver_batch_insert(mysql_store, monkeypatch):
    from contextlib import contextmanager
    from pymysql.cursors import RE_INSERT_VALUES
    ids = devices(mysql_store, 4)
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 1000})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    original, inserts = mysql_store.transaction, []
    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def executemany(self, sql, values):
            if 'INSERT INTO device_policy_state' in sql:
                inserts.append((sql, len(values)))
            return self.cur.executemany(sql, values)
    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    assert policy_rollout.dispatch_one(mysql_store)
    assert len(inserts) == 1 and inserts[0][1] == 4 and RE_INSERT_VALUES.match(inserts[0][0])


def test_high_rate_policy_validates_each_distinct_override_in_chunk(mysql_store, monkeypatch):
    ids = devices(mysql_store, 4)
    base = mysql_store.policy()
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 1000})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    with mysql_store.transaction() as cur:
        for device in ids[2:]:
            cur.execute('INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)',
                        (device, base['policyVersion'], base['policyVersion'],
                         json.dumps({'gatewayOrigin': 'https://invalid.example'}), json.dumps(base)))
    original, validations = mysql_store._validate_effective_policy, []
    error_code = "SYNTHETIC_'\\错误"
    def validate(value):
        validations.append(value['gatewayOrigin'])
        if value['gatewayOrigin'] == 'https://invalid.example':
            raise ApiProblem(error_code, 'synthetic')
        original(value)
    monkeypatch.setattr(mysql_store, '_validate_effective_policy', validate)
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    assert sorted(validations) == ['https://invalid.example', 'https://new-gateway.example']
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert detail['counts'] == {'assigned': 2, 'dispatchFailed': 2}
    assert {item['errorCode'] for item in detail['targets'] if item['state'] == 'dispatchFailed'} == {error_code}


def test_high_rate_policy_version_exhaustion_rolls_back_whole_chunk(mysql_store, monkeypatch):
    ids = devices(mysql_store, 2)
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 1000})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    monkeypatch.setattr(mysql_store, '_next_policy_version', lambda cur, base: 2**63 - 2)
    with pytest.raises(ApiProblem, match='POLICY_VERSION_EXHAUSTED'):
        policy_rollout.dispatch_one(mysql_store)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'pending': 2}
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS n FROM device_policy_state')
        assert cur.fetchone()['n'] == 0


def test_high_rate_policy_preserves_empty_error_code_semantics(mysql_store, monkeypatch):
    ids = devices(mysql_store, 1)
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 1000
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 1000})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    def validate(_value):
        raise ApiProblem('', 'synthetic')
    monkeypatch.setattr(mysql_store, '_validate_effective_policy', validate)
    assert policy_rollout.dispatch_one(mysql_store)
    with mysql_store.transaction() as cur:
        cur.execute('SELECT status,error_code,assigned_version FROM policy_rollout_targets WHERE batch_id=%s', (batch,))
        row = cur.fetchone()
    assert row['status'] == 'assigned' and row['error_code'] == '' and row['assigned_version'] is not None


def test_high_rate_policy_respects_chunk_schedule(mysql_store, monkeypatch):
    from datetime import timedelta
    from controlserver.security import utcnow
    ids = devices(mysql_store, 4)
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 40
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 40})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    clock = [utcnow() + timedelta(seconds=5)]
    monkeypatch.setattr(policy_rollout, 'utcnow', lambda: clock[0])
    assert policy_rollout.dispatch_one(mysql_store)
    assert not policy_rollout.dispatch_one(mysql_store)
    clock[0] += timedelta(milliseconds=49)
    assert not policy_rollout.dispatch_one(mysql_store)
    clock[0] += timedelta(milliseconds=1)
    assert policy_rollout.dispatch_one(mysql_store)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'assigned': 4}


def test_policy_chunk_serializes_heartbeat_and_credential_recovery(mysql_store, monkeypatch):
    from contextlib import contextmanager
    from threading import Event
    import time
    ids = devices(mysql_store, 4)
    hostname = mysql_store.details(ids[0])['device']['hostname']
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = 40
    high = request(mysql_store, ids).model_copy(update={'maxPerSecond': 40})
    batch = policy_rollout.create(mysql_store, high, 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    original, entered, release = mysql_store.transaction, Event(), Event()
    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            result = self.cur.execute(sql, args)
            if sql.startswith('SELECT device_id,heartbeat_json FROM device_heartbeats WHERE device_id IN'):
                entered.set()
                if not release.wait(10): raise RuntimeError('test timed out')
            return result
    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    def report():
        body = copy.deepcopy(FIXTURE)
        body['device'].update(deviceId=ids[1], hostname='updated-synthetic')
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    with ThreadPoolExecutor(max_workers=3) as executor:
        dispatch = executor.submit(policy_rollout.dispatch_one, mysql_store)
        try:
            assert entered.wait(10)
            heartbeat = executor.submit(report)
            recovery = executor.submit(mysql_store.recover_device_credential, ids[0], hostname, 'synthetic', 'admin')
            time.sleep(.2)
            assert not heartbeat.done() and not recovery.done()
        finally:
            release.set()
        assert dispatch.result(timeout=10)
        heartbeat.result(timeout=10)
        assert recovery.result(timeout=10)['deviceId'] == ids[0]
    monkeypatch.setattr(mysql_store, 'transaction', original)
    assert mysql_store.details(ids[1])['device']['hostname'] == 'updated-synthetic'
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'assigned': 2, 'pending': 2}


@pytest.mark.parametrize('rate', [20, 40])
def test_policy_dispatch_does_not_deadlock_with_credential_recovery(mysql_store, monkeypatch, rate):
    from contextlib import contextmanager
    from threading import Event
    ids = devices(mysql_store, 1)
    hostname = mysql_store.details(ids[0])['device']['hostname']
    mysql_store.cfg.POLICY_ROLLOUT_MAX_RATE = rate
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids).model_copy(update={'maxPerSecond': rate}), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    original, recovery_locked, dispatch_waiting, release = mysql_store.transaction, Event(), Event(), Event()
    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            if (sql.startswith('SELECT heartbeat_json FROM device_heartbeats WHERE device_id=') or
                    sql.startswith('SELECT device_id,heartbeat_json FROM device_heartbeats WHERE device_id IN')):
                dispatch_waiting.set()
            result = self.cur.execute(sql, args)
            if sql.startswith('SELECT hostname FROM device_heartbeats WHERE device_id='):
                recovery_locked.set()
                if not release.wait(10): raise RuntimeError('test timed out')
            return result
    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    with ThreadPoolExecutor(max_workers=2) as executor:
        recovery = executor.submit(mysql_store.recover_device_credential, ids[0], hostname, 'synthetic', 'admin')
        try:
            assert recovery_locked.wait(10)
            dispatch = executor.submit(policy_rollout.dispatch_one, mysql_store)
            assert dispatch_waiting.wait(10)
        finally:
            release.set()
        assert recovery.result(timeout=10)['deviceId'] == ids[0]
        assert dispatch.result(timeout=10)
    monkeypatch.setattr(mysql_store, 'transaction', original)
    assert policy_rollout.details(mysql_store, batch, 0, 10)['counts'] == {'assigned': 1}


def test_policy_rollout_mutation_rejects_shared_token_mode(mysql_store):
    from app import create_app
    ids = devices(mysql_store, 1)
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    response = client.post('/admin/v1/policy-rollouts', json=request(mysql_store, ids).model_dump(mode='json'),
        headers={'Authorization': 'Bearer ' + mysql_store.cfg.ADMIN_TOKEN}, base_url='https://localhost')
    assert response.status_code == 403


def test_local_admin_policy_rollout_api(mysql_store, tmp_path):
    import base64
    from werkzeug.security import generate_password_hash
    from app import create_app
    ids = devices(mysql_store, 1)
    accounts = tmp_path / 'admins.json'
    accounts.write_text(json.dumps([
        {'username':'alice', 'role':'admin', 'passwordHash':generate_password_hash('correct password 123')},
        {'username':'bob', 'role':'operator', 'passwordHash':generate_password_hash('correct password 123')},
    ]), encoding='utf-8')
    accounts.chmod(0o600)
    cfg = mysql_store.cfg
    cfg.ADMIN_AUTH_MODE = 'local'
    cfg.ADMIN_ACCOUNTS_PATH = str(accounts)
    cfg.ADMIN_SESSION_KEY_TEXT = base64.b64encode(b'k'*32).decode()
    client = create_app(cfg, mysql_store).test_client()
    def login(user):
        result = client.post('/auth/login', json={'username':user, 'password':'correct password 123'}, base_url='https://localhost')
        assert result.status_code == 200
        return {'Authorization':'Bearer '+result.json['token']}
    admin, operator = login('alice'), login('bob')
    body = request(mysql_store, ids).model_dump(mode='json')
    assert client.post('/admin/v1/policy-rollouts', json=body, headers=operator, base_url='https://localhost').status_code == 403
    created = client.post('/admin/v1/policy-rollouts', json=body, headers=admin, base_url='https://localhost')
    assert created.status_code == 201
    batch = created.json['batchId']
    listed = client.get('/admin/v1/policy-rollouts', headers=admin, base_url='https://localhost')
    assert listed.json['batches'][0]['batchId'] == batch
    detail = client.get('/admin/v1/policy-rollouts/'+batch, headers=admin, base_url='https://localhost')
    assert detail.json['candidatePolicy']['gatewayOrigin'] == 'https://new-gateway.example'
    assert client.post('/admin/v1/policy-rollouts/'+batch+'/resume', json={'reason':'test'}, headers=admin, base_url='https://localhost').status_code == 200
    assert policy_rollout.dispatch_one(mysql_store)
    audit = mysql_store.audits(None, 0, 100)
    assert any(row['actor']=='alice' and row['action']=='POLICY_ROLLOUT_CREATED' for row in audit)


def test_current_v1_heartbeat_is_not_mistaken_for_prior_v2(mysql_store):
    from controlserver.models import HeartbeatRequest
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    legacy = copy.deepcopy(FIXTURE)
    legacy['device']['deviceId'] = ids[0]
    legacy['schemaVersion'] = 1
    for field in ('runtime', 'endpoints', 'activity'):
        legacy.pop(field)
    mysql_store.heartbeat(HeartbeatRequest.model_validate(legacy), 60, '127.0.0.1')
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    target = policy_rollout.details(mysql_store, batch, 0, 10)['targets'][0]
    assert target['state'] == 'dispatchFailed' and target['errorCode'] == 'DEVICE_PROTOCOL_UNSUPPORTED'
    assert mysql_store.policy(ids[0])['gatewayOrigin'] != 'https://new-gateway.example'


def test_v1_heartbeat_does_not_reuse_old_v2_reconciliation(mysql_store):
    from controlserver.analytics import build
    from controlserver.models import HeartbeatRequest
    from controlserver.security import utcnow
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    version = policy_rollout.details(mysql_store, batch, 0, 10)['targets'][0]['assignedVersion']
    current = copy.deepcopy(FIXTURE)
    current['device']['deviceId'] = ids[0]
    current['policy'].update(appliedVersion=version, appliedSchemaVersion=2)
    current['runtime'].update(supportedPolicySchemaVersion=2, lastReconcileResult='completed', lastReconcileErrorCode=None)
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(current), 60, '127.0.0.1')
    assert policy_rollout.details(mysql_store, batch, 0, 10)['appliedTargets'] == 1
    legacy = copy.deepcopy(current)
    legacy['schemaVersion'] = 1
    legacy['policy'].pop('appliedSchemaVersion')
    for field in ('runtime', 'endpoints', 'activity'):
        legacy.pop(field)
    mysql_store.heartbeat(HeartbeatRequest.model_validate(legacy), 60, '127.0.0.1')
    detail = mysql_store.details(ids[0])
    assert detail['device']['schemaVersion'] == 1
    assert detail['device']['operationState'] == 'unknown'
    assert detail['runtime'] is None
    now = utcnow()
    assert mysql_store.dashboard(now)['legacyClients'] == 1
    rows, policy, total = mysql_store.analytics_page('legacyclient', None, now, 0, 10)
    assert total == 1 and rows[0]['device']['deviceId'] == ids[0]
    assert build(rows, policy, now, scope='all')['policy']['appliedDevices'] == 0
    batch_detail = policy_rollout.details(mysql_store, batch, 0, 10)
    assert batch_detail['appliedTargets'] == 0
    assert batch_detail['targets'][0]['applicationState'] == 'unsupported'
    assert policy_rollout.details(mysql_store, batch, 0, 10, 'unsupported')['filteredTargets'] == 1
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(current), 60, '127.0.0.1')
    assert mysql_store.details(ids[0])['device']['schemaVersion'] == 2
    assert policy_rollout.details(mysql_store, batch, 0, 10)['appliedTargets'] == 1


def test_policy_rollout_backup_and_restore_preserve_state(mysql_store, monkeypatch, tmp_path):
    import os
    import sys
    import types
    import importlib
    import tempfile
    from contextlib import contextmanager
    import pymysql
    from controlserver.database import ControlStore

    if os.name == 'nt':
        fake = types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, LOCK_UN=8, flock=lambda *args: None)
        monkeypatch.setitem(sys.modules, 'fcntl', fake)
    backup = importlib.import_module('controlserver.backup')

    @contextmanager
    def credentials(cfg):
        with tempfile.TemporaryDirectory(prefix='synthetic-mysql-') as directory:
            path = Path(directory) / 'client.cnf'
            path.write_text(f'[client]\nhost={cfg.MYSQL_HOST}\nport={cfg.MYSQL_PORT}\nuser={cfg.MYSQL_USER}\npassword=\n', encoding='utf-8')
            yield str(path)

    monkeypatch.setattr(backup, 'mysql_credentials', credentials)
    ids = devices(mysql_store, 1)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'go', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    expected = mysql_store.policy(ids[0])
    binary = Path(os.environ['ENDPOINTAI_TEST_MYSQL_BIN'])
    archive = backup.run_backup(mysql_store.cfg, dump_binary=str(binary / 'mysqldump.exe'))
    target = 'eai_restore_' + uuid4().hex
    connection = pymysql.connect(host='127.0.0.1', port=mysql_store.cfg.MYSQL_PORT, user='root', password='', autocommit=True)
    try:
        with connection.cursor() as cur:
            cur.execute('CREATE DATABASE `' + target + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
        backup.restore_backup(mysql_store.cfg, archive, target, str(binary / 'mysql.exe'))
        restored_cfg = copy.copy(mysql_store.cfg)
        restored_cfg.MYSQL_DATABASE = target
        restored = ControlStore(restored_cfg)
        assert restored.policy(ids[0]) == expected
        assert policy_rollout.details(restored, batch, 0, 10)['counts'] == {'assigned': 1}
    finally:
        with connection.cursor() as cur:
            cur.execute('DROP DATABASE `' + target + '`')
        connection.close()
