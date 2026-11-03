import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import uuid4
import pytest
from app import create_app
from controlserver.database import ControlStore, dbtime, schema_tables
from controlserver.models import HeartbeatV2Request, PolicyUpdateRequest, CreateRemoteCommandRequest, RemoteCommandStatusUpdate, ProxyTrafficState, RemoteCommandStatus
from controlserver.security import utcnow, sign_command, dumps
from controlserver.validation import ApiProblem

FIXTURE = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text())
pytestmark = pytest.mark.mysql


def heartbeat(store):
    value = HeartbeatV2Request.model_validate(copy.deepcopy(FIXTURE["heartbeat"]))
    store.heartbeat(value, 60, "127.0.0.1")
    return value


def command_request():
    return CreateRemoteCommandRequest(type="disableProxy",reason="integration test",expiresInMinutes=10)


def test_initialize_is_idempotent_and_restart_preserves_policy(mysql_store):
    before = mysql_store.policy()
    assert mysql_store.initialize_empty() == "already_initialized"
    assert ControlStore(mysql_store.cfg).policy() == before
    with mysql_store.transaction() as cur:
        cur.execute("ALTER TABLE device_heartbeats DROP COLUMN hostname")
    with pytest.raises(Exception):
        mysql_store.check_schema()


def test_database_disconnect_rolls_back_and_next_request_recovers(mysql_store):
    old = mysql_store.policy()
    with pytest.raises(Exception):
        with mysql_store.transaction() as cur:
            cur.execute("UPDATE control_policy SET policy_version=999 WHERE singleton_id=1")
            cur.execute("SELECT CONNECTION_ID() AS id")
            connection_id = cur.fetchone()["id"]
            with mysql_store.transaction() as other:
                other.execute(f"KILL CONNECTION {int(connection_id)}")
            cur.execute("SELECT 1")
    assert mysql_store.policy() == old
    with mysql_store.transaction() as cur:
        cur.execute("SELECT policy_version FROM control_policy")
        assert cur.fetchone()["policy_version"] == old["policyVersion"]


def test_command_expiring_during_device_lock_wait_is_not_leased(mysql_store):
    import threading
    import time
    h = heartbeat(mysql_store)
    device = h.device.deviceId
    command = mysql_store.create_command(device, command_request(), 'operator')
    started = threading.Event()
    def lease():
        started.set()
        return mysql_store.lease(device)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with mysql_store.transaction() as cur:
            cur.execute('SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE', (str(device),))
            cur.execute('UPDATE remote_commands SET expires_at_utc=%s WHERE command_id=%s',
                        (dbtime(utcnow() + timedelta(seconds=0.5)), command['commandId']))
            future = executor.submit(lease)
            assert started.wait(timeout=3)
            time.sleep(0.8)
        assert future.result(timeout=5) is None
    assert mysql_store.commands(device)[0]['status'] == 'expired'


def test_no_command_lease_does_not_wait_for_device_row_lock(mysql_store):
    h = heartbeat(mysql_store)
    device = h.device.deviceId
    with ThreadPoolExecutor(max_workers=1) as executor:
        with mysql_store.transaction() as cur:
            cur.execute('SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE', (str(device),))
            assert executor.submit(mysql_store.lease, device).result(timeout=2) is None
    command = mysql_store.create_command(device, command_request(), 'operator')
    leased = mysql_store.lease(device)
    assert leased['commandId'] == command['commandId'] and leased['status'] == 'delivered'


def test_v1_heartbeat_events_and_legacy_device(mysql_store):
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    auth = {"Authorization": "Bearer " + mysql_store.cfg.CLIENT_TOKEN}
    body = copy.deepcopy(FIXTURE["heartbeat"])
    body["schemaVersion"] = 1
    body.pop("runtime")
    body.pop("endpoints")
    body.pop("activity")
    beat = client.post("/api/v1/heartbeat", json=body, headers=auth)
    assert beat.status_code == 200
    assert set(beat.json) == {"serverTimeUtc","acceptedPolicyVersion","nextHeartbeatSeconds"}
    admin = {"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}
    listed = client.get("/admin/v1/devices", headers=admin).json
    assert listed[0]["legacyClient"] is True
    assert listed[0]["serviceVersion"] is None
    assert listed[0]["operationState"] == "unknown"
    batch = dict(schemaVersion=1,batchId=str(uuid4()),deviceId=body["device"]["deviceId"],events=[])
    assert client.post("/api/v1/events/batch",json=batch,headers=auth).status_code == 202
    body["agents"] = body["agents"] * 257
    assert client.post("/api/v1/heartbeat",json=body,headers=auth).status_code == 400


def test_policy_concurrent_update_and_allowlist_semantics(mysql_store):
    current = mysql_store.policy()
    update = PolicyUpdateRequest(expectedVersion=current["policyVersion"],
        **{k:v for k,v in current.items() if k in PolicyUpdateRequest.model_fields})
    update.allowlistedBaseUrls = None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: mysql_store.update_policy(update), range(2)))
    assert sum(r is not None for r in results) == 1
    current = mysql_store.policy()
    assert current["allowlistedBaseUrls"] == ["https://claudecode.sf-express.com/ccr"]
    update.expectedVersion = current["policyVersion"]
    update.allowlistedBaseUrls = []
    assert mysql_store.update_policy(update)["allowlistedBaseUrls"] == []


def test_transaction_pool_reuses_connections_and_rolls_back(mysql_store):
    with mysql_store.transaction() as cur:
        cur.execute("SELECT CONNECTION_ID() AS id")
        first = cur.fetchone()["id"]
    with pytest.raises(RuntimeError):
        with mysql_store.transaction() as cur:
            cur.execute("UPDATE control_policy SET policy_version=999 WHERE singleton_id=1")
            raise RuntimeError("synthetic rollback")
    with mysql_store.transaction() as cur:
        cur.execute("SELECT CONNECTION_ID() AS id")
        assert cur.fetchone()["id"] == first
        cur.execute("SELECT policy_version FROM control_policy WHERE singleton_id=1")
        assert cur.fetchone()["policy_version"] != 999


def test_scale_policy_index_is_idempotent_and_used(mysql_store):
    h = heartbeat(mysql_store)
    mysql_store.policy(h.device.deviceId, schema_version=2)
    assert mysql_store.ensure_scale_indexes() == "scale_indexes_ready"
    assert mysql_store.ensure_scale_indexes() == "scale_indexes_ready"
    with mysql_store.transaction() as cur:
        cur.execute("EXPLAIN SELECT effective_policy_version FROM device_policy_state ORDER BY effective_policy_version DESC LIMIT 1 FOR UPDATE")
        plan = cur.fetchone()
    assert plan["key"] == "idx_effective_policy_version"


def test_legacy_stale_policy_refresh_reuses_global_watermark(mysql_store, monkeypatch):
    devices = [uuid4() for _ in range(3)]
    old = [mysql_store.policy(device, schema_version=2) for device in devices]
    current = mysql_store.policy()
    update = PolicyUpdateRequest(expectedVersion=current["policyVersion"],
        **{k: v for k, v in current.items() if k in PolicyUpdateRequest.model_fields})
    published = mysql_store.update_policy(update)
    assert published["policyVersion"] > max(item["policyVersion"] for item in old)
    def no_allocation(*args):
        raise AssertionError("stale policy refresh must not allocate a version")
    monkeypatch.setattr(mysql_store, "_next_policy_version", no_allocation)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as pool:
        refreshed = list(pool.map(lambda device: mysql_store.policy(device, schema_version=2), devices))
    assert all(item["policyVersion"] == published["policyVersion"] for item in refreshed)
    assert all(item["policyVersion"] > previous["policyVersion"] for item, previous in zip(refreshed, old))


def test_global_policy_update_audits_only_successful_cas(mysql_store):
    current = mysql_store.policy()
    update = PolicyUpdateRequest(expectedVersion=current["policyVersion"],
        **{k:v for k,v in current.items() if k in PolicyUpdateRequest.model_fields})
    assert mysql_store.update_policy(update, "synthetic-operator")
    assert mysql_store.update_policy(update, "synthetic-operator") is None
    entries = mysql_store.audits(None, 0, 100)
    assert len(entries) == 1
    assert entries[0]["action"] == "GLOBAL_POLICY_UPDATED"
    assert entries[0]["actor"] == "synthetic-operator"


def test_authentication_timestamp_updates_only_after_five_minutes(mysql_store):
    from controlserver.models import DeviceEnrollmentRequest
    enrolled = mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=uuid4(), hostname="synthetic", serviceVersion="test"))
    device, token = enrolled["deviceId"], enrolled["deviceToken"]
    assert mysql_store.authenticate(device, token)
    with mysql_store.transaction() as cur:
        cur.execute("SELECT last_authenticated_at_utc FROM device_credentials WHERE device_id=%s", (device,))
        first = cur.fetchone()["last_authenticated_at_utc"]
    assert mysql_store.authenticate(device, token)
    with mysql_store.transaction() as cur:
        cur.execute("SELECT last_authenticated_at_utc FROM device_credentials WHERE device_id=%s", (device,))
        assert cur.fetchone()["last_authenticated_at_utc"] == first
        cur.execute("UPDATE device_credentials SET last_authenticated_at_utc=%s WHERE device_id=%s", (first - timedelta(minutes=6), device))
    assert mysql_store.authenticate(device, token)
    with mysql_store.transaction() as cur:
        cur.execute("SELECT last_authenticated_at_utc FROM device_credentials WHERE device_id=%s", (device,))
        assert cur.fetchone()["last_authenticated_at_utc"] >= first


def test_administrator_credential_recovery_is_bound_and_audited(mysql_store):
    from controlserver.models import DeviceEnrollmentRequest
    from controlserver.validation import ApiProblem
    h = heartbeat(mysql_store)
    enrolled = mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=h.device.deviceId,
        hostname=h.device.hostname, serviceVersion="test"))
    device, old = enrolled["deviceId"], enrolled["deviceToken"]
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE device_credentials SET revoked=1 WHERE device_id=%s", (device,))
    with pytest.raises(ApiProblem, match="DEVICE_HOSTNAME_MISMATCH"):
        mysql_store.recover_device_credential(device, "wrong-host", "lost", "admin-1")
    assert not mysql_store.authenticate(device, old)
    recovered = mysql_store.recover_device_credential(device, h.device.hostname, "lost", "admin-1")
    assert not mysql_store.authenticate(device, old)
    assert mysql_store.authenticate(device, recovered["deviceToken"])
    audit = mysql_store.audits(device, 0, 20)
    assert audit[0]["action"] == "DEVICE_CREDENTIAL_RECOVERED"
    assert audit[0]["actor"] == "admin-1" and recovered["deviceToken"] not in str(audit)


def test_assets_replace_and_keep_last_observed_activity(mysql_store):
    h = heartbeat(mysql_store)
    before = mysql_store.details(h.device.deviceId)
    assert before["device"]["agentCount"] == 1
    assert before["device"]["endpointCount"] == 1
    assert before["runtime"]["uptimeSeconds"] == 123
    h.activity[0].state = ProxyTrafficState.NeverObserved
    h = HeartbeatV2Request.model_validate(h.model_dump())
    h.activity[0].requestCountSinceBoot = 0
    mysql_store.heartbeat(h, 15, "127.0.0.1")
    detail = mysql_store.details(h.device.deviceId)
    assert detail["activity"][0]["state"] == "succeeded"
    assert detail["activity"][0]["requestCountSinceBoot"] == 0
    assert detail["device"]["heartbeatIntervalSeconds"] == 15
    h.endpoints, h.activity, h.agents = [], [], []
    mysql_store.heartbeat(h, 60, None)
    detail = mysql_store.details(h.device.deviceId)
    assert detail["endpoints"] == detail["activity"] == detail["agents"] == []


def test_lightweight_heartbeat_preserves_inventory(mysql_store):
    h = heartbeat(mysql_store)
    before = mysql_store.details(h.device.deviceId)
    h.inventoryUnchanged = True
    h.endpoints = []
    h.runtime.uptimeSeconds = 456
    mysql_store.heartbeat(h, 60, "127.0.0.1")
    after = mysql_store.details(h.device.deviceId)
    assert after["endpoints"] == before["endpoints"]
    assert after["agents"] == before["agents"]
    assert after["runtime"]["uptimeSeconds"] == 456
    h.inventoryUnchanged = False
    h.agents, h.endpoints, h.activity = [], [], []
    mysql_store.heartbeat(h, 60, "127.0.0.1")
    after = mysql_store.details(h.device.deviceId)
    assert after["endpoints"] == after["agents"] == after["activity"] == []


def test_heartbeat_rolls_back_entire_snapshot_on_duplicate_asset(mysql_store):
    h = heartbeat(mysql_store)
    old = mysql_store.details(h.device.deviceId)
    h.device.hostname = "must roll back"
    h.endpoints.append(h.endpoints[0])
    with pytest.raises(Exception):
        mysql_store.heartbeat(h, 60, None)
    assert mysql_store.details(h.device.deviceId) == old


def test_expired_executing_command_can_be_resolved_and_accepts_late_result(mysql_store):
    h = heartbeat(mysql_store)
    device = h.device.deviceId
    command = mysql_store.create_command(device, command_request(), "tester")
    mysql_store.lease(device)
    update = RemoteCommandStatusUpdate(schemaVersion=1, deviceId=device, commandId=command["commandId"],
        status="executing", observedAtUtc=utcnow(), resultCode=None, resultSummary=None)
    assert mysql_store.update_command(update)
    assert not mysql_store.resolve_unknown(command["commandId"], "tester", "Verified offline")
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE remote_commands SET expires_at_utc=%s WHERE command_id=%s",
                    (dbtime(utcnow() - timedelta(seconds=1)), command["commandId"]))
    assert mysql_store.lease(device) is None
    before_resolution = mysql_store.commands(device)[0]
    assert before_resolution["status"] == "executing" and before_resolution["deliveryCount"] == 1
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    headers = {"Authorization":"Bearer " + mysql_store.cfg.ADMIN_TOKEN, "X-SF-Admin-Actor":"tester"}
    path = f'/admin/v1/commands/{command["commandId"]}/resolve-unknown'
    assert client.post(path, json={"reason":""}, headers=headers).status_code == 400
    assert client.post(path, json={"reason":"Verified endpoint state"}, headers=headers).status_code == 200
    assert client.post(path, json={"reason":"Duplicate"}, headers=headers).status_code == 409
    assert mysql_store.commands(device)[0]["status"] == "resultUnknown"
    assert mysql_store.lease(device) is None
    assert mysql_store.create_command(device, command_request(), "tester")
    assert mysql_store.update_command(update)
    assert next(row for row in mysql_store.commands(device) if row["commandId"] == command["commandId"])["status"] == "resultUnknown"
    update.status, update.resultCode, update.resultSummary = RemoteCommandStatus.Succeeded, "OK", "Late result"
    assert mysql_store.update_command(update)
    assert mysql_store.update_command(update)
    assert next(row for row in mysql_store.commands(device) if row["commandId"] == command["commandId"])["status"] == "succeeded"
    actions = [entry["action"] for entry in mysql_store.audits(device, 0, 100)]
    assert actions.count("REMOTE_COMMAND_RESULT_UNKNOWN") == 1
    assert actions.count("REMOTE_COMMAND_LATE_RESULT") == 1


@pytest.mark.parametrize("resolve_first", [False, True])
def test_expired_delivered_command_requires_review_or_late_result(mysql_store, resolve_first):
    h = heartbeat(mysql_store)
    device = h.device.deviceId
    command = mysql_store.create_command(device, command_request(), "tester")
    assert mysql_store.lease(device)["status"] == "delivered"
    assert not mysql_store.resolve_unknown(command["commandId"], "tester", "too early")
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE remote_commands SET expires_at_utc=%s WHERE command_id=%s",
                    (dbtime(utcnow() - timedelta(seconds=1)), command["commandId"]))
    assert mysql_store.lease(device) is None
    current = mysql_store.commands(device)[0]
    assert current["status"] == "delivered" and current["deliveryCount"] == 1
    with pytest.raises(ApiProblem, match="DEVICE_COMMAND_ALREADY_ACTIVE"):
        mysql_store.create_command(device, command_request(), "tester")
    if resolve_first:
        assert mysql_store.resolve_unknown(command["commandId"], "tester", "verified")
    result = RemoteCommandStatusUpdate(schemaVersion=1, deviceId=device, commandId=command["commandId"],
        status="succeeded", observedAtUtc=utcnow(), resultCode="OK", resultSummary="Late result")
    assert mysql_store.update_command(result)
    assert mysql_store.commands(device)[0]["status"] == "succeeded"
    assert mysql_store.create_command(device, command_request(), "tester")


def test_commands_concurrent_creation_and_lifecycle(mysql_store):
    h = heartbeat(mysql_store)
    device = h.device.deviceId
    def create(_):
        try:
            return mysql_store.create_command(device, command_request(), "test")
        except ApiProblem as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(create, range(4)))
    assert results.count("DEVICE_COMMAND_ALREADY_ACTIVE") == 3
    command = next(r for r in results if isinstance(r, dict))
    with ThreadPoolExecutor(max_workers=4) as pool:
        delivered = list(pool.map(lambda _: mysql_store.lease(device), range(4)))
    assert {c["commandId"] for c in delivered} == {command["commandId"]}
    assert mysql_store.commands(device)[0]["deliveryCount"] == 4
    assert not mysql_store.cancel(command["commandId"], "test")
    update = RemoteCommandStatusUpdate(schemaVersion=1,deviceId=device,commandId=command["commandId"],
        status="executing",observedAtUtc=utcnow(),resultCode=None,resultSummary=None)
    assert mysql_store.update_command(update)
    assert mysql_store.update_command(update)  # identical executing report is accepted
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE remote_commands SET expires_at_utc=%s WHERE command_id=%s",
                    (dbtime(utcnow()-timedelta(hours=1)), command["commandId"]))
    assert ControlStore(mysql_store.cfg).lease(device) is None
    assert mysql_store.commands(device)[0]["status"] == "executing"
    update.status = RemoteCommandStatus.Succeeded
    update = RemoteCommandStatusUpdate.model_validate(update.model_dump())
    assert mysql_store.update_command(update)
    completed = mysql_store.commands(device)[0]["completedAtUtc"]
    update.observedAtUtc = utcnow() + timedelta(seconds=10)
    assert mysql_store.update_command(update)
    assert mysql_store.commands(device)[0]["completedAtUtc"] == completed
    update.resultCode = "CONFLICTING_RESULT"
    assert not mysql_store.update_command(update)
    assert mysql_store.lease(device) is None
    assert len(mysql_store.audits(device)) == 1


@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_terminal_receipt_retries_are_idempotent_and_identity_bound(mysql_store, status):
    h = heartbeat(mysql_store)
    command = mysql_store.create_command(h.device.deviceId, command_request(), "test")
    mysql_store.lease(h.device.deviceId)
    update = RemoteCommandStatusUpdate(schemaVersion=1, deviceId=h.device.deviceId,
        commandId=command["commandId"], status=status, observedAtUtc=utcnow(),
        resultCode="SYNTHETIC_RESULT", resultSummary="Synthetic result")
    assert mysql_store.update_command(update)
    original = mysql_store.commands(h.device.deviceId)[0]
    duplicate = update.model_copy(update={"observedAtUtc": utcnow() + timedelta(minutes=1)})
    assert mysql_store.update_command(duplicate)
    assert mysql_store.commands(h.device.deviceId)[0] == original
    for changes in ({"deviceId": uuid4()}, {"commandId": uuid4()},
                    {"status": RemoteCommandStatus.Executing},
                    {"status": RemoteCommandStatus.Failed if status == "succeeded" else RemoteCommandStatus.Succeeded},
                    {"resultCode": None}, {"resultSummary": "Different result"}):
        assert not mysql_store.update_command(update.model_copy(update=changes))
        assert mysql_store.commands(h.device.deviceId)[0] == original


def test_pending_expiry_cancel_and_audit(mysql_store):
    h = heartbeat(mysql_store)
    first = mysql_store.create_command(h.device.deviceId, command_request(), "test")
    assert mysql_store.cancel(first["commandId"], "test")
    assert not mysql_store.cancel(first["commandId"], "test")
    second = mysql_store.create_command(h.device.deviceId, command_request(), "test")
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE remote_commands SET expires_at_utc=%s WHERE command_id=%s",
                    (dbtime(utcnow()-timedelta(minutes=1)), second["commandId"]))
    assert mysql_store.lease(h.device.deviceId) is None
    assert mysql_store.commands(h.device.deviceId)[0]["status"] == "expired"
    assert [a["action"] for a in mysql_store.audits(h.device.deviceId)] == [
        "REMOTE_COMMAND_CREATED","REMOTE_COMMAND_CANCELLED","REMOTE_COMMAND_CREATED"]


def test_http_v2_full_flow_device_binding_and_events(mysql_store):
    config = mysql_store.cfg
    client = create_app(config, mysql_store).test_client()
    bootstrap = {"Authorization":"Bearer "+config.CLIENT_TOKEN}
    admin = {"Authorization":"Bearer "+config.ADMIN_TOKEN, "X-SF-Admin-Actor":"tester"}
    enrolled = client.post("/api/v2/enroll", json=FIXTURE["enrollment"], headers=bootstrap)
    assert enrolled.status_code == 200
    device = enrolled.json["deviceId"]
    token = {"Authorization":"Bearer "+enrolled.json["deviceToken"]}
    assert client.get(f"/api/v2/devices/{device}/policy", headers=token).status_code == 200
    assert client.get(f"/api/v2/devices/{uuid4()}/policy", headers=token).status_code == 401
    beat = client.post("/api/v2/heartbeat", json=FIXTURE["heartbeat"], headers=token)
    assert beat.status_code == 200
    assert beat.json["command"] is None
    listing = client.get("/admin/v1/devices?take=1&onlineState=online", headers=admin)
    assert listing.status_code == 200 and listing.headers["X-Total-Count"] == "1"
    assert client.get(f"/admin/v1/devices/{device}", headers=admin).json["endpoints"]
    created = client.post(f"/admin/v1/devices/{device}/commands",
        json=command_request().model_dump(mode="json"), headers=admin)
    assert created.status_code == 202
    beat = client.post("/api/v2/heartbeat", json=FIXTURE["heartbeat"], headers=token)
    command = beat.json["command"]
    assert command["signature"] == sign_command(command["payload"], config.POLICY_HMAC_KEY)
    update = dict(schemaVersion=1,deviceId=device,commandId=created.json["commandId"],status="succeeded",
                  observedAtUtc=FIXTURE["heartbeat"]["observedAtUtc"],resultCode="OK",resultSummary="Synthetic test")
    assert client.post(f"/api/v2/commands/{created.json['commandId']}/status",json=update,headers=token).status_code == 202
    completed = mysql_store.commands(device)[0]["completedAtUtc"]
    assert client.post(f"/api/v2/commands/{created.json['commandId']}/status",json=update,headers=token).status_code == 202
    assert mysql_store.commands(device)[0]["completedAtUtc"] == completed
    conflicting = dict(update, resultCode="CONFLICTING_RESULT")
    assert client.post(f"/api/v2/commands/{created.json['commandId']}/status",json=conflicting,headers=token).status_code == 409
    batch = dict(schemaVersion=1,batchId=str(uuid4()),deviceId=device,events=[
        dict(eventId=str(uuid4()),occurredAtUtc=FIXTURE["heartbeat"]["observedAtUtc"],
             severity="info",type="test",code="TEST",summary="测试")])
    assert client.post("/api/v2/events/batch",json=batch,headers=token).json == dict(accepted=1,duplicates=0,rejected=0,errors=[])
    assert client.post("/api/v2/events/batch",json=batch,headers=token).json["duplicates"] == 1
    # Shared bootstrap alone cannot replace an existing identity.
    assert client.post("/api/v2/enroll",json=FIXTURE["enrollment"],headers=bootstrap).status_code == 409
    assert client.post("/api/v2/enroll",json={**FIXTURE["enrollment"], "previousDeviceToken":"incorrect"},headers=bootstrap).status_code == 409
    assert client.get(f"/api/v2/devices/{device}/policy",headers=token).status_code == 200
    proof = {**FIXTURE["enrollment"], "previousDeviceToken": enrolled.json["deviceToken"]}
    assert client.post("/api/v2/enroll",json=proof,headers=bootstrap).status_code == 200
    assert client.get(f"/api/v2/devices/{device}/policy",headers=token).status_code == 401


def test_enrollment_cannot_restore_a_revoked_device(mysql_store):
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    bootstrap = {"Authorization":"Bearer "+mysql_store.cfg.CLIENT_TOKEN}
    enrolled = client.post("/api/v2/enroll", json=FIXTURE["enrollment"], headers=bootstrap).json
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE device_credentials SET revoked=1 WHERE device_id=%s", (enrolled["deviceId"],))
    proof = {**FIXTURE["enrollment"], "previousDeviceToken": enrolled["deviceToken"]}
    assert client.post("/api/v2/enroll", json=proof, headers=bootstrap).status_code == 409
    with mysql_store.transaction() as cur:
        cur.execute("SELECT revoked FROM device_credentials WHERE device_id=%s", (enrolled["deviceId"],))
        assert cur.fetchone()["revoked"] == 1


def test_global_publish_validates_distinct_overrides_and_rolls_back_invalid(mysql_store, monkeypatch):
    current = mysql_store.policy()
    good = {"gatewayOrigin": "https://good.example"}
    bad = {"gatewayOrigin": "http://bad.example"}
    with mysql_store.transaction() as cur:
        for i in range(40):
            override = bad if i == 39 else good
            cur.execute("INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)",
                (str(uuid4()), current["policyVersion"], i+2, json.dumps(override), json.dumps(current)))
    update = PolicyUpdateRequest(expectedVersion=current["policyVersion"],
        **{k:v for k,v in current.items() if k in PolicyUpdateRequest.model_fields})
    update.gatewayOrigin = "https://global.example"
    update.allowInsecureGateway = False
    with pytest.raises(ApiProblem):
        mysql_store.update_policy(update, "synthetic")
    assert mysql_store.policy() == current
    with mysql_store.transaction() as cur:
        cur.execute("DELETE FROM device_policy_state WHERE JSON_UNQUOTE(JSON_EXTRACT(overrides_json, '$.gatewayOrigin'))=%s", (bad["gatewayOrigin"],))
    calls = []
    original = mysql_store._validate_effective_policy
    def validate(value):
        calls.append(value)
        return original(value)
    monkeypatch.setattr(mysql_store, "_validate_effective_policy", validate)
    published = mysql_store.update_policy(update, "synthetic")
    assert published["policyVersion"] > 40
    assert len(calls) == 2  # Global policy and one shared distinct override.


def test_preserved_enrollment_survives_lost_response_without_allowing_revival(mysql_store):
    from controlserver.models import DeviceEnrollmentRequest
    from controlserver.validation import ApiProblem
    request = DeviceEnrollmentRequest.model_validate(FIXTURE['enrollment'])
    first = mysql_store.enroll(request)
    device, token = first['deviceId'], first['deviceToken']
    proof = request.model_copy(update={'previousDeviceToken': token, 'preserveDeviceToken': True})
    # Pretend the first successful response was lost; the retry must remain usable.
    discarded = mysql_store.enroll(proof)
    retry = mysql_store.enroll(proof)
    assert discarded == retry == first
    assert mysql_store.authenticate(device, token)
    for wrong in (None, 'incorrect'):
        with pytest.raises(ApiProblem, match='DEVICE_ENROLLMENT_CONFLICT'):
            mysql_store.enroll(proof.model_copy(update={'previousDeviceToken': wrong}))
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_credentials SET revoked=1 WHERE device_id=%s', (device,))
    with pytest.raises(ApiProblem, match='DEVICE_ENROLLMENT_CONFLICT'):
        mysql_store.enroll(proof)
    assert not mysql_store.authenticate(device, token)


def test_legacy_enrollment_still_rotates_previous_token(mysql_store):
    from controlserver.models import DeviceEnrollmentRequest
    request = DeviceEnrollmentRequest.model_validate(FIXTURE['enrollment'])
    first = mysql_store.enroll(request)
    second = mysql_store.enroll(request.model_copy(update={'previousDeviceToken': first['deviceToken']}))
    assert first['deviceToken'] != second['deviceToken']
    assert not mysql_store.authenticate(first['deviceId'], first['deviceToken'])
    assert mysql_store.authenticate(first['deviceId'], second['deviceToken'])


def test_preserved_enrollment_http_and_concurrent_retry(mysql_store):
    app = create_app(mysql_store.cfg, mysql_store)
    client = app.test_client()
    bootstrap = {'Authorization': 'Bearer ' + mysql_store.cfg.CLIENT_TOKEN}
    first = client.post('/api/v2/enroll', json=FIXTURE['enrollment'], headers=bootstrap)
    assert first.status_code == 200
    token, device = first.json['deviceToken'], first.json['deviceId']
    proof = {**FIXTURE['enrollment'], 'previousDeviceToken': token, 'preserveDeviceToken': True}
    def retry(_):
        with app.test_client() as worker:
            reply = worker.post('/api/v2/enroll', json=proof, headers=bootstrap)
            return reply.status_code, reply.json
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(retry, range(4)))
    assert all(status == 200 and value['deviceToken'] == token for status, value in results)
    assert mysql_store.authenticate(device, token)
    # An ignored response and a later retry leave the same credential valid.
    assert client.post('/api/v2/enroll', json=proof, headers=bootstrap).json['deviceToken'] == token
    assert mysql_store.authenticate(device, token)


def test_concurrent_first_enrollment_has_one_winner(mysql_store):
    app = create_app(mysql_store.cfg, mysql_store)
    headers = {'Authorization': 'Bearer ' + mysql_store.cfg.CLIENT_TOKEN}
    def enroll(_):
        with app.test_client() as worker:
            response = worker.post('/api/v2/enroll', json=FIXTURE['enrollment'], headers=headers)
            return response.status_code, response.json
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(enroll, range(6)))
    assert sorted(status for status, _ in results) == [200, 409, 409, 409, 409, 409]
    winner = next(body for status, body in results if status == 200)
    assert mysql_store.authenticate(winner['deviceId'], winner['deviceToken'])


def test_initial_device_token_enrollment_is_idempotent_and_never_revives(mysql_store):
    import base64
    from controlserver.models import DeviceEnrollmentRequest
    from controlserver.validation import ApiProblem
    request = DeviceEnrollmentRequest.model_validate(FIXTURE['enrollment'])
    token = base64.b64encode(bytes(range(32))).decode('ascii')
    first_request = request.model_copy(update={'initialDeviceToken': token})
    first = mysql_store.enroll(first_request)  # first response may be lost
    assert first['deviceToken'] == token
    assert mysql_store.enroll(first_request) == first
    assert mysql_store.authenticate(first['deviceId'], token)
    wrong = base64.b64encode(bytes(range(1,33))).decode('ascii')
    with pytest.raises(ApiProblem, match='DEVICE_ENROLLMENT_CONFLICT'):
        mysql_store.enroll(request.model_copy(update={'initialDeviceToken': wrong}))
    assert mysql_store.authenticate(first['deviceId'], token)
    for invalid in ('!' * 44, base64.b64encode(b'short').decode()):
        with pytest.raises(ApiProblem, match='DEVICE_ENROLLMENT_INVALID'):
            mysql_store.enroll(request.model_copy(update={'initialDeviceToken': invalid}))
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE device_credentials SET revoked=1 WHERE device_id=%s", (first['deviceId'],))
    with pytest.raises(ApiProblem, match='DEVICE_ENROLLMENT_CONFLICT'):
        mysql_store.enroll(first_request)


def test_concurrent_proposed_initial_tokens_have_only_one_winner(mysql_store):
    import base64
    from concurrent.futures import ThreadPoolExecutor
    app = create_app(mysql_store.cfg, mysql_store)
    headers = {'Authorization': 'Bearer ' + mysql_store.cfg.CLIENT_TOKEN}
    def enroll(i):
        token = base64.b64encode(bytes([i]) * 32).decode('ascii')
        with app.test_client() as worker:
            response = worker.post('/api/v2/enroll', json={**FIXTURE['enrollment'], 'initialDeviceToken': token}, headers=headers)
            return response.status_code, response.json
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(enroll, range(1,5)))
    assert sorted(status for status, _ in results) == [200, 409, 409, 409]
    winner = next(body for status, body in results if status == 200)
    assert mysql_store.authenticate(winner['deviceId'], winner['deviceToken'])


def test_concurrent_retries_of_same_initial_token_preserve_credential(mysql_store):
    import base64
    from concurrent.futures import ThreadPoolExecutor
    token = base64.b64encode(bytes(range(32))).decode('ascii')
    app = create_app(mysql_store.cfg, mysql_store)
    headers = {'Authorization': 'Bearer ' + mysql_store.cfg.CLIENT_TOKEN}
    def enroll(_):
        with app.test_client() as worker:
            response = worker.post('/api/v2/enroll', json={**FIXTURE['enrollment'], 'initialDeviceToken': token}, headers=headers)
            return response.status_code, response.json
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(enroll, range(4)))
    assert all(status == 200 and body['deviceToken'] == token for status, body in results)
    assert len({body['enrolledAtUtc'] for _, body in results}) == 1
    assert mysql_store.authenticate(results[0][1]['deviceId'], token)


def test_heartbeat_batches_changed_inventory_without_rewriting_unchanged(mysql_store, monkeypatch):
    from contextlib import contextmanager
    h = heartbeat(mysql_store)
    agent, endpoint, activity = h.agents[0], h.endpoints[0], h.activity[0]
    h.agents, h.endpoints, h.activity = [], [], []
    for _ in range(32):
        asset = uuid4()
        h.agents.append(agent.model_copy(update={'instanceId': uuid4()}, deep=True))
        h.endpoints.append(endpoint.model_copy(update={'assetId': asset}, deep=True))
        h.activity.append(activity.model_copy(update={'assetId': asset}, deep=True))
    original = mysql_store.transaction
    batches = []
    fail_activity = []
    class CursorProxy:
        def __init__(self, cur): self.cur = cur
        def __getattr__(self, name): return getattr(self.cur, name)
        def executemany(self, sql, values):
            batches.append((sql, len(values)))
            result = self.cur.executemany(sql, values)
            if fail_activity and 'INSERT INTO proxy_activity' in sql:
                raise RuntimeError('synthetic failure after batch write')
            return result
    @contextmanager
    def wrapped():
        with original() as cur: yield CursorProxy(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    mysql_store.heartbeat(h, 60, '127.0.0.1')
    assert len(batches) == 3 and all(count == 32 for _, count in batches)
    # PyMySQL only combines INSERT statements that match its bulk syntax.
    from pymysql.cursors import RE_INSERT_VALUES
    assert all(RE_INSERT_VALUES.match(sql) for sql, _ in batches)
    detail = mysql_store.details(h.device.deviceId)
    assert len(detail['agents']) == len(detail['endpoints']) == len(detail['activity']) == 32
    batches.clear()
    mysql_store.heartbeat(h, 60, '127.0.0.1')
    assert batches == []
    before = mysql_store.details(h.device.deviceId)
    h.device.hostname = 'rollback-test'
    h.endpoints.append(h.endpoints[0])
    with pytest.raises(ApiProblem, match='HEARTBEAT_V2_INVALID'):
        mysql_store.heartbeat(h, 60, '127.0.0.1')
    assert mysql_store.details(h.device.deviceId) == before
    h.endpoints.pop()
    h.agents[0].running = not h.agents[0].running
    h.endpoints[0].providerId = 'changed-provider'
    h.activity[0].requestCountSinceBoot += 1
    fail_activity.append(True)
    with pytest.raises(RuntimeError, match='synthetic failure after batch write'):
        mysql_store.heartbeat(h, 60, '127.0.0.1')
    assert mysql_store.details(h.device.deviceId) == before
