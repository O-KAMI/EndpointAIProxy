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


def test_heartbeat_rolls_back_entire_snapshot_on_duplicate_asset(mysql_store):
    h = heartbeat(mysql_store)
    old = mysql_store.details(h.device.deviceId)
    h.device.hostname = "must roll back"
    h.endpoints.append(h.endpoints[0])
    with pytest.raises(Exception):
        mysql_store.heartbeat(h, 60, None)
    assert mysql_store.details(h.device.deviceId) == old


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
    assert ControlStore(mysql_store.cfg).lease(device)["status"] == "executing"
    update.status = RemoteCommandStatus.Succeeded
    update = RemoteCommandStatusUpdate.model_validate(update.model_dump())
    assert mysql_store.update_command(update)
    assert not mysql_store.update_command(update)
    assert mysql_store.lease(device) is None
    assert len(mysql_store.audits(device)) == 1


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
    assert client.post(f"/api/v2/commands/{created.json['commandId']}/status",json=update,headers=token).status_code == 409
    batch = dict(schemaVersion=1,batchId=str(uuid4()),deviceId=device,events=[
        dict(eventId=str(uuid4()),occurredAtUtc=FIXTURE["heartbeat"]["observedAtUtc"],
             severity="info",type="test",code="TEST",summary="测试")])
    assert client.post("/api/v2/events/batch",json=batch,headers=token).json == dict(accepted=1,duplicates=0,rejected=0,errors=[])
    assert client.post("/api/v2/events/batch",json=batch,headers=token).json["duplicates"] == 1
    # Reenrollment rotates the device secret; old credentials immediately stop working.
    assert client.post("/api/v2/enroll",json=FIXTURE["enrollment"],headers=bootstrap).status_code == 200
    assert client.get(f"/api/v2/devices/{device}/policy",headers=token).status_code == 401
