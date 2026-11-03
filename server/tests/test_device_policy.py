from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app import create_app
from controlserver.database import ControlStore, SCHEMA_2_CHECKSUM
from controlserver.models import DeviceEnrollmentRequest, DevicePolicyUpdateRequest, PolicyUpdateRequest
from controlserver.security import sign_policy
from controlserver.transport import INTERNAL


@pytest.mark.parametrize("overrides", [
    {"enabled": False}, {"policyVersion": 7}, {"allowlistedBaseUrls": None},
    {"routeMode": None}, {"allowInsecureGateway": None}, {"unknown": "value"},
])
def test_device_overrides_reject_unknown_and_null_fields(overrides):
    with pytest.raises(ValidationError):
        DevicePolicyUpdateRequest(expectedVersion=1, overrides=overrides)


def test_device_overrides_distinguish_omitted_null_and_empty():
    update = DevicePolicyUpdateRequest(expectedVersion=1, overrides={"gatewayOrigin": None, "allowlistedBaseUrls": []})
    assert update.overrides.model_dump(exclude_unset=True) == {"gatewayOrigin": None, "allowlistedBaseUrls": []}


def setup_devices(store):
    devices = [store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=uuid4(),
        hostname="isolated-test", serviceVersion="0.2.3")) for _ in range(2)]
    client = create_app(store.cfg, store).test_client()
    client.environ_base["endpointai.transport"] = INTERNAL
    auth = {"Authorization": "Bearer " + store.cfg.ADMIN_TOKEN}
    return devices, client, auth


def test_device_policy_scope_signature_restart_and_reset(mysql_store):
    devices, client, auth = setup_devices(mysql_store)
    target, other = [d["deviceId"] for d in devices]
    path = f"/admin/v1/devices/{target}/policy"
    global_before = mysql_store.policy()
    version = global_before["policyVersion"]
    payload = dict(expectedVersion=version, overrides=dict(gatewayOrigin="https://isolated.example.com",
        routeMode="fixedGateway", allowInsecureGateway=False,
        allowlistedBaseUrls=["https://EXAMPLE.com/v1/", "https://example.com/v1"]))
    result = client.put(path, headers=auth, json=payload)
    assert result.status_code == 200
    scoped = result.json["effectivePolicy"]
    assert scoped["policyVersion"] > version
    assert scoped["allowlistedBaseUrls"] == ["https://example.com/v1"]
    assert mysql_store.policy() == mysql_store.policy(other) == global_before
    assert ControlStore(mysql_store.cfg).policy(target) == scoped
    assert client.put(path, headers=auth, json=payload).status_code == 409
    response = client.get(f"/api/v2/devices/{target}/policy",
        headers={"Authorization": "Bearer " + devices[0]["deviceToken"]})
    schema_one = lambda p: {k:v for k,v in p.items() if k not in ("allowlistedDomains", "routingRules", "allowlistMigration")}
    assert response.status_code == 200 and response.json == schema_one(scoped)
    assert response.headers["X-SF-Policy-Signature"] == sign_policy(response.data, mysql_store.cfg.POLICY_HMAC_KEY)
    heartbeat = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text())["heartbeat"]
    heartbeat["device"]["deviceId"] = target
    receipt = client.post("/api/v2/heartbeat", json=heartbeat,
        headers={"Authorization": "Bearer " + devices[0]["deviceToken"]})
    assert receipt.status_code == 200
    assert receipt.json["acceptedPolicyVersion"] == scoped["policyVersion"]
    legacy = client.get("/api/v1/policy", headers={"Authorization":"Bearer " + mysql_store.cfg.CLIENT_TOKEN})
    assert legacy.json == schema_one(global_before)
    assert client.get(f"/api/v2/devices/{target}/policy",
        headers={"Authorization": "Bearer " + devices[1]["deviceToken"]}).status_code == 401
    reset = client.delete(path, headers=auth, json={"expectedVersion": scoped["policyVersion"]})
    assert reset.status_code == 200 and not reset.json["hasOverride"]
    inherited = reset.json["effectivePolicy"]
    assert inherited["policyVersion"] > scoped["policyVersion"]
    assert {k:v for k,v in inherited.items() if k not in ("policyVersion","issuedAtUtc")} == {
        k:v for k,v in global_before.items() if k not in ("policyVersion","issuedAtUtc")}
    assert mysql_store.policy() == mysql_store.policy(other) == global_before
    assert ControlStore(mysql_store.cfg).policy(target) == inherited
    assert len(mysql_store.audits(target, 0, 100)) == 2


def test_current_device_policy_reads_do_not_wait_for_global_lock(mysql_store):
    devices, _, _ = setup_devices(mysql_store)
    target, other = [d['deviceId'] for d in devices]
    initial = mysql_store.policy()
    updated = mysql_store.device_policy(target, DevicePolicyUpdateRequest(
        expectedVersion=initial['policyVersion'], overrides={'allowlistedBaseUrls': []}), 'test')
    expected_other = mysql_store.device_policy(other)
    with mysql_store.transaction() as locked:
        locked.execute('SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE')
        locked.fetchone()
        pool = ThreadPoolExecutor(max_workers=2)
        try:
            target_future = pool.submit(mysql_store.device_policy, target)
            other_future = pool.submit(mysql_store.device_policy, other)
            assert target_future.result(timeout=5) == updated
            assert other_future.result(timeout=5) == expected_other
        finally:
            locked.connection.rollback()
            pool.shutdown(wait=True)


def test_device_policy_detail_uses_one_snapshot_during_global_change(mysql_store, monkeypatch):
    from contextlib import contextmanager
    devices, _, _ = setup_devices(mysql_store)
    target = devices[0]['deviceId']
    initial = mysql_store.policy()
    expected = mysql_store.device_policy(target, DevicePolicyUpdateRequest(
        expectedVersion=initial['policyVersion'], overrides={'allowlistedBaseUrls': []}), 'test')
    update = PolicyUpdateRequest(expectedVersion=initial['policyVersion'],
        **{k: v for k, v in initial.items() if k in PolicyUpdateRequest.model_fields})
    update.gatewayOrigin = 'https://new-global.example.com'
    original = mysql_store.transaction
    writer = ControlStore(mysql_store.cfg)
    changed = False
    class Cursor:
        def __init__(self, inner): self.inner = inner
        def __getattr__(self, name): return getattr(self.inner, name)
        def execute(self, sql, args=None):
            nonlocal changed
            result = self.inner.execute(sql, args)
            if not changed and sql == 'SELECT policy_json FROM control_policy WHERE singleton_id=1':
                changed = True
                writer.update_policy(update)
            return result
    @contextmanager
    def wrapped():
        with original() as cur: yield Cursor(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    assert mysql_store.device_policy(target) == expected
    assert changed and writer.policy()['policyVersion'] > initial['policyVersion']


def test_device_policy_concurrent_cas_and_global_inheritance(mysql_store):
    devices, client, auth = setup_devices(mysql_store)
    target, other = [d["deviceId"] for d in devices]
    initial = mysql_store.policy()
    update = DevicePolicyUpdateRequest(expectedVersion=initial["policyVersion"],
        overrides={"allowlistedBaseUrls": []})
    def save(_):
        from controlserver.validation import ApiProblem
        try:
            return mysql_store.device_policy(target, update, "test")["effectivePolicy"]
        except ApiProblem as exc:
            assert exc.code == "POLICY_VERSION_CONFLICT"
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        successful = [p for p in pool.map(save, range(4)) if p]
    assert len(successful) == 1
    global_update = PolicyUpdateRequest(expectedVersion=initial["policyVersion"],
        **{k:v for k,v in initial.items() if k in PolicyUpdateRequest.model_fields},)
    global_update.gatewayOrigin = "https://new-global.example.com"
    new_global = mysql_store.update_policy(global_update)
    assert new_global["policyVersion"] > successful[0]["policyVersion"]
    effective = mysql_store.policy(target)
    assert effective["policyVersion"] == new_global["policyVersion"]
    assert effective["policyVersion"] > successful[0]["policyVersion"]
    assert effective["gatewayOrigin"] == new_global["gatewayOrigin"]
    assert effective["allowlistedBaseUrls"] == []
    assert mysql_store.policy(other) == new_global
    assert mysql_store.policy(target) == effective


def test_device_policy_detail_refreshes_stale_override_before_update(mysql_store):
    devices, _, _ = setup_devices(mysql_store)
    target = devices[0]['deviceId']
    initial = mysql_store.policy()
    current = mysql_store.device_policy(target, DevicePolicyUpdateRequest(
        expectedVersion=initial['policyVersion'], overrides={'allowlistedBaseUrls': []}), 'test')
    update = PolicyUpdateRequest(expectedVersion=initial['policyVersion'],
        **{k: v for k, v in initial.items() if k in PolicyUpdateRequest.model_fields})
    update.gatewayOrigin = 'https://new-global.example.com'
    global_policy = mysql_store.update_policy(update)
    refreshed = mysql_store.device_policy(target)
    assert refreshed['effectivePolicy']['policyVersion'] > current['effectivePolicy']['policyVersion']
    assert refreshed['effectivePolicy']['policyVersion'] >= global_policy['policyVersion']
    assert refreshed['effectivePolicy']['gatewayOrigin'] == global_policy['gatewayOrigin']
    assert refreshed['overrides']['allowlistedBaseUrls'] == []
    changed = mysql_store.device_policy(target, DevicePolicyUpdateRequest(
        expectedVersion=refreshed['effectivePolicy']['policyVersion'], overrides={}), 'test')
    assert changed['effectivePolicy']['policyVersion'] > refreshed['effectivePolicy']['policyVersion']


@pytest.mark.parametrize("overrides", [
    {"gatewayOrigin": "https://user:secret@example.com"},
    {"gatewayOrigin": "https://example.com/path"},
    {"gatewayOrigin": "http://example.com", "allowInsecureGateway": False},
    {"allowlistedBaseUrls": ["https://example.com?secret=value"]},
])
def test_invalid_device_policy_is_atomic(mysql_store, overrides):
    devices, client, auth = setup_devices(mysql_store)
    target = devices[0]["deviceId"]
    before = mysql_store.policy()
    result = client.put(f"/admin/v1/devices/{target}/policy", headers=auth,
        json=dict(expectedVersion=before["policyVersion"], overrides={"routeMode":"fixedGateway", **overrides}))
    assert result.status_code == 400
    assert mysql_store.policy(target) == mysql_store.policy() == before
    assert not mysql_store.audits(target, 0, 100)


def test_device_policy_admin_auth_and_enrollment_required(mysql_store):
    devices, client, auth = setup_devices(mysql_store)
    path = f"/admin/v1/devices/{devices[0]['deviceId']}/policy"
    assert client.get(path).status_code == 401
    assert client.get(f"/admin/v1/devices/{uuid4()}/policy", headers=auth).status_code == 404
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE device_credentials SET revoked=1 WHERE device_id=%s", (devices[0]["deviceId"],))
    assert client.get(path, headers=auth).status_code == 404


def test_schema_two_migration_preserves_global_and_credentials(mysql_store):
    devices, _, _ = setup_devices(mysql_store)
    before = mysql_store.policy()
    with mysql_store.transaction() as cur:
        cur.execute("DROP TABLE device_policy_state")
        cur.execute("UPDATE schema_migrations SET version=2,checksum=%s", (SCHEMA_2_CHECKSUM,))
    assert mysql_store.migrate() == "migrated"
    assert mysql_store.migrate() == "already_migrated"
    assert mysql_store.policy() == before
    assert mysql_store.authenticate(devices[0]["deviceId"], devices[0]["deviceToken"])
    assert not mysql_store.device_policy(devices[0]["deviceId"])["hasOverride"]


def test_distinct_device_versions_and_invalid_global_merge_are_atomic(mysql_store):
    devices, client, auth = setup_devices(mysql_store)
    before = mysql_store.policy()
    versions = []
    for device in devices:
        result = client.put(f"/admin/v1/devices/{device['deviceId']}/policy", headers=auth,
            json=dict(expectedVersion=before["policyVersion"], overrides=dict(routeMode="fixedGateway",
                gatewayOrigin="http://isolated.example.com", allowInsecureGateway=True)))
        assert result.status_code == 200
        versions.append(result.json["effectivePolicy"]["policyVersion"])
    assert versions[1] > versions[0] > before["policyVersion"]
    # A partial override can inherit a field; changing the global base must still validate the merge.
    target = devices[0]["deviceId"]
    result = client.put(f"/admin/v1/devices/{target}/policy", headers=auth,
        json=dict(expectedVersion=versions[0], overrides=dict(routeMode="fixedGateway",
            gatewayOrigin="http://isolated.example.com")))
    assert result.status_code == 200
    payload = {k:v for k,v in before.items() if k in PolicyUpdateRequest.model_fields}
    payload.update(expectedVersion=before["policyVersion"], gatewayOrigin="https://global.example.com",
        allowInsecureGateway=False)
    assert client.put("/admin/v1/policy", headers=auth, json=payload).status_code == 400
    assert mysql_store.policy() == before
    assert mysql_store.policy(target) == result.json["effectivePolicy"]
