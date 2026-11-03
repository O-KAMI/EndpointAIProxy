from concurrent.futures import ThreadPoolExecutor
import base64
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from controlserver.database import ControlStore, employee_ids
from controlserver.models import DevicePolicyUpdateRequest, PolicyUpdateRequest
from controlserver.security import sign_policy
from controlserver.validation import (ApiProblem, domain_policy, matching_domain,
    normalize_domain, normalize_routing_rules, validate_policy)
from test_device_policy import setup_devices


@pytest.mark.parametrize("value,want", [
    ("OpenAI.COM.", "openai.com"), ("例子.公司", "xn--fsqu00a.xn--55qx5d"),
    ("[2001:0db8::1]", "2001:db8::1"), ("127.0.0.1", "127.0.0.1"),
])
def test_domain_normalization(value, want):
    assert normalize_domain(value) == want


@pytest.mark.parametrize("value", ["", "*.openai.com", "https://openai.com", "openai.com:443",
    "openai.com/v1", "a..com", "-a.com", "a_.com"])
def test_domain_rejects_non_hosts(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


@pytest.mark.parametrize("target,want", [
    ("https://openai.com", "openai.com"), ("http://API.OpenAI.COM.:8000/v1", "openai.com"),
    ("https://fakeopenai.com", None), ("https://openai.com.evil.com", None),
    ("https://evil.com/openai.com", None), ("http://127.0.0.1:9999/v1", "127.0.0.1"),
    ("http://foo.127.0.0.1", None), ("http://[2001:db8::1]:8080", "2001:db8::1"),
])
def test_domain_boundaries(target, want):
    assert matching_domain(target, ["openai.com", "127.0.0.1", "2001:db8::1"]) == want


def test_legacy_migration_is_idempotent_and_preserves_compatibility():
    old = dict(allowlistedBaseUrls=["https://api.openai.com/v1", "http://api.openai.com:8080/v2"])
    new = domain_policy(old)
    assert new["allowlistedDomains"] == ["api.openai.com"]
    assert new["allowlistedBaseUrls"] == old["allowlistedBaseUrls"]
    assert len(new["allowlistMigration"]) == 2
    assert domain_policy(new) == new
    assert "allowlistedDomains" not in old


def test_rule_validation_includes_inherited_gateway_and_duplicates(config):
    from controlserver.validation import seed_policy
    p = seed_policy(config)
    p.pop("schemaVersion"); p.pop("serverInstanceId"); p.pop("policyVersion"); p.pop("issuedAtUtc")
    p.update(expectedVersion=1, routeMode="passthroughOriginal", gatewayOrigin="https://default.example", allowInsecureGateway=False,
        routingRules=[dict(domain="openai.com", routeMode="fixedGateway")])
    validate_policy(PolicyUpdateRequest(**p))
    p["gatewayOrigin"] = None
    with pytest.raises(ApiProblem):
        validate_policy(PolicyUpdateRequest(**p))
    p["routingRules"][0]["gatewayOrigin"] = "http://other.example"
    with pytest.raises(ApiProblem):
        validate_policy(PolicyUpdateRequest(**p))
    p["allowInsecureGateway"] = True
    validate_policy(PolicyUpdateRequest(**p))
    with pytest.raises(ValueError):
        normalize_routing_rules([dict(domain=d, routeMode="passthroughOriginal") for d in ["OpenAI.COM.", "openai.com"]])


def test_employee_ids_preserve_leading_zero_deduplicate_and_reject_fallbacks():
    assert employee_ids([dict(accountName=a) for a in ["00123", "SF\\00123", "00456", "", "SYSTEM",
        "S-1-5-21-123", "macos:example", "Administrator", "A00123", "NT AUTHORITY\\SYSTEM"]]) == ["00123", "00456", "A00123"]
    assert employee_ids(None) == []


def test_schema_negotiation_scoped_versions_signatures_and_reset(mysql_store):
    devices, client, auth = setup_devices(mysql_store)
    target, other = devices
    path = f'/api/v2/devices/{target["deviceId"]}/policy'
    device_auth = {"Authorization": "Bearer " + target["deviceToken"]}
    global_before = mysql_store.policy()
    old = client.get(path, headers=device_auth)
    assert old.json["schemaVersion"] == 1
    assert "allowlistedDomains" not in old.json
    new = client.get(path + "?policySchemaVersion=2", headers=device_auth)
    assert new.status_code == 200 and new.json["schemaVersion"] == 2
    assert new.json["policyVersion"] > old.json["policyVersion"]
    assert new.headers["X-SF-Policy-Signature"] == sign_policy(new.data, mysql_store.cfg.POLICY_HMAC_KEY)
    assert client.get(path + "?policySchemaVersion=2", headers=device_auth).json == new.json
    assert mysql_store.policy() == mysql_store.policy(other["deviceId"]) == global_before
    assert ControlStore(mysql_store.cfg).policy(target["deviceId"])["schemaVersion"] == 2
    admin_path = f'/admin/v1/devices/{target["deviceId"]}/policy'
    result = client.put(admin_path, headers=auth, json=dict(expectedVersion=new.json["policyVersion"],
        overrides=dict(allowlistedDomains=[], routingRules=[dict(domain="openai.com", routeMode="passthroughOriginal")])) )
    assert result.status_code == 200
    scoped = result.json["effectivePolicy"]
    assert scoped["schemaVersion"] == 2 and scoped["allowlistedDomains"] == []
    assert mysql_store.policy(other["deviceId"]) == global_before
    reset = client.delete(admin_path, headers=auth, json=dict(expectedVersion=scoped["policyVersion"]))
    assert reset.status_code == 200 and not reset.json["hasOverride"]
    effective = reset.json["effectivePolicy"]
    assert effective["schemaVersion"] == 2 and effective["policyVersion"] > scoped["policyVersion"]
    assert effective["allowlistedDomains"] == global_before["allowlistedDomains"]


def test_schema_negotiation_is_idempotent_across_workers(mysql_store):
    devices, _, _ = setup_devices(mysql_store)
    target = devices[0]["deviceId"]
    def negotiate(_):
        return ControlStore(mysql_store.cfg).policy(target, schema_version=2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        policies = list(pool.map(negotiate, range(8)))
    assert all(p == policies[0] for p in policies)


def test_stateless_policy_negotiation_and_global_update_preserve_watermarks(mysql_store):
    devices, client, admin = setup_devices(mysql_store)
    old, new = devices
    initial = mysql_store.policy()
    new_auth = {"Authorization": "Bearer " + new["deviceToken"]}
    new_path = f'/api/v2/devices/{new["deviceId"]}/policy?policySchemaVersion=2&statelessPolicyVersions=1'
    first = client.get(new_path, headers=new_auth)
    assert first.status_code == 200
    assert first.json["schemaVersion"] == 2 and first.json["policyVersion"] == initial["policyVersion"]
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM device_policy_state WHERE device_id=%s", (new["deviceId"],))
        assert cur.fetchone()["n"] == 0
    old_policy = mysql_store.policy(old["deviceId"], schema_version=2)
    old_state = mysql_store.device_policy(old["deviceId"], DevicePolicyUpdateRequest(
        expectedVersion=old_policy["policyVersion"], overrides={"allowlistedDomains": []}), "test")
    update = PolicyUpdateRequest(expectedVersion=initial["policyVersion"],
        **{k:v for k,v in initial.items() if k in PolicyUpdateRequest.model_fields})
    update.gatewayOrigin = "https://new-global.example.com"
    updated = mysql_store.update_policy(update, "test")
    assert updated["policyVersion"] > old_state["effectivePolicy"]["policyVersion"]
    effective = mysql_store.policy(old["deviceId"], schema_version=2, stateless=True)
    assert effective["policyVersion"] == updated["policyVersion"]
    assert effective["allowlistedDomains"] == []
    with mysql_store.transaction() as cur:
        cur.execute("SELECT base_policy_version,effective_policy_version FROM device_policy_state WHERE device_id=%s", (old["deviceId"],))
        state_before = cur.fetchone()
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda _: mysql_store.policy(old["deviceId"], schema_version=2, stateless=True), range(12)))
    assert all(value == effective for value in values)
    with mysql_store.transaction() as cur:
        cur.execute("SELECT base_policy_version,effective_policy_version FROM device_policy_state WHERE device_id=%s", (old["deviceId"],))
        assert cur.fetchone() == state_before
    assert client.get(new_path, headers=new_auth).json["policyVersion"] == updated["policyVersion"]


def test_heartbeat_advertises_stateless_policy_and_accepts_opt_in(mysql_store):
    from pathlib import Path
    devices, client, _ = setup_devices(mysql_store)
    device = devices[0]
    headers = {"Authorization": "Bearer " + device["deviceToken"]}
    heartbeat = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    heartbeat["device"]["deviceId"] = device["deviceId"]
    first = client.post("/api/v2/heartbeat", headers=headers, json=heartbeat)
    assert first.status_code == 200 and first.json["statelessPolicyVersions"] is True
    heartbeat["statelessPolicyVersions"] = True
    second = client.post("/api/v2/heartbeat", headers=headers, json=heartbeat)
    assert second.status_code == 200
    assert second.json["acceptedPolicyVersion"] == mysql_store.policy()["policyVersion"]
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM device_policy_state WHERE device_id=%s", (device["deviceId"],))
        assert cur.fetchone()["n"] == 0


def test_domain_override_null_rejected():
    for field in ("allowlistedDomains", "routingRules"):
        with pytest.raises(ValidationError):
            DevicePolicyUpdateRequest(expectedVersion=1, overrides={field: None})


def test_encrypted_schema_negotiation_preserves_query_and_raw_signature(mysql_store):
    from controlserver.transport import b64, seal, open_envelope
    devices, client, _ = setup_devices(mysql_store)
    device = devices[0]
    cfg = mysql_store.cfg
    request_id = str(uuid4())
    envelope = seal(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, request_id,
        dict(method="GET", path=f'/api/v2/devices/{device["deviceId"]}/policy',
             query="policySchemaVersion=2", token=device["deviceToken"], body=b64(b"")), "request")
    outer = client.post("/api/transport/v1", json=envelope)
    assert outer.status_code == 200
    inner = open_envelope(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, outer.json, "response", request_id)
    assert inner["status"] == 200
    body = base64.b64decode(inner["body"])
    assert json.loads(body)["schemaVersion"] == 2
    assert inner["headers"]["X-SF-Policy-Signature"] == sign_policy(body, cfg.POLICY_HMAC_KEY)


def test_legacy_global_update_cannot_invalidate_retained_routing_rules(mysql_store):
    current = mysql_store.policy()
    fields = {k:v for k,v in current.items() if k in PolicyUpdateRequest.model_fields}
    initial = PolicyUpdateRequest(expectedVersion=current["policyVersion"], **{**fields,
        "routeMode": "fixedGateway", "gatewayOrigin": "https://default.example",
        "routingRules": [dict(domain="openai.com", routeMode="fixedGateway")]})
    saved = mysql_store.update_policy(initial)
    # A legacy administrator does not send routingRules; the existing rules survive.
    legacy = PolicyUpdateRequest(expectedVersion=saved["policyVersion"], **{**fields,
        "routeMode": "passthroughOriginal", "gatewayOrigin": None, "routingRules": None})
    with pytest.raises(ApiProblem):
        mysql_store.update_policy(legacy)
    assert mysql_store.policy() == saved
