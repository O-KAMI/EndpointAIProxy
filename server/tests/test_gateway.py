from app import create_app
from controlserver.database import ControlStore


def test_gateway_update_preserves_policy_and_rejects_stale_or_invalid_update(mysql_store):
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    auth = {"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}
    old = client.get("/admin/v1/policy", headers=auth).json
    fields = ("enabled", "routeMode", "gatewayOrigin", "allowInsecureGateway",
              "pollIntervalSeconds", "heartbeatIntervalSeconds", "allowlistedBaseUrls")
    payload = {k: old[k] for k in fields}
    payload.update(expectedVersion=old["policyVersion"], gatewayOrigin="http://10.220.22.112:30080")
    updated = client.put("/admin/v1/policy", headers=auth, json=payload)
    assert updated.status_code == 200
    assert updated.json["policyVersion"] == old["policyVersion"] + 1
    for key in fields:
        if key != "gatewayOrigin":
            assert updated.json[key] == old[key]
    assert ControlStore(mysql_store.cfg).policy() == updated.json
    assert client.put("/admin/v1/policy", headers=auth, json=payload).status_code == 409
    payload["expectedVersion"] = updated.json["policyVersion"]
    for invalid in ("http://example.com/v1", "http://user:pass@example.com", "ftp://example.com"):
        payload["gatewayOrigin"] = invalid
        assert client.put("/admin/v1/policy", headers=auth, json=payload).status_code == 400
    payload["gatewayOrigin"] = "http://10.220.22.112:30080"
    payload["allowInsecureGateway"] = False
    assert client.put("/admin/v1/policy", headers=auth, json=payload).status_code == 400
    payload.update(gatewayOrigin=old["gatewayOrigin"], allowInsecureGateway=old["allowInsecureGateway"])
    reverted = client.put("/admin/v1/policy", headers=auth, json=payload)
    assert reverted.status_code == 200
    assert reverted.json["gatewayOrigin"] == old["gatewayOrigin"]
