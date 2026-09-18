from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from controlserver.analytics import build, drill_down, provider, online_state
from controlserver.security import timestamp

NOW = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)
POLICY = dict(policyVersion=2, allowlistedBaseUrls=["https://api.openai.com/v1"])


def terminal(device="one", state="connectionFailed", seen=NOW):
    return dict(device=dict(deviceId=device, hostname=device, osVersion="Windows 11", serviceVersion="0.1.22",
        lastSeenAtUtc=timestamp(seen), heartbeatIntervalSeconds=60, schemaVersion=2, appliedPolicyVersion=2,
        proxyState="listening", operationState="enabled"),
        agents=[dict(instanceId="i", agentType="claudeCli", running=True, installed=True)],
        endpoints=[dict(assetId="a", agentFamily="claude", isCurrent=True, originalTargetBaseUrl="https://api.openai.com/v1",
            effectiveConfiguredBaseUrl="https://gateway.example", routeStatus="attached", observedAtUtc=timestamp(seen))],
        activity=[dict(assetId="a", state=state, requestCountSinceBoot=1, failureCountSinceBoot=1,
            lastRequestAtUtc=timestamp(seen), lastHttpStatusCode=502)])


def test_coverage_instance_dedup_offline_tools():
    row = terminal()
    row["agents"] += [deepcopy(row["agents"][0]), dict(instanceId="j", agentType="claudeIde", running=True),
                      dict(instanceId="s", agentType="ccSwitch", running=True),
                      dict(instanceId="u", agentType="unknownCandidate", running=True)]
    data = build([row, deepcopy(row), terminal("offline", seen=NOW-timedelta(hours=1))], POLICY, NOW)
    assert data["totalDevices"] == data["runningAgentDevices"] == 1
    assert data["agents"][0]["deviceCount"] == 1
    assert data["agents"][0]["instanceCount"] == 2
    assert data["agents"][0]["instancePercentage"] == 100
    assert data["tools"][0]["label"] == "CC Switch"
    assert build([row, terminal("offline", seen=NOW-timedelta(hours=1))], POLICY, NOW, scope="offline")["totalDevices"] == 1


def test_original_provider_and_observed_vs_current():
    row = terminal()
    row["activity"] = []
    assert build([row], POLICY, NOW)["providers"] == []
    assert build([row], POLICY, NOW, provider_mode="configured")["providers"][0]["key"] == "OpenAI"
    row["activity"] = terminal()["activity"]
    row["endpoints"][0]["isCurrent"] = False
    assert build([row], POLICY, NOW)["providers"][0]["key"] == "OpenAI"
    assert build([row], POLICY, NOW, provider_mode="configured")["providers"] == []


@pytest.mark.parametrize("url,name", [("https://api.openai.com/v1", "OpenAI"),
    ("https://ark.cn-beijing.volces.com/api/v3", "火山云"), ("https://api.moonshot.ai/v1", "Kimi"),
    ("https://api.openai.com.evil.example", "未知/中转 · api.openai.com.evil.example"),
    ("https://relay.example/v1", "未知/中转 · relay.example"), (None, "无法识别")])
def test_provider_domains(url, name):
    assert provider(url) == name


def test_failure_recovery_retained_state_mount_and_no_request():
    failed, recovered, empty = terminal(), terminal("recovered", "succeeded"), terminal("empty", "neverObserved")
    empty["activity"] = []
    empty["endpoints"][0]["routeStatus"] = "error"
    failed["activity"][0]["requestCountSinceBoot"] = 0
    failed["activity"][0]["failureCountSinceBoot"] = 0
    data = build([failed, recovered, empty], POLICY, NOW)
    assert data["anomalyDevices"] == 1
    assert data["everAnomalyDevices"] == 1
    assert data["otherUnproxiedDevices"] == 1
    assert data["unknownDevices"] == 1
    assert data["errors"][0]["key"] == "ConnectionFailed"
    assert drill_down([failed, recovered, empty], NOW, kind="error", key="ConnectionFailed")["total"] == 1
    assert drill_down([failed, recovered, empty], NOW, anomaly="none")["total"] == 1


def test_allowlist_exact_normalization_dedup_and_legacy():
    row = terminal()
    row["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed", originalTargetBaseUrl="https://API.OPENAI.COM:443/v1/")
    row["endpoints"].append(dict(row["endpoints"][0], assetId="b"))
    row["activity"][0]["state"] = "allowlistBypassed"
    legacy = dict(device=dict(terminal("legacy")["device"], schemaVersion=1))
    data = build([row, legacy], POLICY, NOW)
    assert data["allowlistDevices"] == 1
    assert data["allowlist"][0]["deviceCount"] == 1
    assert data["providers"] == []
    assert data["legacyDevices"] == 1
    assert drill_down([row, legacy], NOW, kind="allowlist", key=POLICY["allowlistedBaseUrls"][0])["total"] == 1


def test_chart_and_drilldown_pagination_same_filters():
    rows = [terminal(str(i)) for i in range(30)]
    data = build(rows, POLICY, NOW, os="windows")
    for kind, bucket in (("agent", data["agents"][0]), ("provider", data["providers"][0]), ("error", data["errors"][0])):
        page = drill_down(rows, NOW, os="windows", kind=kind, key=bucket["key"], skip=25, take=25)
        assert page["total"] == bucket["deviceCount"] == 30
        assert len(page["devices"]) == 5
    assert drill_down(rows, NOW, os="linux")["total"] == 0
    assert online_state(terminal()["device"], NOW+timedelta(seconds=151)) == "stale"


def test_store_batch_snapshot(mysql_store):
    from controlserver.models import HeartbeatV2Request
    import json
    from pathlib import Path
    heartbeat = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(heartbeat), 60, "127.0.0.1")
    rows, policy = mysql_store.analytics_snapshot()
    assert len(rows) == 1
    original = mysql_store.details(rows[0]["device"]["deviceId"])
    assert rows[0]["device"] == original["device"]
    assert rows[0]["agents"] == original["agents"]
    assert rows[0]["endpoints"] == original["endpoints"]
    assert rows[0]["activity"] == original["activity"]
    assert policy == mysql_store.policy()


def test_analytics_http_auth_pagination_and_counts(mysql_store):
    from app import create_app
    from controlserver.models import HeartbeatV2Request
    from controlserver.transport import INTERNAL
    from pathlib import Path
    from uuid import uuid4
    import json
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    for i in range(30):
        value = deepcopy(body)
        value["device"]["deviceId"] = str(uuid4())
        value["device"]["hostname"] = f"analytics-{i}"
        value["heartbeatId"] = str(uuid4())
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, "127.0.0.1")
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    client.environ_base["endpointai.transport"] = INTERNAL
    auth = {"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}
    assert client.get("/admin/v1/analytics").status_code == 401
    assert client.get("/admin/v1/analytics/devices").status_code == 401
    result = client.get("/admin/v1/analytics", headers=auth)
    assert result.status_code == 200
    data = result.json
    assert data["totalDevices"] == 30
    for kind, buckets in (("agent", data["agents"]), ("provider", data["providers"]),
                          ("error", data["errors"]), ("allowlist", data["allowlist"])):
        for bucket in buckets:
            page = client.get("/admin/v1/analytics/devices", headers=auth,
                query_string=dict(kind=kind, key=bucket["key"], skip=25, take=25))
            assert page.status_code == 200
            assert page.json["total"] == bucket["deviceCount"]
            assert len(page.json["devices"]) == max(0, bucket["deviceCount"]-25)
    assert client.get("/admin/v1/analytics?scope=invalid", headers=auth).status_code == 400
    assert client.get("/admin/v1/analytics/devices?skip=invalid", headers=auth).status_code == 400
