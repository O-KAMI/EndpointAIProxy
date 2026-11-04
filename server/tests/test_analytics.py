from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from controlserver.analytics import build, build_batches, build_partitions, merge_partitions, drill_down, provider, online_state
from controlserver.security import timestamp

NOW = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)
POLICY = dict(policyVersion=2, allowlistedBaseUrls=[])
ALLOWLIST_POLICY = dict(policyVersion=2, allowlistedBaseUrls=["https://api.openai.com/v1"])


def terminal(device="one", state="connectionFailed", seen=NOW):
    return dict(device=dict(deviceId=device, hostname=device, osVersion="Windows 11", serviceVersion="0.1.22",
        lastSeenAtUtc=timestamp(seen), heartbeatIntervalSeconds=60, schemaVersion=2, appliedPolicyVersion=2,
        proxyState="listening", operationState="enabled"),
        runtime=dict(lastReconcileResult="completed", lastReconcileErrorCode=None),
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


def test_applied_policy_uses_each_devices_expected_version():
    scoped, stale, inherited = terminal("scoped"), terminal("stale"), terminal("inherited")
    scoped["device"].update(expectedPolicyVersion=9, appliedPolicyVersion=9)
    stale["device"].update(expectedPolicyVersion=None, appliedPolicyVersion=8)
    data = build([scoped, stale, inherited], POLICY, NOW)
    assert data["policy"]["appliedDevices"] == 2
    assert data["policy"]["pendingDevices"] == 1


def test_applied_policy_requires_successful_reconciliation():
    completed, legacy, failed, missing = (terminal(name) for name in ("completed", "legacy", "failed", "missing"))
    legacy["runtime"]["lastReconcileResult"] = "SUCCESS"
    failed["runtime"].update(lastReconcileResult="failed", lastReconcileErrorCode="CONFIG_ERROR")
    missing["runtime"] = None
    data = build([completed, legacy, failed, missing], POLICY, NOW)
    assert data["policy"]["appliedDevices"] == 2
    assert data["policy"]["pendingDevices"] == 2


def test_drill_down_searches_employee_ids_without_losing_leading_zeroes():
    row = terminal()
    row["device"]["employeeIds"] = ["00123"]
    assert drill_down([row], POLICY, NOW, search="00123")["total"] == 1
    assert drill_down([row], POLICY, NOW, search="99999")["total"] == 0


def test_domain_analytics_uses_effective_rules_and_actual_client_capability():
    row = terminal(state="neverObserved")
    row["device"].update(appliedPolicySchemaVersion=2, supportedPolicySchemaVersion=2)
    row["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed")
    row["effectivePolicy"] = dict(allowlistedDomains=["openai.com", "api.openai.com"], allowlistedBaseUrls=[])
    policy = dict(policyVersion=2, allowlistedDomains=["unrelated.example"], routingRules=[])
    data = build([row], policy, NOW)
    assert data["allowlistDevices"] == 1
    assert data["allowlist"][0]["key"] == "api.openai.com"
    assert data["policy"]["appliedDevices"] == 1
    assert drill_down([row], policy, NOW, kind="allowlist", key="api.openai.com")["total"] == 1
    row["device"].update(appliedPolicySchemaVersion=1, supportedPolicySchemaVersion=1)
    data = build([row], policy, NOW)
    assert data["policy"]["appliedDevices"] == 0
    assert data["policy"]["unsupportedDevices"] == 1


def test_current_targets_include_unrequested_and_exclude_inactive():
    row = terminal()
    row["activity"] = []
    assert build([row], POLICY, NOW)["providers"][0]["key"] == "OpenAI"
    row["endpoints"][0]["isCurrent"] = False
    assert build([row], POLICY, NOW)["providers"] == []


@pytest.mark.parametrize("url,name", [("https://api.openai.com/v1", "OpenAI"),
    ("https://ark.cn-beijing.volces.com/api/v3", "火山云"), ("https://api.moonshot.ai/v1", "Kimi"),
    ("https://api.openai.com.evil.example", "自定义目标 · api.openai.com.evil.example"),
    ("https://relay.example/v1", "自定义目标 · relay.example"),
    ("http://127.0.0.1:18080/r/example", "本地代理地址 · 127.0.0.1"), (None, "无法识别")])
def test_provider_domains(url, name):
    assert provider(url) == name


def test_allowlisted_internal_targets_use_exact_base_url_matching():
    policy = dict(policyVersion=3, allowlistedBaseUrls=[
        "http://claudecode.sf-express.com/ccr", "http://llm-model-hub-apis.sf-express.com"])
    row = terminal()
    row["endpoints"] = [
        dict(row["endpoints"][0], assetId="a", originalTargetBaseUrl="http://claudecode.sf-express.com/ccr"),
        dict(row["endpoints"][0], assetId="b", originalTargetBaseUrl="http://llm-model-hub-apis.sf-express.com"),
        dict(row["endpoints"][0], assetId="c", originalTargetBaseUrl="http://claudecode.sf-express.com/other")]
    keys = {item["key"] for item in build([row], policy, NOW)["providers"]}
    assert "白名单目标 · claudecode.sf-express.com" in keys
    assert "白名单目标 · llm-model-hub-apis.sf-express.com" in keys
    assert "自定义目标 · claudecode.sf-express.com" in keys


def test_current_failure_recovery_retained_state_mount_and_no_request():
    failed, retained, recovered, empty = terminal(), terminal("retained"), terminal("recovered", "succeeded"), terminal("empty", "neverObserved")
    empty["activity"] = []
    empty["endpoints"][0]["routeStatus"] = "error"
    retained["activity"][0]["requestCountSinceBoot"] = 0
    retained["activity"][0]["failureCountSinceBoot"] = 0
    data = build([failed, retained, recovered, empty], POLICY, NOW)
    assert data["anomalyDevices"] == 1
    assert data["everAnomalyDevices"] == 2
    assert data["otherUnproxiedDevices"] == 1
    assert data["unknownDevices"] == 1
    assert data["errors"][0]["key"] == "ConnectionFailed"
    assert drill_down([failed, retained, recovered, empty], POLICY, NOW, kind="error", key="ConnectionFailed")["total"] == 1
    assert drill_down([failed, retained, recovered, empty], POLICY, NOW, anomaly="none")["total"] == 2
    retained_request = drill_down([retained], POLICY, NOW)["devices"][0]["requests"][0]
    assert retained_request["resultScope"] == "previousRun"
    assert retained_request["currentAnomaly"] is False


def test_failure_stops_being_current_when_bypassed_or_inactive():
    bypassed_row, inactive = terminal("bypassed"), terminal("inactive")
    bypassed_row["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed")
    inactive["endpoints"][0]["isCurrent"] = False
    data = build([bypassed_row, inactive], ALLOWLIST_POLICY, NOW)
    assert data["anomalyDevices"] == 0
    assert data["errors"] == []


def test_allowlist_exact_normalization_dedup_and_legacy():
    row = terminal()
    row["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed", originalTargetBaseUrl="https://API.OPENAI.COM:443/v1/")
    row["endpoints"].append(dict(row["endpoints"][0], assetId="b"))
    row["activity"][0]["state"] = "allowlistBypassed"
    legacy = dict(device=dict(terminal("legacy")["device"], schemaVersion=1))
    data = build([row, legacy], ALLOWLIST_POLICY, NOW)
    assert data["allowlistDevices"] == 1
    assert data["allowlist"][0]["deviceCount"] == 1
    assert data["providers"][0]["key"] == "白名单目标 · api.openai.com"
    assert data["legacyDevices"] == 1
    assert drill_down([row, legacy], ALLOWLIST_POLICY, NOW, kind="allowlist", key=ALLOWLIST_POLICY["allowlistedBaseUrls"][0])["total"] == 1


def test_chart_and_drilldown_pagination_same_filters():
    rows = [terminal(str(i)) for i in range(30)]
    data = build(rows, POLICY, NOW, os="windows")
    for kind, bucket in (("agent", data["agents"][0]), ("provider", data["providers"][0]), ("error", data["errors"][0])):
        page = drill_down(rows, POLICY, NOW, os="windows", kind=kind, key=bucket["key"], skip=25, take=25)
        assert page["total"] == bucket["deviceCount"] == 30
        assert len(page["devices"]) == 5
    assert drill_down(rows, POLICY, NOW, os="linux")["total"] == 0
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
    assert rows[0]["device"]["expectedPolicyVersion"] == policy["policyVersion"]
    assert {k:v for k,v in rows[0]["device"].items() if k not in ("expectedPolicyVersion", "expectedPolicySchemaVersion")} == original["device"]
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
    assert client.get("/admin/v1/analytics?providerMode=observed", headers=auth).status_code == 400
    assert client.get("/admin/v1/analytics/devices?skip=invalid", headers=auth).status_code == 400


def test_database_page_matches_full_snapshot_for_scopes_and_pagination(mysql_store):
    import json
    from pathlib import Path
    from uuid import uuid4
    from controlserver.database import dbtime
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    now = utcnow()
    for i in range(6):
        value = deepcopy(body)
        value["device"]["deviceId"] = str(uuid4())
        value["device"]["hostname"] = f"page-fixture-{i}"
        value["users"][0]["accountName"] = ("sf\\00123", " \tadministrator\t ", "sf\\00456", "macos:user", "other", "Jöhn")[i]
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, "127.0.0.1")
        with mysql_store.transaction() as cur:
            cur.execute("UPDATE device_heartbeats SET received_at_utc=%s WHERE device_id=%s",
                        (dbtime(now - timedelta(seconds=(10, 180, 600)[i % 3])), value["device"]["deviceId"]))
    rows, policy = mysql_store.analytics_snapshot()
    dashboard = mysql_store.dashboard(now)
    assert (dashboard["totalDevices"], dashboard["online"], dashboard["stale"], dashboard["offline"]) == (6, 2, 2, 2)
    assert dashboard["legacyClients"] == dashboard["proxyDisabled"] == 0
    for scope in ("all", "online", "stale", "offline", "legacyclient"):
        for skip in (0, 1, 10):
            expected = drill_down(rows, policy, now, scope=scope, os="windows", skip=skip, take=2)
            selected, page_policy, total = mysql_store.analytics_page(scope, "windows", now, skip, 2)
            actual = drill_down(selected, page_policy, now, scope="all", take=2)
            assert total == expected["total"]
            assert actual["devices"] == expected["devices"]

    for search in ("00123", "administrator", "fixture-", "macos", "other", "john", "jöhn"):
        expected = drill_down(rows, policy, now, scope="all", search=search, take=50)
        selected, page_policy, total = mysql_store.analytics_page("all", None, now, 0, 50, employee_search=search)
        actual = drill_down(selected, page_policy, now, scope="all", take=50)
        assert total == expected["total"]
        assert actual["devices"] == expected["devices"]

    def check_search_pages():
        for search in ("fixture-", "00123", "no-such-device"):
            for skip in (0, 1, 10):
                expected = drill_down(rows, policy, now, scope="all", search=search, skip=skip, take=2)
                selected, page_policy, total = mysql_store.analytics_page("all", None, now, skip, 2, employee_search=search)
                actual = drill_down(selected, page_policy, now, scope="all", take=2)
                assert total == expected["total"]
                assert actual["devices"] == expected["devices"]

    check_search_pages()
    mysql_store.ensure_scale_indexes()
    mysql_store.cfg.EMPLOYEE_INDEX = True
    mysql_store.check_schema()
    for search in ("00123", "administrator", "fixture-", "macos", "other", "john", "jöhn"):
        expected = drill_down(rows, policy, now, scope="all", search=search, take=50)
        selected, page_policy, total = mysql_store.analytics_page("all", None, now, 0, 50, employee_search=search)
        actual = drill_down(selected, page_policy, now, scope="all", take=50)
        assert total == expected["total"]
        assert actual["devices"] == expected["devices"]
    check_search_pages()
    value["users"][0]["accountName"] = "updated-employee"
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, "127.0.0.1")
    _, _, total = mysql_store.analytics_page("all", None, now, 0, 50, employee_search="updated-employee")
    assert total == 1
    with mysql_store.transaction() as cur:
        cur.execute("DELETE FROM employee_search_index WHERE device_id=%s", (value["device"]["deviceId"],))
    with pytest.raises(RuntimeError, match="incomplete"):
        mysql_store.check_schema()
    mysql_store.ensure_scale_indexes()
    mysql_store.check_schema()
    _, _, total = mysql_store.analytics_page("all", None, now, 0, 50, employee_search="updated-employee")
    assert total == 1

    from app import create_app
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    auth = {"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}
    result = client.get("/admin/v1/devices", headers=auth,
                        query_string={"search": "page-fixture-", "take": 2, "skip": 1})
    assert result.status_code == 200
    assert result.headers["X-Total-Count"] == "6"
    assert len(result.json) == 2
    assert all("page-fixture-" in item["hostname"] for item in result.json)
    assert "expectedPolicyVersion" not in result.json[0]


def test_expensive_search_shares_complex_query_budget_and_releases_it(mysql_store, monkeypatch):
    import hashlib
    from app import create_app
    from controlserver.security import utcnow
    from controlserver.validation import ApiProblem
    now = utcnow()
    lock = 'eai-complex-' + hashlib.sha256(mysql_store.cfg.MYSQL_DATABASE.encode('utf-8')).hexdigest()[:40]
    with mysql_store.transaction() as cur:
        cur.execute('SELECT GET_LOCK(%s,0) AS acquired', (lock,))
        assert cur.fetchone()['acquired'] == 1
        try:
            with pytest.raises(ApiProblem) as error:
                mysql_store.analytics_page('all', None, now, 0, 10, employee_search='employee')
            assert error.value.status == 503 and error.value.code == 'ANALYTICS_BUSY'
            with pytest.raises(ApiProblem) as error:
                mysql_store.analytics_page('all', None, now, 0, 10, anomaly='latest')
            assert error.value.status == 503 and error.value.code == 'ANALYTICS_BUSY'
            assert mysql_store.analytics_page('all', None, now, 0, 10)[2] == 0
            client = create_app(mysql_store.cfg, mysql_store).test_client()
            response = client.get('/admin/v1/analytics/devices', query_string={'scope': 'all', 'search': 'employee'},
                                  headers={'Authorization': 'Bearer ' + mysql_store.cfg.ADMIN_TOKEN})
            assert response.status_code == 503
        finally:
            cur.execute('SELECT RELEASE_LOCK(%s)', (lock,))
    original = mysql_store._analytics_snapshot
    monkeypatch.setattr(mysql_store, '_analytics_snapshot', lambda *args: (_ for _ in ()).throw(RuntimeError('synthetic')))
    with pytest.raises(RuntimeError, match='synthetic'):
        mysql_store.analytics_page('all', None, now, 0, 10, employee_search='employee')
    monkeypatch.setattr(mysql_store, '_analytics_snapshot', original)
    with mysql_store.transaction() as cur:
        cur.execute('SELECT IS_FREE_LOCK(%s) AS available', (lock,))
        assert cur.fetchone()['available'] == 1
    assert mysql_store.analytics_page('all', None, now, 0, 10, employee_search='employee')[2] == 0


def test_database_failure_filters_match_full_snapshot_and_paginate(mysql_store, monkeypatch):
    import json
    from pathlib import Path
    from uuid import uuid4
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    from app import create_app
    fixture = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    cases = [("connectionFailed", 1, 2, True, "attached"),
             ("routeFailed", 1, 1, True, "attached"),
             ("gatewayReachedWithError", 1, 1, True, "attached"),
             ("succeeded", 1, 2, True, "attached"),
             ("connectionFailed", 0, 1, True, "attached"),
             ("routeFailed", 1, 1, False, "attached"),
             ("connectionFailed", 1, 1, True, "bypassed"),
             ("neverObserved", 0, 0, True, "attached")]
    for i, (state, requests, failures, current, route) in enumerate(cases):
        body = deepcopy(fixture)
        body["device"].update(deviceId=str(uuid4()), hostname=f"failure-fixture-{i}")
        body["endpoints"][0].update(isCurrent=current, routeStatus=route)
        body["activity"][0].update(state=state, requestCountSinceBoot=requests,
                                    failureCountSinceBoot=failures,
                                    lastRequestAtUtc=None if state == "neverObserved" else fixture["activity"][0]["lastRequestAtUtc"])
        if i == 0:
            endpoint, activity = deepcopy(body["endpoints"][0]), deepcopy(body["activity"][0])
            endpoint["assetId"] = activity["assetId"] = str(uuid4())
            activity["state"] = "routeFailed"
            body["endpoints"].append(endpoint)
            body["activity"].append(activity)
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    now = utcnow()
    rows, policy = mysql_store.analytics_snapshot()
    queries = [dict(kind="anomaly"), dict(kind="everAnomaly"),
               dict(kind="error", key="ConnectionFailed"), dict(kind="error", key="RouteFailed"),
               dict(kind="online"), dict(anomaly="latest"), dict(anomaly="ever"),
               dict(anomaly="none"), dict(kind="everAnomaly", anomaly="none"),
               dict(kind="anomaly", search="failure-fixture-0")]
    for indexed in (False, True):
        if indexed:
            mysql_store.ensure_scale_indexes()
            mysql_store.cfg.EMPLOYEE_INDEX = True
            mysql_store.check_schema()
        for query in queries:
            for skip in (0, 1, 20):
                expected = drill_down(rows, policy, now, scope="all", skip=skip, take=2, **query)
                selected, selected_policy, total = mysql_store.analytics_page(
                    "all", None, now, skip, 2, employee_search=query.get("search"),
                    kind=query.get("kind"), key=query.get("key"), anomaly=query.get("anomaly"))
                actual = drill_down(selected, selected_policy, now, scope="all", take=2)
                assert total == expected["total"], (indexed, query, skip)
                assert actual["devices"] == expected["devices"], (indexed, query, skip)
    body["activity"][0].update(state="routeFailed", requestCountSinceBoot=1, failureCountSinceBoot=1)
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    rows, policy = mysql_store.analytics_snapshot()
    expected = drill_down(rows, policy, now, scope="all", anomaly="latest")
    selected, selected_policy, total = mysql_store.analytics_page("all", None, now, 0, 50, anomaly="latest")
    assert total == expected["total"]
    assert drill_down(selected, selected_policy, now, scope="all")["devices"] == expected["devices"]
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    monkeypatch.setattr(mysql_store, "analytics_snapshot", lambda: pytest.fail("full snapshot used"))
    response = client.get("/admin/v1/analytics/devices", query_string={"scope": "all", "anomaly": "latest", "take": 2},
                          headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
    assert response.status_code == 200 and response.json["total"] == 4


def test_activity_index_full_then_unchanged_heartbeat(mysql_store, monkeypatch):
    import json
    from pathlib import Path
    from uuid import uuid4
    from controlserver.models import HeartbeatV2Request
    fixture = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    mysql_store.ensure_scale_indexes()
    mysql_store.cfg.EMPLOYEE_INDEX = True
    body = deepcopy(fixture)
    body["device"]["deviceId"] = str(uuid4())
    body["endpoints"] = []
    body["activity"] = []
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    body["inventoryUnchanged"] = True
    value = HeartbeatV2Request.model_validate(body)
    mysql_store.heartbeat(value, 60, "127.0.0.1")
    mysql_store.check_schema()
    with mysql_store.transaction() as cur:
        cur.execute("SELECT failure_mask,ever_failure,observed FROM activity_search_index WHERE device_id=%s", (body["device"]["deviceId"],))
        assert cur.fetchone() == {"failure_mask": 0, "ever_failure": 0, "observed": 0}
    monkeypatch.setattr(mysql_store, "_refresh_activity_index", lambda *_: pytest.fail("unchanged snapshot was rewritten"))
    mysql_store.heartbeat(value, 60, "127.0.0.1")


def test_dsh_has_independent_family_and_never_observed_is_not_success():
    from controlserver.analytics import agent_family, family_name
    assert agent_family("deepseekHarness") == "DSH"
    assert family_name("deepseekHarness") == "DSH"
    row = terminal(state="neverObserved")
    row["agents"][0]["agentType"] = "deepseekHarness"
    row["endpoints"][0]["agentFamily"] = "deepseekHarness"
    row["activity"] = []
    data = build([row], POLICY, NOW)
    assert data["agents"][0]["label"] == "DSH"
    assert data["anomalyDevices"] == 0
    assert data["unknownDevices"] == 1


def test_batched_summary_matches_full_snapshot():
    rows = [terminal(str(i), seen=NOW-timedelta(seconds=(10, 180, 600)[i % 3])) for i in range(8)]
    rows[0]["agents"] += [dict(instanceId="other", agentType="claudeIde", running=True),
                          dict(instanceId="tool", agentType="ccSwitch", running=True)]
    rows[1]["device"].update(osVersion="macOS", schemaVersion=1, supportedPolicySchemaVersion=1)
    rows[2]["runtime"]["lastReconcileResult"] = "failed"
    rows[3]["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed")
    rows[4]["endpoints"][0]["originalTargetBaseUrl"] = "https://api.anthropic.com/v1"
    rows[5]["activity"][0]["state"] = "routeFailed"
    policy = dict(policyVersion=2, allowlistedDomains=["api.openai.com", "unused.example"], routingRules=[])
    for scope in ("all", "online", "stale", "offline", "legacyclient"):
        for os_filter in (None, "windows", "macos", "missing"):
            for size in (1, 3, 20):
                batches = (rows[i:i+size] for i in range(0, len(rows), size))
                assert build_batches(batches, policy, NOW, scope, os_filter) == build(rows, policy, NOW, scope, os_filter)
            assert build_batches([], policy, NOW, scope, os_filter) == build([], policy, NOW, scope, os_filter)


def test_mysql_batched_summary_matches_snapshot(mysql_store, monkeypatch):
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    import json
    from pathlib import Path
    heartbeat = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(heartbeat), 60, "127.0.0.1")
    now = utcnow()
    rows, policy = mysql_store.analytics_snapshot()
    expected = build(rows, policy, now, scope="all")
    assert mysql_store.analytics_aggregate(now, scope="all") == expected
    monkeypatch.setattr(mysql_store, "analytics_snapshot", lambda: pytest.fail("full snapshot used"))
    from app import create_app
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    response = client.get("/admin/v1/analytics?scope=all", headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
    assert response.status_code == 200
    assert response.json["totalDevices"] == expected["totalDevices"]


def test_legacy_heartbeat_does_not_show_retained_v2_assets_as_current(mysql_store):
    import json
    from pathlib import Path
    from controlserver.models import HeartbeatRequest, HeartbeatV2Request
    from controlserver.security import utcnow
    body = json.loads((Path(__file__).parent / 'fixtures/dotnet-v0.1.19.json').read_text(encoding='utf-8'))['heartbeat']
    body['endpoints'][0].update(isCurrent=True, routeStatus='attached')
    body['activity'][0].update(state='connectionFailed', requestCountSinceBoot=1, failureCountSinceBoot=1)
    device = body['device']['deviceId']
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    mysql_store.ensure_scale_indexes()
    legacy = deepcopy(body)
    legacy['schemaVersion'] = 1
    for key in ('runtime', 'endpoints', 'activity'):
        legacy.pop(key)
    mysql_store.heartbeat(HeartbeatRequest.model_validate(legacy), 60, '127.0.0.1')
    assert mysql_store.devices(device)[0]['endpointCount'] == 0
    detail = mysql_store.details(device)
    assert detail['endpoints'] == detail['activity'] == []
    with mysql_store.transaction() as cur:
        cur.execute('SELECT COUNT(*) AS count FROM agent_endpoint_assets WHERE device_id=%s', (device,))
        assert cur.fetchone()['count'] == 1
    rows, policy = mysql_store.analytics_snapshot()
    assert rows[0]['endpoints'] == rows[0]['activity'] == []
    now = utcnow()
    assert build(rows, policy, now, scope='all')['anomalyDevices'] == 0
    for indexed in (False, True):
        mysql_store.cfg.EMPLOYEE_INDEX = indexed
        for query in (dict(kind='anomaly'), dict(kind='everAnomaly'), dict(kind='error', key='ConnectionFailed'),
                      dict(anomaly='latest'), dict(anomaly='ever'), dict(anomaly='none')):
            assert mysql_store.analytics_page('all', None, now, 0, 10, **query)[2] == 0
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    assert mysql_store.details(device)['endpoints']
    assert mysql_store.analytics_page('all', None, utcnow(), 0, 10, kind='anomaly')[2] == 1


def test_partitioned_summary_matches_all_scopes_and_os_filters():
    rows = [terminal(str(i), seen=NOW-timedelta(seconds=(10, 180, 600)[i % 3])) for i in range(12)]
    rows[0]["agents"] += [dict(instanceId="tool", agentType="ccSwitch", running=True)]
    rows[1]["device"].update(osVersion="macOS", schemaVersion=1)
    rows[2]["device"]["osVersion"] = "Windows Server"
    rows[3]["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed")
    rows[4]["activity"][0]["state"] = "routeFailed"
    policy = dict(policyVersion=2, allowlistedDomains=["api.openai.com", "unused.example"], routingRules=[])
    for size in (1, 3, 50):
        parts = build_partitions((rows[i:i+size] for i in range(0, len(rows), size)), policy, NOW)
        for scope in ("all", "online", "stale", "offline", "legacyclient"):
            for os_filter in (None, "windows", "mac", "missing"):
                assert merge_partitions(parts, policy, NOW, scope, os_filter) == build(rows, policy, NOW, scope, os_filter)
    assert merge_partitions([], policy, NOW) == build([], policy, NOW)


def test_mysql_analytics_cache_refresh_and_http(mysql_store, monkeypatch):
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    from controlserver.analytics_cache import refresh_cache, read_cache
    import json
    from pathlib import Path
    from app import create_app
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    refresh = refresh_cache(mysql_store)
    assert refresh["partitions"] == 1
    now = utcnow()
    result = read_cache(mysql_store.cfg, now, scope="all")
    rows, policy = mysql_store.analytics_snapshot()
    expected = build(rows, policy, datetime.fromisoformat(refresh["updatedAtUtc"].replace("Z", "+00:00")), scope="all")
    assert {k:v for k,v in result.items() if k not in ("cacheAgeSeconds", "cacheStale")} == expected
    assert not result["cacheStale"]
    assert read_cache(mysql_store.cfg, now + timedelta(minutes=6))["cacheStale"]
    from unittest.mock import patch
    with patch.object(mysql_store, "analytics_aggregate", side_effect=RuntimeError("refresh failed")):
        with pytest.raises(RuntimeError, match="refresh failed"):
            refresh_cache(mysql_store)
    assert read_cache(mysql_store.cfg, utcnow(), scope="all")["totalDevices"] == 1
    # A separate database session owns the advisory lock; a second refresh cannot overlap.
    with mysql_store.transaction() as cur:
        from controlserver.analytics_cache import identity
        lock = "eai-analytics-" + identity(mysql_store.cfg)[:40]
        cur.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock,))
        assert cur.fetchone()["acquired"] == 1
        try:
            with pytest.raises(RuntimeError, match="already running"):
                refresh_cache(mysql_store)
        finally:
            cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
    mysql_store.cfg.ANALYTICS_CACHE = True
    monkeypatch.setattr(mysql_store, "analytics_aggregate", lambda *args, **kwargs: pytest.fail("synchronous scan used"))
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    response = client.get("/admin/v1/analytics?scope=all", headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
    assert response.status_code == 200 and response.json["totalDevices"] == 1
    (mysql_store.cfg.DATA_ROOT / "analytics-cache.json").write_text("invalid", encoding="utf-8")
    assert client.get("/admin/v1/analytics", headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}).status_code == 503


def test_mysql_cache_across_multiple_database_pages(mysql_store):
    from controlserver.models import HeartbeatV2Request
    from controlserver.analytics_cache import refresh_cache, read_cache
    from controlserver.security import utcnow
    from uuid import UUID
    import json
    from pathlib import Path
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    source = str(body["device"]["deviceId"])
    with mysql_store.transaction() as cur:
        for i in range(501):
            device = str(UUID(int=i+1))
            cur.execute("""INSERT INTO device_heartbeats
                SELECT %s,received_at_utc,hostname,os_version,applied_policy_version,proxy_state,heartbeat_json
                FROM device_heartbeats WHERE device_id=%s""", (device, source))
            cur.execute("""INSERT INTO device_runtime SELECT %s,schema_version,service_version,
                heartbeat_interval_seconds,operation_state,source_ip,runtime_json
                FROM device_runtime WHERE device_id=%s""", (device, source))
    mysql_store.cfg.ANALYTICS_DETAIL_CACHE = True
    info = refresh_cache(mysql_store)
    now = datetime.fromisoformat(info["updatedAtUtc"].replace("Z", "+00:00"))
    rows, policy = mysql_store.analytics_snapshot()
    assert len(rows) == 502
    for scope in ("all", "online", "offline", "legacyclient"):
        result = read_cache(mysql_store.cfg, utcnow(), scope=scope)
        assert {k:v for k,v in result.items() if k not in ("cacheAgeSeconds", "cacheStale")} == build(rows, policy, now, scope)

    from controlserver.analytics_cache import identity
    from controlserver.analytics_detail_cache import read_detail_cache
    for skip in (0, 499, 500):
        expected = drill_down(rows, policy, now, scope="all", kind="running", skip=skip, take=25)
        actual = read_detail_cache(mysql_store.cfg, utcnow(), identity(mysql_store.cfg), scope="all", kind="running", skip=skip, take=25)
        assert {k:v for k,v in actual.items() if k not in ("cacheAgeSeconds", "cacheStale")} == expected


def test_mysql_complex_filter_pages_match_full_snapshot(mysql_store, monkeypatch):
    from controlserver.models import HeartbeatV2Request
    from controlserver.database import dbtime
    from controlserver.security import utcnow
    from uuid import UUID
    import json
    from pathlib import Path
    from app import create_app
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    source = str(body["device"]["deviceId"])
    now = utcnow()
    with mysql_store.transaction() as cur:
        for i in range(510):
            device = str(UUID(int=i+1))
            cur.execute("""INSERT INTO device_heartbeats
                SELECT %s,%s,hostname,os_version,applied_policy_version,proxy_state,heartbeat_json
                FROM device_heartbeats WHERE device_id=%s""", (device, dbtime(now-timedelta(seconds=i % 3)), source))
            cur.execute("""INSERT INTO device_runtime SELECT %s,schema_version,service_version,
                heartbeat_interval_seconds,operation_state,source_ip,runtime_json
                FROM device_runtime WHERE device_id=%s""", (device, source))
    rows, policy = mysql_store.analytics_snapshot()
    queries = [dict(kind="running"), dict(kind="provider", key="OpenAI"), dict(kind="unrecognized"),
               dict(kind="running", search="0000"), dict(kind="unknown"),
               dict(kind="running", agent="Claude"), dict(kind="running", provider="OpenAI"),
               dict(kind="running", anomaly="latest")]
    for query in queries:
        for skip in (0, 1, 499, 500, 510, 1000):
            expected = drill_down(rows, policy, now, scope="all", skip=skip, take=25, **query)
            actual = mysql_store.analytics_filtered_page(now, scope="all", skip=skip, take=25, **query)
            assert actual == expected, (query, skip)
    # A second worker rejects another scan instead of multiplying database load.
    import hashlib
    lock = "eai-complex-" + hashlib.sha256(mysql_store.cfg.MYSQL_DATABASE.encode("utf-8")).hexdigest()[:40]
    with mysql_store.transaction() as cur:
        cur.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock,))
        assert cur.fetchone()["acquired"] == 1
        try:
            from controlserver.validation import ApiProblem
            with pytest.raises(ApiProblem) as error:
                mysql_store.analytics_filtered_page(now, scope="all", kind="running")
            assert error.value.status == 503 and error.value.code == "ANALYTICS_BUSY"
        finally:
            cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
    monkeypatch.setattr(mysql_store, "analytics_snapshot", lambda: pytest.fail("full snapshot used"))
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    response = client.get("/admin/v1/analytics/devices", query_string={"scope": "all", "kind": "running", "skip": 500},
                          headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
    assert response.status_code == 200


def test_indexed_detail_cache_matches_complex_filters(config):
    from controlserver.analytics_detail_cache import DetailCacheWriter, read_detail_cache
    rows = [terminal(str(i), seen=NOW-timedelta(seconds=(10, 180, 600)[i % 3])) for i in range(18)]
    rows[0]["device"].update(osVersion="macOS", schemaVersion=1, employeeIds=["00123"])
    rows[1]["device"]["employeeIds"] = ["Jöhn", "00123"]
    rows[2]["device"]["employeeIds"] = ["001234"]
    rows[1]["agents"] += [dict(instanceId="tool", agentType="ccSwitch", running=True),
                          dict(instanceId="unknown", agentType="unknownCandidate", running=True)]
    rows[2]["endpoints"][0].update(allowlistBypassed=True, routeStatus="bypassed")
    rows[3]["activity"][0].update(state="succeeded", failureCountSinceBoot=1)
    rows[4]["activity"] = []
    rows[5]["endpoints"][0]["originalTargetBaseUrl"] = "https://api.anthropic.com/v1"
    policy = dict(policyVersion=2, allowlistedBaseUrls=["https://api.openai.com/v1"])
    writer = DetailCacheWriter(config, NOW, "fixture")
    try:
        writer.add(rows[:8], policy)
        writer.add(rows[8:], policy)
        writer.publish()
    finally:
        writer.close()
    queries = [dict(), dict(kind="running"), dict(kind="agent", key="Claude"),
        dict(kind="tool", key="CC Switch"), dict(kind="tool"), dict(kind="tool", key=""), dict(kind="provider", key="OpenAI"),
        dict(kind="error", key="ConnectionFailed"), dict(kind="anomaly"), dict(kind="everAnomaly"),
        dict(kind="allowlist"), dict(kind="allowlist", key="https://api.openai.com/v1"),
        dict(kind="otherUnproxied"), dict(kind="unknown"), dict(kind="online"),
        dict(kind="unexpected"), dict(search="00123"), dict(employeeExact="00123"),
        dict(employeeExact="JÖHN"), dict(employeeExact="fixture-"), dict(employeeExact="00123", agent="Claude"),
        dict(agent="Claude", anomaly="none"),
        dict(provider="OpenAI", anomaly="latest"), dict(allowlist="any"),
        dict(allowlist="https://api.openai.com/v1"), dict(anomaly="ever")]
    for scope in ("all", "online", "stale", "offline", "legacyclient"):
        for os_filter in (None, "windows", "mac", "absent"):
            for query in queries:
                for skip in (0, 2, 25):
                    expected = drill_down(rows, policy, NOW, scope=scope, os=os_filter, skip=skip, take=2, **query)
                    result = read_detail_cache(config, NOW, "fixture", scope=scope, os=os_filter, skip=skip, take=2, **query)
                    assert {k:v for k,v in result.items() if k not in ("cacheAgeSeconds", "cacheStale")} == expected, (scope, os_filter, query, skip)
    assert read_detail_cache(config, NOW+timedelta(minutes=6), "fixture")["cacheStale"]
    from controlserver.validation import ApiProblem
    with pytest.raises(ApiProblem) as error:
        read_detail_cache(config, NOW, "other")
    assert error.value.status == 503
    import sqlite3
    with sqlite3.connect(config.DATA_ROOT / "analytics-detail.sqlite3") as db:
        db.execute("UPDATE meta SET value='1' WHERE key='format'")
    with pytest.raises(ApiProblem) as error:
        read_detail_cache(config, NOW, "fixture")
    assert error.value.status == 503


def test_employee_exact_http_uses_same_semantics_with_or_without_cache(mysql_store):
    import json
    from pathlib import Path
    from app import create_app
    from controlserver.analytics_cache import refresh_cache
    from controlserver.models import HeartbeatV2Request

    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    headers = {"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}
    def lookup(**query):
        response = client.get("/admin/v1/analytics/devices", query_string={"scope": "all", **query}, headers=headers)
        assert response.status_code == 200
        return response.json
    for cached in (False, True):
        mysql_store.cfg.ANALYTICS_DETAIL_CACHE = cached
        if cached:
            refresh_cache(mysql_store)
        assert lookup(employeeExact="TEST")["total"] == 1
        assert lookup(employeeExact="tes")["total"] == 0
        assert lookup(employeeExact="测试终端")["total"] == 0
        assert lookup(search="tes")["total"] == 1
        assert lookup(employeeExact="test", provider="missing")["total"] == 0
        assert ("cacheAgeSeconds" in lookup(employeeExact="test")) == cached


def test_refresh_releases_database_lock_when_writer_cleanup_fails(mysql_store, monkeypatch):
    from controlserver.analytics_cache import identity, refresh_cache
    from controlserver.analytics_detail_cache import DetailCacheWriter
    mysql_store.cfg.ANALYTICS_DETAIL_CACHE = True
    original_close = DetailCacheWriter.close
    def broken_close(writer):
        original_close(writer)
        raise OSError('synthetic cleanup failure')
    monkeypatch.setattr(DetailCacheWriter, 'close', broken_close)
    with pytest.raises(OSError, match='synthetic cleanup failure'):
        refresh_cache(mysql_store)
    other = mysql_store.connect()
    try:
        with other.cursor() as cur:
            cur.execute('SELECT IS_FREE_LOCK(%s) AS free', ('eai-analytics-' + identity(mysql_store.cfg)[:40],))
            assert cur.fetchone()['free'] == 1
    finally:
        other.close()
    monkeypatch.setattr(DetailCacheWriter, 'close', original_close)
    assert refresh_cache(mysql_store)['partitions'] >= 0


def test_mysql_indexed_detail_cache_refresh_and_http(mysql_store, monkeypatch):
    from controlserver.models import HeartbeatV2Request
    from controlserver.analytics_cache import refresh_cache
    from controlserver.security import utcnow
    from app import create_app
    import json
    from pathlib import Path
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, "127.0.0.1")
    mysql_store.cfg.ANALYTICS_DETAIL_CACHE = True
    info = refresh_cache(mysql_store)
    rows, policy = mysql_store.analytics_snapshot()
    now = datetime.fromisoformat(info["updatedAtUtc"].replace("Z", "+00:00"))
    expected = drill_down(rows, policy, now, scope="all", kind="running")
    monkeypatch.setattr(mysql_store, "analytics_filtered_page", lambda *args, **kwargs: pytest.fail("live scan used"))
    client = create_app(mysql_store.cfg, mysql_store).test_client()
    result = client.get("/admin/v1/analytics/devices", query_string={"scope":"all", "kind":"running"},
                        headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
    assert result.status_code == 200
    assert {k:v for k,v in result.json.items() if k not in ("cacheAgeSeconds", "cacheStale")} == expected
    term = rows[0]["device"]["hostname"]
    for skip in (0, 1):
        expected_search = drill_down(rows, policy, now, scope="all", search=term, skip=skip, take=1)
        result = client.get("/admin/v1/analytics/devices",
            query_string={"scope": "all", "snapshot": "1", "search": term, "skip": skip, "take": 1},
            headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
        assert result.status_code == 200
        assert {k:v for k,v in result.json.items() if k not in ("cacheAgeSeconds", "cacheStale")} == expected_search
    refresh_cache(mysql_store)  # Replacing an existing index preserves availability.
    assert client.get("/admin/v1/analytics/devices", query_string={"scope":"all", "kind":"running"},
                      headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}).status_code == 200
    from unittest.mock import patch
    with patch.object(mysql_store, "analytics_aggregate", side_effect=RuntimeError("refresh failure")):
        with pytest.raises(RuntimeError): refresh_cache(mysql_store)
    assert client.get("/admin/v1/analytics/devices", query_string={"scope":"all", "kind":"running"},
                      headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}).status_code == 200
    assert not list(mysql_store.cfg.DATA_ROOT.glob(".analytics-detail-*"))
    (mysql_store.cfg.DATA_ROOT / "analytics-detail.sqlite3").write_bytes(b"damaged")
    assert client.get("/admin/v1/analytics/devices", query_string={"scope":"all", "kind":"running"},
                      headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN}).status_code == 503


@pytest.mark.parametrize('failed_file', ['analytics-cache.json', 'analytics-generation.json'])
def test_partial_paired_cache_publication_is_not_served(mysql_store, monkeypatch, failed_file):
    import json
    import os
    from pathlib import Path
    from controlserver.analytics_cache import identity, read_cache, refresh_cache
    from controlserver.analytics_detail_cache import read_detail_cache
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    from controlserver.validation import ApiProblem
    body = json.loads((Path(__file__).parent / 'fixtures/dotnet-v0.1.19.json').read_text(encoding='utf-8'))['heartbeat']
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(body), 60, '127.0.0.1')
    cfg = mysql_store.cfg
    cfg.ANALYTICS_CACHE = cfg.ANALYTICS_DETAIL_CACHE = True
    refresh_cache(mysql_store)
    assert read_cache(cfg, utcnow(), scope='all')['totalDevices'] == 1
    assert read_detail_cache(cfg, utcnow(), identity(cfg), scope='all')['total'] == 1
    replace = os.replace
    def fail_publication(source, destination):
        if Path(destination).name == failed_file:
            raise OSError('synthetic publication failure')
        return replace(source, destination)
    with monkeypatch.context() as context:
        context.setattr(os, 'replace', fail_publication)
        with pytest.raises(OSError, match='synthetic publication failure'):
            refresh_cache(mysql_store)
    with pytest.raises(ApiProblem) as exc:
        read_detail_cache(cfg, utcnow(), identity(cfg), scope='all')
    assert exc.value.status == 503
    if failed_file == 'analytics-generation.json':
        with pytest.raises(ApiProblem) as exc:
            read_cache(cfg, utcnow(), scope='all')
        assert exc.value.status == 503
    else:
        assert read_cache(cfg, utcnow(), scope='all')['totalDevices'] == 1
    refresh_cache(mysql_store)
    assert read_cache(cfg, utcnow(), scope='all')['totalDevices'] == 1
    assert read_detail_cache(cfg, utcnow(), identity(cfg), scope='all')['total'] == 1


def test_explicit_snapshot_list_is_opt_in_and_never_falls_back(config):
    from app import create_app
    from controlserver.analytics_cache import identity
    from controlserver.analytics_detail_cache import DetailCacheWriter
    from controlserver.security import utcnow

    class Store:
        calls = 0
        def analytics_page(self, *args, **kwargs):
            self.calls += 1
            return [], POLICY, 0
    store = Store()
    config.ANALYTICS_CACHE = False
    config.ANALYTICS_DETAIL_CACHE = True
    now = utcnow()
    rows = [terminal('snapshot-online', seen=now), terminal('snapshot-offline', seen=now-timedelta(hours=1))]
    writer = DetailCacheWriter(config, now, identity(config))
    try:
        writer.add(rows, POLICY)
        writer.publish()
    finally:
        writer.close()
    client = create_app(config, store, check_database=False).test_client()
    headers = {'Authorization': 'Bearer ' + config.ADMIN_TOKEN}
    def get(**query):
        return client.get('/admin/v1/analytics/devices', query_string=query, headers=headers)
    live = get(scope='all')
    assert live.status_code == 200 and live.json['total'] == 0 and store.calls == 1
    snapshot = get(scope='online', snapshot='1')
    assert snapshot.status_code == 200 and snapshot.json['total'] == 1 and store.calls == 1
    assert snapshot.json['devices'][0]['device']['deviceId'] == 'snapshot-online'
    assert 'cacheAgeSeconds' in snapshot.json and snapshot.json['cacheStale'] is False
    assert get(scope='all', snapshot='1', search='offline').json['total'] == 1
    page = get(scope='all', snapshot='1', search='snapshot', skip=1, take=1)
    assert page.status_code == 200 and page.json['total'] == 2
    assert [item['device']['deviceId'] for item in page.json['devices']] == ['snapshot-offline']
    beyond = get(scope='all', snapshot='1', search='snapshot', skip=2, take=1)
    assert beyond.status_code == 200 and beyond.json['total'] == 2 and beyond.json['devices'] == []
    assert store.calls == 1
    assert get(scope='all', snapshot='invalid').status_code == 400
    config.ANALYTICS_DETAIL_CACHE = False
    assert get(scope='all', snapshot='1').status_code == 503 and store.calls == 1
    config.ANALYTICS_DETAIL_CACHE = True
    (config.DATA_ROOT / 'analytics-detail.sqlite3').write_bytes(b'damaged')
    assert get(scope='all', snapshot='1').status_code == 503 and store.calls == 1


@pytest.mark.parametrize('legacy_json', [False, True])
def test_snapshot_trigram_search_matches_original_unicode_and_field_boundaries(config, monkeypatch, legacy_json):
    import sqlite3
    from controlserver.analytics_detail_cache import DetailCacheWriter, read_detail_cache
    if legacy_json:
        monkeypatch.setattr('controlserver.analytics_detail_cache.json_search_preserves_nul', lambda db: False)
    row = terminal('device-identity')
    row['device']['hostname'] = 'before\x00XYZ汉"字测试 😃abc'
    row['device']['employeeIds'] = ['Neo测试345']
    rows = [row, terminal('second-123')]
    writer = DetailCacheWriter(config, NOW, 'fixture')
    try:
        writer.add(rows, POLICY)
        writer.publish()
    finally:
        writer.close()
    queries = ['xyz', 'XYZ汉', '汉"字', '字测试', '😃ab', '\x00XYZ', '测试345', 'neo', '123', '12',
               'missing', 'abc\ndevice', '"字测试', 'BEFORE']
    def verify():
        for term in queries:
            expected = drill_down(rows, POLICY, NOW, scope='all', search=term)
            result = read_detail_cache(config, NOW, 'fixture', scope='all', search=term)
            assert {k:v for k,v in result.items() if k not in ('cacheAgeSeconds', 'cacheStale')} == expected, repr(term)
    verify()
    # A format-3 snapshot created by the previous release has no FTS metadata.
    db = sqlite3.connect(config.DATA_ROOT / 'analytics-detail.sqlite3')
    try:
        db.execute("DELETE FROM meta WHERE key='searchIndex'")
        db.execute('DROP TABLE IF EXISTS search_fts')
        db.commit()
    finally:
        db.close()
    verify()


def test_snapshot_search_large_page_and_out_of_range_total(config):
    from controlserver.analytics_detail_cache import DetailCacheWriter, read_detail_cache
    rows = [terminal('search-device-' + str(i)) for i in range(510)]
    writer = DetailCacheWriter(config, NOW, 'fixture')
    try:
        writer.add(rows, POLICY)
        writer.publish()
    finally:
        writer.close()
    for skip in (0, 500, 510, 900):
        expected = drill_down(rows, POLICY, NOW, scope='all', search='search-device', skip=skip, take=500)
        result = read_detail_cache(config, NOW, 'fixture', scope='all', search='search-device', skip=skip, take=500)
        assert {k: v for k, v in result.items() if k not in ('cacheAgeSeconds', 'cacheStale')} == expected


def test_snapshot_dense_and_selective_search_match_reference(config):
    import sqlite3
    from contextlib import closing
    from controlserver.analytics_detail_cache import DetailCacheWriter, read_detail_cache, use_search_index
    rows = [terminal('dense-device-' + str(i)) for i in range(1030)]
    rows[0]['device']['hostname'] = 'dense-selective-汉字'
    writer = DetailCacheWriter(config, NOW, 'fixture')
    try:
        writer.add(rows, POLICY)
        writer.publish()
    finally:
        writer.close()
    with closing(sqlite3.connect(config.DATA_ROOT / 'analytics-detail.sqlite3')) as db:
        meta = dict(db.execute('SELECT key,value FROM meta'))
        if meta.get('searchIndex') == 'fts5-trigram-v1':
            assert not use_search_index(db, '"dense"')
            assert use_search_index(db, '"selective"')
    for term, skip in (('dense', 0), ('dense', 1000), ('dense', 1050), ('selective', 0), ('汉字', 0)):
        expected = drill_down(rows, POLICY, NOW, scope='all', search=term, skip=skip, take=25)
        result = read_detail_cache(config, NOW, 'fixture', scope='all', search=term, skip=skip, take=25)
        assert {k: v for k, v in result.items() if k not in ('cacheAgeSeconds', 'cacheStale')} == expected


def test_snapshot_optional_index_only_falls_back_for_missing_sqlite_capability():
    import sqlite3
    from controlserver.analytics_detail_cache import create_search_index
    class Failure:
        def __init__(self, message): self.message = message
        def execute(self, _): raise sqlite3.OperationalError(self.message)
    assert create_search_index(Failure('no such module: fts5')) is False
    assert create_search_index(Failure('no such tokenizer: trigram')) is False
    with pytest.raises(sqlite3.OperationalError, match='disk'):
        create_search_index(Failure('disk I/O error'))


def test_snapshot_search_matches_reference_for_mixed_unicode_substrings(config):
    import random
    from controlserver.analytics_detail_cache import DetailCacheWriter, read_detail_cache
    rng = random.Random(42)
    alphabet = 'ab汉字😃" _-\n\r\t\\\x00é\u0301'
    rows = []
    for index in range(20):
        row = terminal('id-' + str(index))
        row['device']['hostname'] = ''.join(rng.choice(alphabet) for _ in range(24))
        rows.append(row)
    writer = DetailCacheWriter(config, NOW, 'fixture')
    try:
        writer.add(rows, POLICY)
        writer.publish()
    finally:
        writer.close()
    for _ in range(100):
        value = rng.choice(rows)['device']['hostname']
        start = rng.randrange(len(value))
        search = value[start:start+rng.randint(1, 7)]
        expected = drill_down(rows, POLICY, NOW, scope='all', search=search)
        actual = read_detail_cache(config, NOW, 'fixture', scope='all', search=search)
        assert {k:v for k,v in actual.items() if k not in ('cacheAgeSeconds', 'cacheStale')} == expected, repr(search)


def test_online_page_matches_full_snapshot_at_interval_boundaries(mysql_store):
    import json
    from pathlib import Path
    from uuid import uuid4
    from controlserver.database import dbtime
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    now = utcnow()
    # Include clock skew, exact microsecond boundaries, a clamped long interval,
    # and legacy heartbeats whose runtime row must not influence their interval.
    samples = [(-5, 15, 2), (-5, 60, 2), (60, 15, 2), (60.000001, 15, 2),
               (150, 60, 2), (150.000001, 60, 2), (7230, 3600, 2),
               (7230.000001, 3600, 2), (150, 0, 2), (150.000001, 0, 2),
               (150, 3600, 1), (150.000001, 3600, 1)]
    for age, interval, schema in samples:
        value = deepcopy(body)
        value['device']['deviceId'] = str(uuid4())
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, '127.0.0.1')
        with mysql_store.transaction() as cur:
            cur.execute("UPDATE device_heartbeats SET received_at_utc=%s, heartbeat_json=JSON_SET(heartbeat_json,'$.schemaVersion',%s) WHERE device_id=%s",
                        (dbtime(now - timedelta(seconds=age)), schema, value['device']['deviceId']))
            cur.execute("UPDATE device_runtime SET heartbeat_interval_seconds=%s WHERE device_id=%s", (interval,value['device']['deviceId']))
    rows, policy = mysql_store.analytics_snapshot()
    for scope, kind in [('online', None), ('online', 'online'), ('all', 'online')]:
        for skip, take in [(0, 2), (1, 4), (3, 4), (5, 4), (8, 4), (20, 4), (0, 50)]:
            expected = drill_down(rows, policy, now, scope='online', skip=skip, take=take)
            selected, selected_policy, total = mysql_store.analytics_page(scope, None, now, skip, take, kind=kind)
            actual = drill_down(selected, selected_policy, now, scope='all', take=take)
            assert isinstance(total, int)
            assert total == expected['total']
            assert actual['devices'] == expected['devices']


def test_online_split_count_and_pages_share_snapshot_during_heartbeat(mysql_store, monkeypatch):
    import json
    from contextlib import contextmanager
    from pathlib import Path
    from uuid import uuid4
    from controlserver.database import dbtime
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    now = utcnow()
    ids = []
    for _ in range(2):
        value = deepcopy(body)
        value['device']['deviceId'] = str(uuid4()); ids.append(value['device']['deviceId'])
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, '127.0.0.1')
    rows, policy = mysql_store.analytics_snapshot()
    expected = drill_down(rows, policy, now, scope='online', take=10)
    original = mysql_store.transaction
    changed = []
    class CursorProxy:
        def __init__(self, cursor): self.cursor = cursor
        def __getattr__(self, name): return getattr(self.cursor, name)
        def execute(self, sql, args=None):
            result = self.cursor.execute(sql, args)
            if 'AS recent_count' in sql and not changed:
                with original() as writer:
                    writer.execute('UPDATE device_heartbeats SET received_at_utc=%s WHERE device_id=%s',
                                   (dbtime(now - timedelta(days=1)), ids[0]))
                changed.append(True)
            return result
    @contextmanager
    def wrapped():
        with original() as cur: yield CursorProxy(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    selected, selected_policy, total = mysql_store.analytics_page('online', None, now, 0, 10)
    actual = drill_down(selected, selected_policy, now, scope='all', take=10)
    assert changed and total == expected['total'] == 2
    assert actual['devices'] == expected['devices']


def test_all_scope_simple_page_skips_runtime_join_but_hydrates_runtime(mysql_store, monkeypatch):
    import json
    from contextlib import contextmanager
    from pathlib import Path
    from uuid import uuid4
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    body = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text())["heartbeat"]
    now = utcnow()
    ids = []
    for i in range(3):
        value = deepcopy(body)
        value['device']['deviceId'] = str(uuid4()); ids.append(value['device']['deviceId'])
        value['device']['hostname'] = f'synthetic-all-{i}'
        value['users'][0]['accountName'] = f'employee-{i}'
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, '127.0.0.1')
    with mysql_store.transaction() as cur:
        cur.execute('DELETE FROM device_runtime WHERE device_id=%s', (ids[0],))
        cur.execute("UPDATE device_heartbeats SET heartbeat_json=JSON_SET(heartbeat_json,'$.schemaVersion',1) WHERE device_id=%s", (ids[1],))
    rows, policy = mysql_store.analytics_snapshot()
    queries = []
    original = mysql_store.transaction
    class CursorProxy:
        def __init__(self, cursor): self.cursor = cursor
        def __getattr__(self, name): return getattr(self.cursor, name)
        def execute(self, sql, args=None):
            if sql.startswith('SELECT COUNT(*) AS total') or sql.startswith('SELECT h.device_id'):
                queries.append(sql)
            return self.cursor.execute(sql, args)
    @contextmanager
    def wrapped():
        with original() as cur: yield CursorProxy(cur)
    monkeypatch.setattr(mysql_store, 'transaction', wrapped)
    for os_filter, search in [(None,None),('windows',None),(None,'employee-1')]:
        queries.clear()
        selected, selected_policy, total = mysql_store.analytics_page('all', os_filter, now, 0, 10, employee_search=search)
        actual = drill_down(selected, selected_policy, now, scope='all', take=10)
        expected = drill_down(rows, policy, now, scope='all', os=os_filter, search=search, take=10)
        assert total == expected['total'] and actual['devices'] == expected['devices']
        assert len(queries) == (1 if search else 2)
        assert all('LEFT JOIN device_runtime' not in sql for sql in queries)
    queries.clear()
    mysql_store.analytics_page('all', None, now, 0, 10, anomaly='latest')
    assert len(queries) == 2 and all('LEFT JOIN device_runtime' in sql for sql in queries)


@pytest.mark.parametrize('indexed', [False, True])
def test_search_preserves_literal_unicode_multiuser_and_hostname_matches(mysql_store, indexed):
    import json
    from pathlib import Path
    from uuid import uuid4
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    body = json.loads((Path(__file__).parent / 'fixtures' / 'dotnet-v0.1.19.json').read_text())['heartbeat']
    for i, accounts in enumerate((['sf\\Jöhn_%', 'sf\\Jöhn_%', 'sf\\other'], [], ['employee-else'])):
        value = deepcopy(body)
        value['device']['deviceId'] = str(uuid4())
        value['device']['hostname'] = f'literal-host-{i}'
        value['users'] = [dict(body['users'][0], accountName=account, sid=f'synthetic-sid-{j}')
                          for j, account in enumerate(accounts)]
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(value), 60, '127.0.0.1')
    if indexed:
        mysql_store.ensure_scale_indexes()
        mysql_store.cfg.EMPLOYEE_INDEX = True
    now = utcnow()
    rows, policy = mysql_store.analytics_snapshot()
    empty_users_id = next(row['device']['deviceId'] for row in rows if row['device']['hostname'] == 'literal-host-1')
    for scope in ('all', 'online'):
        for term in ('JÖHN_%', '%', '_', 'literal-host-', 'literal-host-1', empty_users_id, 'no-such-user'):
            for skip in (0, 1, 10):
                expected = drill_down(rows, policy, now, scope=scope, search=term, skip=skip, take=1)
                selected, selected_policy, total = mysql_store.analytics_page(
                    scope, None, now, skip, 1, employee_search=term)
                actual = drill_down(selected, selected_policy, now, scope='all', take=1)
                assert total == expected['total']
                assert actual['devices'] == expected['devices']
