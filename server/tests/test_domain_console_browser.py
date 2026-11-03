"""Optional browser regression against a loopback server and an isolated MySQL DB."""
import json
import os
from pathlib import Path
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app import create_app
from controlserver.models import HeartbeatV2Request
from test_device_policy import setup_devices

pytestmark = pytest.mark.skipif(os.environ.get("ENDPOINTAI_TEST_BROWSER") != "1",
    reason="Set ENDPOINTAI_TEST_BROWSER=1 and install Playwright to run browser checks")


@pytest.fixture
def console_page(mysql_store):
    playwright = pytest.importorskip("playwright.sync_api")
    devices, _, _ = setup_devices(mysql_store)
    for i, device in enumerate(devices):
        heartbeat = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
        heartbeat["device"].update(deviceId=device["deviceId"], hostname=f"browser-fixture-{i}")
        heartbeat["runtime"]["supportedPolicySchemaVersion"] = 2
        heartbeat["users"] = [dict(sid="fixture-user", accountName="00123"),
            dict(sid="fixture-other", accountName="SF\\00456")]
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(heartbeat), 60, "127.0.0.1")
    server = make_server("127.0.0.1", 0, create_app(mysql_store.cfg, mysql_store), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with playwright.sync_playwright() as pw:
        executable = os.environ.get("ENDPOINTAI_TEST_BROWSER_EXECUTABLE")
        browser = pw.chromium.launch(headless=True, **({"executable_path": executable} if executable else {}))
        try:
            page = browser.new_page(base_url=f"http://127.0.0.1:{server.server_port}", viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{server.server_port}/console")
            page.locator("#token").fill(mysql_store.cfg.ADMIN_TOKEN)
            page.locator("#actor").fill("00123")
            page.locator("#authForm button[type=submit]").click()
            playwright.expect(page.locator("#appShell")).to_be_visible()
            yield page, playwright.expect, mysql_store
            assert not errors
        finally:
            browser.close()
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


def test_automatic_device_editor_conflict_and_reset(console_page):
    page, expect, store = console_page
    page.locator("[data-page=assets]").click()
    expect(page.locator("#devices")).to_contain_text("00123 / 00456")
    page.locator("#devices button").first.click()
    expect(page.locator("#deviceGatewayOverride")).to_be_enabled()
    expect(page.locator("#deviceRouteMode")).to_be_disabled()
    page.locator("#deviceGatewayOverride").check()
    page.locator("#deviceRouteMode").select_option("passthroughOriginal")
    page.locator("#deviceAllowlistOverride").check()
    page.locator("#deviceAllowlist").fill("openai.com")
    page.locator("#deviceRulesOverride").check()
    page.locator("#deviceRoutingRulesEditor button").last.click()
    row = page.locator("#deviceRoutingRulesEditor [data-rule]").last
    row.locator("[data-domain]").fill("anthropic.com")
    row.locator("[data-mode]").select_option("fixedGateway")
    row.locator("[data-gateway]").fill("https://other.example")
    page.locator("#saveDevicePolicy").click()
    expect(page.locator("#devicePolicyState")).to_contain_text("已仅保存")
    page.locator("#reloadDevicePolicy").click()
    expect(page.locator("#deviceAllowlist")).to_have_value("openai.com")
    page.locator("#deviceAllowlist").fill("draft.example")
    identifier = page.locator("#devicePolicyTarget").inner_text()
    path = f"/admin/v1/devices/{identifier}/policy"
    auth = {"Authorization": "Bearer " + store.cfg.ADMIN_TOKEN}
    current = page.request.get(path, headers=auth).json()
    assert page.request.put(path, headers=auth, data=dict(expectedVersion=current["effectivePolicy"]["policyVersion"],
        overrides=dict(allowlistedDomains=["concurrent.example"]))).status == 200
    page.locator("#saveDevicePolicy").click()
    expect(page.locator("#devicePolicyState")).to_contain_text("草稿已保留")
    expect(page.locator("#deviceAllowlist")).to_have_value("draft.example")
    page.locator("#refreshDetail").click()
    expect(page.locator("#deviceAllowlist")).to_have_value("draft.example")
    page.locator("#reloadDevicePolicy").click()
    expect(page.locator("#deviceAllowlist")).to_have_value("concurrent.example")
    page.locator("#resetDevicePolicy").click()
    expect(page.locator("#deviceAllowlistOverride")).not_to_be_checked()
    expect(page.locator("#deviceAllowlist")).to_be_disabled()
    page.locator("#backToList").click()
    page.locator("#devices button").last.click()
    expect(page.locator("#deviceAllowlistOverride")).not_to_be_checked()


def test_global_domain_rules_and_responsive_editor(console_page):
    page, expect, _ = console_page
    page.locator("[data-page=policy]").click()
    page.locator("#allowlistInput").fill("OpenAI.COM.")
    page.locator("#allowlistForm button").click()
    expect(page.locator("#allowlistEntries")).to_contain_text("openai.com")
    page.locator("#gatewayTab").click()
    page.locator("#routingRulesEditor button").last.click()
    row = page.locator("#routingRulesEditor [data-rule]").last
    row.locator("[data-domain]").fill("anthropic.com")
    row.locator("[data-mode]").select_option("fixedGateway")
    row.locator("[data-gateway]").fill("https://other.example")
    page.locator("#savePolicy").click()
    expect(page.locator("#appMessage")).to_contain_text("策略已保存")
    page.reload()
    page.locator("[data-page=policy]").click()
    page.locator("#gatewayTab").click()
    expect(page.locator("#routingRulesEditor [data-domain]")).to_have_value("anthropic.com")
    expect(page.locator("#routingRulesEditor [data-gateway]")).to_have_value("https://other.example")
    page.locator("#routingRulesEditor [data-mode]").select_option("passthroughOriginal")
    page.locator("#savePolicy").click()
    expect(page.locator("#appMessage")).to_contain_text("策略已保存")
    expect(page.locator("#routingRulesEditor [data-gateway]")).to_be_disabled()
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_switching_devices_discards_stale_policy_response(console_page):
    page, expect, store = console_page
    pending = []
    def intercept(route):
        if route.request.method == "GET" and not pending:
            pending.append(route)
        else:
            route.continue_()
    page.route("**/admin/v1/devices/*/policy", intercept)
    page.locator("[data-page=assets]").click()
    page.locator("#devices button").first.click()
    expect(page.locator("#detailView")).to_be_visible()
    page.wait_for_function("document.getElementById('devicePolicyState').textContent.includes('正在加载')")
    first = page.locator("#devicePolicyTarget").inner_text()
    page.locator("#backToList").click()
    page.locator("#devices button").last.click()
    expect(page.locator("#deviceGatewayOverride")).to_be_enabled()
    second = page.locator("#devicePolicyTarget").inner_text()
    assert first != second
    assert len(pending) == 1
    response = page.request.get(pending[0].request.url,
        headers={"Authorization": "Bearer " + store.cfg.ADMIN_TOKEN})
    pending[0].fulfill(status=response.status, json=response.json())
    expect(page.locator("#devicePolicyTarget")).to_have_text(second)
    expect(page.locator("#deviceGatewayOverride")).to_be_enabled()
