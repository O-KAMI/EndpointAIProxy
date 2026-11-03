"""Linux Gunicorn, real MySQL and encrypted v2 policy delivery across a restart."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

import pytest

from controlserver.security import sign_policy
from controlserver.transport import b64, open_envelope, seal


@pytest.mark.skipif(os.name == "nt", reason="Gunicorn requires a Unix process environment")
def test_scoped_policy_real_http_workers_and_restart(mysql_store, tmp_path):
    cfg = mysql_store.cfg
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    opener = build_opener(ProxyHandler({}))

    def http(path, method="GET", body=None, token=cfg.ADMIN_TOKEN):
        headers = {"Authorization": "Bearer " + token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = Request(origin + path, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode())
        try:
            with opener.open(req, timeout=15) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def business(path, token, body=None):
        rid = str(uuid4())
        envelope = seal(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, rid,
            dict(method="GET" if body is None else "POST", path=path, query="", token=token,
                body=b64(b"" if body is None else json.dumps(body).encode())), "request")
        status, raw = http("/api/transport/v1", "POST", envelope, token="unused-outer-token")
        assert status == 200
        response = open_envelope(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, json.loads(raw), "response", rid)
        assert response["status"] == 200
        body_raw = base64.b64decode(response["body"])
        if path.endswith("/policy"):
            assert response["headers"]["X-SF-Policy-Signature"] == sign_policy(body_raw, cfg.POLICY_HMAC_KEY)
        return json.loads(body_raw)

    env = dict(os.environ, APP_ENV="prd", APP_CONFIG=str(tmp_path / "conf"),
        SF_CONTROL_HTTP_HOST="127.0.0.1", SF_CONTROL_HTTP_PORT=str(port),
        SF_CONTROL_CLIENT_TOKEN=cfg.CLIENT_TOKEN, SF_CONTROL_ADMIN_TOKEN=cfg.ADMIN_TOKEN,
        SF_CONTROL_POLICY_HMAC_KEY=cfg.HMAC_TEXT, SF_CONTROL_TRANSPORT_KEY=cfg.TRANSPORT_KEY_TEXT,
        SF_CONTROL_TRANSPORT_KEY_ID=cfg.TRANSPORT_KEY_ID, EAI_MYSQL_HOST=cfg.MYSQL_HOST,
        EAI_MYSQL_PORT=str(cfg.MYSQL_PORT), EAI_MYSQL_USERNAME=cfg.MYSQL_USER,
        EAI_MYSQL_PASSWORD=cfg.MYSQL_PASSWORD, EAI_MYSQL_DATABASE=cfg.MYSQL_DATABASE,
        SF_CONTROL_LOG_DIR=str(cfg.LOG_DIR), SF_CONTROL_DATA_ROOT=str(cfg.DATA_ROOT))
    process = None
    log = (tmp_path / "gunicorn.log").open("ab")

    def start():
        nonlocal process
        process = subprocess.Popen([sys.executable, "app.py"], cwd=Path(__file__).resolve().parents[1],
            env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert process.poll() is None, "Gunicorn exited before readiness"
            try:
                if http("/health/ready")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(.1)
        pytest.fail("Gunicorn readiness timed out")

    try:
        start()
        global_policy = json.loads(http("/admin/v1/policy")[1])
        devices = [business("/api/v2/enroll", cfg.CLIENT_TOKEN, dict(schemaVersion=2,
            deviceId=str(uuid4()), hostname="isolated-http-test", serviceVersion="0.2.3")) for _ in range(2)]
        target, other = devices
        path = "/admin/v1/devices/" + target["deviceId"] + "/policy"
        body = dict(expectedVersion=global_policy["policyVersion"],
            overrides=dict(gatewayOrigin="https://isolated.example.com", allowlistedBaseUrls=[]))
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: http(path, "PUT", body), range(4)))
        assert sorted(status for status, _ in results) == [200, 409, 409, 409]
        scoped = json.loads(next(raw for status, raw in results if status == 200))["effectivePolicy"]
        query = lambda device: business("/api/v2/devices/" + device["deviceId"] + "/policy", device["deviceToken"])
        assert query(target) == scoped
        assert query(other) == global_policy
        assert json.loads(http("/admin/v1/policy")[1]) == global_policy
        process.terminate()
        process.wait(timeout=30)
        start()
        assert query(target) == scoped
        status, raw = http(path, "DELETE", {"expectedVersion": scoped["policyVersion"]})
        assert status == 200
        reset = json.loads(raw)
        assert not reset["hasOverride"]
        assert reset["effectivePolicy"]["policyVersion"] > scoped["policyVersion"]
        assert query(target) == reset["effectivePolicy"]
        assert query(other) == global_policy
        assert json.loads(http("/admin/v1/policy")[1]) == global_policy
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=30)
        log.close()
