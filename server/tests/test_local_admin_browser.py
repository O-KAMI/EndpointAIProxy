"""Optional browser verification with synthetic accounts and isolated MySQL."""
import base64
import json
import os
from pathlib import Path
import subprocess
from threading import Thread

import pytest
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server
from app import create_app


@pytest.mark.skipif(os.environ.get("ENDPOINTAI_TEST_BROWSER") != "1", reason="Optional local browser test")
def test_local_account_login_and_viewer_permissions(mysql_store, tmp_path):
    node = os.environ["ENDPOINTAI_TEST_NODE"]
    accounts = tmp_path / "accounts.json"
    accounts.write_text(json.dumps([{"username": name, "role": role,
        "passwordHash": generate_password_hash("synthetic password 123")}
        for name, role in (("viewer", "viewer"), ("operator", "operator"), ("admin", "admin"))]), encoding="utf-8")
    accounts.chmod(0o600)
    cfg = mysql_store.cfg
    cfg.ADMIN_AUTH_MODE = "local"
    cfg.ADMIN_ACCOUNTS_PATH = str(accounts)
    cfg.ADMIN_SESSION_KEY_TEXT = base64.b64encode(b"s" * 32).decode()
    from controlserver.models import DeviceEnrollmentRequest, HeartbeatV2Request
    fixture = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))
    fixture["heartbeat"]["users"][0]["accountName"] = "sf\\synthetic-worker"
    heartbeat = HeartbeatV2Request.model_validate(fixture["heartbeat"])
    enrolled = mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=heartbeat.device.deviceId,
        hostname=heartbeat.device.hostname, serviceVersion="synthetic"))
    mysql_store.heartbeat(heartbeat, 60, "127.0.0.1")
    mysql_store.ensure_scale_indexes()
    cfg.EMPLOYEE_INDEX = True
    original_policy = mysql_store.policy()
    server = make_server("127.0.0.1", 0, create_app(cfg, mysql_store), threaded=True, ssl_context="adhoc")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ, ENDPOINTAI_TEST_ORIGIN=f"https://127.0.0.1:{server.server_port}",
                   ENDPOINTAI_TEST_HOSTNAME=heartbeat.device.hostname,
                   ENDPOINTAI_TEST_EMPLOYEE="synthetic-worker",
                   ENDPOINTAI_TEST_DEVICE=str(heartbeat.device.deviceId))
        # Allow cold browser-runtime imports; per-action UI waits remain unchanged.
        result = subprocess.run([node, str(Path(__file__).with_name("local_admin_browser.cjs"))],
            env=env, capture_output=True, encoding="utf-8", timeout=180)
        assert result.returncode == 0, result.stderr
        assert mysql_store.policy() == original_policy
        assert not mysql_store.authenticate(enrolled["deviceId"], enrolled["deviceToken"])
        assert mysql_store.audits(enrolled["deviceId"], 0, 10)[0]["action"] == "DEVICE_CREDENTIAL_RECOVERED"
        actions = {item["action"] for item in mysql_store.audits(None, 0, 20)}
        assert {"ROLLOUT_CREATED", "ROLLOUT_RESUME", "ROLLOUT_PAUSE"} <= actions
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.skipif(os.environ.get('ENDPOINTAI_TEST_BROWSER') != '1', reason='Optional local browser test')
def test_policy_batch_filters_show_matching_targets(mysql_store, tmp_path):
    import copy
    from controlserver import policy_rollout
    from controlserver.models import HeartbeatV2Request
    from test_policy_rollout import FIXTURE, devices, request, due
    ids = devices(mysql_store, 2)
    batch = policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')['batchId']
    policy_rollout.change(mysql_store, batch, 'resume', 'test', 'admin')
    assert policy_rollout.dispatch_one(mysql_store)
    due(mysql_store, batch)
    assert policy_rollout.dispatch_one(mysql_store)
    detail = policy_rollout.details(mysql_store, batch, 0, 10)
    for index, target in enumerate(detail['targets']):
        beat = copy.deepcopy(FIXTURE)
        beat['device']['deviceId'] = target['deviceId']
        beat['policy']['appliedVersion'] = target['assignedVersion']
        beat['policy']['appliedSchemaVersion'] = 2 if index == 0 else 1
        beat['runtime']['supportedPolicySchemaVersion'] = 2 if index == 0 else 1
        beat['runtime']['lastReconcileResult'] = 'failed' if index == 0 else 'completed'
        beat['runtime']['lastReconcileErrorCode'] = 'CONFIG_ERROR' if index == 0 else None
        mysql_store.heartbeat(HeartbeatV2Request.model_validate(beat), 60, '127.0.0.1')
    states = policy_rollout.details(mysql_store, batch, 0, 10)['targets']
    assert [item['applicationState'] for item in states] == ['applyFailed', 'unsupported']
    accounts = tmp_path / 'accounts.json'
    accounts.write_text(json.dumps([{'username':'admin', 'role':'admin',
        'passwordHash':generate_password_hash('synthetic password 123')}]), encoding='utf-8')
    accounts.chmod(0o600)
    cfg = mysql_store.cfg
    cfg.ADMIN_AUTH_MODE = 'local'
    cfg.ADMIN_ACCOUNTS_PATH = str(accounts)
    cfg.ADMIN_SESSION_KEY_TEXT = base64.b64encode(b's' * 32).decode()
    server = make_server('127.0.0.1', 0, create_app(cfg, mysql_store), threaded=True, ssl_context='adhoc')
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ, ENDPOINTAI_TEST_ORIGIN=f'https://127.0.0.1:{server.server_port}',
                   ENDPOINTAI_TEST_FAILED=ids[0], ENDPOINTAI_TEST_UNSUPPORTED=ids[1])
        result = subprocess.run([os.environ['ENDPOINTAI_TEST_NODE'], str(Path(__file__).with_name('policy_filter_browser.cjs'))],
            env=env, capture_output=True, encoding='utf-8', timeout=180)
        assert result.returncode == 0, result.stderr
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
