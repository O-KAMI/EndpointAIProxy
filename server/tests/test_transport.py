import base64
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
from urllib.request import urlopen, Request
import pytest
from app import create_app
from controlserver.transport import seal, open_envelope, b64, direction_key, aad
from controlserver.database import schema_checksum, PREVIOUS_CHECKSUM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ID = "production-2026-01"
KEY = bytes(range(32))
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/dotnet-v0.1.19.json").read_text())


def envelope(cfg, path="/api/v1/policy", body=None, token=None, method=None):
    return seal(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, str(uuid4()),
                dict(method=method or ("GET" if body is None else "POST"), path=path, query="",
                     token=cfg.CLIENT_TOKEN if token is None else token,
                     body=b64(b"" if body is None else json.dumps(body).encode())), "request")


def send(client, cfg, wire):
    outer = client.post("/api/transport/v1", json=wire)
    assert outer.status_code == 200, outer.data
    return open_envelope(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, outer.json, "response", wire["requestId"])


def test_transport_policy_token_hidden_and_raw_signature(mysql_store):
    cfg = mysql_store.cfg
    client = create_app(cfg, mysql_store).test_client()
    wire = envelope(cfg)
    text = json.dumps(wire)
    assert cfg.CLIENT_TOKEN not in text and "/api/v1/policy" not in text
    value = send(client, cfg, wire)
    assert value["status"] == 200
    from controlserver.security import sign_policy
    body = base64.b64decode(value["body"])
    assert value["headers"]["X-SF-Policy-Signature"] == sign_policy(body, cfg.POLICY_HMAC_KEY)
    assert json.loads(body)["policyVersion"] == 1
    assert client.get("/api/v1/policy", headers={"Authorization":"Bearer "+cfg.CLIENT_TOKEN}).status_code == 403
    assert client.get("/api/v1/policy", headers={"X-Forwarded-Proto":"https", "endpointai.transport":"true"}).status_code == 403


def test_encrypted_errors_and_plain_admin(mysql_store, monkeypatch):
    cfg = mysql_store.cfg
    client = create_app(cfg, mysql_store).test_client()
    assert send(client, cfg, envelope(cfg, token="wrong"))["status"] == 401
    assert send(client, cfg, envelope(cfg, "/api/v2/enroll", {}))["status"] == 400
    assert send(client, cfg, envelope(cfg, "/api/v2/missing"))["status"] == 404
    assert client.get("/admin/v1/policy").status_code == 401
    assert client.get("/admin/v1/policy", headers={"Authorization":"Bearer "+cfg.ADMIN_TOKEN}).status_code == 200
    def fail(): raise RuntimeError("synthetic failure")
    monkeypatch.setattr(mysql_store, "policy", fail)
    assert send(client, cfg, envelope(cfg))["status"] == 500


@pytest.mark.parametrize("field", ["keyId", "requestId", "timestamp", "nonce", "ciphertext", "tag", "version"])
def test_tamper_fails_without_dispatch(mysql_store, field):
    cfg = mysql_store.cfg
    client = create_app(cfg, mysql_store).test_client()
    wire = envelope(cfg)
    wire[field] = wire[field]+1 if type(wire[field]) is int else ("A" if wire[field][0] != "A" else "B") + wire[field][1:]
    result = client.post("/api/transport/v1", json=wire)
    assert result.status_code == 400 and result.json == {"error":"INVALID_TRANSPORT"}
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM transport_replay")
        assert cur.fetchone()["n"] == 0


def test_wrong_key_expired_replay_and_retry(mysql_store, monkeypatch):
    cfg = mysql_store.cfg
    client = create_app(cfg, mysql_store).test_client()
    wire = envelope(cfg)
    send(client, cfg, wire)
    assert client.post("/api/transport/v1", json=wire).status_code == 400
    assert send(client, cfg, envelope(cfg))["status"] == 200
    with monkeypatch.context() as patch:
        patch.setattr("controlserver.transport.time.time", lambda: time.time_ns()/1e9 - 301)
        expired = envelope(cfg)
    assert client.post("/api/transport/v1", json=expired).status_code == 400
    wrong = seal(os.urandom(32), KEY_ID, str(uuid4()), {}, "request")
    assert client.post("/api/transport/v1", json=wrong).status_code == 400


def test_shared_database_replay_claims_and_nonce_reuse(mysql_store):
    from controlserver.database import ControlStore
    wire = envelope(mysql_store.cfg)
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda _: ControlStore(mysql_store.cfg).claim_transport(wire), range(8)))
    assert sum(claims) == 1
    assert not mysql_store.claim_transport(dict(wire, requestId=str(uuid4())))
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE transport_replay SET expires_at_utc=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND")
    assert mysql_store.claim_transport(wire)


def test_migration_preserves_business_and_is_idempotent(mysql_store):
    from controlserver.models import DeviceEnrollmentRequest, HeartbeatV2Request
    from controlserver.database import schema_tables
    enrolled = mysql_store.enroll(DeviceEnrollmentRequest.model_validate(FIXTURE["enrollment"]))
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(FIXTURE["heartbeat"]),60,"127.0.0.1")
    def snapshot():
        with mysql_store.transaction() as cur:
            rows = {}
            for table in sorted(schema_tables() - {"schema_migrations","transport_replay"}):
                cur.execute(f"SELECT * FROM `{table}`")
                rows[table] = sorted(json.dumps(row,sort_keys=True,default=str) for row in cur.fetchall())
            return rows
    business_before = snapshot()
    before = mysql_store.policy()
    with mysql_store.transaction() as cur:
        cur.execute("DROP TABLE transport_replay")
        cur.execute("UPDATE schema_migrations SET version=1,checksum=%s", (PREVIOUS_CHECKSUM,))
    assert mysql_store.migrate() == "migrated"
    assert mysql_store.policy() == before
    assert snapshot() == business_before
    assert mysql_store.authenticate(enrolled["deviceId"],enrolled["deviceToken"])
    assert mysql_store.migrate() == "already_migrated"
    mysql_store.check_schema()


def dotnet():
    binary = os.environ.get("ENDPOINTAI_TEST_DOTNET")
    if not binary: pytest.skip("Set ENDPOINTAI_TEST_DOTNET for .NET interop")
    return [binary, str(ROOT / "artifacts/interop/Interop.dll")]


def test_dotnet_rejects_unauthenticated_and_malformed_http():
    result = subprocess.run(dotnet()+["aes-rejections"],text=True,capture_output=True,timeout=15)
    assert result.returncode == 0, result.stderr


def test_replay_constraint_drift_prevents_startup(mysql_store):
    with mysql_store.transaction() as cur:
        cur.execute("ALTER TABLE transport_replay DROP INDEX transport_nonce")
    with pytest.raises(RuntimeError, match="unique constraints"):
        create_app(mysql_store.cfg, mysql_store)


@pytest.mark.parametrize("value", [None, "中文和 emoji 🚚", {"bytes":"x"*1_500_000}])
def test_python_dotnet_bidirectional_and_response_binding(value):
    rid = str(uuid4())
    wire = seal(KEY, KEY_ID, rid, value, "response")
    result = subprocess.run(dotnet()+["aes-open",rid,"response"], input=json.dumps(wire), text=True, capture_output=True, check=True)
    assert json.loads(result.stdout) == value
    result = subprocess.run(dotnet()+["aes-seal",rid,"request"], input=json.dumps(value), text=True, capture_output=True, check=True)
    assert open_envelope(KEY, KEY_ID, json.loads(result.stdout), "request", rid) == value
    result = subprocess.run(dotnet()+["aes-open",str(uuid4()),"response"], input=json.dumps(wire), text=True, capture_output=True)
    assert result.returncode != 0


def test_app_py_real_http_original_client_workflow_and_restart(mysql_store, tmp_path):
    cfg = mysql_store.cfg
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    env = dict(os.environ, APP_ENV="prd", APP_CONFIG=str(tmp_path/"conf"),
        SF_CONTROL_HTTP_HOST="127.0.0.1", SF_CONTROL_HTTP_PORT=str(port),
        SF_CONTROL_CLIENT_TOKEN=cfg.CLIENT_TOKEN, SF_CONTROL_ADMIN_TOKEN=cfg.ADMIN_TOKEN,
        SF_CONTROL_POLICY_HMAC_KEY=cfg.HMAC_TEXT, SF_CONTROL_TRANSPORT_KEY=cfg.TRANSPORT_KEY_TEXT,
        SF_CONTROL_TRANSPORT_KEY_ID=cfg.TRANSPORT_KEY_ID, EAI_MYSQL_HOST=cfg.MYSQL_HOST,
        EAI_MYSQL_PORT=str(cfg.MYSQL_PORT), EAI_MYSQL_USERNAME=cfg.MYSQL_USER,
        EAI_MYSQL_PASSWORD="", EAI_MYSQL_DATABASE=cfg.MYSQL_DATABASE,
        SF_CONTROL_LOG_DIR=str(cfg.LOG_DIR), SF_CONTROL_DATA_ROOT=str(cfg.DATA_ROOT),
        EAI_INTEROP_CLIENT_TOKEN=cfg.CLIENT_TOKEN, EAI_INTEROP_ADMIN_TOKEN=cfg.ADMIN_TOKEN)
    log = tmp_path/"gunicorn.log"
    for attempt in range(2):
        with log.open("ab") as output:
            process = subprocess.Popen([sys.executable,"app.py"], cwd=ROOT, env=env, stdout=output, stderr=output)
            try:
                deadline = time.monotonic()+15
                while True:
                    try:
                        with urlopen(origin+"/health/ready",timeout=1) as result: assert result.status == 200
                        break
                    except Exception:
                        if process.poll() is not None or time.monotonic()>deadline:
                            pytest.fail(log.read_text())
                        time.sleep(.05)
                if attempt == 0:
                    run = subprocess.run(dotnet()+["aes-live",origin,""],env=env,text=True,capture_output=True,timeout=30)
                    assert run.returncode == 0, run.stderr
                    assert json.loads(run.stdout)["accepted"] == 1
                    repeated = envelope(cfg)
                    def replay(_):
                        from urllib.error import HTTPError
                        try:
                            with urlopen(Request(origin+"/api/transport/v1",data=json.dumps(repeated).encode(),
                                    headers={"Content-Type":"application/json"}),timeout=10) as result:
                                return result.status
                        except HTTPError as error:
                            return error.code
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        statuses = list(pool.map(replay, range(8)))
                    assert statuses.count(200) == 1 and statuses.count(400) == 7
                else:
                    from urllib.error import HTTPError
                    with pytest.raises(HTTPError) as caught:
                        urlopen(Request(origin+"/api/transport/v1",data=json.dumps(repeated).encode(),
                            headers={"Content-Type":"application/json"}),timeout=5)
                    assert caught.value.code == 400
                wire = envelope(cfg)
                request_bytes = json.dumps(wire).encode()
                with urlopen(Request(origin+"/api/transport/v1",data=request_bytes,headers={"Content-Type":"application/json"}),timeout=5) as result:
                    response_bytes = result.read()
                assert cfg.CLIENT_TOKEN.encode() not in request_bytes
                assert b"gatewayOrigin" not in response_bytes
                assert open_envelope(KEY,KEY_ID,json.loads(response_bytes),"response",wire["requestId"])["status"] == 200
            finally:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
    assert "Using worker: gthread" in log.read_text()
