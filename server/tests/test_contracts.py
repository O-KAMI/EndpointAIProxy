import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4
import pytest
from app import create_app
from config import Config, load_properties
from controlserver.models import DeviceEnrollmentRequest, PolicyUpdateRequest
from controlserver.security import sign_command, timestamp, dumps, utcnow
from controlserver.validation import normalize_allowlist, normalize_base_url, validate_policy, ApiProblem, seed_policy
from controlserver.routes_admin import online_state
from controlserver.certificates import ensure_certificate


def test_properties_preserve_secret_characters(tmp_path):
    path = tmp_path / "values.properties"
    path.write_text('#comment\npassword=a#b!c=d:e\nurl:https://example.com\n', encoding="utf-8")
    assert load_properties(path) == {"password":"a#b!c=d:e", "url":"https://example.com"}


def test_config_environment_selection_and_overrides(tmp_path, monkeypatch):
    (tmp_path / "application.properties").write_text("app.env=prd\nserver.http-port=8080\n")
    (tmp_path / "mysql_prd.properties").write_text("eai.mysql.host=prd.invalid\n")
    (tmp_path / "mysql_sit.properties").write_text("eai.mysql.host=sit.invalid\n")
    assert Config(conf_dir=tmp_path).MYSQL_HOST == "prd.invalid"
    assert Config("sit", tmp_path).MYSQL_HOST == "sit.invalid"
    monkeypatch.setenv("EAI_MYSQL_HOST", "override.invalid")
    assert Config("sit", tmp_path).MYSQL_HOST == "override.invalid"
    with pytest.raises(ValueError):
        Config("docker", tmp_path)


@pytest.mark.parametrize("key", ["", "invalid!", base64.b64encode(b"short").decode()])
def test_missing_or_invalid_hmac_fails(config, key):
    config.HMAC_TEXT = key
    with pytest.raises(ValueError):
        config.validate()


def test_pascal_and_camel_input_contracts():
    device = str(uuid4())
    a = DeviceEnrollmentRequest.model_validate(dict(schemaVersion=2,deviceId=device,hostname="终端",serviceVersion="0.1.19"))
    b = DeviceEnrollmentRequest.model_validate(dict(SchemaVersion=2,DeviceId=device,Hostname="终端",ServiceVersion="0.1.19"))
    assert a == b


@pytest.mark.parametrize("url, expected", [
    (" HTTPS://Example.COM:443/api/ ", "https://example.com/api"),
    ("http://example.com:80/", "http://example.com"),
    ("https://example.com/a/../b", "https://example.com/b"),
    ("http://[::1]:18080/api/", "http://[::1]:18080/api"),
])
def test_allowlist_normalization(url, expected):
    assert normalize_base_url(url) == expected


@pytest.mark.parametrize("url", ["", "ftp://example.com", "https://user@example.com",
    "https://example.com?", "https://example.com#", "https://example.com:99999", "/relative"])
def test_allowlist_rejects_invalid_urls(url):
    with pytest.raises(ValueError):
        normalize_base_url(url)


def test_allowlist_deduplicates_and_limits():
    assert normalize_allowlist(["https://EXAMPLE.com/", "https://example.com"]) == ["https://example.com"]
    with pytest.raises(ValueError):
        normalize_allowlist([f"https://example.com/{i}" for i in range(257)])


def test_policy_bounds_and_http_gateway(config):
    policy = seed_policy(config)
    update = PolicyUpdateRequest(expectedVersion=1, **{k:v for k,v in policy.items() if k in PolicyUpdateRequest.model_fields})
    validate_policy(update)
    update.allowInsecureGateway = False
    with pytest.raises(ApiProblem, match="POLICY_GATEWAY_INVALID"):
        validate_policy(update)
    update.allowInsecureGateway = True
    update.pollIntervalSeconds = 14
    with pytest.raises(ApiProblem, match="POLICY_FIELDS_INVALID"):
        validate_policy(update)


@pytest.mark.parametrize("elapsed,state", [(150,"online"),(151,"stale"),(330,"stale"),(331,"offline")])
def test_online_boundaries(elapsed, state):
    now = utcnow()
    assert online_state(dict(lastSeenAtUtc=timestamp(now-timedelta(seconds=elapsed)), heartbeatIntervalSeconds=60),now) == state


def test_response_signs_exact_bytes(config):
    class Store:
        def policy(self):
            return seed_policy(config)
    app = create_app(config, Store(), check_database=False)
    r = app.test_client().get("/api/v1/policy", headers={"Authorization": "bEaReR " + config.CLIENT_TOKEN})
    assert r.status_code == 200
    encoded = base64.urlsafe_b64encode(hmac.new(config.POLICY_HMAC_KEY, r.data, hashlib.sha256).digest()).rstrip(b"=").decode()
    assert r.headers["X-SF-Policy-Signature"] == "v1:" + encoded
    assert r.headers["Cache-Control"] == "no-store"
    assert r.json["schemaVersion"] == 1


def test_proxy_headers_only_trusted_from_loopback(config):
    config.REQUIRE_HTTPS = True
    config.TRUST_PROXY = True
    app = create_app(config, check_database=False)
    client = app.test_client()
    assert client.get("/console").status_code == 400
    assert client.get("/console", headers={"X-Forwarded-Proto":"https"}).status_code == 200
    assert client.get("/console", headers={"X-Forwarded-Proto":"https"},
                      environ_overrides={"REMOTE_ADDR":"192.0.2.1"}).status_code == 400


def test_wrong_token_and_malformed_json(config):
    app = create_app(config, check_database=False)
    client = app.test_client()
    assert client.get("/admin/v1/policy").status_code == 401
    assert client.get("/api/v1/policy", headers={"Authorization":config.CLIENT_TOKEN}).status_code == 401
    r = client.post("/api/v2/enroll", data="{", content_type="application/json",
                    headers={"Authorization":"Bearer "+config.CLIENT_TOKEN})
    assert r.status_code == 400
    assert r.json["error"]["code"] == "DEVICE_ENROLLMENT_INVALID"


def test_self_signed_certificate_profile_and_reuse(tmp_path):
    info = ensure_certificate(tmp_path, "10.220.22.112")
    key = (tmp_path / "server.key").read_bytes()
    assert info["rsaKeySize"] == 3072
    assert len(base64.b64decode(info["spkiSha256"])) == 32
    assert ensure_certificate(tmp_path, "10.220.22.112") == info
    assert (tmp_path / "server.key").read_bytes() == key
    assert (tmp_path / "server.key").stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="SAN"):
        ensure_certificate(tmp_path, "127.0.0.1")


def test_console_migrates_original_interactions(config):
    r = create_app(config, check_database=False).test_client().get("/console")
    html = r.data.decode()
    for value in ('id="authView"', 'id="detailView"', 'function logicalEndpointKey',
                  'function mergeEndpointObservations', 'function groupModels', 'commandCreateInFlight',
                  'confirmedCommand=commands.find', 'DetailRefreshIntervalMilliseconds=15000', '命令审计'):
        assert value in html
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
