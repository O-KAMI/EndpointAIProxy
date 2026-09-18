import copy
import json
from pathlib import Path
from uuid import uuid4
import pytest
from app import create_app

FIXTURE = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text())


@pytest.mark.parametrize("change", [
    {"schemaVersion":1}, {"deviceId":str(uuid4()).replace("-", "") + "x"},
    {"deviceId":"00000000-0000-0000-0000-000000000000"}, {"hostname":""},
    {"hostname":"a"*256}, {"serviceVersion":""}, {"serviceVersion":"a"*65},
])
def test_enrollment_contract_errors(config, change):
    client = create_app(config, check_database=False).test_client()
    body = dict(FIXTURE["enrollment"], **change)
    result = client.post("/api/v2/enroll",json=body,headers={"Authorization":"Bearer "+config.CLIENT_TOKEN})
    assert result.status_code == 400
    assert result.json["error"]["code"] == "DEVICE_ENROLLMENT_INVALID"


@pytest.mark.parametrize("path", ["/api/v2/heartbeat","/api/v2/events/batch",
    "/api/v2/devices/10000000-0000-0000-0000-000000000001/policy",
    "/api/v2/commands/30000000-0000-0000-0000-000000000003/status"])
def test_prd_v2_rejects_plaintext_before_credentials(config, path):
    config.REQUIRE_HTTPS = True
    client = create_app(config, check_database=False).test_client()
    result = client.get(path) if path.endswith("/policy") else client.post(path,json={})
    assert result.status_code == 400
    assert result.json["error"]["code"] == "DEVICE_CONTROL_HTTPS_REQUIRED"


def test_ready_failure_and_exception_log_trace(config):
    class Store:
        def policy(self):
            raise RuntimeError("Synthetic unavailable database")
    app = create_app(config, Store(), check_database=False)
    client = app.test_client()
    result = client.get("/health/ready")
    assert result.status_code == 503
    assert result.json["error"] == "DATABASE_UNAVAILABLE"
    result = client.get("/admin/v1/policy",headers={"Authorization":"Bearer "+config.ADMIN_TOKEN})
    assert result.status_code == 500
    assert result.headers["X-Request-ID"] == result.json["error"]["traceId"]
    log = (config.LOG_DIR/"app.log").read_text()
    assert "Traceback" in log
    assert config.ADMIN_TOKEN not in log
