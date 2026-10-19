"""Synthetic local requests: no MySQL, real credential files or network calls."""
import logging
from uuid import uuid4
import pytest

from app import create_app
from controlserver.transport import b64, open_envelope, seal


class ReplayStore:
    def __init__(self):
        self.claims = set()

    def claim_transport(self, envelope):
        if envelope["requestId"] in self.claims:
            return False
        self.claims.add(envelope["requestId"])
        return True


def wire(config, path="/api/v2/missing", token="synthetic-secret-token"):
    return seal(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, str(uuid4()),
                dict(method="GET", path=path, query="secret=synthetic-secret-query", token=token,
                     body=b64(b"synthetic-secret-body")), "request")


def test_transport_logs_authenticated_ids_without_payloads(config, caplog):
    app = create_app(config, ReplayStore(), check_database=False)
    caplog.set_level(logging.INFO, logger=app.logger.name)
    request = wire(config)
    result = app.test_client().post("/api/transport/v1", json=request)
    assert result.status_code == 200
    value = open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                          "response", request["requestId"])
    assert value["status"] == 404
    business = value["headers"]["X-Request-ID"]
    logs = [r.getMessage() for r in caplog.records if "controlEnvelopeId=" in r.getMessage()]
    assert len(logs) == 2
    assert all(f"controlEnvelopeId={request['requestId']}" in line for line in logs)
    assert all(f"businessRequestId={business}" in line for line in logs)
    assert "stage=business" in logs[0] and "stage=transport_complete" in logs[1]
    assert all("durationMilliseconds=" in line for line in logs)
    assert result.headers["X-Request-ID"] == business
    assert "synthetic-secret" not in "\n".join(logs)


def test_unauthenticated_envelope_id_not_logged(config, caplog):
    app = create_app(config, ReplayStore(), check_database=False)
    caplog.set_level(logging.INFO, logger=app.logger.name)
    request = wire(config)
    request["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    result = app.test_client().post("/api/transport/v1", json=request)
    assert result.status_code == 400
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert request["requestId"] not in text
    assert "stage=transport_validate" in text


def test_error_logs_do_not_include_exception_messages(config, caplog):
    app = create_app(config, ReplayStore(), check_database=False)
    @app.get("/api/v2/crash")
    def crash():
        raise RuntimeError("synthetic-secret-error")
    caplog.set_level(logging.INFO, logger=app.logger.name)
    request = wire(config, "/api/v2/crash")
    result = app.test_client().post("/api/transport/v1", json=request)
    value = open_envelope(config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID, result.json,
                          "response", request["requestId"])
    assert value["status"] == 500
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "errorClass=INTERNAL_ERROR" in text and "synthetic-secret" not in text


@pytest.mark.parametrize("version", ["0.1.23", "0.1.24"])
def test_rotation_template_covers_upgrade_layout_and_distinguishes_open_console(version):
    from pathlib import Path
    from fnmatch import fnmatch
    import re
    template = (Path(__file__).resolve().parents[1] / "deploy/logrotate-appdeploy.conf").read_text()
    rules = dict(re.findall(r"(?m)^(/[^\n ]+)\s*\{([^}]+)\}", template))
    app_rule = next(body for path, body in rules.items()
                    if fnmatch(f"/app/EndpointAIDLP-Server-{version}/logs/app.log", path))
    console_rule = next(body for path, body in rules.items()
                        if fnmatch(f"/app/EndpointAIDLP-Server-{version}/console.log", path))
    assert "su appdeploy appdeploy" in app_rule and "create 0640 appdeploy appdeploy" in app_rule
    assert "copytruncate" not in app_rule
    assert "copytruncate" in console_rule and "su appdeploy appdeploy" in console_rule
    assert "maxsize 20M" in app_rule and "maxsize 20M" in console_rule


def test_exception_metadata_is_bounded_and_does_not_accept_free_text():
    from controlserver.observability import safe_exception
    import pymysql
    error = pymysql.OperationalError(2003, "synthetic-secret-connection")
    error.sqlstate = "08001"
    assert safe_exception(error)[:3] == ("OperationalError", 2003, "08001")
    error.sqlstate = "synthetic-secret-state"
    assert safe_exception(error)[2] == ""
    assert "synthetic-secret" not in str(safe_exception(error))
    assert safe_exception(RuntimeError("synthetic-secret"))[1] == 0
