import json
import pytest

from flask import Flask
from controlserver.http import parse
from controlserver.models import DevicePolicyUpdateRequest, PolicyUpdateRequest
from controlserver.validation import ApiProblem, validate_policy


def test_policy_error_paths_exclude_values_and_have_allowed_route_modes():
    app = Flask(__name__)
    with app.test_request_context(json={"expectedVersion": 1, "overrides": {
        "routingRules": [{"domain": "example.com", "routeMode": "secret-invalid-mode"}]
    }}):
        try:
            parse(DevicePolicyUpdateRequest, "POLICY_FIELDS_INVALID")
        except ApiProblem as error:
            assert error.code == "POLICY_FIELDS_INVALID"
            encoded = json.dumps(error.details)
            assert "secret-invalid-mode" not in encoded
            detail = next(d for d in error.details if d["field"].endswith("routeMode"))
            assert detail["field"] == "overrides.routingRules.0.routeMode"
            assert detail["allowedValues"] == ["passthroughOriginal", "fixedGateway"]
        else:
            raise AssertionError("invalid route mode accepted")


@pytest.mark.parametrize("changed,code,field", [
    ({"pollIntervalSeconds": 1}, "POLICY_FIELDS_INVALID", "pollIntervalSeconds"),
    ({"gatewayOrigin": "https://secret.invalid/private"}, "POLICY_GATEWAY_INVALID", "gatewayOrigin"),
    ({"allowlistedDomains": ["https://secret.invalid"]}, "POLICY_RULES_INVALID", "allowlistedDomains"),
    ({"routingRules": [{"domain": "example.com", "routeMode": "fixedGateway",
                        "gatewayOrigin": "https://secret.invalid/private"}]},
     "POLICY_GATEWAY_INVALID", "routingRules.0.gatewayOrigin"),
])
def test_semantic_policy_errors_identify_safe_fields(changed, code, field):
    values = dict(expectedVersion=1, enabled=True, routeMode="fixedGateway",
                  gatewayOrigin="https://gateway.example", allowInsecureGateway=False,
                  pollIntervalSeconds=60, heartbeatIntervalSeconds=60)
    with pytest.raises(ApiProblem) as captured:
        validate_policy(PolicyUpdateRequest(**(values | changed)))
    assert captured.value.code == code
    assert captured.value.details[0]["field"] == field
    assert "secret.invalid" not in str(captured.value.details)


@pytest.mark.parametrize("device_override", [False, True])
def test_policy_http_errors_have_trace_and_do_not_echo_url_parser_input(mysql_store, device_override):
    from uuid import uuid4
    from app import create_app
    from controlserver.models import DeviceEnrollmentRequest

    secret = "synthetic-sensitive-port"
    invalid = ["https://gateway.example:" + secret]
    if device_override:
        device = mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=uuid4(),
                                     hostname="synthetic-errors", serviceVersion="synthetic"))["deviceId"]
        path = "/admin/v1/devices/" + device + "/policy"
        payload = dict(expectedVersion=mysql_store.policy()["policyVersion"], overrides=dict(allowlistedBaseUrls=invalid))
    else:
        path = "/admin/v1/policy"
        payload = dict(expectedVersion=mysql_store.policy()["policyVersion"], enabled=True,
                       routeMode="passthroughOriginal", allowInsecureGateway=False,
                       pollIntervalSeconds=60, heartbeatIntervalSeconds=60, allowlistedBaseUrls=invalid)
    response = create_app(mysql_store.cfg, mysql_store).test_client().put(path, json=payload,
                  headers={"Authorization": "Bearer " + mysql_store.cfg.ADMIN_TOKEN})
    assert response.status_code == 400
    error = response.json["error"]
    assert error["code"] == "POLICY_ALLOWLIST_INVALID"
    assert error["traceId"]
    assert error["details"][0]["field"].endswith("allowlistedBaseUrls")
    assert secret not in json.dumps(error)
