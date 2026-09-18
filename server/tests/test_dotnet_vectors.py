import json
from pathlib import Path
from controlserver.models import HeartbeatV2Request, RemoteCommandPayload
from controlserver.security import dumps, sign_command, sign_policy
import pytest
from controlserver.validation import normalize_base_url

FIXTURE = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text())


def test_original_dotnet_signature_vectors():
    key = bytes(range(32))
    for vector in FIXTURE["commandVectors"]:
        parsed = RemoteCommandPayload.model_validate_json(vector["body"])
        assert dumps(parsed) == vector["body"]
        assert sign_command(parsed, key) == vector["signature"]
    assert sign_policy(FIXTURE["policyBody"],key) == FIXTURE["policySignature"]


def test_original_heartbeat_round_trip_preserves_every_field():
    parsed = HeartbeatV2Request.model_validate(FIXTURE["heartbeat"])
    assert json.loads(dumps(parsed)) == FIXTURE["heartbeat"]


@pytest.mark.parametrize("vector", FIXTURE["allowlistVectors"])
def test_original_allowlist_normalization(vector):
    if vector["valid"]:
        assert normalize_base_url(vector["input"]) == vector["normalized"]
    else:
        with pytest.raises(ValueError):
            normalize_base_url(vector["input"])
