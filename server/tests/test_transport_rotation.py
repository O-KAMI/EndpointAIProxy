import base64
from uuid import uuid4

import pytest

from app import create_app
from controlserver.database import PoolExhausted
from controlserver.transport import b64, open_envelope, seal


NEW_KEY = bytes(range(32, 64))
NEW_ID = "rotation-test"


class Store:
    def __init__(self):
        self.claims = set()

    def claim_transport(self, envelope):
        claim = (envelope["keyId"], envelope["requestId"])
        if claim in self.claims:
            return False
        self.claims.add(claim)
        return True

    def policy(self):
        return {"policyVersion": 1}


def wire(key, key_id, token):
    return seal(key, key_id, str(uuid4()), dict(method="GET", path="/api/v1/policy",
                query="", token=token, body=b64(b"")), "request")


def test_rotation_overlap_and_retirement(config):
    old_key, old_id = config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID
    config.TRANSPORT_ADDITIONAL_KEY_ID = NEW_ID
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = base64.b64encode(NEW_KEY).decode()
    client = create_app(config, Store(), check_database=False).test_client()
    for key, key_id in ((old_key, old_id), (NEW_KEY, NEW_ID)):
        request = wire(key, key_id, config.CLIENT_TOKEN)
        result = client.post("/api/transport/v1", json=request)
        assert result.status_code == 200
        assert open_envelope(key, key_id, result.json, "response", request["requestId"])["status"] == 200
        assert client.post("/api/transport/v1", json=request).status_code == 400
    assert client.post("/api/transport/v1", json=wire(old_key, NEW_ID, config.CLIENT_TOKEN)).status_code == 400
    assert client.post("/api/transport/v1", json=wire(NEW_KEY, "unknown", config.CLIENT_TOKEN)).status_code == 400

    config.TRANSPORT_KEY_ID = NEW_ID
    config.TRANSPORT_KEY_TEXT = base64.b64encode(NEW_KEY).decode()
    config.TRANSPORT_ADDITIONAL_KEY_ID = ""
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = ""
    retired = create_app(config, Store(), check_database=False).test_client()
    assert retired.post("/api/transport/v1", json=wire(old_key, old_id, config.CLIENT_TOKEN)).status_code == 400
    request = wire(NEW_KEY, NEW_ID, config.CLIENT_TOKEN)
    result = retired.post("/api/transport/v1", json=request)
    assert open_envelope(NEW_KEY, NEW_ID, result.json, "response", request["requestId"])["status"] == 200


def test_overload_response_uses_request_key(config):
    class Busy(Store):
        def claim_transport(self, envelope):
            raise PoolExhausted()
    config.TRANSPORT_ADDITIONAL_KEY_ID = NEW_ID
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = base64.b64encode(NEW_KEY).decode()
    client = create_app(config, Busy(), check_database=False).test_client()
    request = wire(NEW_KEY, NEW_ID, config.CLIENT_TOKEN)
    result = client.post("/api/transport/v1", json=request)
    value = open_envelope(NEW_KEY, NEW_ID, result.json, "response", request["requestId"])
    assert value["status"] == 503
    assert value["headers"]["Retry-After"] == "5"


@pytest.mark.parametrize("key_id,key_text", [
    ("rotation-test", ""), ("", "a2V5"), ("bad id", "a2V5"),
    ("rotation-test", "not-base64!"), ("rotation-test", "a2V5"),
])
def test_invalid_additional_key_is_rejected(config, key_id, key_text):
    config.TRANSPORT_ADDITIONAL_KEY_ID = key_id
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = key_text
    with pytest.raises(ValueError):
        config.validate()


def test_duplicate_id_and_key_are_rejected(config):
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = base64.b64encode(NEW_KEY).decode()
    config.TRANSPORT_ADDITIONAL_KEY_ID = config.TRANSPORT_KEY_ID
    with pytest.raises(ValueError):
        config.validate()
    config.TRANSPORT_ADDITIONAL_KEY_ID = NEW_ID
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = config.TRANSPORT_KEY_TEXT
    with pytest.raises(ValueError):
        config.validate()


def test_rotation_with_mysql_replay_claims(mysql_store):
    config = mysql_store.cfg
    config.TRANSPORT_ADDITIONAL_KEY_ID = NEW_ID
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = base64.b64encode(NEW_KEY).decode()
    client = create_app(config, mysql_store).test_client()
    for key, key_id in ((config.TRANSPORT_KEY, config.TRANSPORT_KEY_ID), (NEW_KEY, NEW_ID)):
        request = wire(key, key_id, config.CLIENT_TOKEN)
        result = client.post("/api/transport/v1", json=request)
        assert result.status_code == 200
        assert open_envelope(key, key_id, result.json, "response", request["requestId"])["status"] == 200
        assert client.post("/api/transport/v1", json=request).status_code == 400


@pytest.mark.parametrize("device_transport", [False, True])
@pytest.mark.parametrize("device_transport_v2", [False, True])
def test_original_dotnet_client_over_http_with_key_overlap(mysql_store, device_transport, device_transport_v2):
    import json
    import os
    import subprocess
    from threading import Thread
    from werkzeug.serving import make_server
    from test_transport import dotnet

    config = mysql_store.cfg
    config.DEVICE_TRANSPORT = device_transport
    config.DEVICE_TRANSPORT_V2 = device_transport_v2
    if device_transport_v2:
        config.DEVICE_KEY_ID = '2'
        config.DEVICE_KEY_TEXT = base64.b64encode(b'\x55' * 32).decode()
    config.TRANSPORT_ADDITIONAL_KEY_ID = NEW_ID
    config.TRANSPORT_ADDITIONAL_KEY_TEXT = base64.b64encode(NEW_KEY).decode()
    server = make_server("127.0.0.1", 0, create_app(config, mysql_store), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ, EAI_INTEROP_CLIENT_TOKEN=config.CLIENT_TOKEN,
                   EAI_INTEROP_ADMIN_TOKEN=config.ADMIN_TOKEN)
        result = subprocess.run(dotnet() + ["aes-live", f"http://127.0.0.1:{server.server_port}", ""],
                                env=env, capture_output=True, encoding="utf-8", timeout=45)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["accepted"] == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
