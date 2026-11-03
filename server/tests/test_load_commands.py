from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from controlserver.security import sign_command
from tools.load_commands import simulate_command
from tools.load_transport import FIXTURE_KEY


def make_command():
    now = datetime.now(timezone.utc)
    payload = dict(schemaVersion=1, commandId=str(uuid4()), deviceId=str(uuid4()), type='disableProxy',
                   issuedAtUtc=(now - timedelta(seconds=1)).isoformat(),
                   expiresAtUtc=(now + timedelta(minutes=1)).isoformat())
    return {'payload': payload, 'signature': sign_command(payload, FIXTURE_KEY)}


class Client:
    def __init__(self, status=202):
        self.status = status
        self.calls = []

    def request(self, method, path, token, body):
        self.calls.append(body['status'])
        return {'status': self.status}


def test_command_is_verified_and_acknowledged_once():
    client, signed, seen = Client(), make_command(), set()
    device = signed['payload']['deviceId']
    assert simulate_command(client, 'synthetic', device, signed, seen) == 'disabled'
    assert client.calls == ['executing', 'succeeded']
    assert simulate_command(client, 'synthetic', device, signed, seen) is None
    assert client.calls == ['executing', 'succeeded']


def test_invalid_or_expired_command_never_acknowledged():
    client, signed = Client(), make_command()
    signed['signature'] = 'invalid'
    with pytest.raises(ValueError):
        simulate_command(client, 'synthetic', signed['payload']['deviceId'], signed, set())
    signed = make_command()
    signed['payload']['expiresAtUtc'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    signed['signature'] = sign_command(signed['payload'], FIXTURE_KEY)
    with pytest.raises(ValueError):
        simulate_command(client, 'synthetic', signed['payload']['deviceId'], signed, set())
    assert client.calls == []


def test_ambiguous_receipt_is_not_executed_again():
    client, signed, seen = Client(status=503), make_command(), set()
    device = signed['payload']['deviceId']
    with pytest.raises(RuntimeError):
        simulate_command(client, 'synthetic', device, signed, seen)
    assert simulate_command(client, 'synthetic', device, signed, seen) is None
    assert client.calls == ['executing']
