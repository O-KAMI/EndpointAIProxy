"""Simulate signed command receipt without touching local proxy configuration."""
from datetime import datetime, timezone
import hmac
from uuid import UUID

from controlserver.security import sign_command
from tools.load_transport import FIXTURE_KEY


def simulate_command(client, token, expected_device, signed, seen):
    if not isinstance(signed, dict) or set(signed) != {'payload', 'signature'}:
        raise ValueError('Invalid synthetic command')
    payload = signed['payload']
    required = {'schemaVersion', 'commandId', 'deviceId', 'type', 'issuedAtUtc', 'expiresAtUtc'}
    if not isinstance(payload, dict) or set(payload) != required or payload['schemaVersion'] != 1:
        raise ValueError('Invalid synthetic command payload')
    command_id = payload['commandId']
    if (str(UUID(command_id)) != command_id or payload['deviceId'] != expected_device
            or payload['type'] not in ('enableProxy', 'disableProxy')
            or not isinstance(signed['signature'], str)
            or not hmac.compare_digest(signed['signature'], sign_command(payload, FIXTURE_KEY))):
        raise ValueError('Synthetic command authentication failed')
    now = datetime.now(timezone.utc)
    issued = datetime.fromisoformat(payload['issuedAtUtc'].replace('Z', '+00:00'))
    expires = datetime.fromisoformat(payload['expiresAtUtc'].replace('Z', '+00:00'))
    if issued.tzinfo is None or expires.tzinfo is None or issued > now or expires <= now or expires <= issued:
        raise ValueError('Synthetic command is expired or has invalid timestamps')
    if command_id in seen:
        return None
    # Never retry or simulate a second execution after an ambiguous receipt.
    seen.add(command_id)
    path = f'/api/v2/commands/{command_id}/status'
    for status in ('executing', 'succeeded'):
        update = dict(schemaVersion=1, deviceId=expected_device, commandId=command_id,
                      status=status, observedAtUtc=datetime.now(timezone.utc).isoformat())
        response = client.request('POST', path, token, update)
        if response['status'] != 202:
            raise RuntimeError('Synthetic command receipt failed')
    return 'enabled' if payload['type'] == 'enableProxy' else 'disabled'
