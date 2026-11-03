"""Optional device-bound envelope keys derived from high-entropy device credentials."""
import hashlib
import hmac
import re
import uuid

PREFIX = 'dv1_'
DOMAIN = b'sf-endpointai-device-transport-v1\n'


def device_for_key_id(key_id):
    if not isinstance(key_id, str) or not re.fullmatch(r'dv1_[0-9a-f]{32}', key_id):
        return None
    value = uuid.UUID(hex=key_id[len(PREFIX):])
    return str(value) if value.int else None


def device_key_id(device):
    value = uuid.UUID(str(device))
    if not value.int or str(value) != str(device):
        raise ValueError('Invalid device identity')
    return PREFIX + value.hex


def device_master(token_hash, device):
    if not re.fullmatch(r'[A-F0-9]{64}', token_hash):
        raise ValueError('Invalid credential verifier')
    device_key_id(device)
    return hmac.new(bytes.fromhex(token_hash), DOMAIN + device.encode('ascii'), hashlib.sha256).digest()


V2_DOMAIN = b'sf-endpointai-device-transport-v2\n'


def device_v2_key_id(device, generation):
    value = uuid.UUID(str(device))
    if not value.int or str(value) != str(device) or not re.fullmatch(r'[1-9][0-9]{0,9}', generation):
        raise ValueError('Invalid device or key generation')
    return f'dv2_{generation}_{value.hex}'


def device_v2_for_key_id(key_id):
    if not isinstance(key_id, str):
        return None
    match = re.fullmatch(r'dv2_([1-9][0-9]{0,9})_([0-9a-f]{32})', key_id)
    if not match:
        return None
    value = uuid.UUID(hex=match.group(2))
    return (str(value), match.group(1)) if value.int else None


def device_v2_master(secret, token_hash, device):
    if not isinstance(secret, bytes) or len(secret) != 32 or not re.fullmatch(r'[A-F0-9]{64}', token_hash):
        raise ValueError('Invalid server secret or credential verifier')
    device_key_id(device)
    return hmac.new(secret, V2_DOMAIN + device.encode('ascii') + b'\n' + bytes.fromhex(token_hash), hashlib.sha256).digest()
