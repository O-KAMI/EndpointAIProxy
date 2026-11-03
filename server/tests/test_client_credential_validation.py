import base64
import importlib.util
import json
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    'client_credential_validation',
    Path(__file__).resolve().parents[2] / 'go-client/scripts/validate_credentials.py',
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


@pytest.mark.parametrize('origin,pin,valid', [
    ('http://example.test:8080', None, True),
    ('https://example.test', 'valid', True),
    ('https://example.test', None, False),
    ('https://example.test', 'short', False),
    ('http://example.test', 'valid', False),
    ('HTTPS://example.test', None, False),
])
def test_transport_pin_validation(tmp_path, origin, pin, valid):
    key = base64.b64encode(bytes(32)).decode()
    data = dict(origin=origin, clientToken='x' * 16, keyId='v1', transportKey=key, policyPublicKey=key)
    if pin is not None:
        data['certificateSpkiSha256'] = key if pin == 'valid' else base64.b64encode(bytes(31)).decode()
    path = tmp_path / 'synthetic.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    if valid:
        validator.validate(path)
    else:
        with pytest.raises((ValueError, KeyError)):
            validator.validate(path)
