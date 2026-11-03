"""Real Go protected SQLite state, Python envelopes, TLS and isolated MySQL."""
import base64
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import request
from werkzeug.serving import make_server

from app import create_app
from controlserver import credential_rotation as rotation
from test_credential_rotation import renewal, expire


@pytest.mark.parametrize('mode', ['normal', 'prepare-loss-disable', 'commit-loss-expired-grace',
                                  'prepare-expired', 'local-commit-failure', 'revoked'])
def test_go_two_phase_rotation_restart_and_failure(renewal, tmp_path, mode):
    go = os.environ.get('ENDPOINTAI_TEST_GO')
    if not go:
        pytest.skip('Set ENDPOINTAI_TEST_GO for isolated loopback interoperability')
    store, device, _, _ = renewal
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(hours=1)).add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
        .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path/'cert.pem', tmp_path/'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    pin = base64.b64encode(digest.finalize()).decode('ascii')
    app = create_app(store.cfg, store)
    paths = []

    @app.after_request
    def simulate_boundary(response):
        # Inner authenticated requests reach this hook before being encrypted.
        if '/credential/' in request.path:
            paths.append((request.path.rsplit('/', 1)[-1], response.status_code))
            if response.status_code == 200 and request.path.endswith('/prepare'):
                if mode == 'prepare-loss-disable':
                    store.cfg.CREDENTIAL_ROTATION = False
                if mode == 'prepare-expired' and sum(p == 'prepare' for p, _ in paths) == 1:
                    expire(store, device)
                if mode == 'revoked':
                    with store.transaction() as cur:
                        cur.execute('UPDATE device_credentials SET revoked=1 WHERE device_id=%s', (device,))
            if response.status_code == 200 and request.path.endswith('/commit') and mode in ('commit-loss-expired-grace', 'local-commit-failure'):
                expire(store, device)
                rotation.cleanup(store)
        return response

    server = make_server('127.0.0.1', 0, app, threaded=True, ssl_context=(str(cert_path), str(key_path)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    repo = Path(__file__).resolve().parents[2]
    env = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', CGO_ENABLED='0',
               ENDPOINTAI_ROTATION_TEST_ORIGIN=f'https://127.0.0.1:{server.server_port}',
               ENDPOINTAI_ROTATION_TEST_PIN=pin, ENDPOINTAI_ROTATION_TEST_DEVICE=device,
               ENDPOINTAI_ROTATION_TEST_MODE=mode)
    try:
        result = subprocess.run([go, 'test', '-mod=vendor', './internal/control', '-run',
                                 '^TestCredentialRotationPythonInterop$', '-count=1'],
                                cwd=repo/'go-client', env=env, capture_output=True, encoding='utf-8', timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        audit = store.audits(device, 0, 20)
        assert sum(row['action'] == 'DEVICE_CREDENTIAL_ROTATION_PREPARED' for row in audit) == (2 if mode == 'prepare-expired' else 1)
        assert sum(row['action'] == 'DEVICE_CREDENTIAL_ROTATION_COMMITTED' for row in audit) == (0 if mode == 'revoked' else 1)
        assert any(p == 'prepare' for p, _ in paths)
        with store.transaction() as cur:
            cur.execute('SELECT COUNT(*) AS n FROM device_credentials')
            assert cur.fetchone()['n'] == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
