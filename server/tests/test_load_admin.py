import base64
import json
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app import create_app
from controlserver.validation import seed_policy
from tools.load_admin import FIXTURE_ADMIN_TOKEN, SyntheticAdmin
from tools.load_transport import FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID


def test_publishes_through_verified_isolated_control_app(config):
    config.CLIENT_TOKEN = FIXTURE_ENROLLMENT_TOKEN
    config.ADMIN_TOKEN = FIXTURE_ADMIN_TOKEN
    config.TRANSPORT_KEY_ID = FIXTURE_KEY_ID
    config.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    config.HMAC_TEXT = config.TRANSPORT_KEY_TEXT
    config.validate()

    class Store:
        def __init__(self):
            self.current = seed_policy(config)
            self.actor = None

        def claim_transport(self, envelope):
            return True

        def policy(self):
            return self.current.copy()

        def update_policy(self, update, actor):
            self.actor = actor
            self.current['enabled'] = update.enabled
            self.current['policyVersion'] += 1
            return self.current.copy()

        def analytics_page(self, *args, **kwargs):
            return [], {}, 0

    store = Store()
    server = make_server('127.0.0.1', 0, create_app(config, store, check_database=False), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        admin = SyntheticAdmin(f'http://127.0.0.1:{server.server_port}')
        old_enabled = store.current['enabled']
        report = admin.publish_toggle()
        assert report['version'] == 2
        assert report['completed'] >= report['started']
        assert store.current['enabled'] != old_enabled
        assert store.actor == 'synthetic-load'
        assert admin.query_devices() >= 0
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_rejects_remote_admin_target():
    with pytest.raises(ValueError):
        SyntheticAdmin('http://192.168.0.1:8080')


def make_tls_fixtures(tmp_path):
    import ipaddress
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from werkzeug.security import generate_password_hash
    from tools.load_admin import FIXTURE_ADMIN_PASSWORD, FIXTURE_ADMIN_USERNAME

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'isolated fixture')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256()))
    cert_path, key_path, accounts = tmp_path/'cert.pem', tmp_path/'key.pem', tmp_path/'accounts.json'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    accounts.write_text(json.dumps([dict(username=FIXTURE_ADMIN_USERNAME, role='admin',
        passwordHash=generate_password_hash(FIXTURE_ADMIN_PASSWORD))]), encoding='utf-8')
    accounts.chmod(0o600)
    return cert_path, key_path, accounts


def test_local_admin_uses_trusted_tls_and_synthetic_account(config, tmp_path, monkeypatch):
    from tools.load_admin import LocalSyntheticAdmin
    from controlserver import rollout
    from uuid import uuid4

    cert_path, key_path, accounts = make_tls_fixtures(tmp_path)
    config.CLIENT_TOKEN = FIXTURE_ENROLLMENT_TOKEN
    config.TRANSPORT_KEY_ID = FIXTURE_KEY_ID
    config.TRANSPORT_KEY_TEXT = base64.b64encode(FIXTURE_KEY).decode()
    config.HMAC_TEXT = config.TRANSPORT_KEY_TEXT
    config.ADMIN_AUTH_MODE = 'local'
    config.ADMIN_ACCOUNTS_PATH = str(accounts)
    config.ADMIN_SESSION_KEY_TEXT = base64.b64encode(b's' * 32).decode()
    config.validate()

    class Store:
        def claim_transport(self, envelope):
            return True
        def policy(self):
            return seed_policy(config)
        def analytics_page(self, *args, **kwargs):
            return [], {}, 0

    app = create_app(config, Store(), check_database=False)
    batch_id = str(uuid4())
    monkeypatch.setattr(rollout, 'create', lambda store, value, actor:
        dict(batchId=batch_id, status='paused', totalTargets=len(value.deviceIds)))
    monkeypatch.setattr(rollout, 'change', lambda store, batch, action, reason, actor:
        dict(batchId=str(batch), status='running' if action == 'resume' else 'paused'))
    plain = make_server('127.0.0.1', 0, app, threaded=True)
    secure = make_server('127.0.0.1', 0, app, threaded=True, ssl_context=(str(cert_path), str(key_path)))
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (plain, secure)]
    for thread in threads:
        thread.start()
    try:
        admin = LocalSyntheticAdmin(f'http://127.0.0.1:{plain.server_port}',
                                    f'https://127.0.0.1:{secure.server_port}', cert_path)
        assert admin.query_devices() >= 0
        admin.session = 'synthetic-expired-session'
        assert admin.query_devices() >= 0
        batch = admin.create_rollout([str(uuid4()), str(uuid4())])
        assert batch == batch_id
        assert admin.change_rollout(batch, 'resume')['status'] == 'running'
        assert admin.change_rollout(batch, 'pause')['status'] == 'paused'
        with pytest.raises(ValueError):
            LocalSyntheticAdmin(f'http://127.0.0.1:{plain.server_port}', 'https://example.test:443', cert_path)
    finally:
        for server in (plain, secure):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
