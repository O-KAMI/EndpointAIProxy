import base64
import json
import pytest
from werkzeug.security import generate_password_hash

from app import create_app


class Store:
    def policy(self):
        return {"policyVersion": 1}

    def update_policy(self, update, actor):
        self.actor = actor
        return {"policyVersion": 2}

    def recover_device_credential(self, device, hostname, reason, actor):
        self.actor = actor
        return {"deviceId": str(device), "deviceToken": "synthetic", "enrolledAtUtc": "2026-01-01T00:00:00Z"}


def setup(config, tmp_path):
    path = tmp_path / "accounts.json"
    accounts = [{"username": name, "role": role, "passwordHash": generate_password_hash("correct password 123")}
                for name, role in (("alice", "admin"), ("bob", "operator"), ("carol", "viewer"))]
    path.write_text(json.dumps(accounts), encoding="utf-8")
    path.chmod(0o600)
    config.ADMIN_AUTH_MODE = "local"
    config.ADMIN_ACCOUNTS_PATH = str(path)
    config.ADMIN_SESSION_KEY_TEXT = base64.b64encode(b"k" * 32).decode()
    store = Store()
    return create_app(config, store=store, check_database=False).test_client(), path, accounts, store


def login(client, name):
    result = client.post("/auth/login", json={"username": name, "password": "correct password 123"}, base_url="https://localhost")
    assert result.status_code == 200
    return {"Authorization": "Bearer " + result.json["token"]}


def test_local_accounts_roles_and_revocation(config, tmp_path):
    client, path, accounts, _ = setup(config, tmp_path)
    assert client.post("/auth/login", json={"username": "alice", "password": "correct password 123"}).status_code == 403
    assert client.get("/admin/v1/policy", headers={"Authorization": "Bearer " + config.ADMIN_TOKEN}, base_url="https://localhost").status_code == 401
    admin, operator, viewer = [login(client, name) for name in ("alice", "bob", "carol")]
    for headers in (admin, operator, viewer):
        assert client.get("/admin/v1/policy", headers=headers, base_url="https://localhost").status_code == 200
        assert client.get("/admin/v1/policy", headers=headers).status_code == 403
    assert client.put("/admin/v1/policy", json={}, headers=operator, base_url="https://localhost").status_code == 403
    assert client.post("/admin/v1/commands/00000000-0000-0000-0000-000000000001/resolve-unknown", json={}, headers=viewer, base_url="https://localhost").status_code == 403
    # 400 demonstrates that the operator passed authorization and reached input validation.
    assert client.post("/admin/v1/commands/00000000-0000-0000-0000-000000000001/resolve-unknown", json={}, headers=operator, base_url="https://localhost").status_code == 400
    accounts[2]["disabled"] = True
    path.write_text(json.dumps(accounts), encoding="utf-8")
    assert client.get("/admin/v1/policy", headers=viewer, base_url="https://localhost").status_code == 401
    accounts[0]["passwordHash"] = generate_password_hash("new correct password 123")
    path.write_text(json.dumps(accounts), encoding="utf-8")
    assert client.get("/admin/v1/policy", headers=admin, base_url="https://localhost").status_code == 401


def test_authenticated_actor_cannot_be_spoofed(config, tmp_path):
    client, _, _, store = setup(config, tmp_path)
    headers = login(client, "alice")
    headers["X-SF-Admin-Actor"] = "mallory"
    # Exercise the real endpoint with a valid policy body from the configured defaults.
    from controlserver.validation import seed_policy
    policy = seed_policy(config)
    policy["expectedVersion"] = policy.pop("policyVersion")
    result = client.put("/admin/v1/policy", json=policy, headers=headers, base_url="https://localhost")
    assert result.status_code == 200
    assert store.actor == "alice"


def test_role_change_revokes_session_before_new_permissions_apply(config, tmp_path):
    client, path, accounts, _ = setup(config, tmp_path)
    operator = login(client, 'bob')
    assert client.put('/admin/v1/policy', json={}, headers=operator, base_url='https://localhost').status_code == 403
    accounts[1]['role'] = 'admin'
    path.write_text(json.dumps(accounts), encoding='utf-8')
    assert client.get('/admin/v1/policy', headers=operator, base_url='https://localhost').status_code == 401
    assert client.put('/admin/v1/policy', json={}, headers=operator, base_url='https://localhost').status_code == 401
    new_session = login(client, 'bob')
    assert client.put('/admin/v1/policy', json={}, headers=new_session, base_url='https://localhost').status_code == 400
    accounts[1]['role'] = 'viewer'
    path.write_text(json.dumps(accounts), encoding='utf-8')
    assert client.get('/admin/v1/policy', headers=new_session, base_url='https://localhost').status_code == 401


def test_login_rate_limit_separates_accounts_but_bounds_address(config, tmp_path, monkeypatch):
    from controlserver import local_admin
    client, _, _, _ = setup(config, tmp_path)
    monkeypatch.setattr(local_admin, '_attempts', {})
    monkeypatch.setattr(local_admin, 'check_password_hash', lambda _hash, password: password == 'correct password 123')
    def attempt(name, password):
        return client.post('/auth/login', json={'username':name, 'password':password}, base_url='https://localhost').status_code
    assert [attempt('alice', 'wrong') for _ in range(10)] == [401] * 10
    assert attempt('alice', 'correct password 123') == 429
    assert attempt('bob', 'correct password 123') == 200
    assert [attempt('unknown-' + str(i), 'wrong') for i in range(89)] == [401] * 89
    assert attempt('carol', 'correct password 123') == 429


def test_policy_rollout_mutations_require_admin(config, tmp_path):
    client, _, _, _ = setup(config, tmp_path)
    admin, operator, viewer = [login(client, name) for name in ('alice', 'bob', 'carol')]
    for headers in (operator, viewer):
        assert client.post('/admin/v1/policy-rollouts', json={}, headers=headers, base_url='https://localhost').status_code == 403
    assert client.post('/admin/v1/policy-rollouts', json={}, headers=admin, base_url='https://localhost').status_code == 400


def test_loopback_proxy_only_and_configuration(config, tmp_path):
    _, path, _, _ = setup(config, tmp_path)
    config.TRUST_PROXY = True
    with pytest.raises(ValueError, match="loopback"):
        config.validate()
    config.HTTP_HOST = "127.0.0.1"
    client = create_app(config, store=Store(), check_database=False).test_client()
    body = {"username": "alice", "password": "correct password 123"}
    forwarded = {"X-Forwarded-Proto": "https"}
    assert client.post("/auth/login", json=body, headers=forwarded,
                       environ_base={"REMOTE_ADDR": "192.0.2.1"}).status_code == 403
    assert client.post("/auth/login", json=body, headers=forwarded,
                       environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200
    path.unlink()
    with pytest.raises(ValueError, match="administrator accounts"):
        config.validate()


def test_recovery_requires_local_admin_and_server_identity(config, tmp_path):
    client, _, _, store = setup(config, tmp_path)
    path = "/admin/v1/devices/00000000-0000-0000-0000-000000000001/credential-recovery"
    payload = {"hostname": "fixture", "reason": "credential lost"}
    operator, admin = login(client, "bob"), login(client, "alice")
    assert client.post(path, json=payload, headers=operator, base_url="https://localhost").status_code == 403
    admin["X-SF-Admin-Actor"] = "mallory"
    result = client.post(path, json=payload, headers=admin, base_url="https://localhost")
    assert result.status_code == 200 and result.headers["Cache-Control"] == "no-store"
    assert store.actor == "alice"
    assert client.post(path, json=payload, headers=admin).status_code == 403
    config.ADMIN_AUTH_MODE = "legacy"
    assert client.post(path, json=payload, headers={"Authorization": "Bearer " + config.ADMIN_TOKEN}, base_url="https://localhost").status_code == 403


def test_batch_mutation_requires_authenticated_operator(config, tmp_path):
    client, _, _, _ = setup(config, tmp_path)
    operator, viewer = login(client, "bob"), login(client, "carol")
    assert client.post("/admin/v1/rollouts", json={}, headers=viewer, base_url="https://localhost").status_code == 403
    assert client.post("/admin/v1/rollouts", json={}, headers=operator, base_url="https://localhost").status_code == 400
    config.ADMIN_AUTH_MODE = "legacy"
    assert client.post("/admin/v1/rollouts", json={}, headers={"Authorization": "Bearer " + config.ADMIN_TOKEN}, base_url="https://localhost").status_code == 403
