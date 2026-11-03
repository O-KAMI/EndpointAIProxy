"""Deployment ordering and a real schema-2 backup/restore/migration rehearsal on synthetic data."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

import pytest
from config import ROOT
from controlserver.models import DeviceEnrollmentRequest, DevicePolicyUpdateRequest


pytestmark = pytest.mark.skipif(os.name == "nt", reason="Linux lifecycle and fcntl deployment helper")


def updater():
    path = ROOT.parent / "deployment/update-server-0.1.25.py"
    spec = importlib.util.spec_from_file_location("test_update_025_impl", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_downgrade_refuses_any_issued_device_version(mysql_store, monkeypatch):
    update = updater()
    from uuid import uuid4
    device = mysql_store.enroll(DeviceEnrollmentRequest(schemaVersion=2, deviceId=uuid4(),
        hostname="synthetic", serviceVersion="0.2.3"))["deviceId"]
    scoped = mysql_store.device_policy(device, DevicePolicyUpdateRequest(
        expectedVersion=mysql_store.policy()["policyVersion"], overrides={"allowlistedBaseUrls":[]}), "test")
    monkeypatch.setattr(update.base, "processes", lambda _: {})
    def execute(_, operation, env=None):
        exec(operation, {"store": mysql_store, "json": json})
    monkeypatch.setattr(update, "database", execute)
    with pytest.raises(AssertionError, match="Scoped versions exist"):
        update.downgrade_unused_schema()
    mysql_store.check_schema()
    assert mysql_store.policy(device) == scoped["effectivePolicy"]


def test_prepare_retains_new_canonical_sql_and_existing_data_root(tmp_path, monkeypatch):
    update = updater()
    old, new = tmp_path / "old", tmp_path / "new"
    (old / "conf").mkdir(parents=True)
    (old / "conf/endpoint_ai_proxy.sql").write_text("old schema")
    (old / "conf/private.properties").write_text("synthetic-only=true")
    values = dict(APP_CONFIG=str(old / "conf"), SF_CONTROL_DATA_ROOT=str(old / "var"),
        SF_CONTROL_ADMIN_TOKEN="synthetic-admin", SF_CONTROL_HTTP_PORT="8080")
    monkeypatch.setattr(update.base, "NEW", new)
    monkeypatch.setattr(update.base, "processes", lambda _: {1:(0,"identity")})
    monkeypatch.setattr(update.base, "require_unmanaged", lambda _: None)
    monkeypatch.setattr(update.base, "health", lambda _: None)
    monkeypatch.setattr(update, "database", lambda *args: {"schema":2})
    monkeypatch.setattr(update.base, "read_env", lambda directory: dict(values) if directory == old else
        json.loads((new / "launch-env.json").read_text()))
    def extract(_, destination):
        (destination / "conf").mkdir()
        (destination / "conf/endpoint_ai_proxy.sql").write_text("new schema")
    monkeypatch.setattr(update.base, "extract", extract)
    monkeypatch.setattr(update.base, "run", lambda args, **kwargs: b"/synthetic/python" if "print(sys._base_executable)" in args[-1] else b"")
    update.prepare(tmp_path / "archive.zip", old)
    assert (new / "conf/endpoint_ai_proxy.sql").read_text() == "new schema"
    saved = json.loads((new / "launch-env.json").read_text())
    assert saved["SF_CONTROL_DATA_ROOT"] == values["SF_CONTROL_DATA_ROOT"]
    assert saved["SF_CONTROL_ADMIN_TOKEN"] == values["SF_CONTROL_ADMIN_TOKEN"]
    assert saved["APP_CONFIG"] == str(new / "conf")
    assert (new / "launch-env.json").stat().st_mode & 0o077 == 0


def test_failed_upgrade_restarts_new_when_downgrade_is_unsafe(tmp_path, monkeypatch):
    update = updater()
    old, new, binary = tmp_path / "old", tmp_path / "new", tmp_path / "bin"
    binary.mkdir()
    for name in ("mysqld", "mysql", "mysqldump"):
        (binary / name).touch()
    monkeypatch.setattr(update.base, "NEW", new)
    monkeypatch.setattr(update.base, "CANDIDATES", (old,))
    monkeypatch.setattr(sys, "argv", ["update", "--mysql-bin", str(binary)])
    monkeypatch.setattr(update.base, "remember_source", lambda _: None)
    monkeypatch.setattr(update, "prepare", lambda *args: None)
    monkeypatch.setattr(update, "snapshot", lambda *args: {})
    monkeypatch.setattr(update, "stopped_backup", lambda *args: (tmp_path, tmp_path / "backup"))
    monkeypatch.setattr(update, "verify_backup", lambda *args: None)
    monkeypatch.setattr(update, "database", lambda *args: None)
    monkeypatch.setattr(update.base, "run", lambda *args, **kwargs: None)
    lifecycle = []
    monkeypatch.setattr(update.base, "stop", lambda directory: lifecycle.append(("stop", directory)))
    monkeypatch.setattr(update.base, "start", lambda directory: lifecycle.append(("start", directory)))
    def unhealthy(_):
        raise RuntimeError("synthetic health failure")
    def unsafe():
        raise RuntimeError("issued device version")
    monkeypatch.setattr(update.base, "health", unhealthy)
    monkeypatch.setattr(update, "downgrade_unused_schema", unsafe)
    with pytest.raises(update.base.DeploymentError, match="已尝试恢复新版"):
        update.main()
    assert lifecycle == [("stop", old), ("start", new), ("stop", new), ("start", new)]


def test_real_stopped_backup_restore_clone_migration_and_unused_rollback(mysql_store, tmp_path, monkeypatch):
    baseline = os.environ.get("ENDPOINTAI_TEST_BASELINE024")
    binary = os.environ.get("ENDPOINTAI_TEST_MYSQL_BIN")
    if not baseline or not binary:
        pytest.skip("Exact public 0.1.24 baseline and isolated MySQL tools required")
    update = updater()
    old, new = tmp_path / "old024", tmp_path / "new025"
    shutil.copytree(baseline, old, ignore=shutil.ignore_patterns("__pycache__", ".venv", "deployment", "artifacts", "logs", "var"))
    shutil.copytree(ROOT, new, ignore=shutil.ignore_patterns("__pycache__", ".venv", ".pytest_cache", "deployment", "artifacts", "logs", "var"))
    cfg = mysql_store.cfg
    for directory in (old, new):
        (directory / ".venv/bin").mkdir(parents=True)
        (directory / ".venv/bin/python").symlink_to(sys.executable)
        values = dict(APP_ENV="sit",APP_CONFIG=str(directory / "conf"),
            SF_CONTROL_CLIENT_TOKEN=cfg.CLIENT_TOKEN,SF_CONTROL_ADMIN_TOKEN=cfg.ADMIN_TOKEN,
            SF_CONTROL_POLICY_HMAC_KEY=cfg.HMAC_TEXT,SF_CONTROL_TRANSPORT_KEY=cfg.TRANSPORT_KEY_TEXT,
            SF_CONTROL_TRANSPORT_KEY_ID=cfg.TRANSPORT_KEY_ID,EAI_MYSQL_HOST=cfg.MYSQL_HOST,
            EAI_MYSQL_PORT=str(cfg.MYSQL_PORT),EAI_MYSQL_USERNAME=cfg.MYSQL_USER,
            EAI_MYSQL_PASSWORD=cfg.MYSQL_PASSWORD,EAI_MYSQL_DATABASE=cfg.MYSQL_DATABASE,
            SF_CONTROL_LOG_DIR=str(directory / "logs"),SF_CONTROL_DATA_ROOT=str(directory / "var"))
        path = directory / "launch-env.json"
        path.write_text(json.dumps(values)); path.chmod(0o600)
    monkeypatch.setattr(update.base,"NEW",new)
    # Start from schema 2 without dropping or restoring any business table.
    update.downgrade_unused_schema()
    before = update.snapshot(old)
    destination, archive = update.stopped_backup(old, Path(binary))
    update.verify_backup(old, destination, archive, Path(binary), before)
    assert json.loads((destination / "restore-verification/report.json").read_text())["status"] == "passed"
    assert update.snapshot(old) == before
    update.database(new, "store.migrate(); print(json.dumps({'schema':3}))")
    assert update.snapshot(new) == before
    update.downgrade_unused_schema()
    assert update.snapshot(old) == before
    mysql_store.migrate()
    mysql_store.check_schema()
