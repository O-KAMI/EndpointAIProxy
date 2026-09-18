import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import zipfile

import pytest

spec = importlib.util.spec_from_file_location("update_022", Path(__file__).with_name("update-server-0.1.22.py"))
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


@pytest.mark.parametrize("cgroup,managed", [
    ("9:blkio:/system.slice/sshd.service\n2:devices:/system.slice/sshd.service\n1:name=systemd:/user.slice/user-801.slice/session-48201.scope", False),
    ("0::/user.slice/user-801.slice/session-48201.scope", False),
    ("0::/user.slice/user-801.slice/user@801.service/app.slice/app-terminal.scope", False),
    ("1:name=systemd:/system.slice/endpoint.service", True),
    ("0::/system.slice/endpoint.service/workers", True),
    ("0::/user.slice/user-801.slice/user@801.service/app.slice/endpoint.service", True),
])
def test_only_lifecycle_hierarchy_and_application_unit_count(cgroup, managed):
    assert update.systemd_managed_service(cgroup) is managed


def test_login_session_with_sshd_resource_groups_passes_guard(monkeypatch, tmp_path):
    monkeypatch.setattr(update, "processes", lambda _: {123: (1, "identity")})
    original_read = Path.read_text
    cgroup = "9:blkio:/system.slice/sshd.service\n2:devices:/system.slice/sshd.service\n1:name=systemd:/user.slice/user-801.slice/session-48201.scope"
    monkeypatch.setattr(Path, "read_text", lambda path, *a, **kw: cgroup if str(path) == "/proc/123/cgroup" else original_read(path, *a, **kw))
    update.require_unmanaged(tmp_path)


def configure(monkeypatch, tmp_path):
    old, older, new = [tmp_path / name for name in ("old021", "old020", "new022")]
    old.mkdir()
    older.mkdir()
    archive = tmp_path / "source.zip"
    archive.touch()
    monkeypatch.setattr(update, "CANDIDATES", (old, older))
    monkeypatch.setattr(update, "NEW", new)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "argv", ["update", "--archive", str(archive)])
    monkeypatch.setattr(update, "processes", lambda path: {123: (1, "identity")} if path == old else {})
    monkeypatch.setattr(update, "require_unmanaged", lambda _: None)
    return old, older, new


def test_detects_unique_runtime_and_refuses_ambiguous(monkeypatch, tmp_path):
    old, older, _ = configure(monkeypatch, tmp_path)
    assert update.source_directory() == old
    monkeypatch.setattr(update, "processes", lambda _: {123: (1, "identity")})
    with pytest.raises(update.DeploymentError, match="唯一"):
        update.source_directory()
    assert update.source_directory(older) == older


def test_source_record_survives_switch_and_rejects_different_source(monkeypatch, tmp_path):
    old, older, _ = configure(monkeypatch, tmp_path)
    update.remember_source(old)
    monkeypatch.setattr(update, "processes", lambda _: {})
    assert update.source_directory() == old
    assert update.state_path().stat().st_mode & 0o777 == 0o600
    with pytest.raises(update.DeploymentError, match="另一来源"):
        update.remember_source(older)


def test_failed_preparation_never_stops_old_service(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(update, "prepare", lambda *args: (_ for _ in ()).throw(update.DeploymentError("preflight")))
    monkeypatch.setattr(update, "stop", lambda path: calls.append(path))
    with pytest.raises(update.DeploymentError, match="preflight"):
        update.main()
    assert not calls


def test_failed_new_start_restores_actual_old(monkeypatch, tmp_path):
    old, _, new = configure(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(update, "prepare", lambda *args: None)
    monkeypatch.setattr(update, "stop", lambda path: calls.append(("stop", path)))
    monkeypatch.setattr(update, "port_free", lambda: None)
    monkeypatch.setattr(update, "health", lambda path: calls.append(("health", path)))
    def start(path):
        calls.append(("start", path))
        if path == new:
            monkeypatch.setattr(update, "processes", lambda _: {})
            raise update.DeploymentError("unhealthy")
    monkeypatch.setattr(update, "start", start)
    with pytest.raises(update.DeploymentError, match="旧服务已恢复"):
        update.main()
    assert calls == [("stop", old), ("start", new), ("stop", new), ("start", old), ("health", old)]
    assert update.source_directory() == old


def test_rollback_uses_record_without_active_old(monkeypatch, tmp_path):
    old, _, new = configure(monkeypatch, tmp_path)
    (old / "start.py").touch()
    update.remember_source(old)
    calls = []
    monkeypatch.setattr(sys, "argv", ["update", "--action", "rollback"])
    monkeypatch.setattr(update, "processes", lambda _: {})
    monkeypatch.setattr(update, "read_env", lambda _: {})
    monkeypatch.setattr(update, "stop", lambda path: calls.append(("stop", path)))
    monkeypatch.setattr(update, "start", lambda path: calls.append(("start", path)))
    monkeypatch.setattr(update, "health", lambda path: calls.append(("health", path)))
    update.main()
    assert calls == [("stop", new), ("start", old), ("health", old)]


def test_archive_rejects_path_traversal_and_checksum_mismatch(tmp_path):
    archive = tmp_path / "test.zip"
    for name, digest in (("../outside", hashlib.sha256(b"x").hexdigest()), ("app.py", "wrong")):
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(name, b"x")
            z.writestr("manifest.json", json.dumps({name: digest}))
        with pytest.raises(update.DeploymentError):
            update.extract(archive, tmp_path / "out")
    assert not (tmp_path / "outside").exists()


def test_systemd_guard_rejects_before_signal(monkeypatch, tmp_path):
    old, _, _ = configure(monkeypatch, tmp_path)
    monkeypatch.undo()
    monkeypatch.setattr(update, "processes", lambda _: {123: (1, "identity")})
    original_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, *a, **kw: "0::/system.slice/endpoint.service" if str(path) == "/proc/123/cgroup" else original_read(path, *a, **kw))
    killed = []
    monkeypatch.setattr(update.os, "kill", lambda *args: killed.append(args))
    with pytest.raises(update.DeploymentError, match="systemd"):
        update.stop(old)
    assert not killed


@pytest.mark.parametrize("machine,architecture", [("x86_64", "x86_64"), ("aarch64", "aarch64")])
def test_prepare_preserves_secrets_config_and_uses_offline_architecture(monkeypatch, tmp_path, machine, architecture):
    old, _, new = configure(monkeypatch, tmp_path)
    (old / "conf").mkdir()
    (old / "conf/mysql.ini").write_text("existing-database-configuration")
    values = {"SF_CONTROL_ADMIN_TOKEN": "test-only-token", "EAI_MYSQL_PASSWORD": "test-only-password", "APP_CONFIG": str(old / "conf")}
    (old / "launch-env.json").write_text(json.dumps(values))
    (old / "launch-env.json").chmod(0o600)
    monkeypatch.setattr(update, "health", lambda _: None)
    def extract(_, destination):
        (destination / "deployment/wheelhouse" / architecture).mkdir(parents=True)
    monkeypatch.setattr(update, "extract", extract)
    monkeypatch.setattr(update.platform, "machine", lambda: machine)
    calls = []
    def run(args, cwd=None):
        calls.append(args)
        return b"/usr/local/bin/python3.13\n"
    monkeypatch.setattr(update, "run", run)
    update.prepare(tmp_path / "source.zip", old)
    result = json.loads((new / "launch-env.json").read_text())
    assert result["EAI_MYSQL_PASSWORD"] == values["EAI_MYSQL_PASSWORD"]
    assert result["SF_CONTROL_ADMIN_TOKEN"] == values["SF_CONTROL_ADMIN_TOKEN"]
    assert result["APP_CONFIG"] == str(new / "conf")
    assert (new / "conf/mysql.ini").read_text() == "existing-database-configuration"
    install = next(args for args in calls if "install" in args)
    assert "--no-index" in install
    assert str(new / "deployment/wheelhouse" / architecture) in install
    assert not any("init-db" in args or "migrate-db" in args for args in calls)


def test_backup_inherits_credentials_without_printing_or_switching(monkeypatch, tmp_path, capsys):
    old, _, _ = configure(monkeypatch, tmp_path)
    (old / "conf").mkdir()
    (old / "conf/mysql.ini").write_text("test-only-config-secret")
    values = {"APP_ENV": "prd", "APP_CONFIG": str(old / "conf"), "SF_CONTROL_ADMIN_TOKEN": "test-only-token", "EAI_MYSQL_PASSWORD": "test-only-password"}
    source = json.dumps(values)
    (old / "launch-env.json").write_text(source)
    (old / "launch-env.json").chmod(0o600)
    monkeypatch.setattr(update.shutil, "which", lambda *a, **kw: "/usr/bin/mysqldump")
    calls = []
    def run(args, cwd=None, env=None):
        calls.append((args, cwd, env))
        destination = Path(args[-1])
        (destination / "database").mkdir()
        archive = destination / "database/test.sql.gz"
        archive.touch()
        return json.dumps(str(archive)).encode()
    monkeypatch.setattr(update, "run", run)
    monkeypatch.setattr(sys, "argv", ["update", "--action", "backup"])
    monkeypatch.setattr(update, "stop", lambda _: pytest.fail("backup stopped service"))
    update.main()
    assert calls[0][2]["EAI_MYSQL_PASSWORD"] == values["EAI_MYSQL_PASSWORD"]
    assert calls[0][1] == old
    assert "run_backup" in calls[0][0][2]
    assert "init-db" not in calls[0][0][2]
    assert (old / "launch-env.json").read_text() == source
    output = capsys.readouterr().out
    assert "test-only" not in output
    destination = Path(calls[0][0][-1])
    for path in [destination, *destination.rglob("conf*"), destination / "conf/mysql.ini", destination / "launch-env.json"]:
        assert path.stat().st_mode & 0o077 == 0


def test_backup_missing_mysqldump_fails_before_copy_or_stop(monkeypatch, tmp_path):
    old, _, _ = configure(monkeypatch, tmp_path)
    monkeypatch.setattr(update, "read_env", lambda _: {"SF_CONTROL_ADMIN_TOKEN": "test-only"})
    monkeypatch.setattr(update.shutil, "which", lambda *a, **kw: None)
    monkeypatch.setattr(sys, "argv", ["update", "--action", "backup"])
    with pytest.raises(update.DeploymentError, match="mysqldump"):
        update.main()
    assert not (old / "upgrade-backups").exists()
