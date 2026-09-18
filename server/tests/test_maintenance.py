import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4
import pymysql
import pytest
from controlserver.database import ControlStore, schema_tables
from controlserver.backup import run_backup, read_backup_state, restore_backup, mysql_credentials, digest_file
from controlserver.models import PolicyUpdateRequest, HeartbeatV2Request, DeviceEnrollmentRequest, CreateRemoteCommandRequest, EventBatchRequest
from controlserver.security import dumps


def test_backup_state_missing_and_corrupt(config):
    assert read_backup_state(config)["lastError"] == "BACKUP_NOT_RUN"
    config.DATA_ROOT.mkdir()
    (config.DATA_ROOT / "backup-state.json").write_text("invalid")
    assert read_backup_state(config)["lastError"] == "BACKUP_STATE_UNREADABLE"


def test_credentials_file_private_and_not_truncated(config):
    config.MYSQL_PASSWORD = 'one#two!three"four\\five'
    with mysql_credentials(config) as path:
        text = Path(path).read_text()
        assert "one#two!three" in text
        assert Path(path).stat().st_mode & 0o077 == 0
    assert not Path(path).exists()


def test_backup_write_failure_reaps_dump_process(config, monkeypatch):
    from controlserver import backup
    monkeypatch.setattr(ControlStore, "check_schema", lambda self: None)
    real_popen = subprocess.Popen
    children = []
    def launch(*args, **kwargs):
        child = real_popen([sys.executable, "-u", "-c",
            "import sys,time; sys.stdout.write('data'); sys.stdout.flush(); time.sleep(60)"], **kwargs)
        children.append(child)
        return child
    def disk_full(source, destination):
        assert source.read(4) == b"data"
        raise OSError("simulated disk full")
    monkeypatch.setattr(backup.subprocess, "Popen", launch)
    monkeypatch.setattr(backup.shutil, "copyfileobj", disk_full)
    try:
        with pytest.raises(OSError, match="simulated disk full"):
            run_backup(config)
        assert children and all(child.poll() is not None for child in children)
        assert not list(config.BACKUP_DIR.glob(".incomplete-*"))
        assert not list(config.BACKUP_DIR.glob("control-*"))
        assert read_backup_state(config)["lastError"] == "OSError"
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()


def test_backup_manifest_failure_removes_unusable_archive(config, monkeypatch):
    from controlserver import backup
    monkeypatch.setattr(ControlStore, "check_schema", lambda self: None)
    real_popen, real_atomic = subprocess.Popen, backup.atomic_json
    def launch(*args, **kwargs):
        return real_popen([sys.executable, "-c", "print('-- synthetic dump')"], **kwargs)
    def fail_manifest(path, value):
        if path.name.endswith(".sql.gz.json"):
            raise OSError("simulated manifest failure")
        return real_atomic(path, value)
    monkeypatch.setattr(backup.subprocess, "Popen", launch)
    monkeypatch.setattr(backup, "atomic_json", fail_manifest)
    with pytest.raises(OSError, match="simulated manifest failure"):
        run_backup(config)
    assert not list(config.BACKUP_DIR.glob("control-*"))
    assert not list(config.BACKUP_DIR.glob(".incomplete-*"))
    assert read_backup_state(config)["lastSucceededAtUtc"] is None
    assert read_backup_state(config)["lastError"] == "OSError"


@pytest.mark.mysql
def test_empty_legacy_rebuild_and_nonempty_refusal(mysql_store):
    with mysql_store.transaction() as cur:
        for name in schema_tables():
            cur.execute(f"DROP TABLE `{name}`")
        cur.execute("CREATE TABLE devices (id INT PRIMARY KEY)")
        cur.execute("CREATE TABLE unrelated_system (id INT PRIMARY KEY)")
        cur.execute("INSERT INTO unrelated_system VALUES (7)")
        cur.execute("INSERT INTO devices VALUES (1)")
    with pytest.raises(RuntimeError, match="nonempty"):
        mysql_store.initialize_empty()
    with mysql_store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS count FROM devices")
        assert cur.fetchone()["count"] == 1
        cur.execute("DELETE FROM devices")
    assert mysql_store.initialize_empty() == "initialized"
    with mysql_store.transaction() as cur:
        cur.execute("SELECT id FROM unrelated_system")
        assert cur.fetchone()["id"] == 7


@pytest.mark.mysql
def test_consistent_backup_retention_restore_and_failure(mysql_store):
    binary_dir = os.environ.get("ENDPOINTAI_TEST_MYSQL_BIN")
    if not binary_dir:
        pytest.skip("ENDPOINTAI_TEST_MYSQL_BIN required for mysqldump/restore")
    cfg = mysql_store.cfg
    fixture = json.loads((Path(__file__).parent / "fixtures/dotnet-v0.1.19.json").read_text())
    enrolled = mysql_store.enroll(DeviceEnrollmentRequest.model_validate(fixture["enrollment"]))
    beat = HeartbeatV2Request.model_validate(fixture["heartbeat"])
    mysql_store.heartbeat(beat, 60, "127.0.0.1")
    mysql_store.create_command(beat.device.deviceId,
        CreateRemoteCommandRequest(type="enableProxy",reason="restore check",expiresInMinutes=10), "restore-test")
    mysql_store.events(EventBatchRequest.model_validate(dict(schemaVersion=1,batchId=str(uuid4()),
        deviceId=enrolled["deviceId"],events=[dict(eventId=str(uuid4()),
        occurredAtUtc=fixture["heartbeat"]["observedAtUtc"],severity="info",type="test",code="RESTORE",summary="恢复测试")])))
    def contents(store):
        with store.transaction() as cur:
            result = {}
            for table in sorted(schema_tables()):
                cur.execute(f"SELECT * FROM `{table}`")
                result[table] = sorted(dumps(row) for row in cur.fetchall())
            return result
    expected = contents(mysql_store)
    dump = str(Path(binary_dir) / "mysqldump")
    mysql = str(Path(binary_dir) / "mysql")
    for _ in range(8):
        archive = run_backup(cfg, dump_binary=dump)
    assert len(list(cfg.BACKUP_DIR.glob("control-*.sql.gz"))) == 7
    assert len(list(cfg.BACKUP_DIR.glob("control-*.json"))) == 7
    state = read_backup_state(cfg)
    assert state["lastSucceededAtUtc"] and state["lastError"] is None
    with pytest.raises(FileNotFoundError):
        run_backup(cfg, dump_binary="/not/an/executable")
    state2 = read_backup_state(cfg)
    assert state2["lastSucceededAtUtc"] == state["lastSucceededAtUtc"]
    assert state2["lastError"] == "FileNotFoundError"
    assert len(list(cfg.BACKUP_DIR.glob("control-*.sql.gz"))) == 7
    target = "eai_test_restore_" + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f"CREATE DATABASE `{target}` CHARACTER SET utf8mb4")
    try:
        policy = restore_backup(cfg, archive, target, mysql)
        assert policy == mysql_store.policy()
        target_cfg = copy.copy(cfg)
        target_cfg.MYSQL_DATABASE = target
        restored = ControlStore(target_cfg)
        assert contents(restored) == expected
        assert restored.authenticate(enrolled["deviceId"], enrolled["deviceToken"])
        with pytest.raises(RuntimeError, match="empty"):
            restore_backup(cfg, archive, target, mysql)
        # Corruption is detected before any target writes.
        with archive.open("ab") as file:
            file.write(b"corrupt")
        with pytest.raises(ValueError, match="checksum"):
            restore_backup(cfg, archive, target, mysql)
    finally:
        with mysql_store.transaction() as cur:
            cur.execute(f"DROP DATABASE `{target}`")
