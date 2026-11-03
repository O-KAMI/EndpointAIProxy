"""Isolated MySQL backup/restore of a derived employee search index."""
import copy
import gzip
import importlib
import os
import json
from contextlib import contextmanager
from pathlib import Path
import sys
import subprocess
import types
from uuid import uuid4

import pytest


def test_old_backup_cannot_prove_latest_issued_policy_version(mysql_store, tmp_path, monkeypatch):
    binary_dir = os.environ.get('ENDPOINTAI_TEST_MYSQL_BIN')
    if not binary_dir:
        pytest.skip('Requires local MySQL dump and client binaries')
    if os.name == 'nt':
        monkeypatch.setitem(sys.modules, 'fcntl', types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *_: None))
    backup = importlib.import_module('controlserver.backup')
    from controlserver.database import ControlStore
    from controlserver.models import PolicyUpdateRequest
    from controlserver.transport import open_envelope, seal

    @contextmanager
    def credentials(cfg):
        path = tmp_path / (uuid4().hex + '.cnf')
        path.write_text(f'[client]\nhost="{cfg.MYSQL_HOST}"\nport="{cfg.MYSQL_PORT}"\nuser="{cfg.MYSQL_USER}"\npassword=""\n', encoding='utf-8')
        try:
            yield str(path)
        finally:
            path.unlink()

    monkeypatch.setattr(backup, 'mysql_credentials', credentials)
    extension = '.exe' if os.name == 'nt' else ''
    archive = backup.run_backup(mysql_store.cfg, dump_binary=str(Path(binary_dir) / ('mysqldump' + extension)))
    current = mysql_store.policy()
    update = PolicyUpdateRequest(expectedVersion=current['policyVersion'],
        **{key: value for key, value in current.items() if key in PolicyUpdateRequest.model_fields})
    published = mysql_store.update_policy(update)
    key, key_id = b'\x62' * 32, 'synthetic-key'
    envelope = seal(key, key_id, str(uuid4()), {'synthetic': True}, 'request')
    assert mysql_store.claim_transport(envelope)
    assert not mysql_store.claim_transport(envelope)
    target = 'eai_test_' + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f'CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    try:
        restored_policy = backup.restore_backup(mysql_store.cfg, archive, target,
            mysql_binary=str(Path(binary_dir) / ('mysql' + extension)))
        cfg = copy.copy(mysql_store.cfg)
        cfg.MYSQL_DATABASE = target
        restored = ControlStore(cfg)
        assert restored.policy()['policyVersion'] == restored_policy['policyVersion']
        assert restored_policy['policyVersion'] < published['policyVersion']
        assert open_envelope(key, key_id, envelope, 'request') == {'synthetic': True}
        assert restored.claim_transport(envelope)
        import manage
        monkeypatch.setattr(manage, 'Config', lambda *_: mysql_store.cfg)
        monkeypatch.setattr(sys, 'argv', ['manage.py', 'advance-restored-watermark', '--env', 'sit',
            '--target-database', target, '--verified-issued-max', str(published['policyVersion']),
            '--actor', 'test', '--evidence-reference', 'synthetic-audit',
            '--service-stopped', '--confirm-restored-target'])
        manage.main()
        assert restored.policy()['policyVersion'] > published['policyVersion']
        assert mysql_store.policy()['policyVersion'] == published['policyVersion']
    finally:
        with mysql_store.transaction() as cur:
            cur.execute(f'DROP DATABASE `{target}`')


def test_restore_rebuilds_employee_lookup(mysql_store, tmp_path, monkeypatch):
    binary_dir = os.environ.get("ENDPOINTAI_TEST_MYSQL_BIN")
    if not binary_dir:
        pytest.skip("Requires local MySQL dump and client binaries")
    if os.name == "nt":
        # Windows lacks fcntl; exercise data recovery only, not Linux lock semantics.
        monkeypatch.setitem(sys.modules, "fcntl", types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *_: None))
    backup = importlib.import_module("controlserver.backup")
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    fixture = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    fixture["users"][0]["accountName"] = "synthetic-restore-id"
    fixture["activity"][0].update(state="connectionFailed", requestCountSinceBoot=1, failureCountSinceBoot=1)
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(fixture), 60, "127.0.0.1")
    mysql_store.ensure_scale_indexes()
    mysql_store.cfg.EMPLOYEE_INDEX = True
    # NamedTemporaryFile remains locked on Windows; use a closed synthetic config file.
    @contextmanager
    def credentials(cfg):
        path = tmp_path / (uuid4().hex + ".cnf")
        path.write_text(f'[client]\nhost="{cfg.MYSQL_HOST}"\nport="{cfg.MYSQL_PORT}"\nuser="{cfg.MYSQL_USER}"\npassword=""\n', encoding="utf-8")
        try:
            yield str(path)
        finally:
            path.unlink()
    monkeypatch.setattr(backup, "mysql_credentials", credentials)
    extension = ".exe" if os.name == "nt" else ""
    archive = backup.run_backup(mysql_store.cfg, dump_binary=str(Path(binary_dir) / ("mysqldump" + extension)))
    target = "eai_test_" + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f"CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
    try:
        backup.restore_backup(mysql_store.cfg, archive, target, mysql_binary=str(Path(binary_dir) / ("mysql" + extension)))
        from controlserver.database import ControlStore
        cfg = copy.copy(mysql_store.cfg)
        cfg.MYSQL_DATABASE = target
        restored = ControlStore(cfg)
        restored.check_schema()
        _, _, total = restored.analytics_page("all", None, utcnow(), 0, 50, employee_search="synthetic-restore-id")
        assert total == 1
        _, _, total = restored.analytics_page("all", None, utcnow(), 0, 50, anomaly="latest")
        assert total == 1
    finally:
        with mysql_store.transaction() as cur:
            cur.execute(f"DROP DATABASE `{target}`")


def test_schema_three_backup_restores_and_migrates_to_rollout_schema(mysql_store, tmp_path, monkeypatch):
    binary_dir = os.environ.get("ENDPOINTAI_TEST_MYSQL_BIN")
    if not binary_dir:
        pytest.skip("Requires local MySQL dump and client binaries")
    if os.name == "nt":
        monkeypatch.setitem(sys.modules, "fcntl", types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *_: None))
    backup = importlib.import_module("controlserver.backup")
    from controlserver.database import ControlStore, SCHEMA_3_CHECKSUM, schema_tables
    from controlserver.models import HeartbeatV2Request
    from controlserver.security import utcnow
    fixture = json.loads((Path(__file__).parent / "fixtures" / "dotnet-v0.1.19.json").read_text(encoding="utf-8"))["heartbeat"]
    fixture["users"][0]["accountName"] = "old-backup-fixture"
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(fixture), 60, "127.0.0.1")
    mysql_store.ensure_scale_indexes()
    mysql_store.cfg.EMPLOYEE_INDEX = True
    with mysql_store.transaction() as cur:
        cur.execute("UPDATE schema_migrations SET version=3,checksum=%s", (SCHEMA_3_CHECKSUM,))
    @contextmanager
    def credentials(cfg):
        path = tmp_path / (uuid4().hex + ".cnf")
        path.write_text(f'[client]\nhost="{cfg.MYSQL_HOST}"\nport="{cfg.MYSQL_PORT}"\nuser="{cfg.MYSQL_USER}"\npassword=""\n', encoding="utf-8")
        try:
            yield str(path)
        finally:
            path.unlink()
    monkeypatch.setattr(backup, "mysql_credentials", credentials)
    extension = ".exe" if os.name == "nt" else ""
    tables = sorted(schema_tables() - {"rollout_batches", "rollout_targets", "policy_rollout_batches", "policy_rollout_targets"})
    archive = tmp_path / "schema3.sql.gz"
    with credentials(mysql_store.cfg) as defaults:
        result = subprocess.run([str(Path(binary_dir) / ("mysqldump" + extension)),
            f"--defaults-extra-file={defaults}", "--single-transaction", "--no-tablespaces",
            "--set-gtid-purged=OFF", mysql_store.cfg.MYSQL_DATABASE, *tables],
            capture_output=True, encoding="utf-8", check=True)
    with gzip.open(archive, "wt", encoding="utf-8") as output:
        output.write(result.stdout)
    Path(str(archive) + ".json").write_text(json.dumps({"formatVersion": 1, "tables": tables,
        "sha256": backup.digest_file(archive)}), encoding="utf-8")
    target = "eai_test_" + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f"CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
    try:
        backup.restore_backup(mysql_store.cfg, archive, target, mysql_binary=str(Path(binary_dir) / ("mysql" + extension)))
        cfg = copy.copy(mysql_store.cfg)
        cfg.MYSQL_DATABASE = target
        restored = ControlStore(cfg)
        restored.check_schema()
        _, _, total = restored.analytics_page("all", None, utcnow(), 0, 10, employee_search="old-backup-fixture")
        assert total == 1
        with restored.transaction() as cur:
            cur.execute("SELECT COUNT(*) AS count FROM rollout_batches")
            assert cur.fetchone()["count"] == 0
    finally:
        with mysql_store.transaction() as cur:
            cur.execute(f"DROP DATABASE `{target}`")


def test_schema_four_backup_restores_command_batches_to_schema_five(mysql_store, tmp_path, monkeypatch):
    binary_dir = os.environ.get('ENDPOINTAI_TEST_MYSQL_BIN')
    if not binary_dir:
        pytest.skip('Requires local MySQL dump and client binaries')
    if os.name == 'nt':
        monkeypatch.setitem(sys.modules, 'fcntl', types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *_: None))
    backup = importlib.import_module('controlserver.backup')
    from controlserver.database import ControlStore, SCHEMA_4_CHECKSUM, schema_tables
    from controlserver import rollout
    from controlserver.models import CreateRolloutRequest, HeartbeatV2Request
    fixture = json.loads((Path(__file__).parent / 'fixtures/dotnet-v0.1.19.json').read_text(encoding='utf-8'))['heartbeat']
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(fixture), 60, '127.0.0.1')
    ident = fixture['device']['deviceId']
    batch = rollout.create(mysql_store, CreateRolloutRequest(type='disableProxy', reason='fixture',
        expiresInMinutes=60, maxPerSecond=2, deviceIds=[ident], confirmCount=1), 'fixture')['batchId']
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE schema_migrations SET version=4,checksum=%s', (SCHEMA_4_CHECKSUM,))

    @contextmanager
    def credentials(cfg):
        path = tmp_path / (uuid4().hex + '.cnf')
        path.write_text(f'[client]\nhost="{cfg.MYSQL_HOST}"\nport="{cfg.MYSQL_PORT}"\nuser="{cfg.MYSQL_USER}"\npassword=""\n', encoding='utf-8')
        try:
            yield str(path)
        finally:
            path.unlink()

    monkeypatch.setattr(backup, 'mysql_credentials', credentials)
    extension = '.exe' if os.name == 'nt' else ''
    tables = sorted(schema_tables() - {'policy_rollout_batches', 'policy_rollout_targets'})
    archive = tmp_path / 'schema4.sql.gz'
    with credentials(mysql_store.cfg) as defaults:
        result = subprocess.run([str(Path(binary_dir) / ('mysqldump' + extension)),
            f'--defaults-extra-file={defaults}', '--single-transaction', '--no-tablespaces',
            '--set-gtid-purged=OFF', mysql_store.cfg.MYSQL_DATABASE, *tables],
            capture_output=True, encoding='utf-8', check=True)
    with gzip.open(archive, 'wt', encoding='utf-8') as output:
        output.write(result.stdout)
    Path(str(archive) + '.json').write_text(json.dumps({'formatVersion':1, 'tables':tables,
        'sha256':backup.digest_file(archive)}), encoding='utf-8')
    target = 'eai_test_' + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f'CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    try:
        backup.restore_backup(mysql_store.cfg, archive, target, mysql_binary=str(Path(binary_dir) / ('mysql' + extension)))
        cfg = copy.copy(mysql_store.cfg)
        cfg.MYSQL_DATABASE = target
        restored = ControlStore(cfg)
        restored.check_schema()
        assert rollout.details(restored, batch, 0, 10)['totalTargets'] == 1
    finally:
        with mysql_store.transaction() as cur:
            cur.execute(f'DROP DATABASE `{target}`')
