"""Real schema-3 backup, isolated restore, migration and guarded rollback on Linux."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4
import zipfile

import pytest
from config import ROOT


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux backup and process helpers')
def test_schema3_backup_restore_migration_and_unused_rollback(mysql_store, tmp_path, monkeypatch):
    baseline = os.environ.get('ENDPOINTAI_TEST_BASELINE025')
    binary = os.environ.get('ENDPOINTAI_TEST_MYSQL_BIN')
    if not baseline or not binary:
        pytest.skip('Exact public schema-3 baseline and isolated MySQL binaries required')
    cfg = mysql_store.cfg
    assert cfg.MYSQL_HOST == '127.0.0.1' and cfg.MYSQL_DATABASE.startswith('eai_test_')
    target = 'eai_test_' + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute('CREATE DATABASE `' + target + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    spec = importlib.util.spec_from_file_location('native_upgrade026', ROOT.parent / 'deployment/update-server-0.1.26.py')
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    def run(args, cwd=None, env=None):
        result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=600)
        if result.returncode:
            diagnostic = result.stdout.decode('utf-8', errors='replace')
            for key, value in (env or {}).items():
                if len(value) >= 8 and any(word in key for word in ('TOKEN', 'PASSWORD', 'KEY')):
                    diagnostic = diagnostic.replace(value, '<redacted>')
            print(diagnostic)
        candidate.base.require(result.returncode == 0, 'Synthetic upgrade subprocess failed; see redacted test output')
        return result.stdout
    monkeypatch.setattr(candidate.base, 'run', run)
    old, new = tmp_path / 'old025', tmp_path / 'new026'
    ignore = shutil.ignore_patterns('__pycache__', '.pytest_cache', '.venv', 'deployment', 'artifacts', 'logs', 'var')
    shutil.copytree(baseline, old, ignore=ignore)
    shutil.copytree(ROOT, new, ignore=ignore)
    shutil.copytree(ROOT / 'deployment', new / 'deployment')
    monkeypatch.setattr(candidate.base, 'NEW', new)
    for directory in (old, new):
        (directory / '.venv').symlink_to(sys.prefix, target_is_directory=True)
        values = dict(APP_ENV='sit', APP_CONFIG=str(directory / 'conf'),
            SF_CONTROL_CLIENT_TOKEN=cfg.CLIENT_TOKEN, SF_CONTROL_ADMIN_TOKEN=cfg.ADMIN_TOKEN,
            SF_CONTROL_POLICY_HMAC_KEY=cfg.HMAC_TEXT, SF_CONTROL_TRANSPORT_KEY=cfg.TRANSPORT_KEY_TEXT,
            SF_CONTROL_TRANSPORT_KEY_ID=cfg.TRANSPORT_KEY_ID, EAI_MYSQL_HOST='127.0.0.1',
            EAI_MYSQL_PORT=str(cfg.MYSQL_PORT), EAI_MYSQL_USERNAME=cfg.MYSQL_USER,
            EAI_MYSQL_PASSWORD=cfg.MYSQL_PASSWORD, EAI_MYSQL_DATABASE=target,
            SF_CONTROL_LOG_DIR=str(directory / 'logs'), SF_CONTROL_DATA_ROOT=str(directory / 'var'))
        launch = directory / 'launch-env.json'
        launch.write_text(json.dumps(values), encoding='utf-8')
        launch.chmod(0o600)
    try:
        tables = candidate.previous.database(old, """store.initialize_empty(); store.check_schema()
from uuid import uuid4
from controlserver.models import DeviceEnrollmentRequest,DevicePolicyUpdateRequest
device=store.enroll(DeviceEnrollmentRequest(schemaVersion=2,deviceId=uuid4(),hostname='synthetic-upgrade',serviceVersion='0.2.3'))['deviceId']
store.device_policy(device,DevicePolicyUpdateRequest(expectedVersion=store.policy()['policyVersion'],overrides={'allowlistedBaseUrls':[]}), 'synthetic')
from controlserver.database import schema_tables
print(json.dumps(sorted(schema_tables()-{'schema_migrations'})))
""")
        before = candidate.snapshot(old, tables)
        destination, archive = candidate.previous.stopped_backup(old, Path(binary))
        candidate.verify_backup(old, destination, archive, Path(binary), tables, before)
        result = json.loads((destination / 'restore-verification/report.json').read_text())
        assert result['restoredSchema'] == 3 and result['cloneMigratedToSchema'] == 5
        assert result['commonRowsPreserved'] and not result['productionDatabaseModified']
        assert candidate.snapshot(old, tables) == before
        candidate.previous.database(new, "store.migrate();store.check_schema();print(json.dumps({'schema':5}))")
        assert candidate.snapshot(new, tables) == before
        # Gray qualification does not enable ordinary release mutations.
        assert candidate.MUTATION_VALIDATED is False
        candidate.downgrade_unused_schema(old, gray_candidate=True)
        assert candidate.snapshot(old, tables) == before
        candidate.previous.database(new, "store.migrate();store.check_schema();print(json.dumps({'schema':5}))")
        assert candidate.snapshot(new, tables) == before
    finally:
        with mysql_store.transaction() as cur:
            cur.execute('DROP DATABASE `' + target + '`')


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux process lifecycle')
@pytest.mark.parametrize('fail_start', [False, True])
def test_schema3_upgrade_lifecycle_and_failed_start_recovery(mysql_store, tmp_path, monkeypatch, fail_start):
    baseline = os.environ.get('ENDPOINTAI_TEST_BASELINE025')
    binary = os.environ.get('ENDPOINTAI_TEST_MYSQL_BIN')
    if not baseline or not binary:
        pytest.skip('Exact schema-3 baseline and isolated MySQL binaries required')
    cfg = mysql_store.cfg
    assert cfg.MYSQL_HOST == '127.0.0.1' and cfg.MYSQL_DATABASE.startswith('eai_test_')
    target = 'eai_test_' + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute('CREATE DATABASE `' + target + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    spec = importlib.util.spec_from_file_location('lifecycle_upgrade026', ROOT.parent / 'deployment/update-server-0.1.26.py')
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    old, new = tmp_path / 'old025', tmp_path / 'new026'
    shutil.copytree(baseline, old, ignore=shutil.ignore_patterns('__pycache__', '.venv', 'deployment', 'logs', 'var', 'artifacts'))
    (old / '.venv').symlink_to(sys.prefix, target_is_directory=True)
    values = dict(APP_ENV='sit', APP_CONFIG=str(old / 'conf'),
        SF_CONTROL_CLIENT_TOKEN=cfg.CLIENT_TOKEN, SF_CONTROL_ADMIN_TOKEN=cfg.ADMIN_TOKEN,
        SF_CONTROL_POLICY_HMAC_KEY=cfg.HMAC_TEXT, SF_CONTROL_TRANSPORT_KEY=cfg.TRANSPORT_KEY_TEXT,
        SF_CONTROL_TRANSPORT_KEY_ID=cfg.TRANSPORT_KEY_ID, EAI_MYSQL_HOST='127.0.0.1',
        EAI_MYSQL_PORT=str(cfg.MYSQL_PORT), EAI_MYSQL_USERNAME=cfg.MYSQL_USER,
        EAI_MYSQL_PASSWORD=cfg.MYSQL_PASSWORD, EAI_MYSQL_DATABASE=target,
        SF_CONTROL_LOG_DIR=str(old / 'logs'), SF_CONTROL_DATA_ROOT=str(old / 'var'),
        SF_CONTROL_HTTP_PORT='8080')
    launch = old / 'launch-env.json'
    launch.write_text(json.dumps(values), encoding='utf-8')
    launch.chmod(0o600)
    monkeypatch.setattr(candidate.base, 'NEW', new)
    monkeypatch.setattr(candidate.base, 'CANDIDATES', (old,))
    assert candidate.MUTATION_VALIDATED is False
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    opener = build_opener(ProxyHandler({}))
    children, logs = [], []

    def health(directory):
        for path in ('/health/ready', '/console', '/admin/v1/policy'):
            headers = {'Authorization': 'Bearer ' + cfg.ADMIN_TOKEN} if path.startswith('/admin/') else {}
            with opener.open(Request(f'http://127.0.0.1:{port}' + path, headers=headers), timeout=5) as response:
                assert response.status == 200

    def start(directory):
        if directory == new and fail_start:
            raise candidate.base.DeploymentError('Synthetic startup failure')
        env = candidate.previous.environment(directory)
        env.update(SF_CONTROL_HTTP_HOST='127.0.0.1', SF_CONTROL_HTTP_PORT=str(port))
        log = (directory / 'lifecycle.private.log').open('ab')
        logs.append(log)
        child = subprocess.Popen([str(directory / '.venv/bin/python'), 'app.py'], cwd=directory,
            env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        children.append(child)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            assert child.poll() is None, 'Synthetic service exited before readiness'
            try:
                health(directory)
                return
            except OSError:
                time.sleep(.1)
        raise RuntimeError('Synthetic service readiness timeout')

    # Adapt only the shared service port and launcher. All database, archive,
    # stop, restore, migration and rollback steps use the actual candidate.
    monkeypatch.setattr(candidate, 'health', health)
    monkeypatch.setattr(candidate.base, 'health', health)
    monkeypatch.setattr(candidate.base, 'start', start)
    try:
        tables = candidate.previous.database(old, """store.initialize_empty();store.check_schema()
from controlserver.database import schema_tables
print(json.dumps(sorted(schema_tables()-{'schema_migrations'})))
""")
        before = candidate.snapshot(old, tables)
        start(old)
        from tools.package_release import release_files, offline_wheels
        files = release_files() + offline_wheels() + [ROOT / 'deployment/wheelhouse-sha256.json']
        manifest = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
        provided_archive = os.environ.get('ENDPOINTAI_TEST_GRAY_ARCHIVE')
        archive = Path(provided_archive) if provided_archive else tmp_path / 'synthetic-update.zip'
        if not provided_archive:
            with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
                for path in files:
                    z.write(path, path.relative_to(ROOT).as_posix())
                z.writestr('manifest.json', json.dumps(manifest))
        else:
            assert archive.is_file() and not archive.is_symlink()
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if provided_archive:
            assert digest == os.environ['ENDPOINTAI_TEST_GRAY_ARCHIVE_SHA256']
        if fail_start:
            with pytest.raises(candidate.base.DeploymentError, match='升级未完成'):
                candidate.update(archive, digest, old, Path(binary), gray_candidate=True)
            assert candidate.base.processes(old) and not candidate.base.processes(new)
        else:
            destination = candidate.update(archive, digest, old, Path(binary), gray_candidate=True)
            assert (destination / 'restore-verification/report.json').exists()
            assert candidate.base.processes(new) and not candidate.base.processes(old)
            candidate.base.stop(new)
            candidate.downgrade_unused_schema(old, gray_candidate=True)
            start(old)
        health(old)
        candidate.previous.database(old, "store.check_schema();print(json.dumps({'schema':3}))")
        assert candidate.snapshot(old, tables) == before
    finally:
        for directory in (new, old):
            candidate.base.stop(directory)
        for child in children:
            child.wait(timeout=30)
        for log in logs:
            log.close()
        with mysql_store.transaction() as cur:
            cur.execute('DROP DATABASE `' + target + '`')
