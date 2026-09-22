import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import pytest
from config import ROOT


def test_upgrade_backup_uses_existing_database_without_mutation(mysql_store, tmp_path, monkeypatch, capsys):
    script = ROOT.parent / 'deployment/update-server-0.1.23.py'
    binary = os.environ.get('ENDPOINTAI_TEST_MYSQL_BIN')
    if not script.exists() or not binary:
        pytest.skip('Requires deployment bundle and isolated MySQL client')
    spec = importlib.util.spec_from_file_location('upgrade023_backup', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    old = tmp_path / 'old'
    old.mkdir()
    shutil.copytree(ROOT / 'conf', old / 'conf')
    shutil.copy2(ROOT / 'config.py', old / 'config.py')
    shutil.copytree(ROOT / 'controlserver', old / 'controlserver', ignore=shutil.ignore_patterns('__pycache__'))
    (old / '.venv').symlink_to(sys.prefix, target_is_directory=True)
    cfg = mysql_store.cfg
    values = dict(APP_ENV='prd', APP_CONFIG=str(old / 'conf'),
        SF_CONTROL_CLIENT_TOKEN=cfg.CLIENT_TOKEN, SF_CONTROL_ADMIN_TOKEN=cfg.ADMIN_TOKEN,
        SF_CONTROL_POLICY_HMAC_KEY=cfg.HMAC_TEXT, SF_CONTROL_TRANSPORT_KEY=cfg.TRANSPORT_KEY_TEXT,
        EAI_MYSQL_HOST=cfg.MYSQL_HOST, EAI_MYSQL_PORT=str(cfg.MYSQL_PORT),
        EAI_MYSQL_USERNAME=cfg.MYSQL_USER, EAI_MYSQL_PASSWORD=cfg.MYSQL_PASSWORD,
        EAI_MYSQL_DATABASE=cfg.MYSQL_DATABASE)
    launch = old / 'launch-env.json'
    launch.write_text(json.dumps(values))
    launch.chmod(0o600)
    monkeypatch.setenv('PATH', binary + os.pathsep + os.environ.get('PATH', ''))
    before = mysql_store.policy()
    module.backup(old)
    roots = list((old / 'upgrade-backups').iterdir())
    assert len(roots) == 1
    destination = roots[0]
    archives = list((destination / 'database').glob('*.sql.gz'))
    assert len(archives) == 1
    assert b'control_policy' in gzip.decompress(archives[0].read_bytes())
    assert json.loads((destination / 'launch-env.json').read_text()) == values
    assert launch.read_text() == json.dumps(values)
    assert mysql_store.policy() == before
    assert not (old / 'var/backup-state.json').exists()
    assert destination.stat().st_mode & 0o077 == 0
    assert (destination / 'launch-env.json').stat().st_mode & 0o077 == 0
    assert cfg.ADMIN_TOKEN not in capsys.readouterr().out
