"""Real isolated dump/restore; the Windows lock adapter is not POSIX acceptance."""
import copy
import importlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
import sys
import types
from uuid import uuid4

import pytest

from controlserver import credential_rotation as rotation
from controlserver.database import ControlStore
from test_credential_rotation import renewal, OLD, NEXT


@pytest.fixture
def backup_tools(monkeypatch, tmp_path):
    directory = os.environ.get('ENDPOINTAI_TEST_MYSQL_BIN')
    if not directory:
        pytest.skip('Requires isolated local MySQL client and dump tools')
    if os.name == 'nt':
        monkeypatch.setitem(sys.modules, 'fcntl', types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *_: None))
    backup = importlib.import_module('controlserver.backup')
    @contextmanager
    def credentials(cfg):
        path = tmp_path / (uuid4().hex + '.cnf')
        def escape(value):
            return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
        text = '[client]\n' + ''.join(f'{name}="{escape(value)}"\n' for name, value in (
            ('host', cfg.MYSQL_HOST), ('port', cfg.MYSQL_PORT), ('user', cfg.MYSQL_USER), ('password', cfg.MYSQL_PASSWORD)))
        path.write_text(text, encoding='utf-8')
        try: yield str(path)
        finally: path.unlink()
    monkeypatch.setattr(backup, 'mysql_credentials', credentials)
    suffix = '.exe' if os.name == 'nt' else ''
    return backup, str(Path(directory) / ('mysqldump' + suffix)), str(Path(directory) / ('mysql' + suffix))


@pytest.mark.parametrize('committed', [False, True])
def test_non_derived_state_is_backed_up_even_when_preparation_is_disabled(renewal, backup_tools, committed):
    store, device, ident, _ = renewal
    backup, dump, mysql = backup_tools
    rotation.prepare(store, device, ident, OLD, NEXT)
    if committed: rotation.commit(store, device, ident, NEXT)
    store.cfg.CREDENTIAL_ROTATION = False
    archive = backup.run_backup(store.cfg, dump_binary=dump)
    manifest = json.loads(Path(str(archive) + '.json').read_text())
    assert rotation.TABLE in manifest['tables']
    target = 'eai_test_' + uuid4().hex
    with store.transaction() as cur:
        cur.execute(f'CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    try:
        backup.restore_backup(store.cfg, archive, target, mysql_binary=mysql)
        cfg = copy.copy(store.cfg); cfg.MYSQL_DATABASE = target
        restored = ControlStore(cfg); restored.check_schema()
        assert restored._credential_rotation_table
        assert restored.authenticate(device, OLD) and restored.authenticate(device, NEXT)
        assert rotation.commit(restored, device, ident, NEXT)['state'] == 'active'
    finally:
        with store.transaction() as cur: cur.execute(f'DROP DATABASE `{target}`')


def test_restore_refuses_missing_state_before_touching_target(mysql_store, backup_tools):
    backup, dump, mysql = backup_tools
    archive = backup.run_backup(mysql_store.cfg, dump_binary=dump)
    target = 'eai_test_' + uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f'CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    try:
        cfg = copy.copy(mysql_store.cfg); cfg.CREDENTIAL_ROTATION = True
        with pytest.raises(ValueError, match='omits credential renewal state'):
            backup.restore_backup(cfg, archive, target, mysql_binary=mysql)
        with mysql_store.transaction() as cur:
            cur.execute('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=%s', (target,))
            assert cur.fetchone()['n'] == 0
    finally:
        with mysql_store.transaction() as cur: cur.execute(f'DROP DATABASE `{target}`')
