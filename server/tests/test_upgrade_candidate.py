import hashlib
import importlib.util
import sys
import types

import pytest

from config import ROOT


@pytest.fixture
def candidate(monkeypatch):
    if sys.platform == 'win32':
        monkeypatch.setitem(sys.modules, 'fcntl', types.ModuleType('fcntl'))
    spec = importlib.util.spec_from_file_location('update_026_candidate', ROOT.parent / 'deployment/update-server-0.1.26.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_archive_requires_matching_independent_hash(candidate, tmp_path):
    archive = tmp_path / 'candidate.zip'
    archive.write_bytes(b'synthetic release')
    candidate.check_archive(archive, hashlib.sha256(archive.read_bytes()).hexdigest())
    for invalid in ('', '0' * 64):
        with pytest.raises(candidate.base.DeploymentError):
            candidate.check_archive(archive, invalid)


@pytest.mark.parametrize('action', ['update', 'rollback'])
def test_unvalidated_mutations_are_blocked_before_process_operations(candidate, monkeypatch, action):
    assert candidate.MUTATION_VALIDATED is False
    monkeypatch.setattr(candidate.sys, 'platform', 'linux')
    monkeypatch.setattr(candidate.os, 'umask', lambda mask: None)
    monkeypatch.setattr(candidate.sys, 'argv', ['updater', '--action', action])
    monkeypatch.setattr(candidate.base, 'processes', lambda path: pytest.fail('unexpected process operation'))
    with pytest.raises(candidate.base.DeploymentError, match='尚未通过隔离 Linux 验收'):
        candidate.main()


def test_internal_mutation_entrypoints_are_also_guarded(candidate):
    with pytest.raises(candidate.base.DeploymentError, match='尚未通过隔离 Linux 验收'):
        candidate.update(None, '', None, None)
    with pytest.raises(candidate.base.DeploymentError, match='尚未通过隔离 Linux 验收'):
        candidate.downgrade_unused_schema(None)


def test_backup_root_rejects_symlinks_before_stopping_service(candidate, tmp_path, monkeypatch):
    root = tmp_path / 'upgrade-backups'
    monkeypatch.setattr(type(root), 'is_symlink', lambda path: path == root)
    with pytest.raises(candidate.base.DeploymentError, match='符号链接'):
        candidate.check_backup_root(tmp_path)


def test_temporary_database_credentials_removed_when_setup_fails(candidate, tmp_path, monkeypatch):
    monkeypatch.setattr(candidate.base, 'run', lambda *args, **kwargs: b'')
    def fail_directory(*args, **kwargs):
        raise OSError('synthetic failure')
    monkeypatch.setattr(candidate.tempfile, 'TemporaryDirectory', fail_directory)
    with pytest.raises(OSError, match='synthetic failure'):
        candidate.verify_backup(tmp_path, tmp_path, tmp_path / 'backup', tmp_path, [], {})
    assert not (tmp_path / 'restore-verification' / 'init.sql').exists()
