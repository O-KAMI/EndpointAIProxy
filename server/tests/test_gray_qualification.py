import hashlib
import importlib.util
import json
import zipfile

import pytest
from config import ROOT


@pytest.fixture
def qualification(tmp_path):
    spec = importlib.util.spec_from_file_location('gray_test_qualification', ROOT.parent / 'deployment/gray_qualification.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source, deployment = tmp_path / 'server', tmp_path / 'deployment'
    source.mkdir(); deployment.mkdir()
    (source / 'app.py').write_bytes(b'synthetic source')
    (deployment / 'update.py').write_bytes(b'synthetic updater')
    record = dict(version='0.1.26', channel='gray-candidate', targetSchema=5,
        fullRolloutAccepted=False, validatedLinuxArchitectures=['x86_64'],
        runtimeFiles={'app.py': hashlib.sha256(b'synthetic source').hexdigest()},
        upgraderFiles={'update.py': hashlib.sha256(b'synthetic updater').hexdigest()})
    (deployment / 'gray-upgrade-0.1.26.json').write_text(json.dumps(record), encoding='utf-8')
    return module, source, deployment, record


def test_gray_qualification_rejects_changed_source_and_updater(qualification):
    module, source, deployment, record = qualification
    assert module.qualified_source(source, deployment) == record
    (source / 'app.py').write_bytes(b'changed source')
    with pytest.raises(RuntimeError, match='source mismatch'):
        module.qualified_source(source, deployment)
    (source / 'app.py').write_bytes(b'synthetic source')
    (deployment / 'update.py').write_bytes(b'changed updater')
    with pytest.raises(RuntimeError, match='source mismatch'):
        module.qualified_source(source, deployment)


def test_gray_qualification_rejects_unverified_platform_and_release_claim(qualification, monkeypatch):
    module, _, deployment, record = qualification
    monkeypatch.setattr(module.sys, 'platform', 'linux')
    monkeypatch.setattr(module.platform, 'machine', lambda: 'aarch64')
    with pytest.raises(RuntimeError, match='platform'):
        module.qualified_execution(deployment)
    monkeypatch.setattr(module.platform, 'machine', lambda: 'x86_64')
    assert module.qualified_execution(deployment) == record
    record['fullRolloutAccepted'] = True
    (deployment / 'gray-upgrade-0.1.26.json').write_text(json.dumps(record), encoding='utf-8')
    with pytest.raises(RuntimeError, match='Invalid'):
        module.qualified_execution(deployment)


@pytest.mark.parametrize('contents', [b'wrong source', None])
def test_gray_archive_must_match_qualified_runtime(qualification, tmp_path, contents):
    module, _, _, record = qualification
    archive = tmp_path / 'update.zip'
    with zipfile.ZipFile(archive, 'x') as target:
        target.writestr('app.py' if contents is not None else 'other.py', contents or b'synthetic source')
    with pytest.raises(RuntimeError, match='native qualification'):
        module.check_archive(archive, record)
