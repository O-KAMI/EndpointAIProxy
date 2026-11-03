import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import pytest
from config import ROOT


def test_release_excludes_actual_credentials_and_artifacts():
    spec = importlib.util.spec_from_file_location("package_release", ROOT/"tools/package_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    names = {p.relative_to(ROOT).as_posix() for p in module.release_files()}
    assert "conf/mysql_prd.properties" not in names
    assert "conf/mysql_sit.properties" not in names
    assert "conf/mysql_prd.properties.example" in names
    assert "deploy/nginx.conf" not in names
    assert "controlserver/templates/console.html" in names
    assert not any(n.startswith((".venv/","artifacts/")) or n.endswith((".key",".pfx")) for n in names)


def test_secret_generation_is_private_and_never_overwrites(tmp_path):
    target = tmp_path/"secrets.env"
    command = [sys.executable,str(ROOT/"manage.py"),"secrets","--output",str(target)]
    result = subprocess.run(command,text=True,capture_output=True)
    if os.name != "posix":
        assert result.returncode != 0
        assert not target.exists()
        assert "POSIX file permissions" in result.stderr
        return
    assert result.returncode == 0
    before = target.read_bytes()
    assert target.stat().st_mode & 0o077 == 0
    assert len(before.splitlines()) == 5
    assert before.splitlines()[0].split(b"=")[1].decode() not in result.stdout
    assert subprocess.run(command,capture_output=True).returncode != 0
    assert target.read_bytes() == before


def test_offline_release_requires_both_complete_locked_architectures(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("package_release_offline", ROOT/"tools/package_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    wheels = module.offline_wheels()
    assert {path.parent.name for path in wheels} == {"aarch64", "x86_64"}
    assert not any(path.is_symlink() for path in wheels)
    (tmp_path / "requirements.txt").write_text("required-package==1.0\n")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    with pytest.raises(RuntimeError, match="Incomplete offline dependencies"):
        module.offline_wheels()


def test_offline_release_rejects_wheel_content_change(tmp_path, monkeypatch):
    import hashlib
    import json
    import shutil
    spec = importlib.util.spec_from_file_location('package_release_hash_check', ROOT / 'tools/package_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    wheel = next((ROOT / 'deployment/wheelhouse/x86_64').glob('annotated_types-*.whl'))
    (tmp_path / 'requirements.txt').write_text('annotated-types==0.8.0\n', encoding='utf-8')
    hashes = {}
    for architecture in ('x86_64', 'aarch64'):
        folder = tmp_path / 'deployment/wheelhouse' / architecture
        folder.mkdir(parents=True)
        copy = folder / wheel.name
        shutil.copyfile(wheel, copy)
        hashes[copy.relative_to(tmp_path).as_posix()] = hashlib.sha256(copy.read_bytes()).hexdigest()
    (tmp_path / 'deployment/wheelhouse-sha256.json').write_text(json.dumps(hashes), encoding='utf-8')
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    assert len(module.offline_wheels()) == 2
    with copy.open('ab') as output:
        output.write(b'synthetic alteration')
    with pytest.raises(RuntimeError, match='hash mismatch'):
        module.offline_wheels()


def test_offline_release_rejects_python_incompatible_wheel(tmp_path, monkeypatch):
    import zipfile
    spec = importlib.util.spec_from_file_location('package_release_tags', ROOT / 'tools/package_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / 'requirements.txt').write_text('synthetic==1.0\n', encoding='utf-8')
    for architecture in ('x86_64', 'aarch64'):
        folder = tmp_path / 'deployment/wheelhouse' / architecture
        folder.mkdir(parents=True)
        with zipfile.ZipFile(folder / 'synthetic-1.0-py2-none-any.whl', 'w') as output:
            output.writestr('synthetic-1.0.dist-info/METADATA', 'Name: synthetic\nVersion: 1.0\n')
            output.writestr('synthetic-1.0.dist-info/WHEEL', 'Tag: py2-none-any\n')
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    with pytest.raises(RuntimeError, match='Python version, ABI or platform'):
        module.offline_wheels()


def test_offline_release_rejects_mismatched_filename_and_tags(tmp_path, monkeypatch):
    import zipfile
    spec = importlib.util.spec_from_file_location('package_release_wrong_name', ROOT / 'tools/package_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / 'requirements.txt').write_text('synthetic==1.0\n', encoding='utf-8')
    folder = tmp_path / 'deployment/wheelhouse/x86_64'
    folder.mkdir(parents=True)
    with zipfile.ZipFile(folder / 'synthetic-1.0-py2-none-any.whl', 'w') as output:
        output.writestr('synthetic-1.0.dist-info/METADATA', 'Name: synthetic\nVersion: 1.0\n')
        output.writestr('synthetic-1.0.dist-info/WHEEL', 'Tag: py3-none-any\n')
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    with pytest.raises(RuntimeError, match='filename and metadata'):
        module.offline_wheels()


def test_schema_five_delivery_is_blocked_before_creating_files(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    spec = importlib.util.spec_from_file_location("package_delivery_candidate", ROOT / "tools/package_delivery.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / "delivery"
    with pytest.raises(RuntimeError, match="schema 3/4 to 5"):
        module.package_delivery(target)
    assert not target.exists()


def test_schema_five_raw_update_is_also_blocked_before_creating_files(tmp_path):
    spec = importlib.util.spec_from_file_location('package_release_candidate', ROOT / 'tools/package_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / 'new-directory' / 'update.zip'
    with pytest.raises(RuntimeError, match='schema 3/4 to 5'):
        module.build_release(target, update=True)
    assert not target.parent.exists()


def test_update_archive_manifest_uses_portable_paths(tmp_path, monkeypatch):
    import hashlib
    import json
    import zipfile
    spec = importlib.util.spec_from_file_location('package_release_portable', ROOT / 'tools/package_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / 'source'
    files = []
    for relative in ('app.py', 'start.py', 'requirements.txt', 'controlserver/templates/console.html',
                     'deployment/wheelhouse-sha256.json'):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic', encoding='utf-8')
        files.append(path)
    monkeypatch.setattr(module, 'ROOT', source)
    monkeypatch.setattr(module, 'release_files', lambda: files[:-1])
    monkeypatch.setattr(module, 'offline_wheels', lambda: [])
    monkeypatch.setattr(module, 'require_update_validated', lambda: None)
    output = tmp_path / 'synthetic.zip'
    module.build_release(output, update=True)
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        assert set(archive.namelist()) == set(manifest) | {'manifest.json'}
        assert 'controlserver/templates/console.html' in manifest
        assert all('\\' not in path for path in manifest)
        assert all(hashlib.sha256(archive.read(path)).hexdigest() == digest for path, digest in manifest.items())


def test_release_rejects_policy_private_seed_in_public_properties(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("package_release_seed_check", ROOT / "tools/package_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf/application.properties").write_text("auth.policy-ed25519-seed=synthetic-only\n", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    with pytest.raises(RuntimeError, match="contains secrets"):
        module.release_files()
