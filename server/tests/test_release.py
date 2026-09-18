import importlib.util
from pathlib import Path
import subprocess
import sys
from config import ROOT


def test_release_excludes_actual_credentials_and_artifacts():
    spec = importlib.util.spec_from_file_location("package_release", ROOT/"tools/package_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    names = {str(p.relative_to(ROOT)) for p in module.release_files()}
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
    assert result.returncode == 0
    before = target.read_bytes()
    assert target.stat().st_mode & 0o077 == 0
    assert len(before.splitlines()) == 5
    assert before.splitlines()[0].split(b"=")[1].decode() not in result.stdout
    assert subprocess.run(command,capture_output=True).returncode != 0
    assert target.read_bytes() == before
