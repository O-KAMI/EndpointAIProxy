"""Build a source-only release from an explicit allowlist; never package actual credentials."""
import argparse
from email.parser import BytesParser
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zipfile
from packaging.tags import compatible_tags, cpython_tags, parse_tag
from packaging.utils import parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.1.26"


def require_update_validated(gray_candidate=False):
    if RELEASE_VERSION == "0.1.26":
        if not gray_candidate:
            raise RuntimeError("0.1.26 ordinary delivery is blocked; gray delivery requires explicit opt-in and matching native qualification")
        deployment = ROOT.parent / 'deployment'
        spec = importlib.util.spec_from_file_location('gray_release_qualification', deployment / 'gray_qualification.py')
        gray = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gray)
        gray.qualified_source(ROOT, deployment)


def offline_wheels():
    """Reject an incomplete or mismatched offline lock before producing a release."""
    normalize = lambda value: re.sub(r"[-_.]+", "-", value).lower()
    required = {}
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, version = line.split("==", 1)
        required[normalize(name)] = version
    wheels = []
    for architecture in ("x86_64", "aarch64"):
        platforms = ["manylinux_2_28_" + architecture, "manylinux_2_17_" + architecture,
                     "manylinux2014_" + architecture]
        supported = set(cpython_tags((3, 13), abis=["cp313"], platforms=platforms))
        supported.update(compatible_tags((3, 13), interpreter="cp313", platforms=platforms))
        candidates = sorted((ROOT / "deployment/wheelhouse" / architecture).glob("*.whl"))
        installed = {}
        for path in candidates:
            if path.is_symlink():
                raise RuntimeError("Linked offline dependency")
            with zipfile.ZipFile(path) as archive:
                metadata_names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
                wheel_names = [n for n in archive.namelist() if n.endswith(".dist-info/WHEEL")]
                if len(metadata_names) != 1 or len(wheel_names) != 1 or archive.testzip() is not None:
                    raise RuntimeError("Invalid offline wheel")
                metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
                tags = BytesParser().parsebytes(archive.read(wheel_names[0])).get_all("Tag", [])
            name = normalize(metadata["Name"])
            wheel_name, wheel_version, _, filename_tags = parse_wheel_filename(path.name)
            wheel_tags = set().union(*(parse_tag(tag) for tag in tags)) if tags else set()
            if normalize(str(wheel_name)) != name or str(wheel_version) != metadata["Version"] or wheel_tags != filename_tags:
                raise RuntimeError("Offline wheel filename and metadata do not match")
            if name in installed or required.get(name) != metadata["Version"]:
                raise RuntimeError("Offline dependencies do not match requirements.txt")
            if not supported.intersection(wheel_tags):
                raise RuntimeError("Offline wheel has the wrong Python version, ABI or platform")
            installed[name] = metadata["Version"]
        if installed != required:
            raise RuntimeError("Incomplete offline dependencies for " + architecture)
        wheels.extend(candidates)
    manifest = ROOT / "deployment/wheelhouse-sha256.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise RuntimeError("Offline dependency hash manifest missing or linked")
    expected = json.loads(manifest.read_text(encoding="utf-8"))
    actual = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in wheels}
    if expected != actual:
        raise RuntimeError("Offline dependency hash mismatch")
    return wheels


def release_files():
    names = {"app.py", "start.py", "config.py", "manage.py", "requirements.txt", "requirements-dev.txt",
             "pytest.ini", "README.md", ".gitignore", "conf/application.properties",
             "conf/endpoint_ai_proxy.sql", "conf/product.properties"}
    for pattern in ("controlserver/*.py", "controlserver/templates/*.html", "conf/*.example",
                    "deploy/*", "docs/*.md", "tests/*.py", "tests/*.cjs", "tests/fixtures/*.json",
                    "tests/dotnet/*.cs", "tests/dotnet/*.csproj", "tools/*.py"):
        names.update(str(path.relative_to(ROOT)) for path in ROOT.glob(pattern) if path.is_file())
    paths = [ROOT / name for name in sorted(names) if (ROOT / name).is_file()]
    forbidden = {"mysql_sit.properties", "mysql_prd.properties", "secrets.env"}
    if any(p.name in forbidden or p.suffix in (".key", ".pfx") or p.is_symlink() for p in paths):
        raise RuntimeError("A forbidden or linked file appeared in the release allowlist")
    # Application properties must remain a public template even if locally modified.
    import sys
    sys.path.insert(0, str(ROOT))
    from config import load_properties
    props = load_properties(ROOT / "conf/application.properties")
    if any(value and (key == "transport.key" or any(word in key.lower() for word in ("password", "token", "hmac", "secret", "seed")))
           for key, value in props.items()):
        raise RuntimeError("application.properties contains secrets; move them to deployment-only configuration")
    return paths


def build_release(output, update=False, gray_candidate=False):
    if update:
        require_update_validated(True) if gray_candidate else require_update_validated()
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    files = release_files()
    if update:
        files += offline_wheels() + [ROOT / "deployment/wheelhouse-sha256.json"]
        if any(p.is_symlink() for p in files):
            raise RuntimeError("Linked release file")
    manifest = {}
    with output.open("xb") as target, zipfile.ZipFile(target, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            name = path.relative_to(ROOT).as_posix()
            if not update:
                name = "EndpointAIDLP-Server-" + RELEASE_VERSION + "/" + name
            archive.write(path, arcname=name)
            manifest[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if update:
            archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
    with output.open("rb") as file:
        digest = hashlib.file_digest(file,"sha256").hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest}  {output.name}\n")
    return len(files), digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--update", action="store_true", help="Include locked Linux offline wheels and per-file manifest")
    parser.add_argument('--gray-candidate', action='store_true', help='Build an explicitly qualified gray update; ordinary 0.1.26 delivery remains blocked')
    args = parser.parse_args()
    count, digest = build_release(args.output, args.update, args.gray_candidate)
    output = Path(args.output)
    print(f"Packaged {count} source files: {output}")
    print("SHA256: " + digest)


if __name__ == "__main__":
    main()
