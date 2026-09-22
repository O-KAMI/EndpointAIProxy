"""Build a source-only release from an explicit allowlist; never package actual credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def release_files():
    names = {"app.py", "start.py", "config.py", "manage.py", "requirements.txt", "requirements-dev.txt",
             "pytest.ini", "README.md", ".gitignore", "conf/application.properties",
             "conf/endpoint_ai_proxy.sql", "conf/product.properties"}
    for pattern in ("controlserver/*.py", "controlserver/templates/*.html", "conf/*.example",
                    "deploy/*", "docs/*.md", "tests/*.py", "tests/fixtures/*.json",
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
    if any(value and (key == "transport.key" or any(word in key.lower() for word in ("password", "token", "hmac", "secret")))
           for key, value in props.items()):
        raise RuntimeError("application.properties contains secrets; move them to deployment-only configuration")
    return paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--update", action="store_true", help="Include locked Linux offline wheels and per-file manifest")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    files = release_files()
    if args.update:
        files += sorted((ROOT / "deployment/wheelhouse").glob("*/*.whl"))
        if any(p.is_symlink() for p in files):
            raise RuntimeError("Linked release file")
    manifest = {}
    with output.open("xb") as target, zipfile.ZipFile(target, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            name = str(path.relative_to(ROOT))
            if not args.update:
                name = "EndpointAIDLP-Server-0.1.23/" + name
            archive.write(path, arcname=name)
            manifest[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if args.update:
            archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
    with output.open("rb") as file:
        digest = hashlib.file_digest(file,"sha256").hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest}  {output.name}\n")
    print(f"Packaged {len(files)} source files: {output}")
    print("SHA256: " + digest)


if __name__ == "__main__":
    main()
