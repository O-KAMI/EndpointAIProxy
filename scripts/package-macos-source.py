"""Create a credential-free, vendored Go macOS source handoff; never install or sign."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ["go-client/go.mod", "go-client/go.sum", "go-client/README.md",
         "go-client/scripts/build.sh", "go-client/scripts/validate_credentials.py",
         "go-client/scripts/soak.py", "go-client/scripts/benchmark.py",
         "installer/macos/Build-Pkg.sh", "installer/macos/InstallerSupport.sh",
         "installer/macos/Notarize-Pkg.sh", "installer/macos/preinstall", "installer/macos/postinstall",
         "installer/macos/run-service.sh", "installer/macos/com.sf.endpointai.proxy.plist",
         "installer/macos/service.entitlements.plist", "installer/macos/sf-endpointai-diagnostics",
         "installer/macos/sf-endpointai-proxy.conf.example", "installer/macos/uninstall.sh",
         "installer/macos/Set-ProductionClientControl.sh", "installer/macos/Collect-MacInstallerLogs.sh",
         "installer/macos/Recover-MacInstallation.sh", "installer/macos/tests/validate_go_pkg.py",
         "installer/macos/tests/test_installer.py"]


def source_files(version):
    files = [ROOT / name for name in FILES]
    files.append(ROOT / ("docs/MACOS-GO-" + version.replace(".", "") + "-HANDOFF.md"))
    supplemental = ROOT / ("docs/CLIENT-" + version.replace(".", "") + "-ADDITIONAL-ACCEPTANCE.md")
    if supplemental.exists():
        files.append(supplemental)
    for name in ("go-client/cmd", "go-client/internal", "go-client/vendor"):
        base = ROOT / name
        for path in base.rglob("*"):
            if path.is_symlink():
                raise RuntimeError("Source tree contains a symbolic link")
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT).as_posix()
            if name != "go-client/vendor" and path.suffix != ".go" and "/testdata/" not in relative:
                continue
            if path.suffix.lower() in (".key", ".pfx", ".p12", ".pem") or path.name.lower() in ("client-credentials.json", "secrets.env"):
                raise RuntimeError("Forbidden source filename")
            files.append(path)
    if not (ROOT / "go-client/vendor/modules.txt").is_file():
        raise RuntimeError("Vendored Go dependencies are missing")
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("A source input is missing or linked")
    return sorted(set(files))


def build(output, version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid version")
    output = Path(output).absolute()
    prefix = "EndpointAIProxy-Go-macOS-" + version
    files = source_files(version)
    manifest = {"productVersion": version, "credentialsIncluded": False, "signedPackageIncluded": False,
                "purpose": "macOS source handoff; native signing and notarization remain required", "files": []}
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves all previous candidates.
    with output.open("xb") as target:
        try:
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in files:
                    relative = path.relative_to(ROOT).as_posix()
                    data = path.read_bytes()
                    item = zipfile.ZipInfo(prefix + "/" + relative, (1980, 1, 1, 0, 0, 0))
                    item.compress_type = zipfile.ZIP_DEFLATED
                    executable = relative.startswith("installer/macos/") and (path.suffix == ".sh" or path.name in ("preinstall", "postinstall", "sf-endpointai-diagnostics"))
                    executable |= relative == "go-client/scripts/build.sh"
                    item.external_attr = (0o100755 if executable else 0o100644) << 16
                    archive.writestr(item, data)
                    manifest["files"].append(dict(path=relative, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
                archive.writestr(prefix + "/source-manifest.json", json.dumps(manifest, indent=2) + "\n")
            for item in manifest["files"]:
                if hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() != item["sha256"]:
                    raise RuntimeError("Source changed while packaging")
        except BaseException:
            target.close()
            output.unlink(missing_ok=True)
            raise
    with output.open("rb") as source:
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", default="0.2.5")
    args = parser.parse_args()
    print("Source archive SHA-256: " + build(args.output, args.version))


if __name__ == "__main__":
    main()
