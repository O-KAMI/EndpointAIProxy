"""Inspect a signed Go PKG on macOS without installing or exposing credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args):
    # Output may include private paths: capture it and report only the fixed check name.
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def validate(package, architecture, version, scratch):
    package, scratch = map(Path, (package, scratch))
    require(package.is_file() and scratch.is_dir(), "Input paths are missing")
    require(architecture in ("arm64", "x86_64"), "Unsupported architecture")
    require(os.name == "posix" and scratch.stat().st_uid == os.geteuid() and scratch.stat().st_mode & 0o077 == 0,
            "Scratch directory must be private and owned by this account")
    digest = hashlib.sha256()
    with package.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    digest = digest.hexdigest()
    run(["/usr/sbin/pkgutil", "--check-signature", str(package)])
    run(["/usr/sbin/spctl", "--assess", "--type", "install", str(package)])
    run(["/usr/bin/xcrun", "stapler", "validate", str(package)])
    with tempfile.TemporaryDirectory(prefix="endpointai-go-pkg-", dir=scratch) as temp:
        expanded = Path(temp) / "expanded"
        run(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)])
        info = ET.parse(expanded / "PackageInfo").getroot().attrib
        require(info.get("identifier") == "com.sf.endpointai.proxy" and info.get("version") == version
                and info.get("auth") == "root" and info.get("install-location") == "/", "Invalid package identity")
        scripts = expanded / "Scripts"
        for name in ("preinstall", "postinstall"):
            require((scripts / name).read_bytes() == (SOURCE / name).read_bytes(), "Installer script differs")
        expected = (SOURCE / "InstallerSupport.sh").read_text(encoding="utf-8").replace(
            "SF_VERSION=0.1.22\n", "SF_VERSION=" + version + "\n").replace(
            "SF_IMPLEMENTATION=dotnet\n", "SF_IMPLEMENTATION=go\n")
        require((scripts / "InstallerSupport.sh").read_text(encoding="utf-8") == expected,
                "Installer support script differs")
        require((scripts / "external-credentials").read_text(encoding="utf-8").strip() == "v1"
                and not (scripts / "client-credentials.json").exists(), "External credential mode is required")
        require(not any("credentials" in p.name.lower() and p.suffix.lower() == ".json" for p in expanded.rglob("*")),
                "Credential file present in package")
        require((scripts / "package-arch").read_text().strip() == architecture
                and (scripts / "package-version").read_text().strip() == version, "Package architecture or version differs")
        payload = expanded / "Payload"
        binary = payload / "Library/Application Support/SF/EndpointAIProxy/bin/Sf.EndpointAI.Client.Service"
        description = subprocess.check_output(["/usr/bin/file", "-b", str(binary)], text=True)
        require("Mach-O" in description and architecture in description, "Service architecture differs")
        run(["/usr/bin/codesign", "--verify", "--strict", str(binary)])
        run(["/usr/sbin/spctl", "--assess", "--type", "execute", str(binary)])
        require(not any(p.name.endswith((".dll", ".dylib")) for p in binary.parent.iterdir()),
                "Unexpected runtime library in Go payload")
        require(not any("client-credentials" in p.name for p in payload.rglob("*")), "Credential leaked into payload")
        require(not any(p.name.startswith("._") for p in expanded.rglob("*")), "AppleDouble file in package")
        bom = subprocess.check_output(["/usr/bin/lsbom", "-f", str(expanded / "Bom")], text=True)
        lines = bom.splitlines()
        require(bool(lines) and all(len(parts) > 2 and parts[2] == "0/0" for parts in (line.split("\t") for line in lines)),
                "Package file ownership is not root/wheel")
    print(json.dumps(dict(status="passed", version=version, architecture=architecture, sha256=digest,
                          signed=True, notarizationTicket=True, installationPerformed=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--private-scratch", required=True)
    args = parser.parse_args()
    validate(args.package, args.architecture, args.version, args.private_scratch)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit("Go PKG validation failed; private output withheld: " + type(exc).__name__)
