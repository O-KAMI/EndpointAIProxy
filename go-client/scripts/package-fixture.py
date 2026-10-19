#!/usr/bin/env python3
"""Build and inspect a macOS PKG with synthetic enrollment material; never install."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import plistlib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    ap.add_argument("--development-app", type=Path)
    ap.add_argument("--version", default="0.2.2")
    ap.add_argument("--artifact-suffix", default="", help="Separate immutable verification builds, for example -r3")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="endpointai-package-") as temporary:
        temp = Path(temporary).resolve()
        credential = temp / "synthetic-credentials.json"
        credential.write_text(json.dumps({"origin": "http://control.example.invalid:8080", "keyId": "synthetic-only",
                                         "clientToken": "synthetic-only-" + base64.urlsafe_b64encode(os.urandom(24)).decode(),
                                         "transportKey": base64.b64encode(os.urandom(32)).decode(), "policyHmacKey": base64.b64encode(os.urandom(32)).decode()}))
        credential.chmod(0o600)
        env = {k: v for k, v in os.environ.items() if k not in ("APP_SIGN_IDENTITY", "INSTALLER_SIGN_IDENTITY", "DEVELOPMENT_APP_BUNDLE", "CLIENT_CREDENTIALS_FILE")}
        env.update(CLIENT_IMPLEMENTATION="go", ARTIFACT_SUFFIX=args.artifact_suffix, VERSION=args.version, ARCH=args.architecture, CLIENT_CREDENTIALS_FILE=str(credential))
        kind = "go"
        if args.development_app:
            env["DEVELOPMENT_APP_BUNDLE"] = str(args.development_app.resolve())
            kind = "go-development"
        subprocess.run(["/bin/zsh", str(ROOT / "installer/macos/Build-Pkg.sh")], env=env, check=True)
        rid = "osx-arm64" if args.architecture == "arm64" else "osx-x64"
        directory = ROOT / "artifacts/macos" / f"{kind}-{args.version}{args.artifact_suffix}" / rid
        if args.development_app:
            components = plistlib.loads((directory / "components.plist").read_bytes())
            assert all(item["BundleIsRelocatable"] is False for item in components)
        packages = list(directory.glob("*.pkg"))
        if len(packages) != 1:
            raise RuntimeError("Expected exactly one candidate package.")
        package = packages[0]
        expanded = temp / "expanded"
        subprocess.run(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)], check=True, capture_output=True)
        info = ET.parse(expanded / "PackageInfo").getroot().attrib
        assert info["identifier"] == "com.sf.endpointai.proxy" and info["version"] == args.version and info["auth"] == "root"
        assert (expanded / "Scripts/package-arch").read_text().strip() == args.architecture
        assert (expanded / "Scripts/package-version").read_text().strip() == args.version
        assert (expanded / "Scripts/client-credentials.json").read_bytes() == credential.read_bytes()
        support = (expanded / "Scripts/InstallerSupport.sh").read_text()
        assert f"SF_VERSION={args.version}" in support and "SF_IMPLEMENTATION=go" in support
        payload = expanded / "Payload"
        program = payload / "Library/Application Support/SF/EndpointAIProxy/bin"
        binary = program / "Sf.EndpointAI.Client.Service"
        if args.development_app:
            app = program / "EndpointAIProxy.app"
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True, capture_output=True)
            assert (app / "Contents/embedded.provisionprofile").read_bytes() == (args.development_app / "Contents/embedded.provisionprofile").read_bytes()
            assert binary.read_text().startswith("#!/bin/zsh")
            binary = app / "Contents/MacOS/Sf.EndpointAI.Client.Service"
        description = subprocess.check_output(["/usr/bin/file", "-b", str(binary)], text=True)
        assert "Mach-O" in description and args.architecture in description
        assert not any(p.suffix in (".dll", ".dylib") for p in program.rglob("*"))
        assert not any("credentials" in p.name for p in payload.rglob("*"))
        bom = subprocess.check_output(["/usr/bin/lsbom", "-f", str(expanded / "Bom")], text=True)
        assert all(line.split("\t")[2] == "0/0" for line in bom.splitlines())
        report = {"status": "static-inspection-passed", "package": str(package), "bytes": package.stat().st_size,
                  "sha256": hashlib.sha256(package.read_bytes()).hexdigest(), "architecture": args.architecture,
                  "synthetic_credentials": True, "development_program_signature": bool(args.development_app),
                  "installer_signature": "unsigned", "native_installation": "not performed", "production_distribution": False}
        report_path = ROOT / "artifacts/go-client/verification" / (f"pkg-{kind}-{args.version}-{args.architecture}{args.artifact_suffix}.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"report": str(report_path), "status": report["status"], "bytes": report["bytes"]}))

if __name__ == "__main__":
    main()
