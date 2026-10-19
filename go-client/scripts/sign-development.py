#!/usr/bin/env python3
"""Sign an isolated macOS development app with its device provisioning profile.

Private inputs remain external; the temporary keychain and its search-list entry
are removed even on failure. This does not create a Developer ID release package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shlex
import shutil
import ssl
import subprocess
import tempfile

def execute(args, **kwargs):
    r = subprocess.run([str(a) for a in args], capture_output=True, **kwargs)
    if r.returncode:
        if str(args[0]) == "/usr/bin/codesign":
            raise RuntimeError("Code signing failed: " + r.stderr.decode(errors="replace")[:1500])
        raise RuntimeError("Signing step failed: " + str(args[0]) + " " + str(args[1]))
    return r.stdout

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", required=True, type=Path)
    ap.add_argument("--certificate", required=True, type=Path)
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--intermediate", type=Path)
    ap.add_argument("--version", default="0.2.2")
    ap.add_argument("--skip-native", action="store_true", help="Static signing only for a foreign CPU architecture.")
    ap.add_argument("--without-timestamp", action="store_true", help="Development-device validation only when Apple's timestamp service is unavailable.")
    ap.add_argument("--password-env", default="ENDPOINTAI_P12_PASSWORD")
    ap.add_argument("--use-filename-password-hint", action="store_true")
    args = ap.parse_args()
    if not args.binary.is_file():
        ap.error("Input binary does not exist.")
    if args.output.exists():
        ap.error("Output must be a new directory; existing artifacts are preserved.")
    profile = plistlib.loads(execute(["/usr/bin/security", "cms", "-D", "-i", args.profile]))
    if profile.get("Platform") != ["OSX"]:
        ap.error("Expected an OSX development profile.")
    hardware = plistlib.loads(execute(["/usr/sbin/system_profiler", "SPHardwareDataType", "-xml"]))[0]["_items"][0]
    machine_id = hardware.get("provisioning_UDID") or hardware.get("provisioning_udid")
    if not machine_id or machine_id not in profile.get("ProvisionedDevices", []):
        ap.error("This Mac is not authorized by the provisioning profile.")
    entitlements = profile.get("Entitlements", {})
    app_id = entitlements.get("com.apple.application-identifier", "")
    bundle_id = "com.sf.endpointai.proxy"
    if not app_id.endswith("." + bundle_id):
        ap.error("Profile application identity does not match the client.")
    password = os.environ.get(args.password_env)
    if password is None and args.use_filename_password_hint:
        parts = args.certificate.stem.split("_")
        if len(parts) >= 3:
            password = parts[-2]
    if password is None:
        import getpass
        password = getpass.getpass("Certificate password: ")
    private_env = os.environ.copy()
    private_env["ENDPOINTAI_SIGN_INPUT_PASSWORD"] = password
    pem = execute(["/usr/bin/openssl", "pkcs12", "-in", args.certificate, "-nokeys", "-passin", "env:ENDPOINTAI_SIGN_INPUT_PASSWORD"], env=private_env).decode()
    allowed = {hashlib.sha256(c).digest() for c in profile.get("DeveloperCertificates", [])}
    matched = [ssl.PEM_cert_to_DER_cert(c) for c in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S) if hashlib.sha256(ssl.PEM_cert_to_DER_cert(c)).digest() in allowed]
    if len(matched) != 1:
        ap.error("Expected one signing certificate authorized by the profile.")
    certificate_expiry = execute(["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-enddate"], input=matched[0]).decode().strip().removeprefix("notAfter=")
    identity = hashlib.sha1(matched[0]).hexdigest().upper()
    original_search = shlex.split(execute(["/usr/bin/security", "list-keychains", "-d", "user"]).decode())
    args.output.mkdir(parents=True, mode=0o700)
    app = args.output / "EndpointAIProxy.app"
    contents = app / "Contents"
    executable = contents / "MacOS" / "Sf.EndpointAI.Client.Service"
    executable.parent.mkdir(parents=True)
    shutil.copy2(args.binary, executable)
    executable.chmod(0o755)
    shutil.copy2(args.profile, contents / "embedded.provisionprofile")
    info = {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": executable.name, "CFBundleName": "EndpointAIProxy", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": args.version, "CFBundleVersion": args.version, "LSBackgroundOnly": True, "LSMinimumSystemVersion": "14.0"}
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    with tempfile.TemporaryDirectory(prefix="endpointai-sign-") as temporary:
        temp = Path(temporary)
        keychain = temp / "development.keychain-db"
        keychain_password = secrets.token_urlsafe(32)
        created = False
        try:
            execute(["/usr/bin/security", "create-keychain", "-p", keychain_password, keychain])
            created = True
            execute(["/usr/bin/security", "unlock-keychain", "-p", keychain_password, keychain])
            execute(["/usr/bin/security", "list-keychains", "-d", "user", "-s", keychain, *original_search])
            # Import Apple's public intermediate into this keychain only; do not
            # add a trust override or change the user's/System trust settings.
            intermediate = temp / "AppleWWDRCAG3.cer"
            if args.intermediate:
                shutil.copy2(args.intermediate, intermediate)
            else:
                execute(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "30", "--output", intermediate, "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer"])
            execute(["/usr/bin/security", "verify-cert", "-p", "basic", "-c", intermediate])
            execute(["/usr/bin/security", "import", intermediate, "-k", keychain])
            execute(["/usr/bin/security", "import", args.certificate, "-k", keychain, "-P", password, "-T", "/usr/bin/codesign"])
            execute(["/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", keychain_password, keychain])
            leaf_path = temp / "signing-certificate.der"
            leaf_path.write_bytes(matched[0])
            execute(["/usr/bin/security", "verify-cert", "-p", "codeSign", "-c", leaf_path])
            available = execute(["/usr/bin/security", "find-identity", "-p", "codesigning", keychain]).decode()
            if identity not in available:
                raise RuntimeError("Imported certificate is not an available signing identity.")
            entitlement_path = temp / "entitlements.plist"
            entitlement_path.write_bytes(plistlib.dumps(entitlements))
            timestamp = "--timestamp=none" if args.without_timestamp else "--timestamp"
            execute(["/usr/bin/codesign", "--force", timestamp, "--options", "runtime", "--keychain", keychain, "--entitlements", entitlement_path, "--sign", identity, app])
            execute(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app])
        finally:
            if created:
                subprocess.run(["/usr/bin/security", "delete-keychain", str(keychain)], capture_output=True)
            execute(["/usr/bin/security", "list-keychains", "-d", "user", "-s", *original_search])
    version_output = args.version if args.skip_native else execute([executable, "--version"]).decode().strip()
    if version_output != args.version:
        raise RuntimeError("Signed native executable reported an unexpected version.")
    report = {"kind": "device-development-signing", "version": version_output, "profile_name": profile.get("Name"), "profile_expires_utc": str(profile.get("ExpirationDate")), "authorized_device_count": len(profile.get("ProvisionedDevices", [])), "this_device_authorized": True, "certificate_matches_profile": True, "native_version_execution": "not performed" if args.skip_native else "passed", "temporary_keychain_removed": True, "trusted_timestamp_requested": not args.without_timestamp, "production_distribution": "not validated; Developer ID/Installer signing and notarization remain separate"}
    report["certificate_expires_utc"] = certificate_expiry
    (args.output / "signing-result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "development-static-signature-verified" if args.skip_native else "development-native-start-verified", "report": str(args.output / "signing-result.json")}, ensure_ascii=False))

if __name__ == "__main__":
    main()
