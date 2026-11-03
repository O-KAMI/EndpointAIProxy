"""Package a validated Windows candidate and its exact acceptance helpers privately."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def build(directory, output):
    directory, output = Path(directory).resolve(strict=True), Path(output).absolute()
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest["signature"] != "unsigned" or manifest["installed"] or manifest["nativeLifecycleAcceptance"] != "pending":
        raise RuntimeError("Only a pending unsigned candidate may be packaged")
    inputs = {entry["name"]: entry["sha256"] for entry in manifest["deliveryFiles"]}
    inputs[manifest["msi"]["name"]] = manifest["msi"]["sha256"]
    helpers = {entry["name"]: entry["sha256"] for entry in manifest["payload"]}
    inputs["MigrationHelper.exe"] = helpers["Sf.EndpointAI.InstallerActions.exe"]
    for name in ("manifest.json", "source-inputs.json", "build-report.json", "msi-validation.json",
                 manifest["msi"]["name"] + ".sha256", "MigrationHelper.exe.sha256", "Collect-InstallerLogs.ps1"):
        inputs.setdefault(name, None)
    if digest(directory / "source-inputs.json") != manifest["sourceInputsSha256"]:
        raise RuntimeError("Source input manifest changed")
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise RuntimeError("Invalid delivery path")
        path = directory.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file() or (expected and digest(path) != expected):
            raise RuntimeError("Missing or altered delivery input: " + name)
    handoff = ROOT / ("docs/WINDOWS-GO-" + manifest["productVersion"].replace(".", "") + "-HANDOFF.md")
    additions = [ROOT / "scripts/Observe-WindowsSoak.ps1", ROOT / "scripts/SoakObservation-Support.ps1"]
    supplemental = ROOT / ("docs/CLIENT-" + manifest["productVersion"].replace(".", "") + "-ADDITIONAL-ACCEPTANCE.md")
    if not supplemental.exists():
        supplemental = None
    if any(path.is_symlink() or not path.is_file() for path in additions + ([supplemental] if supplemental else [])):
        raise RuntimeError("Windows soak observer missing or linked")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as target:
        try:
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(inputs):
                    archive.write(directory.joinpath(*PurePosixPath(name).parts), name)
                archive.write(handoff, handoff.name)
                for path in additions:
                    archive.write(path, "scripts/" + path.name)
                hashes = {"scripts/" + path.name: digest(path) for path in additions}
                if supplemental:
                    archive.write(supplemental, supplemental.name)
                    hashes[supplemental.name] = digest(supplemental)
                archive.writestr("handoff-additions.json", json.dumps(hashes, indent=2) + "\n")
        except BaseException:
            target.close()
            output.unlink(missing_ok=True)
            raise
    return digest(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print("Protected handoff SHA-256: " + build(args.candidate_dir, args.output))


if __name__ == "__main__":
    main()
