"""Build a new, credential-free appdeploy delivery without replacing older releases."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

from package_release import ROOT, RELEASE_VERSION, build_release, offline_wheels


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def package_delivery(destination):
    wheels = offline_wheels()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    name = "EndpointAIDLP-Server-" + RELEASE_VERSION
    folder = destination / (name + "-delivery")
    folder.mkdir()
    count, payload_hash = build_release(folder / (name + "-update.zip"), update=True)
    for filename in ("update-server-" + RELEASE_VERSION + ".py",
                     "README-SERVER-UPGRADE-" + RELEASE_VERSION + ".md", "test_update_024.py"):
        source = ROOT.parent / "deployment" / filename
        if source.is_symlink():
            raise RuntimeError("Linked deployment input")
        shutil.copyfile(source, folder / filename)
    shutil.copyfile(ROOT / "docs" / ("ACCEPTANCE-" + RELEASE_VERSION + ".md"),
                    folder / ("ACCEPTANCE-" + RELEASE_VERSION + ".md"))
    manifest = dict(version=RELEASE_VERSION, schemaVersion=2, pythonVersion="3.13.15",
        builtAtUtc=datetime.now(timezone.utc).isoformat(), payloadSha256=payload_hash,
        sourceAndDependencyFiles=count, databaseMigration=False, realCredentialsIncluded=False,
        supportedPriorVersions=["0.1.23", "0.1.22", "0.1.21"],
        offlineDependencies=[dict(path=str(path.relative_to(ROOT)), sha256=digest(path)) for path in wheels])
    (folder / "BUILD-MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    entries = sorted(folder.iterdir())
    sums = folder / ("SHA256SUMS-SERVER-" + RELEASE_VERSION + ".txt")
    sums.write_text("".join(f"{digest(path)}  {path.name}\n" for path in entries))
    archive = destination / (name + "-delivery.zip")
    with archive.open("xb") as target, zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(folder.iterdir()):
            output.write(path, str(Path(folder.name) / path.name))
    archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n")
    return archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, help="A new directory; existing output is never overwritten")
    args = parser.parse_args()
    archive = package_delivery(args.output_dir)
    print("Delivery: " + str(archive))
    print("SHA256: " + digest(archive))


if __name__ == "__main__":
    main()
