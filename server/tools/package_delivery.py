"""Build a new, credential-free appdeploy delivery without replacing older releases."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

from package_release import ROOT, RELEASE_VERSION, build_release, offline_wheels, require_update_validated


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def package_delivery(destination, gray_candidate=False):
    require_update_validated(True) if gray_candidate else require_update_validated()
    wheels = offline_wheels()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    name = "EndpointAIDLP-Server-" + RELEASE_VERSION
    folder = destination / (name + "-delivery")
    folder.mkdir()
    count, payload_hash = build_release(folder / (name + "-update.zip"), update=True, gray_candidate=gray_candidate)
    deployment_files = ("update-server-" + RELEASE_VERSION + ".py",
                     "README-SERVER-UPGRADE-" + RELEASE_VERSION + ".md",
                     "update-server-0.1.25.py", "update-server-0.1.24.py", "upgrade-snapshot.py")
    if gray_candidate:
        deployment_files += ('gray_qualification.py', 'gray-upgrade-0.1.26.json')
    for filename in deployment_files:
        source = ROOT.parent / "deployment" / filename
        if source.is_symlink():
            raise RuntimeError("Linked deployment input")
        shutil.copyfile(source, folder / filename)
    if gray_candidate:
        qualification = json.loads((folder / 'gray-upgrade-0.1.26.json').read_text(encoding='utf-8'))
        evidence = ROOT.parent / qualification['evidence']
        if evidence.is_symlink() or not evidence.resolve().is_relative_to((ROOT / 'docs').resolve()):
            raise RuntimeError('Invalid gray evidence document')
        shutil.copyfile(evidence, folder / evidence.name)
        readme = folder / ('README-SERVER-UPGRADE-' + RELEASE_VERSION + '.md')
        text = readme.read_text(encoding='utf-8').replace('../' + qualification['evidence'], evidence.name)
        readme.write_text(text, encoding='utf-8')
    shutil.copyfile(ROOT / "docs" / ("ACCEPTANCE-" + RELEASE_VERSION + ".md"),
                    folder / ("ACCEPTANCE-" + RELEASE_VERSION + ".md"))
    manifest = dict(version=RELEASE_VERSION, schemaVersion=5, pythonVersion="3.13.15",
        builtAtUtc=datetime.now(timezone.utc).isoformat(), payloadSha256=payload_hash,
        sourceAndDependencyFiles=count, databaseMigration=True, realCredentialsIncluded=False,
        supportedPriorVersions=["0.1.25"],
        offlineDependencies=[dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path)) for path in wheels])
    if gray_candidate:
        manifest.update(releaseChannel='gray-candidate', fullRolloutAccepted=False,
                        qualificationSha256=digest(folder / 'gray-upgrade-0.1.26.json'))
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
    parser.add_argument('--gray-candidate', action='store_true')
    args = parser.parse_args()
    archive = package_delivery(args.output_dir, args.gray_candidate)
    print("Delivery: " + str(archive))
    print("SHA256: " + digest(archive))


if __name__ == "__main__":
    main()
