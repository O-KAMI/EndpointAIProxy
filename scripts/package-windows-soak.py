"""Package credential-free synthetic Windows soak tools without touching an MSI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(helper, output, version="0.2.12"):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid version")
    helper = Path(helper)
    inputs = {
        "soak.py": ROOT / "go-client/scripts/soak.py",
        "benchmark.py": ROOT / "go-client/scripts/benchmark.py",
        "soak-control.exe": helper,
    }
    tag = version.replace(".", "")
    for name in (f"WINDOWS-GO-{tag}-ACTIVE-SOAK.md", f"WINDOWS-GO-{tag}-HANDOFF.md",
                 f"CLIENT-{tag}-ADDITIONAL-ACCEPTANCE.md"):
        inputs[name] = ROOT / "docs" / name
    if any(path.is_symlink() or not path.is_file() for path in inputs.values()):
        raise ValueError("A required soak input is missing or linked")
    output = Path(output).absolute()
    with output.open("xb") as target:
        try:
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                hashes = {}
                for name, path in inputs.items():
                    data = path.read_bytes()
                    archive.writestr(name, data)
                    hashes[name] = hashlib.sha256(data).hexdigest()
                archive.writestr("manifest.json", json.dumps({"credentialsIncluded": False, "files": hashes}, indent=2) + "\n")
        except BaseException:
            target.close()
            output.unlink(missing_ok=True)
            raise
    return hashlib.sha256(output.read_bytes()).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-helper", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", default="0.2.12")
    args = parser.parse_args()
    print("Synthetic Windows soak archive SHA-256:", build(args.control_helper, args.output, args.version))
