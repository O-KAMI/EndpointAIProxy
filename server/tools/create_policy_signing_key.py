"""Generate a new Ed25519 signing seed and public key in a new private Linux directory."""
import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def create(directory):
    if os.name != "posix":
        raise RuntimeError("Use a private Linux account to generate a signing key")
    directory = Path(directory).absolute()
    if directory.resolve(strict=False) != directory:
        raise ValueError("The destination path must not contain symbolic links")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    if directory.stat().st_uid != os.geteuid() or directory.stat().st_mode & 0o077:
        raise RuntimeError("Signing key directory is not private")
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for name, contents in (("signing-seed.env", "SF_CONTROL_POLICY_ED25519_SEED=" + base64.b64encode(seed).decode() + "\n"),
                           ("policy-public-key.txt", base64.b64encode(public).decode() + "\n")):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(contents)
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, help="New private directory, with an existing parent")
    args = parser.parse_args()
    path = create(args.directory)
    print("Key files created in " + str(path) + "; private key values withheld.")


if __name__ == "__main__":
    main()
