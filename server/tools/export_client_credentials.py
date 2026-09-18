"""Export only endpoint credentials from a private server env file. Never prints secrets."""
import argparse
import base64
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-env", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = {}
    for line in Path(args.server_env).read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            source[key] = value
    value = dict(origin="http://10.220.22.112:8080", keyId=source["SF_CONTROL_TRANSPORT_KEY_ID"],
                 transportKey=source["SF_CONTROL_TRANSPORT_KEY"], clientToken=source["SF_CONTROL_CLIENT_TOKEN"],
                 policyHmacKey=source["SF_CONTROL_POLICY_HMAC_KEY"])
    if len(base64.b64decode(value["transportKey"], validate=True)) != 32:
        raise ValueError("Invalid AES key")
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write("\n")
    print(f"Client credentials created at {target}; no administrator token included.")


if __name__ == "__main__":
    main()
