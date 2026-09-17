"""Validate private PKG build input; never output values or raw exceptions."""
import base64
import json
from pathlib import Path
import re
import sys


def validate(path):
    data = json.loads(Path(path).read_text())
    if set(data) != {"origin", "keyId", "transportKey", "clientToken", "policyHmacKey"}:
        raise ValueError("Unexpected fields")
    if data["origin"] != "http://control.example.invalid:8080":
        raise ValueError("Unexpected origin")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", data["keyId"]):
        raise ValueError("Invalid key ID")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,}", data["clientToken"]):
        raise ValueError("Invalid token")
    if len(base64.b64decode(data["transportKey"], validate=True)) != 32:
        raise ValueError("Invalid AES key")
    if len(base64.b64decode(data["policyHmacKey"], validate=True)) < 32:
        raise ValueError("Invalid HMAC key")


if __name__ == "__main__":
    try:
        validate(sys.argv[1])
    except Exception:
        sys.exit("Client credential validation failed; values withheld.")
    print("Client credentials validated; values withheld.")
