"""Validate Go candidate credentials without disclosing private values."""
import base64
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

def valid_origin(origin):
    u = urlsplit(origin)
    if u.scheme != "http" or not u.hostname or u.username is not None or u.password is not None or u.path not in ("", "/") or u.query or u.fragment or "?" in origin or "#" in origin or re.search(r"\s", origin) or u.netloc.endswith(":"):
        return False
    if u.port is not None and not 1 <= u.port <= 65535:
        return False
    try:
        ipaddress.ip_address(u.hostname)
    except ValueError:
        if len(u.hostname) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in u.hostname.split(".")):
            return False
    return True

def validate(path):
    data = json.loads(Path(path).read_text())
    if set(data) != {"origin", "keyId", "transportKey", "clientToken", "policyHmacKey"} or not valid_origin(data["origin"]):
        raise ValueError("Invalid fields or origin")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", data["keyId"]) or not re.fullmatch(r"[A-Za-z0-9_-]{16,}", data["clientToken"]):
        raise ValueError("Invalid identifier")
    if len(base64.b64decode(data["transportKey"], validate=True)) != 32 or len(base64.b64decode(data["policyHmacKey"], validate=True)) < 32:
        raise ValueError("Invalid key")

if __name__ == "__main__":
    try:
        validate(sys.argv[1])
    except Exception:
        sys.exit("Client credential validation failed; values withheld.")
    print("Client credentials validated; values withheld.")
