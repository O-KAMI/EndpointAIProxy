"""Validate Go candidate credentials without disclosing private values."""
import base64
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

def valid_origin(origin):
    if not origin.startswith(("http://", "https://")):
        return False
    u = urlsplit(origin)
    if u.scheme not in ("http", "https") or not u.hostname or u.username is not None or u.password is not None or u.path not in ("", "/") or u.query or u.fragment or "?" in origin or "#" in origin or re.search(r"\s", origin) or u.netloc.endswith(":"):
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
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    fields = set(data)
    common = {"origin", "keyId", "transportKey", "clientToken"}
    if isinstance(data.get("origin"), str) and data["origin"].startswith("https://"):
        common.add("certificateSpkiSha256")
    if fields not in (common | {"policyHmacKey"}, common | {"policyPublicKey"}) or not valid_origin(data["origin"]):
        raise ValueError("Invalid fields or origin")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", data["keyId"]) or not re.fullmatch(r"[A-Za-z0-9_-]{16,}", data["clientToken"]):
        raise ValueError("Invalid identifier")
    policy = base64.b64decode(data.get("policyPublicKey", data.get("policyHmacKey", "")), validate=True)
    if "certificateSpkiSha256" in common and len(base64.b64decode(data["certificateSpkiSha256"], validate=True)) != 32:
        raise ValueError("Invalid certificate pin")
    if len(base64.b64decode(data["transportKey"], validate=True)) != 32 or (len(policy) != 32 if "policyPublicKey" in data else len(policy) < 32):
        raise ValueError("Invalid key")

if __name__ == "__main__":
    try:
        validate(sys.argv[1])
    except Exception:
        sys.exit("Client credential validation failed; values withheld.")
    print("Client credentials validated; values withheld.")
