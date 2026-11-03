"""Local administrator identities; account changes revoke existing sessions."""
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time

from flask import Blueprint, g, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from .http import bearer, cfg, response

auth_bp = Blueprint("local_auth", __name__)
_dummy_hash = generate_password_hash("invalid-account-password")
_attempts = {}
_attempt_lock = threading.Lock()


def load_accounts(path):
    if not path:
        raise ValueError("Local administrator account file is required")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise ValueError("Invalid local administrator account file")
            if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise ValueError("Local administrator account file must be owner-only")
            data = json.load(handle)
        if not isinstance(data, list) or not data:
            raise ValueError("Local administrator accounts must be a nonempty list")
        accounts = {}
        for item in data:
            name, role, password_hash = item["username"], item["role"], item["passwordHash"]
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", name)
                    or name in accounts or role not in ("viewer", "operator", "admin")
                    or not isinstance(password_hash, str) or not password_hash.startswith("scrypt:")
                    or not isinstance(item.get("disabled", False), bool)):
                raise ValueError("Invalid local administrator account")
            accounts[name] = item
        if not any(a["role"] == "admin" and not a.get("disabled", False) for a in accounts.values()):
            raise ValueError("At least one enabled local administrator is required")
        return accounts
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise ValueError("Cannot read valid owner-only local administrator accounts") from None


def serializer():
    return URLSafeTimedSerializer(cfg().ADMIN_SESSION_KEY, salt="endpointai-local-admin-v1")


def fingerprint(account):
    value = json.dumps([account["passwordHash"], account["role"]], ensure_ascii=True, separators=(',', ':'))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@auth_bp.get("/auth/mode")
def mode():
    result = response({"mode": cfg().ADMIN_AUTH_MODE})
    result.headers["Cache-Control"] = "no-store"
    return result


@auth_bp.post("/auth/login")
def login():
    if cfg().ADMIN_AUTH_MODE != "local":
        return response(status=404)
    if not request.is_secure:
        return response(status=403)
    if request.content_length is None or request.content_length > 4096:
        return response(status=400)
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        return response(status=400)
    username, password = value.get("username"), value.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 512:
        return response(status=400)
    now = time.monotonic()
    # Per-worker defense in depth; ingress must also limit login attempts.
    address = request.remote_addr or "unknown"
    address_key, account_key = ("address", address), ("account", address, username)
    with _attempt_lock:
        for k in list(_attempts):
            if now - _attempts[k][0] > 300:
                del _attempts[k]
        if len(_attempts) + sum(k not in _attempts for k in (address_key, account_key)) > 10000:
            return response(status=429)
        address_started, address_count = _attempts.get(address_key, (now, 0))
        account_started, account_count = _attempts.get(account_key, (now, 0))
        if address_count >= 100 or account_count >= 10:
            return response(status=429)
        _attempts[address_key] = (address_started, address_count + 1)
        _attempts[account_key] = (account_started, account_count + 1)
    try:
        account = load_accounts(cfg().ADMIN_ACCOUNTS_PATH).get(username)
    except ValueError:
        return response(status=503)
    try:
        valid = check_password_hash(account["passwordHash"] if account else _dummy_hash, password)
    except (ValueError, TypeError):
        valid = False
    if not valid or not account or account.get("disabled", False):
        return response(status=401)
    with _attempt_lock:
        _attempts.pop(account_key, None)
    token = serializer().dumps({"username": username, "fingerprint": fingerprint(account)})
    result = response({"token": token, "username": username, "role": account["role"]})
    result.headers["Cache-Control"] = "no-store"
    return result


def authorize():
    if not request.is_secure:
        return response(status=403)
    try:
        session = serializer().loads(bearer() or "", max_age=8 * 60 * 60)
        account = load_accounts(cfg().ADMIN_ACCOUNTS_PATH).get(session["username"])
        if not account or account.get("disabled", False) or not hmac.compare_digest(
                fingerprint(account), session["fingerprint"]):
            return response(status=401)
    except (BadSignature, SignatureExpired, ValueError, KeyError, TypeError):
        return response(status=401)
    g.admin_actor = account["username"]
    if request.method in ("GET", "HEAD", "OPTIONS") or account["role"] == "admin":
        return None
    if account["role"] == "operator" and request.method == "POST" and request.endpoint in (
            "admin.create_command", "admin.cancel", "admin.resolve_unknown",
            "admin.create_rollout", "admin.change_rollout"):
        return None
    return response(status=403)
