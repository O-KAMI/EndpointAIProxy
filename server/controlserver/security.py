"""Serialization shared by persistence and HMAC signing."""
import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID
from pydantic import BaseModel


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    fraction = f"{value.microsecond:06d}".rstrip("0")
    return value.strftime("%Y-%m-%dT%H:%M:%S") + ("." + fraction if fraction else "") + "+00:00"


def wire(value):
    if isinstance(value, BaseModel):
        return wire(value.model_dump())
    if isinstance(value, datetime):
        return timestamp(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [wire(item) for item in value]
    return value


def dumps(value):
    return json.dumps(wire(value), ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def safe_compare(actual, expected):
    return hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest().upper()


def generate_device_token():
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def sign_policy(body, key):
    body = body.encode("utf-8") if isinstance(body, str) else body
    signature = hmac.new(key, body, hashlib.sha256).digest()
    return "v1:" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def sign_command(payload, key):
    derived = hmac.new(key, b"sf-endpoint-ai-command-v1", hashlib.sha256).digest()
    return sign_policy(dumps(payload), derived)
