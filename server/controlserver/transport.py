"""Versioned authenticated envelope. Business bytes and signatures are never reserialized."""
import base64
import json
import os
import re
import time
import uuid
from flask import request, g
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .http import response

MAX_PLAIN = 30_000_000
MAX_WIRE = 56_000_000
INTERNAL = object()


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def direction_key(master, direction):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sf-endpointai-transport-v1",
                info=direction.encode("ascii")).derive(master)


def aad(envelope, direction):
    return (f"sf-endpointai-transport-v1\n{direction}\n{envelope['keyId']}\n"
            f"{envelope['requestId']}\n{envelope['timestamp']}\n{envelope['nonce']}").encode("ascii")


def seal(master, key_id, request_id, value, direction):
    envelope = dict(version=1, keyId=key_id, requestId=request_id,
                    timestamp=int(time.time()), nonce=b64(os.urandom(12)))
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher = AESGCM(direction_key(master, direction)).encrypt(unb64(envelope["nonce"]), data, aad(envelope, direction))
    envelope.update(ciphertext=b64(cipher[:-16]), tag=b64(cipher[-16:]))
    return envelope


def open_envelope(master, key_id, envelope, direction, expected_id=None):
    if not isinstance(envelope, dict) or set(envelope) != {"version", "keyId", "requestId", "timestamp", "nonce", "ciphertext", "tag"}:
        raise ValueError("Invalid envelope")
    if type(envelope["version"]) is not int or envelope["version"] != 1 or envelope["keyId"] != key_id:
        raise ValueError("Invalid envelope")
    rid = envelope["requestId"]
    if not isinstance(rid, str) or str(uuid.UUID(rid)) != rid or (expected_id is not None and rid != expected_id):
        raise ValueError("Invalid request ID")
    if type(envelope["timestamp"]) is not int or abs(time.time() - envelope["timestamp"]) > 300:
        raise ValueError("Expired envelope")
    nonce, tag = unb64(envelope["nonce"]), unb64(envelope["tag"])
    if len(nonce) != 12 or len(tag) != 16 or b64(nonce) != envelope["nonce"]:
        raise ValueError("Invalid nonce/tag")
    cipher = unb64(envelope["ciphertext"])
    if len(cipher) > 41_000_000:
        raise ValueError("Oversize envelope")
    plain = AESGCM(direction_key(master, direction)).decrypt(nonce, cipher + tag, aad(envelope, direction))
    return json.loads(plain)


def install_transport(app):
    app.config["MAX_CONTENT_LENGTH"] = MAX_WIRE

    @app.before_request
    def encrypted_only():
        if request.path.startswith(("/api/v1/", "/api/v2/")) and request.environ.get("endpointai.transport") is not INTERNAL:
            return response({"error": "ENCRYPTED_TRANSPORT_REQUIRED"}, 403)
        if request.path != "/api/transport/v1" and request.content_length and request.content_length > MAX_PLAIN:
            return response({"error": "REQUEST_TOO_LARGE"}, 413)

    @app.post("/api/transport/v1")
    def transport():
        cfg = app.extensions["control_config"]
        try:
            envelope = request.get_json()
            inner = open_envelope(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, envelope, "request")
            if not isinstance(inner, dict) or set(inner) != {"method", "path", "query", "token", "body"}:
                raise ValueError("Invalid inner request")
            method, path, query, token = (inner[k] for k in ("method", "path", "query", "token"))
            if method not in ("GET", "POST") or not isinstance(path, str) or not re.fullmatch(r"/api/v[12]/[A-Za-z0-9/_-]+", path):
                raise ValueError("Invalid route")
            if not isinstance(query, str) or len(query) > 8192 or any(c in query for c in "\r\n#"):
                raise ValueError("Invalid query")
            if not isinstance(token, str) or len(token) > 4096 or any(c.isspace() for c in token):
                raise ValueError("Invalid token")
            body = unb64(inner["body"])
            if len(body) > MAX_PLAIN:
                raise ValueError("Oversize body")
        except Exception:
            return response({"error": "INVALID_TRANSPORT"}, 400)
        # Claim after authentication, before dispatch, in its own committed transaction.
        if not app.extensions["control_store"].claim_transport(envelope):
            return response({"error": "INVALID_TRANSPORT"}, 400)
        peer = request.remote_addr
        with app.test_request_context(path, method=method, query_string=query, data=body,
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                environ_overrides={"REMOTE_ADDR": peer, "endpointai.transport": INTERNAL}):
            try:
                result = app.full_dispatch_request()
            except Exception as exc:
                result = app.handle_exception(exc)
            value = dict(status=result.status_code, body=b64(result.get_data()),
                         headers={k: v for k, v in result.headers.items() if k.lower() in
                                  ("x-sf-policy-signature", "content-type", "x-request-id")})
        return response(seal(cfg.TRANSPORT_KEY, cfg.TRANSPORT_KEY_ID, envelope["requestId"], value, "response"))
