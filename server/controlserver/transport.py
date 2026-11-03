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
from cryptography.exceptions import InvalidTag
from .http import response
from .database import PoolExhausted
from .device_transport import device_for_key_id, device_master, device_v2_for_key_id, device_v2_master
from .security import hash_token, safe_compare

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
        started = time.perf_counter()
        g.control_stage = "transport_validate"
        try:
            envelope = request.get_json()
            key_id = envelope.get("keyId") if isinstance(envelope, dict) else None
            v2_identity = device_v2_for_key_id(key_id) if cfg.DEVICE_TRANSPORT_V2 else None
            device_id = v2_identity[0] if v2_identity else (device_for_key_id(key_id) if cfg.DEVICE_TRANSPORT else None)
            if device_id is not None:
                if not request.is_secure:
                    raise ValueError("Device envelope requires HTTPS")
                secret = cfg.DEVICE_TRANSPORT_V2_KEYS.get(v2_identity[1]) if v2_identity else None
                if v2_identity and secret is None:
                    raise ValueError("Unknown device key generation")
                try:
                    storage = app.extensions["control_store"]
                    get_verifiers = getattr(storage, 'device_transport_verifiers', None)
                    verifiers = get_verifiers(device_id) if get_verifiers is not None else (storage.device_transport_verifier(device_id),)
                except Exception:
                    return response({"error": "CONTROL_BUSY"}, 503)
                if not verifiers or len(verifiers) > 2:
                    raise ValueError("Inactive device credential")
                for verifier in verifiers:
                    if verifier is None:
                        continue
                    master_key = device_v2_master(secret, verifier, device_id) if v2_identity else device_master(verifier, device_id)
                    try:
                        inner = open_envelope(master_key, key_id, envelope, "request")
                        break
                    except InvalidTag:
                        continue
                else:
                    raise ValueError("Invalid device envelope")
            elif isinstance(key_id, str) and key_id in cfg.TRANSPORT_KEYS:
                master_key = cfg.TRANSPORT_KEYS[key_id]
                inner = open_envelope(master_key, key_id, envelope, "request")
            else:
                raise ValueError("Invalid envelope key")
            # This ID is canonical and authenticated; never record unauthenticated envelope fields.
            g.control_envelope_id = envelope["requestId"]
            if not isinstance(inner, dict) or set(inner) != {"method", "path", "query", "token", "body"}:
                raise ValueError("Invalid inner request")
            method, path, query, token = (inner[k] for k in ("method", "path", "query", "token"))
            if method not in ("GET", "POST") or not isinstance(path, str) or not re.fullmatch(r"/api/v[12]/[A-Za-z0-9/_-]+", path):
                raise ValueError("Invalid route")
            if not isinstance(query, str) or len(query) > 8192 or any(c in query for c in "\r\n#"):
                raise ValueError("Invalid query")
            if not isinstance(token, str) or len(token) > 4096 or any(c.isspace() for c in token):
                raise ValueError("Invalid token")
            if device_id is not None:
                allowed = ((method == "GET" and path == f"/api/v2/devices/{device_id}/policy")
                    or (method == "POST" and (path in ("/api/v2/heartbeat", "/api/v2/heartbeat/light", "/api/v2/heartbeat/light-compact", "/api/v2/events/batch")
                        or path in (f"/api/v2/devices/{device_id}/credential/prepare", f"/api/v2/devices/{device_id}/credential/commit")
                        or re.fullmatch(r"/api/v2/commands/[0-9a-f-]{36}/status", path))))
                if not allowed or not safe_compare(hash_token(token), verifier):
                    raise ValueError("Device envelope identity mismatch")
            body = unb64(inner["body"])
            if len(body) > MAX_PLAIN:
                raise ValueError("Oversize body")
        except Exception:
            return response({"error": "INVALID_TRANSPORT"}, 400)
        # Claim after authentication, before dispatch, in its own committed transaction.
        g.control_stage = "transport_replay"
        try:
            claimed = app.extensions["control_store"].claim_transport(envelope)
        except PoolExhausted:
            # No business dispatch or replay claim occurred; authenticate the retry signal.
            g.control_stage = "transport_overloaded"
            g.business_status = 503
            g.control_error_code = "CONTROL_BUSY"
            value = dict(status=503, body=b64(b'{"error":"CONTROL_BUSY"}'),
                         headers={"Content-Type": "application/json", "Retry-After": "5"})
            result = response(seal(master_key, key_id, envelope["requestId"], value, "response"))
            result.headers["Cache-Control"] = "no-store"
            return result
        if not claimed:
            return response({"error": "INVALID_TRANSPORT"}, 400)
        peer, secure = request.remote_addr, request.is_secure
        with app.test_request_context(path, method=method, query_string=query, data=body,
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                environ_overrides={"REMOTE_ADDR": peer, "endpointai.transport": INTERNAL,
                                   "endpointai.control_envelope_id": envelope["requestId"],
                                   "endpointai.transport_device": device_id,
                                   "endpointai.transport_device_v2": v2_identity is not None,
                                   "endpointai.transport_tls": secure}):
            try:
                result = app.full_dispatch_request()
            except Exception as exc:
                result = app.handle_exception(exc)
            value = dict(status=result.status_code, body=b64(result.get_data()),
                         headers={k: v for k, v in result.headers.items() if k.lower() in
                                  ("x-sf-policy-signature", "content-type", "x-request-id", "retry-after")})
        # Flask nested request contexts share g: restore the outer timing/stage explicitly.
        # Preserve the existing outer trace/response-ID behavior while naming the business ID.
        g.control_envelope_id = envelope["requestId"]
        g.business_request_id = value["headers"].get("X-Request-ID", "")
        g.business_status = value["status"]
        g.control_stage = "transport_complete"
        g.request_started = started
        result = response(seal(master_key, key_id, envelope["requestId"], value, "response"))
        result.headers["Cache-Control"] = "no-store"
        return result
