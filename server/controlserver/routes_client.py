from flask import Blueprint, request
from .http import cfg, store, response, parse, token_required, require_https, authenticate_device, bearer
from .models import (DeviceEnrollmentRequest, HeartbeatRequest, HeartbeatV2Request,
                     EventBatchRequest, RemoteCommandStatusUpdate, CredentialRotationPrepare, CredentialRotationCommit)
from .security import dumps, sign_policy, sign_command, sign_ed25519, timestamp, utcnow, hash_token
from .device_transport import device_v2_key_id, device_v2_master
from .transport import b64
from .validation import ApiProblem, validate_heartbeat

client_bp = Blueprint("client", __name__)


def policy_response(device=None):
    schema = request.args.get("policySchemaVersion", "1")
    stateless = request.args.get("statelessPolicyVersions") == "1"
    signature_mode = request.args.get("policySignature", "hmac-v1")
    if signature_mode not in ("hmac-v1", "ed25519-v1") or (device is None and signature_mode != "hmac-v1"):
        raise ApiProblem("POLICY_SIGNATURE_UNSUPPORTED", "Unsupported policy signature mode.")
    if signature_mode == "ed25519-v1" and cfg().POLICY_SIGNING_KEY is None:
        raise ApiProblem("POLICY_SIGNATURE_UNAVAILABLE", "Requested policy signing mode is unavailable.", 503)
    if schema not in ("1", "2") or (device is None and schema != "1"):
        raise ApiProblem("POLICY_SCHEMA_UNSUPPORTED", "Supported policy schemas are 1 and 2.")
    if stateless and (device is None or schema != "2"):
        raise ApiProblem("POLICY_SCHEMA_UNSUPPORTED", "Stateless policy versions require schema 2.")
    policy = store().policy(device, schema_version=int(schema), stateless=stateless) if device is not None else store().policy()
    policy = dict(policy, schemaVersion=int(schema))
    policy.pop("allowlistMigration", None)
    if schema == "1":
        policy.pop("allowlistedDomains", None)
        policy.pop("routingRules", None)
    body = dumps(policy)
    result = response()
    result.set_data(body.encode("utf-8"))
    result.headers["X-SF-Policy-Version"] = str(policy["policyVersion"])
    result.headers["X-SF-Policy-Signature"] = (sign_ed25519(body, cfg().POLICY_SIGNING_KEY, "policy")
        if signature_mode == "ed25519-v1" else sign_policy(body, cfg().POLICY_HMAC_KEY))
    result.headers["Cache-Control"] = "no-store"
    return result


@client_bp.get("/api/v1/policy")
@token_required("client")
def v1_policy():
    return policy_response()


@client_bp.post("/api/v1/heartbeat")
@token_required("client")
def v1_heartbeat():
    h = parse(HeartbeatRequest, "HEARTBEAT_INVALID")
    validate_heartbeat(h, 1)
    policy = store().policy()
    store().heartbeat(h, policy["heartbeatIntervalSeconds"], request.remote_addr)
    return response(dict(serverTimeUtc=timestamp(utcnow()),acceptedPolicyVersion=policy["policyVersion"],
                         nextHeartbeatSeconds=policy["heartbeatIntervalSeconds"]))


def events(version):
    if version == 2:
        require_https()
    batch = parse(EventBatchRequest, "EVENT_BATCH_INVALID")
    if batch.schemaVersion != 1 or not batch.deviceId.int or len(batch.events) > 100:
        raise ApiProblem("EVENT_BATCH_INVALID", "The event batch exceeds the prototype contract limits.")
    if version == 2:
        authenticate_device(batch.deviceId)
    return response(store().events(batch), 202)


@client_bp.post("/api/v1/events/batch")
@token_required("client")
def v1_events():
    return events(1)


@client_bp.post("/api/v2/enroll")
@token_required("client")
def enroll():
    require_https()
    enrollment = parse(DeviceEnrollmentRequest, "DEVICE_ENROLLMENT_INVALID")
    if (enrollment.schemaVersion != 2 or not enrollment.deviceId.int or not enrollment.hostname.strip()
            or len(enrollment.hostname) > 255 or not enrollment.serviceVersion.strip()
            or len(enrollment.serviceVersion) > 64):
        raise ApiProblem("DEVICE_ENROLLMENT_INVALID", "The enrollment request is invalid.")
    return response(store().enroll(enrollment))


@client_bp.get("/api/v2/devices/<uuid:device_id>/policy")
def v2_policy(device_id):
    require_https()
    authenticate_device(device_id)
    return policy_response(device_id)


@client_bp.post("/api/v2/heartbeat")
@client_bp.post("/api/v2/heartbeat/light")
@client_bp.post("/api/v2/heartbeat/light-compact")
def v2_heartbeat():
    require_https()
    heartbeat = parse(HeartbeatV2Request, "HEARTBEAT_V2_INVALID")
    compact = request.path.endswith("/light-compact")
    light = compact or request.path.endswith("/light")
    if (heartbeat.inventoryUnchanged != light or heartbeat.compactInventory != compact
            or (compact and (heartbeat.users or heartbeat.agents or heartbeat.endpoints))):
        raise ApiProblem("HEARTBEAT_V2_INVALID", "Invalid heartbeat inventory mode.")
    validate_heartbeat(heartbeat, 2)
    authenticate_device(heartbeat.device.deviceId)
    if heartbeat.ed25519Signatures and cfg().POLICY_SIGNING_KEY is None:
        raise ApiProblem("POLICY_SIGNATURE_UNAVAILABLE", "Requested command signing mode is unavailable.", 503)
    policy = store().policy(heartbeat.device.deviceId, stateless=heartbeat.statelessPolicyVersions)
    if compact:
        store().heartbeat(heartbeat, policy["heartbeatIntervalSeconds"], request.remote_addr, compact_inventory=True)
    else:
        store().heartbeat(heartbeat, policy["heartbeatIntervalSeconds"], request.remote_addr)
    command = store().lease(heartbeat.device.deviceId)
    signed = None
    if command:
        payload = dict(schemaVersion=1, commandId=command["commandId"], deviceId=command["deviceId"],
                       type=command["type"], issuedAtUtc=command["createdAtUtc"], expiresAtUtc=command["expiresAtUtc"])
        signature = (sign_ed25519(dumps(payload), cfg().POLICY_SIGNING_KEY, "command")
                     if heartbeat.ed25519Signatures else sign_command(payload, cfg().POLICY_HMAC_KEY))
        signed = dict(payload=payload, signature=signature)
    capabilities = {}
    if request.environ.get("endpointai.transport_tls"):
        if cfg().DEVICE_TRANSPORT:
            capabilities["deviceTransport"] = True
        if cfg().DEVICE_TRANSPORT_V2 and heartbeat.deviceTransportV2:
            device = str(heartbeat.device.deviceId)
            generation = cfg().DEVICE_KEY_ID
            key = device_v2_master(cfg().DEVICE_TRANSPORT_V2_KEYS[generation], hash_token(bearer()), device)
            capabilities["deviceTransportV2"] = {"keyId": device_v2_key_id(device, generation), "key": b64(key)}
            if cfg().CREDENTIAL_ROTATION and heartbeat.credentialRotationV1:
                from .credential_rotation import MIN_AGE
                capabilities['credentialRotationV1'] = {'minAgeSeconds': int(MIN_AGE.total_seconds())}
    return response(dict(serverTimeUtc=timestamp(utcnow()),acceptedPolicyVersion=policy["policyVersion"],
                         nextHeartbeatSeconds=policy["heartbeatIntervalSeconds"],command=signed,
                         statelessPolicyVersions=True, lightweightInventory=True, compactInventory=True, **capabilities))


def _renewal_request(device_id, model):
    if (not request.environ.get('endpointai.transport_device_v2')
            or request.environ.get('endpointai.transport_device') != str(device_id)):
        raise ApiProblem('CREDENTIAL_ROTATION_TRANSPORT_REQUIRED', 'Renewal requires device transport V2 over HTTPS.', 403)
    authenticate_device(device_id)
    value = parse(model, 'CREDENTIAL_ROTATION_INVALID')
    if not value.rotationId.int:
        raise ApiProblem('CREDENTIAL_ROTATION_INVALID', 'Invalid renewal identity.')
    return value


def _renewal_response(value, token):
    generation = cfg().DEVICE_KEY_ID
    key = device_v2_master(cfg().DEVICE_TRANSPORT_V2_KEYS[generation], hash_token(token), value['deviceId'])
    result = response(dict(value, serverTimeUtc=timestamp(utcnow()),
                           deviceTransportV2={'keyId': device_v2_key_id(value['deviceId'], generation), 'key': b64(key)}))
    result.headers['Cache-Control'] = 'no-store'
    return result


@client_bp.post('/api/v2/devices/<uuid:device_id>/credential/prepare')
def prepare_credential(device_id):
    value = _renewal_request(device_id, CredentialRotationPrepare)
    from .credential_rotation import prepare
    state = prepare(store(), device_id, value.rotationId, bearer(), value.nextDeviceToken)
    return _renewal_response(state, value.nextDeviceToken)


@client_bp.post('/api/v2/devices/<uuid:device_id>/credential/commit')
def commit_credential(device_id):
    value = _renewal_request(device_id, CredentialRotationCommit)
    from .credential_rotation import commit
    state = commit(store(), device_id, value.rotationId, bearer())
    return _renewal_response(state, bearer())


@client_bp.post("/api/v2/events/batch")
def v2_events():
    return events(2)


@client_bp.post("/api/v2/commands/<uuid:command_id>/status")
def command_status(command_id):
    require_https()
    update = parse(RemoteCommandStatusUpdate, "COMMAND_STATUS_INVALID")
    if (update.schemaVersion != 1 or update.commandId != command_id or not update.deviceId.int
            or update.status.value not in ("executing", "succeeded", "failed")
            or (update.resultCode is not None and len(update.resultCode) > 128)
            or (update.resultSummary is not None and len(update.resultSummary) > 512)):
        raise ApiProblem("COMMAND_STATUS_INVALID", "The command status update is invalid.")
    authenticate_device(update.deviceId)
    if not store().update_command(update):
        raise ApiProblem("COMMAND_STATUS_CONFLICT", "The command is missing, belongs to another device, or conflicts with its stored result.", 409)
    return response(status=202)
