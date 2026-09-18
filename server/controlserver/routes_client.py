from flask import Blueprint, request
from .http import cfg, store, response, parse, token_required, require_https, authenticate_device
from .models import (DeviceEnrollmentRequest, HeartbeatRequest, HeartbeatV2Request,
                     EventBatchRequest, RemoteCommandStatusUpdate)
from .security import dumps, sign_policy, sign_command, timestamp, utcnow
from .validation import ApiProblem, validate_heartbeat

client_bp = Blueprint("client", __name__)


def policy_response():
    policy = store().policy()
    body = dumps(policy)
    result = response()
    result.set_data(body.encode("utf-8"))
    result.headers["X-SF-Policy-Version"] = str(policy["policyVersion"])
    result.headers["X-SF-Policy-Signature"] = sign_policy(body, cfg().POLICY_HMAC_KEY)
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
    return policy_response()


@client_bp.post("/api/v2/heartbeat")
def v2_heartbeat():
    require_https()
    heartbeat = parse(HeartbeatV2Request, "HEARTBEAT_V2_INVALID")
    validate_heartbeat(heartbeat, 2)
    authenticate_device(heartbeat.device.deviceId)
    policy = store().policy()
    store().heartbeat(heartbeat, policy["heartbeatIntervalSeconds"], request.remote_addr)
    command = store().lease(heartbeat.device.deviceId)
    signed = None
    if command:
        payload = dict(schemaVersion=1, commandId=command["commandId"], deviceId=command["deviceId"],
                       type=command["type"], issuedAtUtc=command["createdAtUtc"], expiresAtUtc=command["expiresAtUtc"])
        signed = dict(payload=payload, signature=sign_command(payload, cfg().POLICY_HMAC_KEY))
    return response(dict(serverTimeUtc=timestamp(utcnow()),acceptedPolicyVersion=policy["policyVersion"],
                         nextHeartbeatSeconds=policy["heartbeatIntervalSeconds"],command=signed))


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
        raise ApiProblem("COMMAND_STATUS_CONFLICT", "The command is terminal, missing, or belongs to another device.", 409)
    return response(status=202)
