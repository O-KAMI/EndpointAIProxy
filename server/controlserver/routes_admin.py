import re
from uuid import UUID
from flask import Blueprint, request
from .http import cfg, store, response, parse, token_required
from .models import PolicyUpdateRequest, CreateRemoteCommandRequest, DeviceOnlineState
from .security import utcnow, timestamp
from .validation import ApiProblem, validate_policy
from .analytics import build, drill_down, online_state

admin_bp = Blueprint("admin", __name__, url_prefix="/admin/v1")
admin_bp.before_request(token_required("admin")(lambda: None))


def actor():
    value = request.headers.get("X-SF-Admin-Actor", "").strip()
    return value if re.fullmatch(r"[a-zA-Z0-9._@-]{1,64}", value) else "admin-token"


def pagination(default_take=100):
    try:
        return max(0, int(request.args.get("skip", 0))), min(500, max(1, int(request.args.get("take", default_take))))
    except ValueError:
        raise ApiProblem("QUERY_INVALID", "Pagination must use integers.") from None


def analytics_query():
    scope = request.args.get("scope", "online").lower()
    if scope not in {"online", "all", "stale", "offline", "legacyclient"} or "providerMode" in request.args:
        raise ApiProblem("QUERY_INVALID", "Invalid analytics query.")
    return dict(scope=scope, os=request.args.get("os"))


@admin_bp.get("/analytics")
def analytics():
    query = analytics_query()
    rows, policy = store().analytics_snapshot()
    return response(build(rows, policy, utcnow(), **query))


@admin_bp.get("/analytics/devices")
def analytics_devices():
    query = analytics_query()
    skip, take = pagination(50)
    rows, policy = store().analytics_snapshot()
    filters = {key: request.args.get(key) for key in ("kind", "key", "search", "agent", "provider", "anomaly", "allowlist")}
    return response(drill_down(rows, policy, utcnow(), skip=skip, take=take, **query, **filters))


@admin_bp.get("/policy")
def get_policy():
    return response(store().policy())


@admin_bp.put("/policy")
def put_policy():
    update = parse(PolicyUpdateRequest, "POLICY_FIELDS_INVALID")
    validate_policy(update)
    result = store().update_policy(update)
    if result is None:
        raise ApiProblem("POLICY_VERSION_CONFLICT", "The policy changed after it was read; reload and retry.", 409)
    return response(result)


@admin_bp.get("/devices")
def devices():
    skip, take = pagination()
    search = request.args.get("search", "")
    state = request.args.get("onlineState")
    try:
        state = DeviceOnlineState(state).value if state is not None else None
    except ValueError:
        raise ApiProblem("QUERY_INVALID", "Invalid online state.") from None
    now = utcnow()
    rows = [dict(d, onlineState=online_state(d, now), legacyClient=d["schemaVersion"] < 2) for d in store().devices()]
    rows = [d for d in rows if (not search.strip() or search.lower() in d["hostname"].lower()
            or search.lower() in d["deviceId"].lower()) and (state is None or d["onlineState"] == state)]
    total = len(rows)
    rows = [{k:v for k,v in d.items() if k != "heartbeatIntervalSeconds"} for d in rows[skip:skip + take]]
    result = response(rows)
    result.headers["X-Total-Count"] = str(total)
    return result


@admin_bp.get("/dashboard")
def dashboard():
    now = utcnow()
    devices = store().devices()
    states = [online_state(d, now) for d in devices]
    return response(dict(totalDevices=len(devices),online=states.count("online"),
        stale=states.count("stale"),offline=states.count("offline"),
        legacyClients=sum(d["schemaVersion"] < 2 for d in devices),
        proxyDisabled=sum(d["operationState"] == "disabled" for d in devices),updatedAtUtc=timestamp(now)))


@admin_bp.get("/devices/<uuid:device_id>")
def details(device_id):
    detail = store().details(device_id)
    return response(detail) if detail is not None else response(status=404)


@admin_bp.get("/devices/<uuid:device_id>/commands")
def commands(device_id):
    return response(store().commands(device_id))


@admin_bp.post("/devices/<uuid:device_id>/commands")
def create_command(device_id):
    who = actor()
    try:
        value = parse(CreateRemoteCommandRequest, "REMOTE_COMMAND_INVALID")
        if ((cfg().REQUIRE_HTTPS and not request.is_secure) or not value.reason.strip()
                or len(value.reason) > 256 or not 1 <= value.expiresInMinutes <= 1440):
            raise ApiProblem("REMOTE_COMMAND_INVALID", "Remote commands require HTTPS, an allowed type, a reason, and a 1-1440 minute expiry.")
        command = store().create_command(device_id, value, who)
        if command is None:
            store().audit(who, "REMOTE_COMMAND_REJECTED", device_id, summary="DEVICE_NOT_FOUND")
            return response(status=404)
        return response(command, 202)
    except ApiProblem as exc:
        store().audit(who, "REMOTE_COMMAND_REJECTED", device_id, summary=exc.code)
        raise


@admin_bp.post("/commands/<uuid:command_id>/cancel")
def cancel(command_id):
    if not store().cancel(command_id, actor()):
        raise ApiProblem("COMMAND_NOT_CANCELLABLE", "Only a pending command can be cancelled.", 409)
    return response()


@admin_bp.get("/audit")
def audit():
    skip, take = pagination()
    try:
        device = UUID(request.args["deviceId"]) if "deviceId" in request.args else None
    except ValueError:
        raise ApiProblem("QUERY_INVALID", "Invalid device ID.") from None
    return response(store().audits(device, skip, take))
