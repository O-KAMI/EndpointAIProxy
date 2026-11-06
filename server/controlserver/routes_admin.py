import re
from uuid import UUID
from flask import Blueprint, g, request
from .http import cfg, store, response, parse, token_required
from .models import (PolicyUpdateRequest, CreateRemoteCommandRequest, DeviceOnlineState, ResolveUnknownCommandRequest, RecoverDeviceCredentialRequest, CreateRolloutRequest, RolloutChangeRequest,
                     DevicePolicyUpdateRequest, DevicePolicyResetRequest, CreatePolicyRolloutRequest, ExtendPolicyRolloutRequest)
from .security import utcnow
from .validation import ApiProblem, validate_policy
from .analytics import drill_down, online_state
from .database import short_account_name

admin_bp = Blueprint("admin", __name__, url_prefix="/admin/v1")
admin_bp.before_request(token_required("admin")(lambda: None))


def actor():
    if cfg().ADMIN_AUTH_MODE == "local":
        return g.admin_actor
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
    if cfg().ANALYTICS_CACHE:
        from .analytics_cache import read_cache
        return response(read_cache(cfg(), utcnow(), **query))
    return response(store().analytics_aggregate(utcnow(), **query))


@admin_bp.get("/analytics/devices")
def analytics_devices():
    query = analytics_query()
    skip, take = pagination(50)
    filters = {key: request.args.get(key) for key in ("kind", "key", "search", "agent", "provider", "anomaly", "allowlist", "employeeExact")}
    if filters["employeeExact"]:
        filters["employeeExact"] = short_account_name(filters["employeeExact"])
        if not filters["employeeExact"]:
            raise ApiProblem("QUERY_INVALID", "An exact account search requires a nonempty short account.")
    now = utcnow()
    snapshot = request.args.get("snapshot", "0")
    if snapshot not in ("0", "1"):
        raise ApiProblem("QUERY_INVALID", "Invalid snapshot selection.")
    if snapshot == "1":
        if not cfg().ANALYTICS_DETAIL_CACHE:
            raise ApiProblem("ANALYTICS_CACHE_UNAVAILABLE", "Analytics snapshot is not enabled.", 503)
        from .analytics_cache import identity
        from .analytics_detail_cache import read_detail_cache
        return response(read_detail_cache(cfg(), now, identity(cfg()), skip=skip, take=take, **query, **filters))
    sql_kind = filters["kind"] in (None, "", "online", "anomaly", "everAnomaly", "error")
    if sql_kind and not any(filters[name] for name in ("agent", "provider", "allowlist", "employeeExact")):
        rows, policy, total = store().analytics_page(query["scope"], query["os"], now, skip, take,
                                                       employee_search=filters["search"], kind=filters["kind"],
                                                       key=filters["key"], anomaly=filters["anomaly"])
        result = drill_down(rows, policy, now, scope="all", take=take)
        result.update(total=total, skip=skip)
        return response(result)
    if cfg().ANALYTICS_DETAIL_CACHE:
        from .analytics_cache import identity
        from .analytics_detail_cache import read_detail_cache
        return response(read_detail_cache(cfg(), now, identity(cfg()), skip=skip, take=take, **query, **filters))
    return response(store().analytics_filtered_page(now, skip=skip, take=take, **query, **filters))


@admin_bp.get("/policy")
def get_policy():
    return response(store().policy())


@admin_bp.put("/policy")
def put_policy():
    update = parse(PolicyUpdateRequest, "POLICY_FIELDS_INVALID")
    validate_policy(update)
    result = store().update_policy(update, actor())
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
    page, _, total = store().analytics_page(state.lower() if state else "all", None, now, skip, take, hostname_search=search)
    rows = []
    for detail in page:
        d = detail["device"]
        item = {k: v for k, v in d.items() if k not in
                ("heartbeatIntervalSeconds", "expectedPolicyVersion", "expectedPolicySchemaVersion")}
        item.update(onlineState=online_state(d, now), legacyClient=d["schemaVersion"] < 2)
        rows.append(item)
    result = response(rows)
    result.headers["X-Total-Count"] = str(total)
    return result


@admin_bp.get("/dashboard")
def dashboard():
    return response(store().dashboard(utcnow()))


@admin_bp.get("/devices/<uuid:device_id>")
def details(device_id):
    detail = store().details(device_id)
    return response(detail) if detail is not None else response(status=404)


@admin_bp.post("/devices/<uuid:device_id>/credential-recovery")
def recover_device_credential(device_id):
    # Shared-token mode cannot establish the identity of the administrator.
    if cfg().ADMIN_AUTH_MODE != "local" or not request.is_secure:
        return response(status=403)
    value = parse(RecoverDeviceCredentialRequest, "RECOVERY_REQUEST_INVALID")
    if not value.reason.strip() or value.hostname != value.hostname.strip():
        raise ApiProblem("RECOVERY_REQUEST_INVALID", "A hostname and reason are required.")
    result = response(store().recover_device_credential(device_id, value.hostname, value.reason.strip(), actor()))
    result.headers["Cache-Control"] = "no-store"
    return result


@admin_bp.get("/devices/<uuid:device_id>/policy")
def get_device_policy(device_id):
    return response(store().device_policy(device_id))


@admin_bp.put("/devices/<uuid:device_id>/policy")
def put_device_policy(device_id):
    update = parse(DevicePolicyUpdateRequest, "POLICY_FIELDS_INVALID")
    return response(store().device_policy(device_id, update, actor()))


@admin_bp.delete("/devices/<uuid:device_id>/policy")
def reset_device_policy(device_id):
    update = parse(DevicePolicyResetRequest, "POLICY_FIELDS_INVALID")
    return response(store().device_policy(device_id, update, actor(), reset=True))


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


@admin_bp.post("/commands/<uuid:command_id>/resolve-unknown")
def resolve_unknown(command_id):
    value = parse(ResolveUnknownCommandRequest, "REMOTE_COMMAND_INVALID")
    reason = value.reason.strip()
    if not reason or len(reason) > 256:
        raise ApiProblem("REMOTE_COMMAND_INVALID", "A reason of up to 256 characters is required.")
    if not store().resolve_unknown(command_id, actor(), reason):
        raise ApiProblem("COMMAND_NOT_RESOLVABLE", "Only expired delivered or executing commands can be marked outcome unknown.", 409)
    return response()


@admin_bp.get("/rollouts")
def rollouts():
    from . import rollout
    skip, take = pagination(25)
    result = rollout.list_batches(store(), skip, take)
    result["maxRate"] = cfg().ROLLOUT_MAX_RATE
    return response(result)


@admin_bp.post("/rollouts")
def create_rollout():
    if cfg().ADMIN_AUTH_MODE != "local" or not request.is_secure:
        return response(status=403)
    from . import rollout
    value = parse(CreateRolloutRequest, "ROLLOUT_INVALID")
    return response(rollout.create(store(), value, actor()), 201)


@admin_bp.get("/rollouts/<uuid:batch_id>")
def rollout_details(batch_id):
    from . import rollout
    skip, take = pagination(50)
    return response(rollout.details(store(), batch_id, skip, take, request.args.get("state")))


@admin_bp.get("/rollouts/<uuid:batch_id>/targets")
def rollout_targets_cursor(batch_id):
    from . import rollout
    after = request.args.get('after', '')
    try:
        if after and str(UUID(after)) != after:
            raise ValueError()
        take = int(request.args.get('take', '100'))
        if not 1 <= take <= 500:
            raise ValueError()
    except (ValueError, TypeError):
        raise ApiProblem('ROLLOUT_QUERY_INVALID', 'Invalid target cursor or page size.') from None
    return response(rollout.target_cursor(store(), batch_id, after, take))


@admin_bp.post("/rollouts/<uuid:batch_id>/<action>")
def change_rollout(batch_id, action):
    if cfg().ADMIN_AUTH_MODE != "local" or not request.is_secure:
        return response(status=403)
    if action not in ("pause", "resume", "retry"):
        return response(status=404)
    from . import rollout
    value = parse(RolloutChangeRequest, "ROLLOUT_INVALID")
    return response(rollout.change(store(), batch_id, action, value.reason, actor()))


@admin_bp.get("/policy-rollouts")
def policy_rollouts():
    from . import policy_rollout
    skip, take = pagination(25)
    return response(policy_rollout.list_batches(store(), skip, take))


@admin_bp.post("/policy-rollouts")
def create_policy_rollout():
    if cfg().ADMIN_AUTH_MODE != "local" or not request.is_secure:
        return response(status=403)
    from . import policy_rollout
    return response(policy_rollout.create(store(), parse(CreatePolicyRolloutRequest, "POLICY_ROLLOUT_INVALID"), actor()), 201)


@admin_bp.get("/policy-rollouts/<uuid:batch_id>")
def policy_rollout_details(batch_id):
    from . import policy_rollout
    skip, take = pagination(50)
    return response(policy_rollout.details(store(), batch_id, skip, take, request.args.get("state")))


@admin_bp.post("/policy-rollouts/<uuid:batch_id>/extend")
def extend_policy_rollout(batch_id):
    if cfg().ADMIN_AUTH_MODE != "local" or not request.is_secure:
        return response(status=403)
    from . import policy_rollout
    return response(policy_rollout.extend(store(), batch_id, parse(ExtendPolicyRolloutRequest, "POLICY_ROLLOUT_INVALID"), actor()))


@admin_bp.post("/policy-rollouts/<uuid:batch_id>/<action>")
def change_policy_rollout(batch_id, action):
    if cfg().ADMIN_AUTH_MODE != "local" or not request.is_secure:
        return response(status=403)
    if action not in ("pause", "resume", "retry", "abort", "promote"):
        return response(status=404)
    from . import policy_rollout
    value = parse(RolloutChangeRequest, "POLICY_ROLLOUT_INVALID")
    return response(policy_rollout.change(store(), batch_id, action, value.reason, actor()))


@admin_bp.get("/audit")
def audit():
    skip, take = pagination()
    try:
        device = UUID(request.args["deviceId"]) if "deviceId" in request.args else None
    except ValueError:
        raise ApiProblem("QUERY_INVALID", "Invalid device ID.") from None
    return response(store().audits(device, skip, take))
