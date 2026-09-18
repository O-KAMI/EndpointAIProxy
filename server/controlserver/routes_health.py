import json
from flask import Blueprint, current_app
from .http import cfg, store, response

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
@health_bp.get("/health/live")
def live():
    return response({"status": "live"})


@health_bp.get("/health/ready")
def ready():
    try:
        policy = store().policy()
    except Exception:
        current_app.logger.exception("Readiness database check failed")
        return response({"status": "not_ready", "error": "DATABASE_UNAVAILABLE"}, 503)
    from .backup import read_backup_state
    state = read_backup_state(cfg())
    return response(dict(status="degraded" if state["lastError"] else "ready",
                         policyVersion=policy["policyVersion"], **state))
