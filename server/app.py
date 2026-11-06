"""Application factory. Importing app never installs dependencies or alters the database."""
import logging
import logging.handlers
import os
import sys
import re
import hashlib
import threading
import time
from uuid import uuid4
from flask import Flask, g, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from controlserver.database import ControlStore, PoolExhausted
from controlserver.http import response
from controlserver.observability import safe_exception
from controlserver.validation import ApiProblem, seed_policy

CONTROL_ERROR_CODES = frozenset({
    "UNAUTHORIZED", "CONTROL_BUSY", "INTERNAL_ERROR", "HTTP_ERROR",
    "DEVICE_CONTROL_HTTPS_REQUIRED", "COMMAND_STATUS_CONFLICT", "COMMAND_STATUS_INVALID",
    "DEVICE_ENROLLMENT_INVALID", "DEVICE_ENROLLMENT_CONFLICT", "DEVICE_NOT_FOUND",
    "EVENT_BATCH_INVALID", "HEARTBEAT_INVALID", "HEARTBEAT_V2_INVALID", "INVENTORY_BASELINE_MISSING",
    "POLICY_SCHEMA_UNSUPPORTED", "POLICY_SIGNATURE_UNAVAILABLE", "POLICY_SIGNATURE_UNSUPPORTED",
    "CREDENTIAL_ROTATION_UNAVAILABLE", "CREDENTIAL_ROTATION_INVALID", "CREDENTIAL_ROTATION_CONFLICT",
    "CREDENTIAL_ROTATION_NOT_DUE", "CREDENTIAL_ROTATION_TRANSPORT_REQUIRED",
})


class LoopbackProxy:
    """Trust a single Nginx hop only when the actual TCP peer is loopback."""
    def __init__(self, app):
        self.original = app
        self.proxy = ProxyFix(app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)

    def __call__(self, environ, start_response):
        target = self.proxy if environ.get("REMOTE_ADDR") in ("127.0.0.1", "::1") else self.original
        return target(environ, start_response)


def create_app(config=None, store=None, check_database=True):
    cfg = (config or Config()).validate()
    seed_policy(cfg)  # Validate configured defaults even when persisted policy exists.
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 30_000_000
    app.extensions["control_config"] = cfg
    app.extensions["control_store"] = store or ControlStore(cfg)
    cfg.LOG_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    logger = logging.getLogger("endpointai." + hashlib.sha256(str(cfg.LOG_DIR.resolve()).encode()).hexdigest()[:16])
    app.logger = logger
    logger.setLevel(logging.INFO)
    success_lock = threading.Lock()
    success_counts = {}
    failure_counts = {}
    exception_counts = {}
    success_minute = [int(time.time() // 60)]
    def flush_success_locked(minute):
        if minute != success_minute[0]:
            for (method, name, status), (count, total, maximum, buckets) in success_counts.items():
                logger.info("CONTROL_SUCCESS_AGGREGATE method=%s route=%s status=%s count=%s durationTotalMilliseconds=%.3f durationMaxMilliseconds=%.3f le50=%s le100=%s le200=%s le500=%s le1000=%s",
                            method, name, status, count, total, maximum, *buckets)
            for (method, name, status, business_status, error_code), (count, total, maximum) in failure_counts.items():
                logger.warning("CONTROL_FAILURE_AGGREGATE method=%s route=%s status=%s businessStatus=%s errorCode=%s count=%s durationTotalMilliseconds=%.3f durationMaxMilliseconds=%.3f",
                               method, name, status, business_status, error_code, count, total, maximum)
            for (stage, kind, number, state, frames), count in exception_counts.items():
                logger.error("CONTROL_EXCEPTION_AGGREGATE stage=%s errorType=%s errorNumber=%s sqlState=%s safeFrames=%s count=%s",
                             stage, kind, number, state, frames, count)
            success_counts.clear()
            failure_counts.clear()
            exception_counts.clear()
            success_minute[0] = minute
    def flush_success():
        with success_lock:
            flush_success_locked(int(time.time() // 60))
    app.extensions["flush_control_success"] = flush_success
    if not any(getattr(h, "_endpointai", False) for h in logger.handlers):
        handler = logging.handlers.WatchedFileHandler(cfg.LOG_DIR / "app.log", encoding="utf-8")
        handler._endpointai = True
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    if cfg.TRUST_PROXY:
        app.wsgi_app = LoopbackProxy(app.wsgi_app)
    if check_database:
        try:
            app.extensions["control_store"].check_schema()
        except Exception as exc:
            logger.error("Database schema validation failed; service not started stage=startup errorClass=DATABASE_SCHEMA_INVALID errorType=%s errorNumber=%s sqlState=%s safeFrames=%s", *safe_exception(exc))
            raise

    from controlserver.routes_client import client_bp
    from controlserver.routes_admin import admin_bp
    from controlserver.routes_health import health_bp
    from controlserver.console import console_bp
    from controlserver.local_admin import auth_bp
    for blueprint in (client_bp, admin_bp, health_bp, console_bp, auth_bp):
        app.register_blueprint(blueprint)
    from controlserver.transport import install_transport
    install_transport(app)

    @app.before_request
    def isolate_role():
        if cfg.SERVICE_ROLE == "client" and not request.path.startswith(("/api/", "/health")):
            return response(status=404)
        if cfg.SERVICE_ROLE == "admin" and request.path.startswith("/api/"):
            return response(status=404)

    @app.before_request
    def trace():
        g.trace_id = str(uuid4())
        g.request_started = time.perf_counter()
        g.control_envelope_id = request.environ.get("endpointai.control_envelope_id", "")
        g.control_stage = "business" if g.control_envelope_id else "request"
        g.control_error_code = None
        # Legacy in-process test compatibility; production 0.1.21 Config disables HTTPS.
        # Network ingress is enforced by install_transport, independent of proxy headers.
        command_creation = request.method == "POST" and re.fullmatch(r"/admin/v1/devices/[^/]+/commands", request.path)
        if cfg.REQUIRE_HTTPS and not request.is_secure and not (
                request.path in ("/health", "/health/live", "/health/ready")
                or request.path.startswith("/api/v2/") or command_creation):
            raise ApiProblem("DEVICE_CONTROL_HTTPS_REQUIRED", "Control access requires HTTPS.")

    @app.after_request
    def record(result):
        result.headers["X-Request-ID"] = g.get("trace_id", "")
        if not request.path.startswith("/health"):
            # Log matched route templates, not attacker-supplied paths or query strings.
            route = request.url_rule.rule if request.url_rule else "<unmatched>"
            duration = max(0, (time.perf_counter() - g.get("request_started", time.perf_counter())) * 1000)
            envelope_id = g.get("control_envelope_id", "")
            successful_control = (bool(envelope_id) and result.status_code < 400
                                  and g.get("business_status", 200) < 400)
            if successful_control:
                with success_lock:
                    flush_success_locked(int(time.time() // 60))
                    key = (request.method, route, result.status_code)
                    count, total, maximum, buckets = success_counts.get(key, (0, 0.0, 0.0, [0] * 5))
                    for index, limit in enumerate((50, 100, 200, 500, 1000)):
                        if duration <= limit:
                            buckets[index] += 1
                    success_counts[key] = (count + 1, total + duration, max(maximum, duration), buckets)
                if int(envelope_id.replace("-", ""), 16) % 1000:
                    return result
            elif request.path.startswith('/api/') and (result.status_code >= 400 or g.get('business_status', 200) >= 400):
                # Keep the first five examples per fixed route/status/code per minute;
                # aggregate every failure so an outage cannot flood normal logs.
                method = request.method if request.method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS') else 'OTHER'
                code = g.get('control_error_code') or ('CONTROL_BUSY' if g.get('control_stage') == 'transport_overloaded' else 'OTHER')
                if code not in CONTROL_ERROR_CODES: code = 'OTHER'
                with success_lock:
                    flush_success_locked(int(time.time() // 60))
                    key = (method, route, result.status_code, g.get('business_status', 200), code)
                    count, total, maximum = failure_counts.get(key, (0, 0.0, 0.0))
                    count += 1
                    failure_counts[key] = (count, total + duration, max(maximum, duration))
                if count > 5:
                    return result
            logger.info("%s %s %s requestId=%s controlEnvelopeId=%s businessRequestId=%s stage=%s errorCode=%s durationMilliseconds=%.3f",
                        result.status_code, request.method,
                        route, g.get("trace_id", ""),
                        g.get("control_envelope_id", ""), g.get("business_request_id", "") or
                        (g.get("trace_id", "") if g.get("control_stage") == "business" else ""),
                        g.get("control_stage", "request"), g.get('control_error_code') if g.get('control_error_code') in CONTROL_ERROR_CODES else '',
                        duration)
        return result

    @app.errorhandler(ApiProblem)
    def problem(exc):
        g.control_error_code = exc.code if exc.code in CONTROL_ERROR_CODES else 'OTHER'
        if exc.status == 401:
            return response(status=401)
        error = {"code": exc.code, "message": exc.message, "traceId": g.get("trace_id")}
        if exc.details:
            error["details"] = exc.details
        return response({"error": error}, exc.status)

    @app.errorhandler(PoolExhausted)
    def pool_exhausted(exc):
        g.control_error_code = 'CONTROL_BUSY'
        result = response({"error": {"code": "CONTROL_BUSY", "message": "Control service is busy."}}, 503)
        result.headers["Retry-After"] = "5"
        return result

    @app.errorhandler(HTTPException)
    def http_error(exc):
        g.control_error_code = 'HTTP_ERROR'
        return response({"error": {"code": f"HTTP_{exc.code}", "message": exc.name, "traceId": g.get("trace_id")}}, exc.code)

    @app.errorhandler(Exception)
    def unexpected(exc):
        g.control_error_code = 'INTERNAL_ERROR'
        # Exception messages/stack locals can contain credentials or request bodies.
        stage = g.get("control_stage", "request")
        metadata = safe_exception(exc)
        log_example = True
        if request.path.startswith('/api/'):
            stage = stage if stage in ('request', 'business', 'transport_validate', 'transport_replay', 'transport_complete', 'transport_overloaded') else 'other'
            with success_lock:
                flush_success_locked(int(time.time() // 60))
                key = (stage, *metadata)
                if key not in exception_counts and len(exception_counts) >= 255:
                    key = ('other', 'OTHER', 0, '', '')
                count = exception_counts.get(key, 0) + 1
                exception_counts[key] = count
                log_example = count <= 5
        if log_example:
            logger.error("Unhandled request exception requestId=%s stage=%s errorClass=INTERNAL_ERROR errorType=%s errorNumber=%s sqlState=%s safeFrames=%s",
                         g.get("trace_id", ""), stage, *metadata)
        return response({"error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred.",
                                   "traceId": g.get("trace_id")}}, 500)

    logger.info("EndpointAIDLP 0.1.26 initialized environment=%s", cfg.APP_ENV)
    return app


def start_replay_maintenance(app):
    def maintain():
        removed = 0
        reported = time.monotonic()
        while True:
            time.sleep(1)
            try:
                store = app.extensions["control_store"]
                removed += store.cleanup_transport()
            except Exception as exc:
                app.logger.error("Replay maintenance failed stage=replay_cleanup errorType=%s errorNumber=%s sqlState=%s safeFrames=%s", *safe_exception(exc))
            if time.monotonic() - reported >= 60:
                try:
                    age = app.extensions["control_store"].replay_expired_age_seconds()
                    app.logger.info("REPLAY_MAINTENANCE_METRICS pid=%s deleted=%s oldestExpiredSeconds=%s", os.getpid(), removed, age)
                    removed = 0
                except Exception as exc:
                    app.logger.error("Replay metrics failed stage=replay_metrics errorType=%s errorNumber=%s sqlState=%s safeFrames=%s", *safe_exception(exc))
                if getattr(app.extensions['control_store'], '_credential_rotation_table', False):
                    try:
                        from controlserver.credential_rotation import cleanup
                        deleted = cleanup(app.extensions['control_store'])
                        app.logger.info('CREDENTIAL_ROTATION_MAINTENANCE pid=%s deleted=%s', os.getpid(), deleted)
                    except Exception as exc:
                        app.logger.error('Credential renewal maintenance failed stage=credential_cleanup errorType=%s errorNumber=%s sqlState=%s safeFrames=%s', *safe_exception(exc))
                reported = time.monotonic()

    threading.Thread(target=maintain, name="replay-maintenance", daemon=True).start()


def start_rollout_dispatch(app):
    from controlserver.rollout import dispatch_one
    from controlserver.policy_rollout import dispatch_one as dispatch_policy
    def maintain(stage, dispatch):
        while True:
            try:
                dispatched = dispatch(app.extensions["control_store"])
                time.sleep(0.05 if dispatched else 1)
            except Exception as exc:
                app.logger.error("Rollout dispatch failed stage=%s errorType=%s errorNumber=%s sqlState=%s safeFrames=%s", stage, *safe_exception(exc))
                time.sleep(5)
    for stage, dispatch in (("command", dispatch_one), ("policy", dispatch_policy)):
        threading.Thread(target=maintain, args=(stage, dispatch), name=stage+"-rollout-dispatch", daemon=True).start()


def start_pool_metrics(app):
    def report():
        last_exhausted = 0
        while True:
            time.sleep(60)
            app.extensions["flush_control_success"]()
            store = app.extensions["control_store"]
            data = store.pool_metrics.snapshot()
            app.logger.info("POOL_METRICS pid=%s role=%s limit=%s inUse=%s attempts=%s exhausted=%s waitMilliseconds=%.3f maxWaitMilliseconds=%.3f",
                            os.getpid(), app.extensions["control_config"].SERVICE_ROLE,
                            store._pool_limit, data["inUse"], data["attempts"], data["exhausted"],
                            data["waitMilliseconds"], data["maxWaitMilliseconds"])
            if data["exhausted"] > last_exhausted:
                app.logger.warning("POOL_EXHAUSTION_ALERT pid=%s role=%s count=%s",
                                   os.getpid(), app.extensions["control_config"].SERVICE_ROLE,
                                   data["exhausted"] - last_exhausted)
            last_exhausted = data["exhausted"]
    threading.Thread(target=report, name="pool-metrics", daemon=True).start()


if __name__ == "__main__":
    from gunicorn.app.base import BaseApplication

    class ProductionServer(BaseApplication):
        def load_config(self):
            cfg = Config().validate()
            host = f"[{cfg.HTTP_HOST}]" if ":" in cfg.HTTP_HOST else cfg.HTTP_HOST
            for key, value in dict(bind=f"{host}:{cfg.HTTP_PORT}", workers=1 if cfg.SERVICE_ROLE == "admin" else 2,
                    threads=2 if cfg.SERVICE_ROLE == "admin" else 4, worker_class="gthread", timeout=60, graceful_timeout=30,
                    accesslog=None, errorlog="-", forwarded_allow_ips="",
                    secure_scheme_headers={}, umask=0o027).items():
                self.cfg.set(key, value)

        def load(self):
            app = create_app()
            start_pool_metrics(app)
            if app.extensions["control_config"].SERVICE_ROLE != "admin":
                start_replay_maintenance(app)
                start_rollout_dispatch(app)
            return app

    ProductionServer().run()
