"""Application factory. Importing app never installs dependencies or alters the database."""
import logging
import logging.handlers
import sys
import re
import hashlib
from uuid import uuid4
from flask import Flask, g, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from controlserver.database import ControlStore
from controlserver.http import response
from controlserver.validation import ApiProblem, seed_policy


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
        except Exception:
            logger.exception("Database schema validation failed; service not started")
            raise

    from controlserver.routes_client import client_bp
    from controlserver.routes_admin import admin_bp
    from controlserver.routes_health import health_bp
    from controlserver.console import console_bp
    for blueprint in (client_bp, admin_bp, health_bp, console_bp):
        app.register_blueprint(blueprint)
    from controlserver.transport import install_transport
    install_transport(app)

    @app.before_request
    def trace():
        g.trace_id = str(uuid4())
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
            logger.info("%s %s %s requestId=%s", result.status_code, request.method,
                        request.url_rule.rule if request.url_rule else "<unmatched>", g.get("trace_id"))
        return result

    @app.errorhandler(ApiProblem)
    def problem(exc):
        if exc.status == 401:
            return response(status=401)
        return response({"error": {"code": exc.code, "message": exc.message, "traceId": None}}, exc.status)

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return response({"error": {"code": f"HTTP_{exc.code}", "message": exc.name, "traceId": g.get("trace_id")}}, exc.code)

    @app.errorhandler(Exception)
    def unexpected(exc):
        logger.exception("Unhandled request exception requestId=%s", g.get("trace_id"))
        return response({"error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred.",
                                   "traceId": g.get("trace_id")}}, 500)

    logger.info("EndpointAIDLP 0.1.22 initialized environment=%s", cfg.APP_ENV)
    return app


if __name__ == "__main__":
    from gunicorn.app.base import BaseApplication

    class ProductionServer(BaseApplication):
        def load_config(self):
            cfg = Config().validate()
            for key, value in dict(bind=f"{cfg.HTTP_HOST}:{cfg.HTTP_PORT}", workers=2,
                    threads=4, worker_class="gthread", timeout=60, graceful_timeout=30,
                    accesslog=None, errorlog="-", forwarded_allow_ips="",
                    secure_scheme_headers={}, umask=0o027).items():
                self.cfg.set(key, value)

        def load(self):
            return create_app()

    ProductionServer().run()
