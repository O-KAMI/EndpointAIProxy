"""Explicit sit/prd configuration; importing this module has no side effects."""
import base64
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_properties(path):
    values = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        positions = [i for sep in ("=", ":") if (i := line.find(sep)) >= 0]
        if not positions:
            raise ValueError(f"Invalid properties line in {path.name}")
        index = min(positions)
        values[line[:index].strip()] = line[index + 1:].strip()
    return values


class Config:
    def __init__(self, env=None, conf_dir=None):
        self.CONF_DIR = Path(conf_dir or os.environ.get("APP_CONFIG") or ROOT / "conf")
        props = load_properties(self.CONF_DIR / "application.properties")

        def setting(key, name, default=None, source=None):
            return os.environ.get(name, (props if source is None else source).get(key, default))

        def boolean(key, name, default):
            value = setting(key, name, default).lower()
            if value not in ("true", "false"):
                raise ValueError(f"{key} must be true or false")
            return value == "true"

        self.APP_ENV = env or setting("app.env", "APP_ENV", "sit")
        if self.APP_ENV not in ("sit", "prd"):
            raise ValueError("app.env / APP_ENV must be sit or prd")
        self.HTTP_PORT = int(setting("server.http-port", "SF_CONTROL_HTTP_PORT", "8080"))
        if not 1 <= self.HTTP_PORT <= 65535:
            raise ValueError("Invalid HTTP port")
        self.HTTP_HOST = setting("server.http-host", "SF_CONTROL_HTTP_HOST", "0.0.0.0")
        self.REQUIRE_HTTPS = False
        self.TRUST_PROXY = False
        self.TRANSPORT_KEY_ID = setting("transport.key-id", "SF_CONTROL_TRANSPORT_KEY_ID", "production-2026-01")
        self.TRANSPORT_KEY_TEXT = setting("transport.key", "SF_CONTROL_TRANSPORT_KEY", "")
        self.CLIENT_TOKEN = setting("auth.client-token", "SF_CONTROL_CLIENT_TOKEN", "")
        self.ADMIN_TOKEN = setting("auth.admin-token", "SF_CONTROL_ADMIN_TOKEN", "")
        self.HMAC_TEXT = setting("auth.policy-hmac-key", "SF_CONTROL_POLICY_HMAC_KEY", "")
        self.ROUTE_MODE = setting("policy.route-mode", "SF_CONTROL_ROUTE_MODE", "FixedGateway")
        self.GATEWAY_ORIGIN = setting("policy.gateway-origin", "SF_CONTROL_GATEWAY_ORIGIN", "http://security-proxy.sf-express.com")
        self.ALLOW_INSECURE_GATEWAY = boolean("policy.allow-insecure-gateway", "SF_CONTROL_ALLOW_INSECURE_GATEWAY", "true")
        self.POLL_INTERVAL = int(setting("policy.poll-interval-seconds", "SF_CONTROL_POLL_INTERVAL_SECONDS", "60"))
        self.HEARTBEAT_INTERVAL = int(setting("policy.heartbeat-interval-seconds", "SF_CONTROL_HEARTBEAT_INTERVAL_SECONDS", "60"))
        self.ENABLED = boolean("policy.enabled", "SF_CONTROL_ENABLED", "true")
        self.SERVER_ID = setting("policy.server-id", "SF_CONTROL_SERVER_ID")
        self.POLICY_VERSION = int(setting("policy.version", "SF_CONTROL_POLICY_VERSION", "1"))
        mysql = load_properties(self.CONF_DIR / f"mysql_{self.APP_ENV}.properties")
        for attr, prop, name, default in (
            ("HOST", "host", "HOST", "localhost"), ("PORT", "port", "PORT", "3306"),
            ("DATABASE", "database", "DATABASE", "endpoint_ai_proxy"),
            ("USER", "username", "USERNAME", ""), ("PASSWORD", "password", "PASSWORD", ""),
        ):
            value = setting(f"eai.mysql.{prop}", f"EAI_MYSQL_{name}", default, mysql)
            setattr(self, f"MYSQL_{attr}", int(value) if attr == "PORT" else value)
        if not 1 <= self.MYSQL_PORT <= 65535:
            raise ValueError("Invalid MySQL port")
        self.DATA_ROOT = Path(setting("server.data-root", "SF_CONTROL_DATA_ROOT", str(ROOT / "var")))
        self.LOG_DIR = Path(setting("server.log-dir", "SF_CONTROL_LOG_DIR", str(ROOT / "logs")))
        self.BACKUP_DIR = self.DATA_ROOT / "backups"

    def validate(self):
        if not self.CLIENT_TOKEN or not self.ADMIN_TOKEN:
            raise ValueError("Client and admin tokens are required")
        try:
            key = base64.b64decode(self.HMAC_TEXT, validate=True)
        except ValueError:
            raise ValueError("Policy HMAC key must be Base64") from None
        if len(key) < 32:
            raise ValueError("Policy HMAC key must contain at least 32 bytes")
        self.POLICY_HMAC_KEY = key
        if not self.MYSQL_USER or not self.MYSQL_DATABASE:
            raise ValueError("MySQL user and database are required")
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", self.MYSQL_DATABASE):
            raise ValueError("MySQL database must contain only letters, digits and underscore")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.TRANSPORT_KEY_ID):
            raise ValueError("Invalid transport key ID")
        try:
            self.TRANSPORT_KEY = base64.b64decode(self.TRANSPORT_KEY_TEXT, validate=True)
        except ValueError:
            raise ValueError("Transport key must be Base64") from None
        if len(self.TRANSPORT_KEY) != 32:
            raise ValueError("A 32-byte AES transport key is required")
        return self
