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
        self.SERVICE_ROLE = setting("server.role", "SF_CONTROL_ROLE", "all")
        self.ROLLOUT_MAX_RATE = int(setting("rollout.max-per-second", "SF_CONTROL_ROLLOUT_MAX_RATE", "20"))
        self.POLICY_ROLLOUT_MAX_RATE = int(setting("policy-rollout.max-per-second", "SF_CONTROL_POLICY_ROLLOUT_MAX_RATE", "20"))
        self.EMPLOYEE_INDEX = boolean("analytics.employee-index", "SF_CONTROL_EMPLOYEE_INDEX", "false")
        self.ANALYTICS_CACHE = boolean("analytics.cache", "SF_CONTROL_ANALYTICS_CACHE", "false")
        self.ANALYTICS_DETAIL_CACHE = boolean("analytics.detail-cache", "SF_CONTROL_ANALYTICS_DETAIL_CACHE", "false")
        self.REQUIRE_HTTPS = False
        self.TRUST_PROXY = boolean("server.trust-loopback-proxy", "SF_CONTROL_TRUST_LOOPBACK_PROXY", "false")
        self.DEVICE_TRANSPORT = boolean("transport.device-keys", "SF_CONTROL_DEVICE_TRANSPORT", "false")
        self.DEVICE_TRANSPORT_V2 = boolean("transport.device-keys-v2", "SF_CONTROL_DEVICE_TRANSPORT_V2", "false")
        self.CREDENTIAL_ROTATION = boolean("auth.credential-rotation", "SF_CONTROL_CREDENTIAL_ROTATION", "false")
        self.DEVICE_KEY_ID = setting("transport.device-key-id", "SF_CONTROL_DEVICE_KEY_ID", "")
        self.DEVICE_KEY_TEXT = setting("transport.device-key-secret", "SF_CONTROL_DEVICE_KEY_SECRET", "")
        self.DEVICE_PREVIOUS_KEY_ID = setting("transport.device-previous-key-id", "SF_CONTROL_DEVICE_PREVIOUS_KEY_ID", "")
        self.DEVICE_PREVIOUS_KEY_TEXT = setting("transport.device-previous-key-secret", "SF_CONTROL_DEVICE_PREVIOUS_KEY_SECRET", "")
        self.TRANSPORT_KEY_ID = setting("transport.key-id", "SF_CONTROL_TRANSPORT_KEY_ID", "production-2026-01")
        self.TRANSPORT_KEY_TEXT = setting("transport.key", "SF_CONTROL_TRANSPORT_KEY", "")
        self.TRANSPORT_ADDITIONAL_KEY_ID = setting("transport.additional-key-id", "SF_CONTROL_TRANSPORT_ADDITIONAL_KEY_ID", "")
        self.TRANSPORT_ADDITIONAL_KEY_TEXT = setting("transport.additional-key", "SF_CONTROL_TRANSPORT_ADDITIONAL_KEY", "")
        self.CLIENT_TOKEN = setting("auth.client-token", "SF_CONTROL_CLIENT_TOKEN", "")
        self.ADMIN_TOKEN = setting("auth.admin-token", "SF_CONTROL_ADMIN_TOKEN", "")
        self.ADMIN_AUTH_MODE = setting("auth.admin-mode", "SF_CONTROL_ADMIN_AUTH_MODE", "legacy")
        self.ADMIN_ACCOUNTS_PATH = setting("auth.local-accounts-path", "SF_CONTROL_ADMIN_ACCOUNTS_PATH", "")
        self.ADMIN_SESSION_KEY_TEXT = setting("auth.local-session-key", "SF_CONTROL_ADMIN_SESSION_KEY", "")
        self.HMAC_TEXT = setting("auth.policy-hmac-key", "SF_CONTROL_POLICY_HMAC_KEY", "")
        self.ED25519_SEED_TEXT = setting("auth.policy-ed25519-seed", "SF_CONTROL_POLICY_ED25519_SEED", "")
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
        if self.SERVICE_ROLE not in ("all", "client", "admin"):
            raise ValueError("Invalid service role")
        if not 1 <= self.ROLLOUT_MAX_RATE <= 5000:
            raise ValueError("Invalid rollout rate limit")
        if not 1 <= self.POLICY_ROLLOUT_MAX_RATE <= 5000:
            raise ValueError("Invalid policy rollout rate limit")
        if self.SERVICE_ROLE != "all" and self.HTTP_HOST not in ("127.0.0.1", "::1"):
            raise ValueError("Split services require a loopback-only application listener")
        if self.ADMIN_AUTH_MODE not in ("legacy", "local"):
            raise ValueError("Invalid admin authentication mode")
        if not self.CLIENT_TOKEN or (self.ADMIN_AUTH_MODE == "legacy" and not self.ADMIN_TOKEN):
            raise ValueError("Client and legacy admin tokens are required")
        if self.ADMIN_AUTH_MODE == "local":
            if self.TRUST_PROXY and self.HTTP_HOST not in ("127.0.0.1", "::1"):
                raise ValueError("Local admin proxy requires a loopback-only application listener")
            try:
                self.ADMIN_SESSION_KEY = base64.b64decode(self.ADMIN_SESSION_KEY_TEXT, validate=True)
            except ValueError:
                raise ValueError("Admin session key must be Base64") from None
            if len(self.ADMIN_SESSION_KEY) < 32:
                raise ValueError("Admin session key must contain at least 32 bytes")
            from controlserver.local_admin import load_accounts
            load_accounts(self.ADMIN_ACCOUNTS_PATH)
        try:
            key = base64.b64decode(self.HMAC_TEXT, validate=True)
        except ValueError:
            raise ValueError("Policy HMAC key must be Base64") from None
        if len(key) < 32:
            raise ValueError("Policy HMAC key must contain at least 32 bytes")
        self.POLICY_HMAC_KEY = key
        self.POLICY_SIGNING_KEY = None
        signing_seed = None
        if self.ED25519_SEED_TEXT:
            try:
                seed = base64.b64decode(self.ED25519_SEED_TEXT, validate=True)
                if len(seed) != 32:
                    raise ValueError()
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                self.POLICY_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(seed)
                signing_seed = seed
            except (ValueError, TypeError):
                raise ValueError("Policy Ed25519 seed must be Base64-encoded 32 bytes") from None
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
        self.TRANSPORT_KEYS = {self.TRANSPORT_KEY_ID: self.TRANSPORT_KEY}
        extra_id, extra_text = self.TRANSPORT_ADDITIONAL_KEY_ID, self.TRANSPORT_ADDITIONAL_KEY_TEXT
        if bool(extra_id) != bool(extra_text):
            raise ValueError("Additional transport key ID and key must be supplied together")
        if extra_id:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", extra_id) or extra_id == self.TRANSPORT_KEY_ID:
                raise ValueError("Invalid additional transport key ID")
            try:
                extra_key = base64.b64decode(extra_text, validate=True)
            except (ValueError, TypeError):
                raise ValueError("Additional transport key must be Base64") from None
            if len(extra_key) != 32 or extra_key == self.TRANSPORT_KEY:
                raise ValueError("Additional transport key must be a distinct 32-byte key")
            self.TRANSPORT_KEYS[extra_id] = extra_key
        if self.CREDENTIAL_ROTATION and not self.DEVICE_TRANSPORT_V2:
            raise ValueError("Credential renewal requires device transport V2")
        if self.DEVICE_TRANSPORT or self.DEVICE_TRANSPORT_V2:
            if self.APP_ENV == "prd" and (self.HTTP_HOST not in ("127.0.0.1", "::1") or not self.TRUST_PROXY):
                raise ValueError("Device transport in production requires a loopback listener and trusted TLS proxy")
            from controlserver.device_transport import device_for_key_id, device_v2_for_key_id
            if any(device_for_key_id(key_id) is not None or device_v2_for_key_id(key_id) is not None for key_id in self.TRANSPORT_KEYS):
                raise ValueError("Shared transport key ID collides with device key namespace")
        self.DEVICE_TRANSPORT_V2_KEYS = {}
        if self.DEVICE_TRANSPORT_V2:
            pairs = [(self.DEVICE_KEY_ID, self.DEVICE_KEY_TEXT),
                     (self.DEVICE_PREVIOUS_KEY_ID, self.DEVICE_PREVIOUS_KEY_TEXT)]
            if not all(pairs[0]) or bool(pairs[1][0]) != bool(pairs[1][1]):
                raise ValueError("Device key generation and secret must be supplied together")
            for generation, text in pairs:
                if not generation:
                    continue
                if not re.fullmatch(r"[1-9][0-9]{0,9}", generation) or generation in self.DEVICE_TRANSPORT_V2_KEYS:
                    raise ValueError("Invalid device key generation")
                try:
                    secret = base64.b64decode(text, validate=True)
                except (ValueError, TypeError):
                    raise ValueError("Device key secret must be Base64") from None
                if (len(secret) != 32 or secret in self.TRANSPORT_KEYS.values() or secret == self.POLICY_HMAC_KEY
                        or secret == signing_seed or secret == getattr(self, "ADMIN_SESSION_KEY", None)
                        or secret in self.DEVICE_TRANSPORT_V2_KEYS.values()):
                    raise ValueError("Device key secret must be a distinct 32-byte secret")
                self.DEVICE_TRANSPORT_V2_KEYS[generation] = secret
        return self
