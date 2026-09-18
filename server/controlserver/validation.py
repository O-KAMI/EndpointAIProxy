"""Semantic limits copied from the original control server."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit, quote
from uuid import UUID, uuid4
from .models import PolicyUpdateRequest, RouteMode
from .security import timestamp, utcnow, wire

CCR_BASE_URL = "https://claudecode.sf-express.com/ccr"


class ApiProblem(Exception):
    def __init__(self, code, message, status=400):
        self.code, self.message, self.status = code, message, status
        super().__init__(code)


def fail(code, message):
    raise ApiProblem(code, message)


def normalize_base_url(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError("Each allowlisted Base URL must contain between 1 and 2048 characters.")
    text = value.strip()
    parsed = urlsplit(text)
    if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or "?" in text or "#" in text or any(ord(c) < 32 for c in text)
            or "\\" in text):
        raise ValueError("An allowlisted Base URL must be an absolute HTTP or HTTPS URL without credentials, query, or fragment.")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = "[" + str(ipaddress.IPv6Address(host)) + "]"
    else:
        if not re.fullmatch(r"[a-z0-9_.-]+", host):
            raise ValueError("Invalid URL hostname")
        try:
            host = socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            pass
    port = parsed.port
    authority = host + (f":{port}" if port is not None and port != (443 if scheme == "https" else 80) else "")
    # Uri normalizes dot segments and encodes Unicode/space while retaining escaped path delimiters.
    parts = []
    path = quote(re.sub(r"%(?![0-9a-fA-F]{2})", "%25", parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    for part in path.split("/"):
        dot = re.sub("%2e", ".", part, flags=re.IGNORECASE)
        if dot == "..":
            if parts:
                parts.pop()
        elif dot != ".":
            parts.append(part)
    path = "/".join(parts)
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((scheme, authority, path, "", "")).rstrip("/")


def normalize_allowlist(values):
    result = []
    for value in values:
        if len(result) >= 256:
            raise ValueError("The Base URL allowlist cannot contain more than 256 entries.")
        normalized = normalize_base_url(value)
        if normalized not in result:
            result.append(normalized)
    return result


def validate_policy(update):
    if (update.expectedVersion < 1 or update.expectedVersion >= 2**63 - 1
            or not 15 <= update.pollIntervalSeconds <= 3600
            or not 15 <= update.heartbeatIntervalSeconds <= 3600):
        fail("POLICY_FIELDS_INVALID", "Policy version and intervals are outside the accepted range.")
    if update.allowlistedBaseUrls is not None:
        try:
            normalize_allowlist(update.allowlistedBaseUrls)
        except ValueError as exc:
            fail("POLICY_ALLOWLIST_INVALID", str(exc))
    if update.routeMode != RouteMode.FixedGateway:
        return
    try:
        uri = urlsplit(update.gatewayOrigin or "")
        valid = (uri.scheme.lower() == "https" or (update.allowInsecureGateway and uri.scheme.lower() == "http"))
        valid = valid and bool(uri.hostname) and uri.username is None and uri.password is None
        valid = valid and uri.path in ("", "/") and not uri.query and not uri.fragment
        _ = uri.port
        # The same host grammar as the allowlist; gateway must also have no path.
        if valid:
            normalize_base_url(update.gatewayOrigin)
    except ValueError:
        valid = False
    if not valid:
        fail("POLICY_GATEWAY_INVALID", "Fixed gateway mode requires a valid origin; HTTP must be explicitly allowed.")


def seed_policy(cfg):
    if cfg.SERVER_ID and not UUID(cfg.SERVER_ID).int:
        raise ValueError("Server instance ID cannot be the empty UUID")
    update = PolicyUpdateRequest(
        expectedVersion=cfg.POLICY_VERSION, enabled=cfg.ENABLED, routeMode=cfg.ROUTE_MODE,
        gatewayOrigin=cfg.GATEWAY_ORIGIN, allowInsecureGateway=cfg.ALLOW_INSECURE_GATEWAY,
        pollIntervalSeconds=cfg.POLL_INTERVAL, heartbeatIntervalSeconds=cfg.HEARTBEAT_INTERVAL,
        allowlistedBaseUrls=[CCR_BASE_URL],
    )
    validate_policy(update)
    return dict(schemaVersion=1, serverInstanceId=str(UUID(cfg.SERVER_ID) if cfg.SERVER_ID else uuid4()),
                policyVersion=cfg.POLICY_VERSION,
                **{k: v for k, v in wire(update).items() if k != "expectedVersion"},
                issuedAtUtc=timestamp(utcnow()))


def validate_heartbeat(h, version):
    invalid = (h.schemaVersion != version or not h.heartbeatId.int or not h.device.deviceId.int
               or len(h.agents) > 256 or len(h.users) > 64 or len(h.device.hostname) > 255
               or any(len(a.userSid) > 184 or len(a.displayName) > 128 for a in h.agents))
    if version == 2:
        invalid |= (len(h.endpoints) > 512 or len(h.activity) > 512
                    or len(h.device.serviceVersion) > 64 or h.runtime.uptimeSeconds < 0)
        for endpoint in h.endpoints:
            invalid |= len(endpoint.userSid) > 184 or not 1 <= len(endpoint.agentFamily) <= 32
            for key, limit in (("providerId", 256), ("endpointId", 256), ("configuredModel", 256),
                               ("originalTargetBaseUrl", 2048), ("effectiveConfiguredBaseUrl", 2048), ("localRouteUrl", 2048)):
                value = getattr(endpoint, key)
                invalid |= value is not None and len(value) > limit
    if invalid:
        fail("HEARTBEAT_INVALID" if version == 1 else "HEARTBEAT_V2_INVALID", "The heartbeat exceeds the accepted contract limits.")
