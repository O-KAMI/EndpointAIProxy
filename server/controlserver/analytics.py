"""Latest reported state analytics, using terminals rather than request counts."""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlsplit
from .security import timestamp
from .validation import normalize_base_url

FAILED = {"connectionFailed", "routeFailed", "gatewayReachedWithError"}
DOMAINS = (("api.openai.com", "OpenAI"), ("api.anthropic.com", "Anthropic"),
    ("generativelanguage.googleapis.com", "Google Gemini"), ("aiplatform.googleapis.com", "Google Vertex AI"),
    ("openai.azure.com", "Azure OpenAI"), ("services.ai.azure.com", "Azure AI"),
    ("volces.com", "火山云"), ("moonshot.cn", "Kimi"), ("moonshot.ai", "Kimi"),
    ("deepseek.com", "DeepSeek"), ("dashscope.aliyuncs.com", "阿里云百炼"),
    ("dashscope-intl.aliyuncs.com", "阿里云百炼"), ("api.z.ai", "智谱"), ("open.bigmodel.cn", "智谱"),
    ("api.minimax.io", "MiniMax"), ("api.minimaxi.com", "MiniMax"), ("api.x.ai", "xAI"))


def online_state(device, now):
    seen = datetime.fromisoformat(device["lastSeenAtUtc"].replace("Z", "+00:00"))
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    elapsed = (now - seen).total_seconds()
    interval = max(15, min(3600, device.get("heartbeatIntervalSeconds") or 60))
    return "online" if elapsed <= interval * 2 + 30 else "stale" if elapsed <= interval * 5 + 30 else "offline"


def agent_family(value):
    value = (value or "").lower()
    if value in {"claudecode", "claudecli", "claudeide", "claudedesktop"}:
        return "Claude"
    if value in {"codexcli", "codexide", "codexdesktop"}:
        return "Codex"
    if value in {"qodercli", "qoderide"}:
        return "Qoder"
    return "CC Switch" if value == "ccswitch" else None


def family_name(value):
    return {"claude": "Claude", "codex": "Codex", "qoder": "Qoder"}.get((value or "").lower(), value or "")


def provider(target, allowlisted=False):
    try:
        uri = urlsplit(target or "")
        if uri.scheme.lower() not in {"http", "https"} or not uri.hostname:
            return "无法识别"
        host = uri.hostname.encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return "无法识别"
    try:
        if ipaddress.ip_address(host).is_loopback:
            return "本地代理地址 · " + host
    except ValueError:
        pass
    if allowlisted:
        return "白名单目标 · " + host
    for domain, name in DOMAINS:
        if host == domain or host.endswith("." + domain):
            return name
    return "自定义目标 · " + host


def allowlist_key(value):
    try:
        return normalize_base_url(value)
    except ValueError:
        return value


def bypassed(endpoint):
    return (endpoint.get("allowlistBypassed") is True and endpoint.get("routeStatus") == "bypassed"
            and bool((endpoint.get("originalTargetBaseUrl") or "").strip()))


def unique(values, key):
    return list({v.get(key): v for v in values}.values())


def project(detail, now, policy):
    device = detail["device"]
    agents = detail.get("agents") or []
    endpoints = unique(detail.get("endpoints") or [], "assetId")
    current = [e for e in endpoints if e.get("isCurrent")]
    activity = {}
    for a in detail.get("activity") or []:
        old = activity.get(a.get("assetId"))
        if old is None or (a.get("lastRequestAtUtc") or "") > (old.get("lastRequestAtUtc") or ""):
            activity[a.get("assetId")] = a
    allowlisted = {allowlist_key(value) for value in policy.get("allowlistedBaseUrls") or []}
    requests = []
    for e in endpoints:
        a = activity.get(e.get("assetId"), {})
        request_count = a.get("requestCountSinceBoot") or 0
        result_scope = "currentRun" if request_count > 0 else "previousRun" if a.get("lastRequestAtUtc") else "neverObserved"
        is_current = e.get("isCurrent") is True
        is_bypassed = bypassed(e)
        current_anomaly = (is_current and not is_bypassed and e.get("routeStatus") == "attached"
            and result_scope == "currentRun" and a.get("state") in FAILED)
        target = e.get("originalTargetBaseUrl")
        requests.append(dict(assetId=e.get("assetId"), agentFamily=family_name(e.get("agentFamily")),
            provider=provider(target, allowlist_key(target) in allowlisted if target else False), targetBaseUrl=target,
            state=a.get("state", "neverObserved"), lastHttpStatusCode=a.get("lastHttpStatusCode"),
            lastErrorCode=a.get("lastErrorCode"), lastOutcome=a.get("lastOutcome"),
            lastFailureAtUtc=a.get("lastFailureAtUtc"), lastRequestAtUtc=a.get("lastRequestAtUtc"),
            observedAtUtc=e.get("observedAtUtc"), everFailed=(a.get("failureCountSinceBoot") or 0) > 0,
            observed=result_scope != "neverObserved", resultScope=result_scope, isCurrent=is_current,
            routeStatus=e.get("routeStatus"), allowlistBypassed=is_bypassed, currentAnomaly=current_anomaly))
    running = sorted({agent_family(a.get("agentType")) for a in agents if a.get("running")}
                     - {None, "CC Switch"})
    providers = sorted({provider(e.get("originalTargetBaseUrl"),
        allowlist_key(e.get("originalTargetBaseUrl")) in allowlisted if e.get("originalTargetBaseUrl") else False)
        for e in current})
    discovered = ({agent_family(a.get("agentType")) for a in agents if not a.get("running") and a.get("installed")}
                  | {family_name(e.get("agentFamily")) for e in current}) - set(running) - {None, ""}
    return dict(device=device, onlineState=online_state(device, now), runningAgents=running,
        discoveredAgents=sorted(discovered), providers=providers,
        allowlist=sorted({allowlist_key(e["originalTargetBaseUrl"]) for e in current if bypassed(e)}),
        hasAnomaly=any(r["currentAnomaly"] for r in requests),
        everAnomaly=any(r["everFailed"] for r in requests),
        otherUnproxied=device.get("operationState") in {"disabled", "disableFailed", "enableFailed"}
            or device.get("proxyState") in {"stopped", "degraded"}
            or any(not bypassed(e) and e.get("routeStatus") != "attached" for e in current),
        dataInsufficient=(device.get("schemaVersion") or 1) < 2
            or any(p == "无法识别" or p.startswith("本地代理地址") for p in providers)
            or any(e.get("assetId") not in activity for e in current), requests=requests)


def select(details, policy, now, scope="online", os=None):
    rows = []
    for detail in {d["device"]["deviceId"]: d for d in details}.values():
        view = project(detail, now, policy)
        if (scope == "all" or (scope == "legacyclient" and (view["device"].get("schemaVersion") or 1) < 2)
                or view["onlineState"] == scope):
            if not os or os.lower() in (view["device"].get("osVersion") or "").lower():
                rows.append((detail, view))
    return rows


def build(details, policy, now, scope="online", os=None):
    rows = select(details, policy, now, scope, os)
    total = len(rows)
    def percent(n, denominator=total):
        return round(100 * n / denominator, 1) if denominator else 0
    def buckets(entries):
        groups = defaultdict(list)
        for device, key, family in entries:
            groups[key].append((device, family))
        return sorted([dict(key=k, label=k, deviceCount=len({d for d, _ in g}), instanceCount=0,
            percentage=percent(len({d for d, _ in g})), instancePercentage=0,
            agentFamilies=sorted({f for _, f in g if f})) for k, g in groups.items()],
            key=lambda b: (-b["deviceCount"], b["key"]))
    instances = [(v["device"]["deviceId"], agent_family(a.get("agentType"))) for d, v in rows
        for a in unique(d.get("agents") or [], "instanceId") if a.get("running") and agent_family(a.get("agentType"))]
    def agent_buckets(tools):
        selected = [(d, f) for d, f in instances if (f == "CC Switch") == tools]
        result = buckets((d, f, f) for d, f in selected)
        for b in result:
            b["instanceCount"] = sum(f == b["key"] for _, f in selected)
            b["instancePercentage"] = percent(b["instanceCount"], len(selected))
        return result
    allowlist = buckets((v["device"]["deviceId"], allowlist_key(e["originalTargetBaseUrl"]), family_name(e.get("agentFamily")))
        for d, v in rows for e in unique(d.get("endpoints") or [], "assetId") if e.get("isCurrent") and bypassed(e))
    for url in policy.get("allowlistedBaseUrls") or []:
        if not any(b["key"] == url for b in allowlist):
            allowlist.append(dict(key=url, label=url, deviceCount=0, instanceCount=0, percentage=0, instancePercentage=0, agentFamilies=[]))
    applied = sum(v["device"].get("appliedPolicyVersion") == policy["policyVersion"] for _, v in rows)
    return dict(updatedAtUtc=timestamp(now), dataObservedAtUtc=max((v["device"]["lastSeenAtUtc"] for _, v in rows), default=None),
        scope=scope, totalDevices=total,
        onlineDevices=sum(v["onlineState"] == "online" for _, v in rows),
        runningAgentDevices=sum(bool(v["runningAgents"]) for _, v in rows),
        anomalyDevices=sum(v["hasAnomaly"] for _, v in rows), everAnomalyDevices=sum(v["everAnomaly"] for _, v in rows),
        allowlistDevices=sum(bool(v["allowlist"]) for _, v in rows), otherUnproxiedDevices=sum(v["otherUnproxied"] for _, v in rows),
        unknownDevices=sum(v["dataInsufficient"] for _, v in rows),
        legacyDevices=sum((v["device"].get("schemaVersion") or 1) < 2 for _, v in rows), agents=agent_buckets(False), tools=agent_buckets(True),
        providers=buckets((v["device"]["deviceId"], p, "") for _, v in rows for p in v["providers"]),
        errors=buckets((v["device"]["deviceId"], r["state"][0].upper() + r["state"][1:], r["agentFamily"])
            for _, v in rows for r in v["requests"] if r["currentAnomaly"]),
        allowlist=sorted(allowlist, key=lambda b: (-b["deviceCount"], b["key"])),
        operatingSystems=sorted({d["device"].get("osVersion") or "" for d in details}),
        policy=dict(version=policy["policyVersion"], appliedDevices=applied, pendingDevices=total-applied))


def drill_down(details, policy, now, scope="online", os=None, kind=None, key=None,
               search=None, skip=0, take=50, agent=None, provider=None, anomaly=None, allowlist=None):
    selected = []
    for detail, v in select(details, policy, now, scope, os):
        matches = {"online": v["onlineState"] == "online", "running": bool(v["runningAgents"]),
            "agent": key in v["runningAgents"], "tool": any(a.get("running") and agent_family(a.get("agentType")) == key for a in detail.get("agents") or []),
            "provider": key in v["providers"], "error": any(r["currentAnomaly"] and r["state"].lower() == (key or "").lower() for r in v["requests"]),
            "anomaly": v["hasAnomaly"], "everAnomaly": v["everAnomaly"],
            "allowlist": bool(v["allowlist"]) if key is None else key in v["allowlist"],
            "otherUnproxied": v["otherUnproxied"], "unknown": v["dataInsufficient"]}
        if not matches.get(kind, True):
            continue
        if search and not any(search.lower() in str(v["device"].get(k) or "").lower() for k in ("hostname", "deviceId")):
            continue
        if agent and agent not in v["runningAgents"] or provider and provider not in v["providers"]:
            continue
        if anomaly == "latest" and not v["hasAnomaly"] or anomaly == "ever" and not v["everAnomaly"]:
            continue
        if anomaly == "none" and (v["hasAnomaly"] or not any(r["observed"] for r in v["requests"])):
            continue
        if allowlist and not (v["allowlist"] if allowlist == "any" else allowlist in v["allowlist"]):
            continue
        selected.append(v)
    selected.sort(key=lambda v: v["device"]["deviceId"])
    selected.sort(key=lambda v: v["device"]["lastSeenAtUtc"], reverse=True)
    skip, take = max(0, skip), min(500, max(1, take))
    return dict(total=len(selected), skip=skip, take=take, updatedAtUtc=timestamp(now), devices=selected[skip:skip+take])
