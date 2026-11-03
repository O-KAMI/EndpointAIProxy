"""Latest reported state analytics, using terminals rather than request counts."""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlsplit
from .security import timestamp
from .validation import normalize_base_url
from .validation import matching_domain

MAX_SUMMARY_PARTITIONS = 4096
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
    if value == "deepseekharness":
        return "DSH"
    return "CC Switch" if value == "ccswitch" else None


def family_name(value):
    return {"claude": "Claude", "codex": "Codex", "qoder": "Qoder", "deepseekharness": "DSH"}.get((value or "").lower(), value or "")


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
    policy = detail.get("effectivePolicy") or policy
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
    def rule_key(target):
        if device.get("appliedPolicySchemaVersion", 1) >= 2:
            return matching_domain(target, policy.get("allowlistedDomains") or [])
        key = allowlist_key(target) if target else None
        return key if key in allowlisted else None
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
            provider=provider(target, bool(rule_key(target))), targetBaseUrl=target,
            allowlistKey=rule_key(target) or (allowlist_key(target) if is_bypassed else None),
            state=a.get("state", "neverObserved"), lastHttpStatusCode=a.get("lastHttpStatusCode"),
            lastErrorCode=a.get("lastErrorCode"), lastOutcome=a.get("lastOutcome"),
            lastFailureAtUtc=a.get("lastFailureAtUtc"), lastRequestAtUtc=a.get("lastRequestAtUtc"),
            observedAtUtc=e.get("observedAtUtc"), everFailed=(a.get("failureCountSinceBoot") or 0) > 0,
            observed=result_scope != "neverObserved", resultScope=result_scope, isCurrent=is_current,
            routeStatus=e.get("routeStatus"), allowlistBypassed=is_bypassed, currentAnomaly=current_anomaly))
    running = sorted({agent_family(a.get("agentType")) for a in agents if a.get("running")}
                     - {None, "CC Switch"})
    providers = sorted({provider(e.get("originalTargetBaseUrl"), bool(rule_key(e.get("originalTargetBaseUrl"))))
        for e in current})
    discovered = ({agent_family(a.get("agentType")) for a in agents if not a.get("running") and a.get("installed")}
                  | {family_name(e.get("agentFamily")) for e in current}) - set(running) - {None, ""}
    return dict(device=device, onlineState=online_state(device, now), runningAgents=running,
        discoveredAgents=sorted(discovered), providers=providers,
        allowlist=sorted({r["allowlistKey"] for r in requests if r["isCurrent"] and r["allowlistBypassed"]}),
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


def build(details, policy, now, scope="online", os=None, _selected=None):
    rows = select(details, policy, now, scope, os) if _selected is None else _selected
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
    allowlist = buckets((v["device"]["deviceId"], r["allowlistKey"], r["agentFamily"])
        for d, v in rows for r in v["requests"] if r["isCurrent"] and r["allowlistBypassed"])
    for url in policy.get("allowlistedDomains", policy.get("allowlistedBaseUrls")) or []:
        if not any(b["key"] == url for b in allowlist):
            allowlist.append(dict(key=url, label=url, deviceCount=0, instanceCount=0, percentage=0, instancePercentage=0, agentFamilies=[]))
    required_schema = 2 if "allowlistedDomains" in policy or "routingRules" in policy else 1
    applied = sum(((d.get("runtime") or {}).get("lastReconcileResult") or "").lower() in {"success", "completed"}
                  and not (d.get("runtime") or {}).get("lastReconcileErrorCode")
                  and v["device"].get("appliedPolicySchemaVersion", 1) >= required_schema
                  and v["device"].get("appliedPolicyVersion") == v["device"].get("expectedPolicyVersion", policy["policyVersion"])
                  and v["device"].get("appliedPolicyVersion") is not None for d, v in rows)
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
        policy=dict(version=policy["policyVersion"], appliedDevices=applied, pendingDevices=total-applied,
            unsupportedDevices=sum(v["device"].get("supportedPolicySchemaVersion", 1) < required_schema for _, v in rows)))



class SummaryAccumulator:
    """Merge summaries for disjoint device sets without retaining the devices."""
    counters = ("totalDevices", "onlineDevices", "runningAgentDevices", "anomalyDevices",
                "everAnomalyDevices", "allowlistDevices", "otherUnproxiedDevices", "unknownDevices", "legacyDevices")

    def __init__(self, policy, now, scope="online"):
        self.result = build([], policy, now, scope)
        self.groups = {name: {} for name in ("agents", "tools", "providers", "errors", "allowlist")}
        self.operating_systems = set()

    def add(self, part):
        result = self.result
        for key in self.counters:
            result[key] += part[key]
        for key in ("appliedDevices", "pendingDevices", "unsupportedDevices"):
            result["policy"][key] += part["policy"][key]
        if part["dataObservedAtUtc"] and (not result["dataObservedAtUtc"] or part["dataObservedAtUtc"] > result["dataObservedAtUtc"]):
            result["dataObservedAtUtc"] = part["dataObservedAtUtc"]
        self.operating_systems.update(part["operatingSystems"])
        for name, merged in self.groups.items():
            for bucket in part[name]:
                current = merged.setdefault(bucket["key"], dict(key=bucket["key"], label=bucket["label"],
                    deviceCount=0, instanceCount=0, agentFamilies=set()))
                current["deviceCount"] += bucket["deviceCount"]
                current["instanceCount"] += bucket["instanceCount"]
                current["agentFamilies"].update(bucket["agentFamilies"])

    def finish(self):
        result = self.result
        total = result["totalDevices"]
        for name, merged in self.groups.items():
            instances = sum(bucket["instanceCount"] for bucket in merged.values())
            for bucket in merged.values():
                bucket["percentage"] = round(100 * bucket["deviceCount"] / total, 1) if total else 0
                bucket["instancePercentage"] = round(100 * bucket["instanceCount"] / instances, 1) if instances else 0
                bucket["agentFamilies"] = sorted(bucket["agentFamilies"])
            if merged:
                result[name] = sorted(merged.values(), key=lambda bucket: (-bucket["deviceCount"], bucket["key"]))
        result["operatingSystems"] = sorted(self.operating_systems)
        return result


def build_batches(batches, policy, now, scope="online", os=None):
    """Merge unique-device batches without retaining the entire inventory in memory."""
    accumulator = SummaryAccumulator(policy, now, scope)
    for batch in batches:
        accumulator.add(build(batch, policy, now, scope, os))
    return accumulator.finish()


def build_partitions(batches, policy, now, observer=None):
    """Build disjoint summaries by OS, online state, and legacy status in one scan."""
    accumulators = {}
    for batch in batches:
        partitions = defaultdict(list)
        projected = [(detail, project(detail, now, policy)) for detail in batch]
        if observer is not None:
            observer(projected)
        for detail, view in projected:
            device = detail["device"]
            key = (device.get("osVersion") or "", view["onlineState"], (device.get("schemaVersion") or 1) < 2)
            partitions[key].append((detail, view))
        for key, pairs in partitions.items():
            if key not in accumulators:
                if len(accumulators) >= MAX_SUMMARY_PARTITIONS:
                    raise RuntimeError("Analytics cache contains too many partitions")
                accumulators[key] = SummaryAccumulator(policy, now, "all")
            rows = [detail for detail, _ in pairs]
            accumulators[key].add(build(rows, policy, now, "all", _selected=pairs))
    return [dict(os=key[0], state=key[1], legacy=key[2], summary=value.finish())
            for key, value in accumulators.items()]


def merge_partitions(partitions, policy, now, scope="online", os=None):
    accumulator = SummaryAccumulator(policy, now, scope)
    systems = set()
    for part in partitions:
        systems.add(part["os"])
        if (scope == "all" or (scope == "legacyclient" and part["legacy"]) or part["state"] == scope):
            if not os or os.lower() in part["os"].lower():
                accumulator.add(part["summary"])
    result = accumulator.finish()
    result["operatingSystems"] = sorted(systems)
    return result


def drill_down(details, policy, now, scope="online", os=None, kind=None, key=None,
               search=None, skip=0, take=50, agent=None, provider=None, anomaly=None, allowlist=None, employeeExact=None):
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
        if search and not any(search.lower() in str(value or "").lower() for value in
                              (v["device"].get("hostname"), v["device"].get("deviceId"), *(v["device"].get("employeeIds") or []))):
            continue
        if employeeExact and not any(employeeExact.lower() == employee.lower() for employee in v["device"].get("employeeIds") or []):
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
