"""Explicitly refreshed, local, bounded analytics read model."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from uuid import uuid4
from .analytics import MAX_SUMMARY_PARTITIONS, merge_partitions
from .security import timestamp, utcnow
from .validation import ApiProblem

MAX_BYTES = 32 * 1024 * 1024


def identity(cfg):
    value = f"{cfg.MYSQL_HOST}:{cfg.MYSQL_PORT}/{cfg.MYSQL_DATABASE}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def publish_file(directory, name, encoded):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(dir=directory, prefix=".analytics-")
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, directory / name)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def check_generation(cfg, database, generation):
    if not (cfg.ANALYTICS_CACHE and cfg.ANALYTICS_DETAIL_CACHE):
        return
    with (cfg.DATA_ROOT / 'analytics-generation.json').open('rb') as source:
        raw = source.read(2049)
    if len(raw) > 2048 or json.loads(raw) != {'database': database, 'generation': generation} or not generation:
        raise ValueError('incomplete analytics cache generation')


def refresh_cache(store):
    cfg = store.cfg
    lock_name = "eai-analytics-" + identity(cfg)[:40]
    with store.transaction() as lock_cursor:
        lock_cursor.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock_name,))
        if lock_cursor.fetchone()["acquired"] != 1:
            raise RuntimeError("Another analytics refresh is already running")
        writer = None
        try:
            now = utcnow()
            generation = uuid4().hex
            if cfg.ANALYTICS_DETAIL_CACHE:
                from .analytics_detail_cache import DetailCacheWriter
                writer = DetailCacheWriter(cfg, now, identity(cfg), generation)
            partitions, policy = store.analytics_aggregate(now, partitions=True, observer=writer.add_projected if writer else None)
            if len(partitions) > MAX_SUMMARY_PARTITIONS:
                raise RuntimeError("Analytics cache contains too many partitions")
            payload = dict(formatVersion=1, database=identity(cfg), generation=generation, updatedAtUtc=timestamp(now),
                           policy={key: policy[key] for key in ("policyVersion", "allowlistedDomains", "allowlistedBaseUrls", "routingRules") if key in policy and key != "routingRules"},
                           partitions=partitions)
            if "routingRules" in policy:
                payload["policy"]["routingRules"] = []
            encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_BYTES:
                raise RuntimeError("Analytics cache exceeds size limit")
            lock_cursor.execute("SELECT IS_USED_LOCK(%s) = CONNECTION_ID() AS owned", (lock_name,))
            if lock_cursor.fetchone()["owned"] != 1:
                raise RuntimeError("Analytics refresh lock was lost")
            if writer:
                writer.publish()
            directory = cfg.DATA_ROOT
            publish_file(directory, 'analytics-cache.json', encoded)
            if writer:
                publish_file(directory, 'analytics-generation.json', json.dumps(
                    {'database': identity(cfg), 'generation': generation}, separators=(',', ':')).encode('utf-8'))
            return dict(updatedAtUtc=payload["updatedAtUtc"], partitions=len(partitions), bytes=len(encoded))
        finally:
            try:
                if writer:
                    writer.close()
            finally:
                lock_cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))


def read_cache(cfg, now, scope="online", os=None):
    try:
        path = cfg.DATA_ROOT / "analytics-cache.json"
        with path.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("oversized")
        payload = json.loads(raw)
        if payload["formatVersion"] != 1 or payload["database"] != identity(cfg) or len(payload["partitions"]) > MAX_SUMMARY_PARTITIONS:
            raise ValueError("invalid cache")
        check_generation(cfg, payload['database'], payload.get('generation'))
        created = datetime.fromisoformat(payload["updatedAtUtc"].replace("Z", "+00:00"))
        if created.tzinfo is None:
            raise ValueError("invalid timestamp")
        age = (now - created.astimezone(timezone.utc)).total_seconds()
        if age < -60:
            raise ValueError("future timestamp")
        result = merge_partitions(payload["partitions"], payload["policy"], created, scope, os)
        result["cacheAgeSeconds"] = max(0, int(age))
        result["cacheStale"] = age > 300
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError):
        raise ApiProblem("ANALYTICS_CACHE_UNAVAILABLE", "Analytics snapshot unavailable; run the refresh job.", 503) from None
