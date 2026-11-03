"""Synthetic inventory pagination probe against an explicitly isolated loopback MySQL."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
import time
from uuid import UUID, uuid4

import pymysql

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import Config
from controlserver.analytics import drill_down
from controlserver.database import ControlStore, dbtime
from controlserver.models import PolicyUpdateRequest, CreateRolloutRequest, CreatePolicyRolloutRequest
from controlserver import rollout, policy_rollout
from tools.rollout_batch_probe import heartbeat_row_load, WorkersNotStopped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-mysql", action="store_true",
                        help="Confirm the loopback MySQL is a disposable test instance")
    parser.add_argument("--port", type=int, default=13306)
    parser.add_argument("--devices", type=int, default=150000)
    parser.add_argument("--online", type=int, default=100000)
    parser.add_argument("--assets-per-device", type=int, default=1)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--policy-samples", type=int, default=1000)
    parser.add_argument("--idle-lease-samples", type=int, default=0,
                        help="Compare command-free lease paths on synthetic devices")
    parser.add_argument("--duplicate-overrides", action="store_true", help="Measure repeated device override validation")
    parser.add_argument("--summary", action="store_true", help="Measure batched analytics summary")
    parser.add_argument("--summary-cache", action="store_true", help="Measure analytics cache refresh and reads")
    parser.add_argument("--complex-filter", action="store_true", help="Measure bounded complex filtering")
    parser.add_argument("--detail-cache", action="store_true", help="Measure indexed detail cache refresh and filtering")
    parser.add_argument("--compare-search", action="store_true", help="Compare broad search pagination with the previous two-query path")
    parser.add_argument("--explain-search", action="store_true", help="Run EXPLAIN ANALYZE for synthetic broad indexed search")
    parser.add_argument("--compare-correlated-search", action="store_true", help="Compare indexed per-device lookup against the previous materialized membership search")
    parser.add_argument("--compare-json-search", action="store_true", help="Compare candidate JSON_SEARCH on synthetic indexed data")
    parser.add_argument("--compare-ascii-json-search", action="store_true", help="Compare experimental ASCII-only JSON prefilter on synthetic indexed data")
    parser.add_argument("--rollout-targets", type=int, default=0)
    parser.add_argument("--rollout-filter-probe", action="store_true", help="Measure mixed-status command batch filters")
    parser.add_argument("--policy-rollout-targets", type=int, default=0)
    parser.add_argument("--policy-rollout-dispatches", type=int, default=20)
    parser.add_argument("--policy-rate", type=int, default=20)
    parser.add_argument("--policy-respect-rate", action="store_true", help="Preserve dispatch schedule and application worker delays")
    parser.add_argument("--policy-profile", action="store_true", help="Aggregate synthetic policy dispatch SQL phase durations")
    parser.add_argument("--policy-heartbeat-workers", type=int, default=0)
    parser.add_argument("--policy-heartbeat-rps", type=int, default=0)
    parser.add_argument("--policy-timeout", type=int, default=600)
    args = parser.parse_args()
    if (not args.isolated_mysql or not 1 <= args.port <= 65535
            or not 25 <= args.online <= args.devices <= 300000
            or not 0 <= args.assets_per_device <= 5 or not 1 <= args.samples <= 100
            or not 0 <= args.policy_samples <= 10000 or not 0 <= args.idle_lease_samples <= 10000
            or not 0 <= args.rollout_targets <= args.devices
            or (args.rollout_filter_probe and args.rollout_targets < 75)
            or not 0 <= args.policy_rollout_targets <= min(args.devices, 150000)
            or not 0 <= args.policy_rollout_dispatches <= 1000 or not 1 <= args.policy_rate <= 5000
            or not 1 <= args.policy_timeout <= 600
            or not 0 <= args.policy_heartbeat_workers <= 32 or not 0 <= args.policy_heartbeat_rps <= 2000
            or bool(args.policy_heartbeat_workers) != bool(args.policy_heartbeat_rps)
            or (args.policy_heartbeat_workers and (not args.policy_respect_rate
                or not args.policy_rollout_targets or not args.policy_rollout_dispatches))):
        parser.error("Confirm an isolated MySQL and provide valid device, asset and sample counts.")

    for key in list(os.environ):
        if key.startswith(("SF_CONTROL_", "EAI_MYSQL_")) or key in ("APP_ENV", "APP_CONFIG"):
            os.environ.pop(key)
    user = os.environ.get("ENDPOINTAI_TEST_MYSQL_USER", "root")
    password = os.environ.get("ENDPOINTAI_TEST_MYSQL_PASSWORD", "")
    name = "eai_scale_" + uuid4().hex
    assert re.fullmatch(r"eai_scale_[0-9a-f]{32}", name)
    connection = pymysql.connect(host="127.0.0.1", port=args.port, user=user, password=password,
                                 autocommit=True, connect_timeout=3)
    created = False
    try:
        with connection.cursor() as cur:
            cur.execute("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
            created = True
        with TemporaryDirectory(prefix="eai-scale-probe-") as temporary:
            cfg = Config(env="sit", conf_dir=Path(temporary))
            cfg.CLIENT_TOKEN, cfg.ADMIN_TOKEN = "synthetic-client", "synthetic-admin"
            cfg.HMAC_TEXT = base64.b64encode(bytes(range(32))).decode("ascii")
            cfg.TRANSPORT_KEY_TEXT = cfg.HMAC_TEXT
            cfg.MYSQL_HOST, cfg.MYSQL_PORT = "127.0.0.1", args.port
            cfg.MYSQL_USER, cfg.MYSQL_PASSWORD, cfg.MYSQL_DATABASE = user, password, name
            cfg.LOG_DIR, cfg.DATA_ROOT = Path(temporary) / "logs", Path(temporary) / "data"
            cfg.BACKUP_DIR = cfg.DATA_ROOT / "backups"
            cfg.POLICY_ROLLOUT_MAX_RATE = args.policy_rate
            cfg.validate()
            store = ControlStore(cfg)
            store.initialize_empty()
            def heartbeat(i):
                return json.dumps({"schemaVersion": 2, "users": [{"sid": "synthetic-sid", "accountName": "employee-%08d" % i}],
                    "agents": [], "runtime": {"supportedPolicySchemaVersion": 2},
                    "policy": {"appliedSchemaVersion": 2}}, separators=(",", ":"))
            runtime = json.dumps({"lastReconcileResult": "completed", "lastReconcileErrorCode": None},
                                 separators=(",", ":"))
            now = datetime.now(timezone.utc)
            started = time.perf_counter()
            with store.transaction() as cur:
                for base in range(0, args.devices, 1000):
                    end = min(base + 1000, args.devices)
                    pairs = [(i, str(UUID(int=i + 1))) for i in range(base, end)]
                    cur.executemany("INSERT INTO device_heartbeats VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        [(device, dbtime(now - timedelta(seconds=5 if i < args.online else 3600)),
                          "fixture-" + str(i), "Windows 11", 1, "listening", heartbeat(i)) for i, device in pairs])
                    cur.executemany("INSERT INTO device_runtime VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        [(device, 2, "synthetic", 60, "enabled", None, runtime) for _, device in pairs])
                    assets, activity = [], []
                    for i, device in pairs:
                        for ordinal in range(args.assets_per_device):
                            asset = str(UUID(int=(i + 1) * 8 + ordinal))
                            data = dict(assetId=asset, userSid="synthetic", agentFamily="claude",
                                configurationSource="direct", providerId="fixture", endpointId=None,
                                isCurrent=True, originalTargetBaseUrl="https://example.invalid/v1",
                                allowlistBypassed=False, routeStatus="attached", observedAtUtc=now.isoformat())
                            assets.append((device, asset, "claude", json.dumps(data, separators=(",", ":"))))
                            failure = i % 1000 == 0
                            activity.append((device, asset, json.dumps(dict(assetId=asset,
                                state="connectionFailed" if failure else "neverObserved",
                                requestCountSinceBoot=1 if failure else 0,
                                failureCountSinceBoot=1 if failure else 0), separators=(",", ":"))))
                    if assets:
                        cur.executemany("INSERT INTO agent_endpoint_assets VALUES (%s,%s,%s,%s)", assets)
                        cur.executemany("INSERT INTO proxy_activity VALUES (%s,%s,%s)", activity)
            print(json.dumps(dict(stage="synthetic_rows_loaded", devices=args.devices, online=args.online,
                                  assetsPerDevice=args.assets_per_device,
                                  seconds=round(time.perf_counter() - started, 3))), flush=True)
            if args.idle_lease_samples:
                def previous_idle_lease(device):
                    with store.transaction() as cur:
                        cur.execute('SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE', (device,))
                        if not cur.fetchone(): raise RuntimeError('Missing synthetic device')
                        store._expire(cur, device, dbtime(datetime.now(timezone.utc)))
                        cur.execute("""SELECT * FROM remote_commands WHERE device_id=%s
                            AND status IN ('pending','delivered','executing') ORDER BY created_at_utc LIMIT 1 FOR UPDATE""", (device,))
                        if cur.fetchone(): raise RuntimeError('Probe requires no commands')
                def measure(mode):
                    def sample(i):
                        device = str(UUID(int=i % args.online + 1))
                        started = time.perf_counter()
                        if mode == 'previous': previous_idle_lease(device)
                        elif store.lease(device) is not None: raise RuntimeError('Unexpected command')
                        return time.perf_counter() - started
                    started = time.perf_counter()
                    with ThreadPoolExecutor(max_workers=8) as executor:
                        durations = sorted(executor.map(sample, range(args.idle_lease_samples)))
                    return dict(totalSeconds=round(time.perf_counter()-started, 3),
                        p95Milliseconds=round(durations[int((len(durations)-1)*0.95)]*1000, 3),
                        p99Milliseconds=round(durations[int((len(durations)-1)*0.99)]*1000, 3))
                previous_first, current_first = measure('previous'), measure('current')
                current_second, previous_second = measure('current'), measure('previous')
                print(json.dumps(dict(stage='idle_command_lease', samplesPerRun=args.idle_lease_samples, workers=8,
                    previous=[previous_first, previous_second], current=[current_first, current_second],
                    runOrder=['previous','current','current','previous'], includesHttp=False,
                    concurrentHeartbeats=False, concurrentCommandCreation=False)), flush=True)
            if args.detail_cache:
                from controlserver.analytics_cache import refresh_cache, identity
                from controlserver.analytics_detail_cache import read_detail_cache
                cfg.ANALYTICS_DETAIL_CACHE = True
                started = time.perf_counter()
                refresh_cache(store)
                refresh_seconds = round(time.perf_counter() - started, 3)
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    page = read_detail_cache(cfg, datetime.now(timezone.utc), identity(cfg), scope="online",
                                             provider="自定义目标 · example.invalid", skip=0, take=25)
                    timings.append(round(time.perf_counter() - started, 3))
                    if page["total"] != args.online or len(page["devices"]) != 25:
                        raise RuntimeError("Unexpected synthetic cached filter result")
                print(json.dumps(dict(stage="detail_cache", total=page["total"], refreshSeconds=refresh_seconds,
                    readSeconds=timings, bytes=(cfg.DATA_ROOT / "analytics-detail.sqlite3").stat().st_size,
                    includesHttp=False, concurrentHeartbeats=False)), flush=True)
                for term, offset, expected in (("employee-00000001", 0, 1), ("employee-", 0, args.online),
                                               ("employee-", args.online - 25, args.online)):
                    times = []
                    for _ in range(args.samples):
                        started = time.perf_counter()
                        result = read_detail_cache(cfg, datetime.now(timezone.utc), identity(cfg), scope="online",
                                                   search=term, skip=offset, take=25)
                        times.append(round(time.perf_counter() - started, 3))
                        if result["total"] != expected or len(result["devices"]) != min(25, max(0, expected - offset)):
                            raise RuntimeError("Unexpected synthetic snapshot search result")
                    print(json.dumps(dict(stage="detail_cache_search", broad=term == "employee-", offset=offset,
                        total=expected, seconds=times, includesHttp=False, concurrentHeartbeats=False)), flush=True)
                import sqlite3
                with closing(sqlite3.connect(cfg.DATA_ROOT / "analytics-detail.sqlite3")) as snapshot:
                    meta = dict(snapshot.execute("SELECT key,value FROM meta"))
                    if meta.get("searchIndex") == "fts5-trigram-v1":
                        clause = """ FROM devices d WHERE d.state=?
                            AND d.rowid IN (SELECT rowid FROM search_fts WHERE search_fts MATCH ?)
                            AND EXISTS (SELECT 1 FROM json_each(d.searchable) WHERE instr(value,?)>0)"""
                        params = ("online", '"employee-"', "employee-")
                        for offset in (0, args.online - 25):
                            results = []
                            for window in (False, True):
                                times = []
                                for _ in range(args.samples):
                                    started = time.perf_counter()
                                    if window:
                                        result = snapshot.execute("SELECT d.id,COUNT(*) OVER()" + clause +
                                            " ORDER BY d.seen DESC,d.id LIMIT ? OFFSET ?", (*params, 25, offset)).fetchall()
                                        ids, total = [row[0] for row in result], result[0][1] if result else 0
                                    else:
                                        total = snapshot.execute("SELECT COUNT(*)" + clause, params).fetchone()[0]
                                        ids = [row[0] for row in snapshot.execute("SELECT d.id" + clause +
                                            " ORDER BY d.seen DESC,d.id LIMIT ? OFFSET ?", (*params, 25, offset))]
                                    times.append(round(time.perf_counter() - started, 3))
                                results.append((times, total, ids))
                            if results[0][1:] != results[1][1:]: raise RuntimeError("Snapshot search comparison mismatch")
                            print(json.dumps(dict(stage="detail_cache_window_comparison", offset=offset,
                                previousSeconds=results[0][0], candidateSeconds=results[1][0], total=results[0][1],
                                includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.complex_filter:
                started = time.perf_counter()
                page = store.analytics_filtered_page(now, scope="online", skip=0, take=25,
                                                     provider="自定义目标 · example.invalid")
                seconds = round(time.perf_counter() - started, 3)
                if page["total"] != args.online or len(page["devices"]) != 25:
                    raise RuntimeError("Unexpected synthetic complex filter result")
                print(json.dumps(dict(stage="complex_filter", total=page["total"], seconds=seconds,
                    returned=len(page["devices"]), includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.summary_cache:
                from controlserver.analytics_cache import refresh_cache, read_cache
                started = time.perf_counter()
                cache_info = refresh_cache(store)
                refresh_seconds = round(time.perf_counter() - started, 3)
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    summary = read_cache(cfg, datetime.now(timezone.utc), scope="online")
                    timings.append(round(time.perf_counter() - started, 3))
                    if summary["totalDevices"] != args.online:
                        raise RuntimeError("Unexpected synthetic cached summary count")
                print(json.dumps(dict(stage="summary_cache", total=summary["totalDevices"],
                    refreshSeconds=refresh_seconds, readSeconds=timings, bytes=cache_info["bytes"],
                    includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.summary:
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    summary = store.analytics_aggregate(now, scope="online")
                    timings.append(round(time.perf_counter() - started, 3))
                    if summary["totalDevices"] != args.online:
                        raise RuntimeError("Unexpected synthetic summary count")
                print(json.dumps(dict(stage="batched_summary", total=summary["totalDevices"],
                    seconds=timings, includesHttp=False, concurrentHeartbeats=False)), flush=True)
            for offset in (0, args.online - 25):
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    rows, policy, total = store.analytics_page("online", None, now, offset, 25)
                    page = drill_down(rows, policy, now, scope="all", take=25)
                    timings.append(round(time.perf_counter() - started, 3))
                    if total != args.online or len(page["devices"]) != 25:
                        raise RuntimeError("Unexpected synthetic pagination result")
                print(json.dumps(dict(stage="page_query", offset=offset, total=total,
                    returned=len(page["devices"]), seconds=timings, includesHttp=False,
                    concurrentHeartbeats=False)), flush=True)
            timings = []
            for _ in range(args.samples):
                started = time.perf_counter()
                rows, policy, total = store.analytics_page("online", None, now, 0, 25,
                                                           employee_search="employee-00000001")
                page = drill_down(rows, policy, now, scope="all", take=25)
                timings.append(round(time.perf_counter() - started, 3))
                if total != 1 or len(page["devices"]) != 1:
                    raise RuntimeError("Unexpected synthetic employee search result")
            print(json.dumps(dict(stage="employee_search", total=total, seconds=timings,
                                  includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.assets_per_device:
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    rows, policy, total = store.analytics_page("online", None, now, 0, 25, anomaly="latest")
                    page = drill_down(rows, policy, now, scope="all", take=25)
                    timings.append(round(time.perf_counter() - started, 3))
                    expected = (args.online + 999) // 1000
                    if total != expected or len(page["devices"]) != min(expected, 25):
                        raise RuntimeError("Unexpected synthetic failure filter result")
                print(json.dumps(dict(stage="failure_filter_without_index", total=total, seconds=timings,
                                      includesHttp=False, concurrentHeartbeats=False)), flush=True)
            started = time.perf_counter()
            store.ensure_scale_indexes()
            cfg.EMPLOYEE_INDEX = True
            store.check_schema()
            backfill = time.perf_counter() - started
            timings = []
            for _ in range(args.samples):
                started = time.perf_counter()
                rows, policy, total = store.analytics_page("online", None, now, 0, 25,
                                                           employee_search="employee-00000001")
                page = drill_down(rows, policy, now, scope="all", take=25)
                timings.append(round(time.perf_counter() - started, 3))
                if total != 1 or len(page["devices"]) != 1:
                    raise RuntimeError("Unexpected synthetic indexed employee search result")
            print(json.dumps(dict(stage="employee_index_search", total=total, seconds=timings,
                                  backfillSeconds=round(backfill, 3), includesHttp=False,
                                  concurrentHeartbeats=False)), flush=True)
            if args.explain_search:
                original_transaction = store.transaction
                class ExplainSearchCursor:
                    def __init__(self, cursor): self.cursor = cursor
                    def __getattr__(self, name): return getattr(self.cursor, name)
                    def execute(self, sql, params=None):
                        if sql.startswith("SELECT h.device_id,COUNT(*) OVER() AS total"):
                            self.cursor.execute("EXPLAIN ANALYZE " + sql, params)
                            print(json.dumps(dict(stage="broad_search_plan", plan=self.cursor.fetchone()["EXPLAIN"],
                                includesHttp=False, concurrentHeartbeats=False)), flush=True)
                        return self.cursor.execute(sql, params)
                @contextmanager
                def explain_transaction():
                    with original_transaction() as cursor:
                        yield ExplainSearchCursor(cursor)
                store.transaction = explain_transaction
                rows, _, total = store.analytics_page("online", None, now, 0, 25, employee_search="employee-")
                store.transaction = original_transaction
                if total != args.online or len(rows) != 25:
                    raise RuntimeError("Unexpected synthetic search plan result")
            if args.compare_correlated_search:
                original_transaction = store.transaction
                current = """EXISTS (
                        SELECT 1 FROM employee_search_index ei,
                        JSON_TABLE(ei.employees_json, '$[*]' COLUMNS (
                            account_name LONGTEXT PATH '$')) u
                        WHERE ei.device_id=h.device_id
                        AND INSTR(LOWER(u.account_name) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0)"""
                previous = """h.device_id IN (
                        SELECT ei.device_id FROM employee_search_index ei,
                        JSON_TABLE(ei.employees_json, '$[*]' COLUMNS (
                            account_name LONGTEXT PATH '$')) u
                        WHERE INSTR(LOWER(u.account_name) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0)"""
                class MembershipCursor:
                    def __init__(self, cursor): self.cursor = cursor
                    def __getattr__(self, name): return getattr(self.cursor, name)
                    def execute(self, sql, params=None):
                        if sql.startswith("SELECT h.device_id,COUNT(*) OVER() AS total"):
                            if sql.count(current) != 1: raise RuntimeError("Search query changed")
                            sql = sql.replace(current, previous)
                        return self.cursor.execute(sql, params)
                @contextmanager
                def membership_transaction():
                    with original_transaction() as cursor: yield MembershipCursor(cursor)
                try:
                    for term, offset in (("employee-00000001", 0), ("employee-", 0),
                                         ("employee-", args.online - 25), ("fixture-", 0)):
                        outputs = []
                        for label, transaction in (("previous", membership_transaction), ("current", original_transaction),
                                                   ("current", original_transaction), ("previous", membership_transaction)):
                            store.transaction = transaction
                            timings = []
                            for _ in range(args.samples):
                                started = time.perf_counter()
                                rows, _, total = store.analytics_page("online", None, now, offset, 25, employee_search=term)
                                timings.append(round(time.perf_counter() - started, 3))
                            outputs.append((label, timings, total, [row["device"]["deviceId"] for row in rows]))
                        if any(output[2:] != outputs[0][2:] for output in outputs):
                            raise RuntimeError("Correlated search result mismatch")
                        print(json.dumps(dict(stage="correlated_search_comparison", term=term, offset=offset,
                            timings=[output[:2] for output in outputs], total=outputs[0][2], includesHttp=False,
                            concurrentHeartbeats=False)), flush=True)
                finally:
                    store.transaction = original_transaction
            if args.compare_json_search:
                original_transaction = store.transaction
                class JsonSearchCursor:
                    def __init__(self, cursor): self.cursor = cursor
                    def __getattr__(self, name): return getattr(self.cursor, name)
                    def execute(self, sql, params=None):
                        original = """SELECT 1 FROM employee_search_index ei,
                        JSON_TABLE(ei.employees_json, '$[*]' COLUMNS (
                            account_name LONGTEXT PATH '$')) u
                        WHERE ei.device_id=h.device_id
                        AND INSTR(LOWER(u.account_name) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0"""
                        candidate = """SELECT 1 FROM employee_search_index ei
                        WHERE ei.device_id=h.device_id AND JSON_SEARCH(LOWER(CAST(ei.employees_json AS CHAR CHARACTER SET utf8mb4)) COLLATE utf8mb4_bin,
                        'one',CONCAT('%%',REPLACE(REPLACE(REPLACE(LOWER(%s),CHAR(92),CONCAT(CHAR(92),CHAR(92))),
                        '%%',CONCAT(CHAR(92),'%%')),'_',CONCAT(CHAR(92),'_')),'%%'),CHAR(92)) IS NOT NULL"""
                        if sql.startswith("SELECT h.device_id,COUNT(*) OVER() AS total"):
                            if sql.count(original) != 1: raise RuntimeError("Search query changed")
                            sql = sql.replace(original, candidate)
                        return self.cursor.execute(sql, params)
                @contextmanager
                def json_transaction():
                    with original_transaction() as cursor: yield JsonSearchCursor(cursor)
                for term, offset in (("employee-00000001", 0), ("employee-", 0), ("employee-", args.online - 25)):
                    outputs = []
                    for transaction in (original_transaction, json_transaction):
                        store.transaction = transaction
                        times = []
                        for _ in range(args.samples):
                            started = time.perf_counter()
                            rows, _, total = store.analytics_page("online", None, now, offset, 25, employee_search=term)
                            times.append(round(time.perf_counter() - started, 3))
                        outputs.append((times, total, [row["device"]["deviceId"] for row in rows]))
                    store.transaction = original_transaction
                    if outputs[0][1:] != outputs[1][1:]: raise RuntimeError("JSON search result mismatch")
                    print(json.dumps(dict(stage="json_search_comparison", broad=term == "employee-", offset=offset,
                        previousSeconds=outputs[0][0], candidateSeconds=outputs[1][0], total=outputs[0][1],
                        includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.compare_ascii_json_search:
                original_transaction = store.transaction
                class AsciiSearchCursor:
                    def __init__(self, cursor): self.cursor = cursor
                    def __getattr__(self, name): return getattr(self.cursor, name)
                    def execute(self, sql, params=None):
                        original = """SELECT 1 FROM employee_search_index ei,
                        JSON_TABLE(ei.employees_json, '$[*]' COLUMNS (
                            account_name LONGTEXT PATH '$')) u
                        WHERE ei.device_id=h.device_id
                        AND INSTR(LOWER(u.account_name) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0"""
                        candidate = """SELECT 1 FROM employee_search_index ei
                        WHERE ei.device_id=h.device_id AND INSTR(LOWER(CAST(ei.employees_json AS CHAR CHARACTER SET utf8mb4)) COLLATE utf8mb4_bin,
                                    LOWER(%s) COLLATE utf8mb4_bin)>0
                        AND (LOCATE(CHAR(92),CAST(ei.employees_json AS CHAR CHARACTER SET utf8mb4))=0 OR EXISTS (
                            SELECT 1 FROM JSON_TABLE(ei.employees_json, '$[*]' COLUMNS (account_name LONGTEXT PATH '$')) u
                            WHERE INSTR(LOWER(u.account_name) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0))"""
                        if sql.startswith("SELECT h.device_id,COUNT(*) OVER() AS total"):
                            if sql.count(original) != 1: raise RuntimeError("Search query changed")
                            sql = sql.replace(original, candidate)
                            params = (*params[:-2], params[-3], *params[-2:])
                        return self.cursor.execute(sql, params)
                @contextmanager
                def ascii_transaction():
                    with original_transaction() as cursor: yield AsciiSearchCursor(cursor)
                for term, offset in (("employee-00000001", 0), ("employee-", 0), ("employee-", args.online - 25)):
                    outputs = []
                    for transaction in (original_transaction, ascii_transaction):
                        store.transaction = transaction
                        times = []
                        for _ in range(args.samples):
                            started = time.perf_counter()
                            rows, _, total = store.analytics_page("online", None, now, offset, 25, employee_search=term)
                            times.append(round(time.perf_counter() - started, 3))
                        outputs.append((times, total, [row["device"]["deviceId"] for row in rows]))
                    store.transaction = original_transaction
                    if outputs[0][1:] != outputs[1][1:]: raise RuntimeError("ASCII search result mismatch")
                    print(json.dumps(dict(stage="ascii_json_search_comparison", broad=term == "employee-", offset=offset,
                        previousSeconds=outputs[0][0], candidateSeconds=outputs[1][0], total=outputs[0][1],
                        includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.compare_search:
                original_transaction = store.transaction
                class PreviousSearchCursor:
                    def __init__(self, cursor):
                        self.cursor = cursor
                        self.total = None
                    def __getattr__(self, name):
                        return getattr(self.cursor, name)
                    def execute(self, sql, params=None):
                        prefix = "SELECT h.device_id,COUNT(*) OVER() AS total"
                        if sql.startswith(prefix):
                            body, order = sql[len(prefix):].rsplit(" ORDER BY ", 1)
                            self.cursor.execute("SELECT COUNT(*) AS total" + body, params[:-2])
                            self.total = self.cursor.fetchone()["total"]
                            return self.cursor.execute("SELECT h.device_id" + body + " ORDER BY " + order, params)
                        return self.cursor.execute(sql, params)
                    def fetchall(self):
                        rows = self.cursor.fetchall()
                        if self.total is not None:
                            rows = [{**row, "total": self.total} for row in rows]
                            self.total = None
                        return rows
                @contextmanager
                def previous_transaction():
                    with original_transaction() as cursor:
                        yield PreviousSearchCursor(cursor)
                for offset in (0, args.online - 25):
                    outputs = []
                    for legacy in (True, False):
                        store.transaction = previous_transaction if legacy else original_transaction
                        times = []
                        for _ in range(args.samples):
                            started = time.perf_counter()
                            rows, policy, total = store.analytics_page("online", None, now, offset, 25,
                                                                       employee_search="employee-")
                            times.append(round(time.perf_counter() - started, 3))
                            if total != args.online or len(rows) != 25:
                                raise RuntimeError("Unexpected broad search page")
                        outputs.append((times, [row["device"]["deviceId"] for row in rows]))
                    store.transaction = original_transaction
                    if outputs[0][1] != outputs[1][1]:
                        raise RuntimeError("Broad search page changed")
                    print(json.dumps(dict(stage="broad_employee_search_comparison", offset=offset,
                        previousSeconds=outputs[0][0], windowSeconds=outputs[1][0], total=args.online,
                        includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.assets_per_device:
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    rows, policy, total = store.analytics_page("online", None, now, 0, 25, anomaly="latest")
                    page = drill_down(rows, policy, now, scope="all", take=25)
                    timings.append(round(time.perf_counter() - started, 3))
                    expected = (args.online + 999) // 1000
                    if total != expected or len(page["devices"]) != min(expected, 25):
                        raise RuntimeError("Unexpected synthetic failure filter result")
                print(json.dumps(dict(stage="failure_filter_indexed", total=total, seconds=timings,
                                      includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.policy_rollout_targets:
                with store.transaction() as cur:
                    for base in range(0, args.policy_rollout_targets, 1000):
                        end = min(base+1000, args.policy_rollout_targets)
                        cur.executemany("INSERT INTO device_credentials VALUES (%s,%s,%s,NULL,0)",
                            [(str(UUID(int=i+1)), "a"*64, dbtime(now)) for i in range(base,end)])
                initial = store.policy()
                policy = PolicyUpdateRequest(expectedVersion=initial["policyVersion"],
                    **{key:value for key,value in initial.items() if key in PolicyUpdateRequest.model_fields})
                policy.gatewayOrigin = "https://synthetic.example"
                request = CreatePolicyRolloutRequest(policy=policy, reason="synthetic scale test", maxPerSecond=args.policy_rate,
                    deviceIds=[str(UUID(int=i+1)) for i in range(args.policy_rollout_targets)], confirmCount=args.policy_rollout_targets)
                started = time.perf_counter()
                batch = policy_rollout.create(store, request, "synthetic")
                create_seconds = time.perf_counter()-started
                policy_rollout.change(store, batch["batchId"], "resume", "synthetic", "synthetic")
                timings = []
                chunk = min(250, (args.policy_rate + 19)//20) if args.policy_rate > 20 else 1
                phase_seconds, phase_calls = {}, {}
                original_transaction = store.transaction
                if args.policy_profile:
                    class PolicyTimedCursor:
                        def __init__(self, cursor): self.cursor = cursor
                        def __getattr__(self, name): return getattr(self.cursor, name)
                        def _call(self, method, sql, *values):
                            normalized = ' '.join(sql.lower().split())
                            label = next((label for prefix, label in (
                                ('select 1 from policy_rollout_batches', 'due_check'),
                                ('select policy_json from control_policy', 'policy_lock'),
                                ('select * from policy_rollout_batches', 'batch_lock'),
                                ('select device_id from policy_rollout_targets', 'target_lock'),
                                ('select device_id,heartbeat_json from device_heartbeats', 'heartbeat_lock'),
                                ('select device_id,revoked from device_credentials', 'credential_lock'),
                                ('select * from device_policy_state', 'state_lock'),
                                ('select effective_policy_version as version', 'version_watermark'),
                                ('insert into device_policy_state', 'state_insert'),
                                ('update policy_rollout_targets ', 'target_update'),
                                ('update policy_rollout_batches set', 'schedule_update'))
                                if normalized.startswith(prefix)), 'other')
                            started = time.perf_counter()
                            try: return method(sql, *values)
                            finally:
                                phase_seconds[label] = phase_seconds.get(label, 0) + time.perf_counter() - started
                                phase_calls[label] = phase_calls.get(label, 0) + 1
                        def execute(self, sql, *values): return self._call(self.cursor.execute, sql, *values)
                        def executemany(self, sql, values): return self._call(self.cursor.executemany, sql, values)
                    @contextmanager
                    def policy_profiled():
                        with original_transaction() as cur: yield PolicyTimedCursor(cur)
                    store.transaction = policy_profiled
                with heartbeat_row_load(args.port, user, password, name,
                        [str(device) for device in request.deviceIds],
                        args.policy_heartbeat_workers, args.policy_heartbeat_rps) as row_results:
                    dispatch_started = time.perf_counter()
                    for _ in range(min(args.policy_rollout_dispatches, (args.policy_rollout_targets + chunk - 1)//chunk)):
                        if not args.policy_respect_rate:
                            with store.transaction() as cur:
                                cur.execute("UPDATE policy_rollout_batches SET next_dispatch_at_utc=UTC_TIMESTAMP(6) WHERE batch_id=%s", (batch["batchId"],))
                        while True:
                            if row_results is not None and any(result["errors"] for result in row_results):
                                raise RuntimeError("Synthetic row-load worker failed")
                            if time.perf_counter() - dispatch_started > args.policy_timeout:
                                raise RuntimeError("Synthetic policy dispatch timeout")
                            started = time.perf_counter()
                            if policy_rollout.dispatch_one(store): break
                            if not args.policy_respect_rate: raise RuntimeError("Policy dispatch did not progress")
                            time.sleep(1)  # Match the application worker when no work is due.
                        timings.append(round(time.perf_counter()-started, 3))
                        if args.policy_respect_rate: time.sleep(.05)  # Match the application worker after dispatch.
                    dispatch_elapsed = time.perf_counter() - dispatch_started
                store.transaction = original_transaction
                started = time.perf_counter()
                detail = policy_rollout.details(store, batch["batchId"], 0, 25)
                details_seconds = time.perf_counter()-started
                if detail["counts"].get("assigned",0) != min(len(timings)*chunk, args.policy_rollout_targets): raise RuntimeError("Unexpected policy assignment count")
                with store.transaction() as cur:
                    cur.execute("SELECT COUNT(DISTINCT assigned_version) AS n,MIN(assigned_version) AS low "
                                "FROM policy_rollout_targets WHERE batch_id=%s AND status='assigned'", (batch["batchId"],))
                    versions = cur.fetchone()
                if versions["n"] != detail["counts"].get("assigned", 0) or (versions["n"] and versions["low"] <= initial["policyVersion"]):
                    raise RuntimeError("Synthetic policy versions are not unique and above the base")
                row_summary = None
                if row_results is not None:
                    latencies = sorted(value for result in row_results for value in result['latencies'])
                    completed = sum(result['completed'] for result in row_results)
                    row_summary = dict(model='heartbeat_row_update_only', requestedPerSecond=args.policy_heartbeat_rps,
                        attempted=sum(result['attempted'] for result in row_results), completed=completed,
                        effectivePerSecond=round(completed / dispatch_elapsed, 1),
                        missedSchedule=sum(result['missed'] for result in row_results),
                        errors=sum(result['errors'] for result in row_results),
                        p95Seconds=round(latencies[(len(latencies)-1)*95//100], 4) if latencies else None)
                print(json.dumps(dict(stage="policy_rollout", targets=args.policy_rollout_targets, configuredRate=args.policy_rate,
                    createSeconds=round(create_seconds,3), dispatchSeconds=timings, dispatchElapsed=round(dispatch_elapsed,3),
                    assigned=detail["counts"].get("assigned",0), uniqueAssignedVersions=versions["n"],
                    detailSeconds=round(details_seconds,3), rateEnforcementBypassed=not args.policy_respect_rate,
                    phaseSeconds={key: round(value, 3) for key, value in phase_seconds.items()}, phaseCalls=phase_calls,
                    concurrentRowUpdates=row_summary, includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.rollout_targets:
                request = CreateRolloutRequest(type="disableProxy", reason="synthetic scale test",
                    expiresInMinutes=60, maxPerSecond=5,
                    deviceIds=[str(UUID(int=i + 1)) for i in range(args.rollout_targets)],
                    confirmCount=args.rollout_targets)
                phase = {'targetValidationSeconds': 0.0, 'targetInsertSeconds': 0.0,
                         'otherSqlSeconds': 0.0, 'validationCalls': 0, 'insertCalls': 0}
                original_transaction = store.transaction
                class TimedCursor:
                    def __init__(self, cursor):
                        self.cursor = cursor
                    def __getattr__(self, name):
                        return getattr(self.cursor, name)
                    def execute(self, sql, *args):
                        group = 'targetValidationSeconds' if sql.startswith('SELECT device_id FROM device_heartbeats WHERE device_id IN') else 'otherSqlSeconds'
                        started = time.perf_counter()
                        try:
                            return self.cursor.execute(sql, *args)
                        finally:
                            phase[group] += time.perf_counter() - started
                            if group == 'targetValidationSeconds': phase['validationCalls'] += 1
                    def executemany(self, sql, *args):
                        group = 'targetInsertSeconds' if sql.startswith('INSERT INTO rollout_targets') else 'otherSqlSeconds'
                        started = time.perf_counter()
                        try:
                            return self.cursor.executemany(sql, *args)
                        finally:
                            phase[group] += time.perf_counter() - started
                            if group == 'targetInsertSeconds': phase['insertCalls'] += 1
                @contextmanager
                def timed_transaction():
                    with original_transaction() as cur:
                        yield TimedCursor(cur)
                store.transaction = timed_transaction
                try:
                    started = time.perf_counter()
                    batch = rollout.create(store, request, "synthetic")
                    create_seconds = time.perf_counter() - started
                finally:
                    store.transaction = original_transaction
                timings = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    details = rollout.details(store, batch["batchId"], 0, 25)
                    timings.append(round(time.perf_counter() - started, 3))
                    if details["counts"] != {"pending": args.rollout_targets} or len(details["targets"]) != 25:
                        raise RuntimeError("Unexpected synthetic rollout snapshot")
                print(json.dumps(dict(stage="rollout_snapshot", targets=args.rollout_targets,
                    createSeconds=round(create_seconds, 3), createSqlPhases={k: round(v, 3) for k, v in phase.items()}, detailSeconds=timings,
                    dispatched=False, includesHttp=False, concurrentHeartbeats=False)), flush=True)
                if args.rollout_filter_probe:
                    # UUIDs here are synthetic small integers, generated above in this disposable database.
                    bucket = "MOD(CONV(RIGHT(device_id,12),16,10),3)"
                    with store.transaction() as cur:
                        cur.execute("UPDATE rollout_targets SET status='dispatchFailed',error_code='SYNTHETIC' "
                                    "WHERE batch_id=%s AND " + bucket + "=0", (batch['batchId'],))
                        cur.execute("""INSERT INTO remote_commands
                            (command_id,device_id,command_type,status,created_at_utc,expires_at_utc,created_by,reason)
                            SELECT UUID(),device_id,'disableProxy','resultUnknown',%s,%s,'synthetic','synthetic filter'
                            FROM rollout_targets WHERE batch_id=%s AND """ + bucket + "=1",
                                    (dbtime(now), dbtime(now + timedelta(minutes=60)), batch['batchId']))
                        cur.execute("""UPDATE rollout_targets t JOIN remote_commands c ON c.device_id=t.device_id
                            SET t.status='issued',t.command_id=c.command_id WHERE t.batch_id=%s AND c.reason='synthetic filter'""",
                                    (batch['batchId'],))
                    for state in ('dispatchFailed', 'resultUnknown'):
                        measurements = []
                        for _ in range(args.samples):
                            started = time.perf_counter()
                            details = rollout.details(store, batch['batchId'], 0, 25, state)
                            measurements.append(round(time.perf_counter() - started, 3))
                            if (details['filteredTargets'] != details['counts'].get(state)
                                    or len(details['targets']) != 25
                                    or any(target['state'] != state for target in details['targets'])):
                                raise RuntimeError('Unexpected synthetic command filter result')
                        print(json.dumps(dict(stage='rollout_filter', state=state, targets=args.rollout_targets,
                            matching=details['filteredTargets'], seconds=measurements, returned=25,
                            includesHttp=False, concurrentHeartbeats=False)), flush=True)
            if args.policy_samples:
                initial = store.policy()
                with store.transaction() as cur:
                    for base in range(0, args.devices, 1000):
                        end = min(base + 1000, args.devices)
                        cur.executemany("INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)", [
                            (str(UUID(int=i + 1)), initial["policyVersion"], i + 2,
                             json.dumps({"gatewayOrigin":"https://synthetic.example"}) if args.duplicate_overrides else None,
                             json.dumps({**initial, "schemaVersion": 2, "policyVersion": i + 2}, separators=(",", ":")))
                            for i in range(base, end)])
                if args.duplicate_overrides:
                    from controlserver.validation import domain_policy
                    started = time.perf_counter()
                    with store.transaction() as cur:
                        cur.execute("SELECT overrides_json FROM device_policy_state WHERE overrides_json IS NOT NULL")
                        for row in cur.fetchall():
                            override = json.loads(row["overrides_json"]) if isinstance(row["overrides_json"], str) else row["overrides_json"]
                            store._validate_effective_policy({**initial, **domain_policy(override, overrides=True)})
                    print(json.dumps(dict(stage="repeated_override_validation_baseline", devices=args.devices,
                        seconds=round(time.perf_counter()-started, 3), includesHttp=False,
                        concurrentHeartbeats=False)), flush=True)
                update = PolicyUpdateRequest(expectedVersion=initial["policyVersion"],
                    **{key:value for key, value in initial.items() if key in PolicyUpdateRequest.model_fields})
                started = time.perf_counter()
                updated = store.update_policy(update, "synthetic-probe")
                publish_seconds = time.perf_counter() - started
                def policy_read(i):
                    started = time.perf_counter()
                    policy = store.policy(str(UUID(int=i + 1)), schema_version=2, stateless=True)
                    if policy["policyVersion"] != updated["policyVersion"]:
                        raise RuntimeError("Unexpected synthetic effective policy version")
                    return time.perf_counter() - started
                started = time.perf_counter()
                with ThreadPoolExecutor(max_workers=8) as executor:
                    durations = list(executor.map(policy_read, range(args.policy_samples)))
                elapsed = time.perf_counter() - started
                with store.transaction() as cur:
                    cur.execute("SELECT COUNT(*) AS total FROM device_policy_state WHERE base_policy_version=%s",
                                (initial["policyVersion"],))
                    unchanged = cur.fetchone()["total"]
                if unchanged != args.devices:
                    raise RuntimeError("Stateless reads unexpectedly wrote device policy state")
                ordered = sorted(durations)
                print(json.dumps(dict(stage="stateless_policy_reads", policies=args.policy_samples,
                    workers=8, totalSeconds=round(elapsed, 3), publishSeconds=round(publish_seconds, 3),
                    p95Seconds=round(ordered[int((len(ordered)-1)*0.95)], 3),
                    devicePolicyRowsUnchanged=unchanged, includesHttp=False)), flush=True)
    except WorkersNotStopped:
        created = False  # Do not drop a database that a worker might still be using.
        raise
    finally:
        if created:
            with connection.cursor() as cur:
                cur.execute("DROP DATABASE `" + name + "`")
        connection.close()


if __name__ == "__main__":
    main()
