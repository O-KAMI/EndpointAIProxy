"""MySQL storage. Each operation owns its connection and transaction."""
import hashlib
import base64
import binascii
import json
import os
import queue
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pymysql
from pymysql.cursors import DictCursor
from config import ROOT
from .security import dumps, generate_device_token, hash_token, timestamp, utcnow, wire
from .validation import ApiProblem, normalize_allowlist, seed_policy, validate_policy
from .validation import domain_policy, normalize_domains, normalize_routing_rules
from .observability import PoolMetrics

SCHEMA_PATH = ROOT / "conf" / "endpoint_ai_proxy.sql"
SCHEMA_VERSION = 5
SCHEMA_4_CHECKSUM = "e31fa79ae65856e7eca63cecf56beac2d809470f130c8bf8c33e53672f80686a"
PREVIOUS_CHECKSUM = "26e356840574088656a60eeedd69a319172563e03009864ad61f9a82d1fc0d28"
SCHEMA_2_CHECKSUM = "82e6e26dc3e40d28dfbef108696722b2f150a58baa7b41f8078465697afdc007"
SCHEMA_3_CHECKSUM = "648e38f3fc03a249d36eb23f89ce8451d6055f5a9580b4cadf9b9c10148b7564"
LEGACY_TABLES = {"server_policy", "devices", "device_users", "agent_inventory",
                 "endpoint_assets", "proxy_activity", "device_runtime", "events",
                 "remote_commands", "audit_log"}


class PoolExhausted(Exception):
    pass


def schema_statements():
    source = SCHEMA_PATH.read_text(encoding="utf-8")
    return [part.strip() for part in re.sub(r"--[^\n]*", "", source).split(";") if part.strip()]


def schema_tables():
    return {re.search(r"CREATE TABLE (\w+)", sql)[1] for sql in schema_statements()}


def schema_checksum():
    return hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()


def dbtime(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def decode(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else value


def employee_ids(users):
    values = set()
    system_accounts = {"system", "local service", "network service", "administrator", "guest",
                       "defaultaccount", "wdagutilityaccount", "root", "daemon"}
    for user in users or []:
        account = (user.get("accountName") or "").strip()
        if account.lower().startswith("sf\\"):
            account = account[3:]
        if (account and account != user.get("sid") and not re.match(r"S-\d-", account, re.I)
                and not account.lower().startswith("macos:")
                and account.rsplit("\\", 1)[-1].lower() not in system_accounts):
            values.add(account)
    return sorted(values)


class ControlStore:
    def __init__(self, cfg):
        self.cfg = cfg
        self._pool_pid = os.getpid()
        self._pool_lock = threading.Lock()
        self._pool_limit = 2 if cfg.SERVICE_ROLE == "admin" else 8
        self._pool_idle = queue.LifoQueue(maxsize=self._pool_limit)
        self._pool_slots = threading.BoundedSemaphore(self._pool_limit)
        self.pool_metrics = PoolMetrics()
        self._credential_rotation_table = False

    def connect(self):
        c = self.cfg
        return pymysql.connect(host=c.MYSQL_HOST, port=c.MYSQL_PORT, user=c.MYSQL_USER,
            password=c.MYSQL_PASSWORD, database=c.MYSQL_DATABASE, charset="utf8mb4",
            cursorclass=DictCursor, autocommit=False, connect_timeout=5, read_timeout=30,
            write_timeout=30, init_command="SET time_zone = '+00:00'")

    @contextmanager
    def transaction(self):
        # Gunicorn workers must never reuse a connection inherited across fork.
        if self._pool_pid != os.getpid():
            with self._pool_lock:
                if self._pool_pid != os.getpid():
                    self._pool_idle = queue.LifoQueue(maxsize=self._pool_limit)
                    self._pool_slots = threading.BoundedSemaphore(self._pool_limit)
                    self.pool_metrics = PoolMetrics()
                    self._pool_pid = os.getpid()
        slots, idle = self._pool_slots, self._pool_idle
        started = time.monotonic()
        acquired = slots.acquire(timeout=5)
        self.pool_metrics.acquired(time.monotonic() - started, acquired)
        if not acquired:
            raise PoolExhausted("Control database connection pool exhausted")
        connection = None
        discard = False
        try:
            try:
                connection = idle.get_nowait()
            except queue.Empty:
                connection = self.connect()
            else:
                try:
                    connection.ping(reconnect=False)
                except pymysql.err.Error:
                    if connection.open:
                        connection.close()
                    connection = self.connect()
            with connection.cursor() as cur:
                yield cur
            connection.commit()
        except BaseException as exc:
            # A failed database operation can leave session state (including
            # advisory locks) uncertain even when rollback itself succeeds.
            discard = isinstance(exc, pymysql.err.Error)
            try:
                if connection is not None:
                    connection.rollback()
            except BaseException:
                discard = True
            raise
        finally:
            try:
                if connection is not None:
                    if discard or not connection.open:
                        if connection.open:
                            connection.close()
                    else:
                        idle.put_nowait(connection)
            finally:
                self.pool_metrics.released()
                slots.release()

    def check_schema(self):
        with self.transaction() as cur:
            from .credential_rotation import TABLE, check_table, schema_identity
            cur.execute("SELECT version, checksum FROM schema_migrations")
            rows = cur.fetchall()
            renewal_schema = rows == [schema_identity()]
            if not renewal_schema and rows != [{"version": SCHEMA_VERSION, "checksum": schema_checksum()}]:
                raise RuntimeError("Database schema mismatch; run the documented database initialization/migration.")
            cur.execute("SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=DATABASE()")
            present = {r["TABLE_NAME"] for r in cur.fetchall()}
            if not schema_tables() <= present:
                raise RuntimeError("Database tables are incomplete")
            self._credential_rotation_table = renewal_schema and TABLE in present
            if renewal_schema and TABLE not in present:
                raise RuntimeError('Credential renewal storage is missing for schema 6')
            if self.cfg.CREDENTIAL_ROTATION and not self._credential_rotation_table:
                raise RuntimeError("Credential renewal storage is missing; prepare it with all services stopped")
            if TABLE in present:
                check_table(cur)
                if not renewal_schema:
                    cur.execute('SELECT 1 FROM device_credential_rotations LIMIT 1')
                    if cur.fetchone():
                        raise RuntimeError('Credential renewal state exists without its schema 6 marker')
            self._check_replay_constraints(cur)
            self._check_device_policy_constraints(cur)
            self._check_rollout_constraints(cur)
            if self.cfg.EMPLOYEE_INDEX:
                self._check_employee_index(cur)
                self._check_activity_index(cur)
                cur.execute("""SELECT 1 FROM device_heartbeats h LEFT JOIN employee_search_index e
                    ON e.device_id=h.device_id WHERE e.device_id IS NULL LIMIT 1""")
                if cur.fetchone():
                    raise RuntimeError("Employee search index is incomplete; rebuild with services stopped")
                cur.execute("""SELECT 1 FROM device_heartbeats h LEFT JOIN activity_search_index a
                    ON a.device_id=h.device_id WHERE a.device_id IS NULL LIMIT 1""")
                if cur.fetchone():
                    raise RuntimeError("Activity search index is incomplete; rebuild with services stopped")
            # Check required columns against the canonical SQL, not just the version marker.
            for sql in schema_statements():
                table = re.search(r"CREATE TABLE (\w+)", sql)[1]
                columns = re.findall(r"^    (\w+) (?:INT|CHAR|VARCHAR|TINYINT|BIGINT|DATETIME|BOOLEAN|TEXT|JSON)\b", sql, re.M)
                cur.execute("SELECT " + ",".join(f"`{name}`" for name in columns) + f" FROM `{table}` LIMIT 0")
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1")
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Database seed policy is missing")
            from .models import EndpointPolicy, PolicyUpdateRequest
            from .validation import validate_policy
            policy = EndpointPolicy.model_validate(decode(row["policy_json"]))
            validate_policy(PolicyUpdateRequest(expectedVersion=policy.policyVersion,
                **{k:v for k,v in policy.model_dump().items() if k in PolicyUpdateRequest.model_fields}))

    def initialize_empty(self):
        """Explicit maintenance operation. Caller must stop all application instances."""
        c = self.connect()
        lock = "endpointai-init-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
        try:
            with c.cursor() as cur:
                cur.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock,))
                if cur.fetchone()["acquired"] != 1:
                    raise RuntimeError("Database initialization already running")
                cur.execute("SHOW FULL TABLES")
                entries = cur.fetchall()
                present = {list(r.values())[0] for r in entries}
                from .credential_rotation import TABLE
                known = schema_tables() | LEGACY_TABLES | {TABLE}
                if any(list(r.values())[0] in known and list(r.values())[1] != "BASE TABLE" for r in entries):
                    raise RuntimeError("Project table name conflicts with a database view")
                if "schema_migrations" in present:
                    cur.execute("SELECT COUNT(*) AS count FROM schema_migrations")
                    if cur.fetchone()["count"]:
                        self.check_schema()
                        return "already_initialized"
                # Inspect every target before any destructive DDL (MySQL DDL commits).
                for table in sorted(present & known):
                    cur.execute(f"SELECT 1 FROM `{table}` LIMIT 1")
                    if cur.fetchone():
                        raise RuntimeError(f"Refusing to rebuild nonempty project table: {table}")
                cur.execute("""SELECT TABLE_NAME,REFERENCED_TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE
                    WHERE REFERENCED_TABLE_SCHEMA=DATABASE()
                    AND REFERENCED_TABLE_NAME IS NOT NULL""")
                if any(r["TABLE_NAME"] in known or r["REFERENCED_TABLE_NAME"] in known for r in cur.fetchall()):
                    raise RuntimeError("Existing foreign-key relationships require manual review")
                for table in sorted(present & known):
                    cur.execute(f"DROP TABLE `{table}`")
                for sql in schema_statements():
                    cur.execute(sql)
                policy = seed_policy(self.cfg)
                cur.execute("INSERT INTO control_policy VALUES (1,%s,%s)", (policy["policyVersion"], dumps(policy)))
                cur.execute("INSERT INTO schema_migrations VALUES (%s,%s,%s)",
                            (SCHEMA_VERSION, schema_checksum(), dbtime(utcnow())))
                c.commit()
                return "initialized"
        finally:
            try:
                with c.cursor() as cur:
                    cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
            finally:
                c.close()

    def policy(self, device=None, schema_version=None, stateless=False):
        with self.transaction() as cur:
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1")
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Policy not initialized")
            policy = domain_policy(decode(row["policy_json"]))
            if device is None:
                return policy
            cur.execute("SELECT base_policy_version,effective_policy_json,overrides_json FROM device_policy_state WHERE device_id=%s", (str(device),))
            state = cur.fetchone()
            if stateless:
                if state and state["base_policy_version"] == policy["policyVersion"]:
                    effective = domain_policy(decode(state["effective_policy_json"]))
                elif state:
                    overrides = domain_policy(decode(state["overrides_json"]), overrides=True) if state["overrides_json"] is not None else {}
                    effective = {**policy, **overrides}
                else:
                    effective = policy
                return {**effective, "schemaVersion": 2}
            if state is None and schema_version != 2:
                return policy
            if state and state["base_policy_version"] == policy["policyVersion"]:
                effective = domain_policy(decode(state["effective_policy_json"]))
                if schema_version != 2 or effective["schemaVersion"] == 2:
                    return effective
        if state and state["base_policy_version"] != policy["policyVersion"]:
            # A global publication advances past every previously issued device
            # version. Reuse it for stale overrides without allocating a new
            # version or exclusively locking the global row for each device.
            with self.transaction() as cur:
                cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR SHARE")
                current = domain_policy(decode(cur.fetchone()["policy_json"]))
                cur.execute("SELECT * FROM device_policy_state WHERE device_id=%s FOR UPDATE", (str(device),))
                existing = cur.fetchone()
                if existing:
                    previous = domain_policy(decode(existing["effective_policy_json"]))
                    target_schema = max(previous["schemaVersion"], schema_version or 1)
                    if existing["base_policy_version"] == current["policyVersion"] and previous["schemaVersion"] == target_schema:
                        return previous
                    if (existing["base_policy_version"] != current["policyVersion"]
                            and current["policyVersion"] > existing["effective_policy_version"]):
                        overrides = domain_policy(decode(existing["overrides_json"]), overrides=True) if existing["overrides_json"] is not None else {}
                        effective = {**current, **overrides, "schemaVersion": target_schema,
                                     "policyVersion": current["policyVersion"], "issuedAtUtc": timestamp(utcnow())}
                        self._validate_effective_policy(effective)
                        cur.execute("""UPDATE device_policy_state SET base_policy_version=%s,
                            effective_policy_version=%s,effective_policy_json=%s WHERE device_id=%s""",
                            (current["policyVersion"], current["policyVersion"], dumps(effective), str(device)))
                        return effective
        # Only a changed global base needs allocation. Ordinary heartbeats do not serialize on the singleton lock.
        with self.transaction() as cur:
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
            return self._device_policy(cur, domain_policy(decode(cur.fetchone()["policy_json"])), device, schema_version)["effectivePolicy"]

    def revert_unused_rollout_schema(self):
        """Permit a stopped-service rollback only before any batch data exists."""
        with self.transaction() as cur:
            lock = "endpointai-init-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
            cur.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                raise RuntimeError("Database maintenance already running")
            try:
                cur.execute("SELECT version,checksum FROM schema_migrations FOR UPDATE")
                if cur.fetchall() != [{"version": SCHEMA_VERSION, "checksum": schema_checksum()}]:
                    raise RuntimeError("Rollback requires the exact current schema")
                for table in ("rollout_batches", "rollout_targets", "policy_rollout_batches", "policy_rollout_targets"):
                    cur.execute(f"SELECT COUNT(*) AS count FROM {table}")
                    if cur.fetchone()["count"]:
                        raise RuntimeError("Rollback refused: rollout data exists")
                cur.execute("UPDATE schema_migrations SET version=3,checksum=%s,applied_at_utc=%s WHERE version=%s",
                            (SCHEMA_3_CHECKSUM, dbtime(utcnow()), SCHEMA_VERSION))
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        return "reverted_to_schema_3"

    def revert_unused_policy_rollout_schema(self):
        """Permit schema 4 rollback only before any policy rollout data exists."""
        with self.transaction() as cur:
            lock = "endpointai-init-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
            cur.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                raise RuntimeError("Database maintenance already running")
            try:
                cur.execute("SELECT version,checksum FROM schema_migrations FOR UPDATE")
                if cur.fetchall() != [{"version": SCHEMA_VERSION, "checksum": schema_checksum()}]:
                    raise RuntimeError("Rollback requires the exact current schema")
                for table in ("policy_rollout_batches", "policy_rollout_targets"):
                    cur.execute(f"SELECT COUNT(*) AS count FROM {table}")
                    if cur.fetchone()["count"]:
                        raise RuntimeError("Rollback refused: policy rollout data exists")
                cur.execute("UPDATE schema_migrations SET version=4,checksum=%s,applied_at_utc=%s WHERE version=%s",
                            (SCHEMA_4_CHECKSUM, dbtime(utcnow()), SCHEMA_VERSION))
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        return "reverted_to_schema_4"

    @staticmethod
    def _next_policy_version(cur, policy):
        # Every allocator holds the singleton policy lock, including global updates.
        # A locking read observes commits made while this transaction waited for
        # that lock, even if a prior non-locking read established an older snapshot.
        cur.execute("SELECT effective_policy_version AS version FROM device_policy_state "
                    "ORDER BY effective_policy_version DESC LIMIT 1 FOR UPDATE")
        row = cur.fetchone()
        version = max(policy["policyVersion"], row["version"] if row else 0) + 1
        if version >= 2**63-1:
            raise ApiProblem("POLICY_VERSION_EXHAUSTED", "Policy version space exhausted.", 409)
        return version

    def _device_policy(self, cur, policy, device, schema_version=None):
        cur.execute("SELECT * FROM device_policy_state WHERE device_id=%s FOR UPDATE", (str(device),))
        row = cur.fetchone()
        policy = domain_policy(policy)
        overrides = decode(row["overrides_json"]) if row else None
        if overrides is not None:
            overrides = domain_policy(overrides, overrides=True)
        effective = policy
        previous = decode(row["effective_policy_json"]) if row else policy
        target_schema = max(previous["schemaVersion"], schema_version or 1)
        if row and row["base_policy_version"] == policy["policyVersion"] and previous["schemaVersion"] != target_schema:
            cur.execute("""SELECT t.batch_id FROM policy_rollout_targets t JOIN policy_rollout_batches b ON b.batch_id=t.batch_id
                WHERE t.device_id=%s AND t.status='assigned' AND b.status IN ('paused','running','dispatchComplete')
                LIMIT 1 FOR UPDATE""", (str(device),))
            assigned = cur.fetchone()
            if assigned:
                effective = {**previous, "schemaVersion": target_schema, "policyVersion": self._next_policy_version(cur, policy),
                             "issuedAtUtc": timestamp(utcnow())}
                self._validate_effective_policy(effective)
                cur.execute("UPDATE device_policy_state SET effective_policy_version=%s,effective_policy_json=%s WHERE device_id=%s",
                            (effective["policyVersion"], dumps(effective), str(device)))
                cur.execute("UPDATE policy_rollout_targets SET assigned_version=%s WHERE batch_id=%s AND device_id=%s",
                            (effective["policyVersion"], assigned["batch_id"], str(device)))
                return dict(deviceId=str(device), globalPolicyVersion=policy["policyVersion"], hasOverride=overrides is not None,
                            overrides={k:v for k,v in (overrides or {}).items() if k != "allowlistMigration"}, effectivePolicy=effective)
        if row or target_schema == 2:
            if row is None or row["base_policy_version"] != policy["policyVersion"] or previous["schemaVersion"] != target_schema:
                effective = {**policy, **(overrides or {}),
                    "schemaVersion": target_schema,
                    "policyVersion": self._next_policy_version(cur, policy), "issuedAtUtc": timestamp(utcnow())}
                self._validate_effective_policy(effective)
                cur.execute("""INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE base_policy_version=VALUES(base_policy_version),
                    effective_policy_version=VALUES(effective_policy_version),overrides_json=VALUES(overrides_json),
                    effective_policy_json=VALUES(effective_policy_json)""",
                    (str(device), policy["policyVersion"], effective["policyVersion"],
                     dumps(overrides) if overrides is not None else None, dumps(effective)))
                if previous["schemaVersion"] != target_schema:
                    self._audit(cur, "client-capability", "POLICY_SCHEMA_NEGOTIATED", device,
                        summary="schema=" + str(target_schema) + ";effectiveVersion=" + str(effective["policyVersion"]))
            else:
                effective = domain_policy(previous)
        return dict(deviceId=str(device), globalPolicyVersion=policy["policyVersion"],
                    hasOverride=overrides is not None,
                    overrides={k:v for k,v in (overrides or {}).items() if k != "allowlistMigration"}, effectivePolicy=effective)

    @staticmethod
    def _validate_effective_policy(policy):
        from .models import PolicyUpdateRequest
        validate_policy(PolicyUpdateRequest(expectedVersion=policy["policyVersion"],
            **{k:v for k,v in policy.items() if k in PolicyUpdateRequest.model_fields}))

    def device_policy(self, device, update=None, actor=None, reset=False):
        if update is None:
            # Common read-only detail requests must not lock the global policy
            # row. Both reads use the same transaction snapshot; stale state
            # falls through to the existing serialized refresh below.
            with self.transaction() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
                cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1")
                policy = domain_policy(decode(cur.fetchone()["policy_json"]))
                cur.execute("SELECT device_id FROM device_credentials WHERE device_id=%s AND revoked=0", (str(device),))
                if not cur.fetchone():
                    raise ApiProblem("DEVICE_NOT_FOUND", "An enrolled active device is required.", 404)
                cur.execute("SELECT base_policy_version,effective_policy_json,overrides_json FROM device_policy_state WHERE device_id=%s", (str(device),))
                state = cur.fetchone()
                if state is None or state["base_policy_version"] == policy["policyVersion"]:
                    overrides = domain_policy(decode(state["overrides_json"]), overrides=True) if state and state["overrides_json"] is not None else None
                    effective = domain_policy(decode(state["effective_policy_json"])) if state else policy
                    return dict(deviceId=str(device), globalPolicyVersion=policy["policyVersion"],
                                hasOverride=overrides is not None,
                                overrides={k:v for k,v in (overrides or {}).items() if k != "allowlistMigration"},
                                effectivePolicy=effective)
        with self.transaction() as cur:
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
            policy = domain_policy(decode(cur.fetchone()["policy_json"]))
            cur.execute("SELECT device_id FROM device_credentials WHERE device_id=%s AND revoked=0", (str(device),))
            if not cur.fetchone():
                raise ApiProblem("DEVICE_NOT_FOUND", "An enrolled active device is required.", 404)
            current = self._device_policy(cur, policy, device)
            if update is None:
                return current
            self._assert_no_policy_rollout(cur)
            if current["effectivePolicy"]["policyVersion"] != update.expectedVersion:
                raise ApiProblem("POLICY_VERSION_CONFLICT", "The device policy changed; reload and retry.", 409)
            overrides = None if reset else wire(update.overrides.model_dump(exclude_unset=True))
            if overrides is not None and "allowlistedBaseUrls" in overrides:
                try:
                    overrides["allowlistedBaseUrls"] = normalize_allowlist(overrides["allowlistedBaseUrls"])
                except ValueError as exc:
                    raise ApiProblem("POLICY_ALLOWLIST_INVALID", str(exc)) from None
            if overrides is not None:
                overrides = domain_policy(overrides, overrides=True)
                try:
                    if "allowlistedDomains" in overrides:
                        overrides["allowlistedDomains"] = normalize_domains(overrides["allowlistedDomains"])
                    if "routingRules" in overrides:
                        overrides["routingRules"] = normalize_routing_rules(overrides["routingRules"])
                except ValueError as exc:
                    raise ApiProblem("POLICY_RULES_INVALID", str(exc)) from None
            effective = {**policy, **(overrides or {}),
                "schemaVersion": current["effectivePolicy"]["schemaVersion"],
                "policyVersion": self._next_policy_version(cur, policy), "issuedAtUtc": timestamp(utcnow())}
            self._validate_effective_policy(effective)
            # A reset retains the watermark: returning an older global version would be ignored by clients.
            cur.execute("""INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE base_policy_version=VALUES(base_policy_version),
                effective_policy_version=VALUES(effective_policy_version),overrides_json=VALUES(overrides_json),
                effective_policy_json=VALUES(effective_policy_json)""",
                (str(device), policy["policyVersion"], effective["policyVersion"],
                 dumps(overrides) if overrides is not None else None, dumps(effective)))
            self._audit(cur, actor, "DEVICE_POLICY_RESET" if reset else "DEVICE_POLICY_UPDATED", device,
                        summary="effectiveVersion=" + str(effective["policyVersion"]))
            return dict(deviceId=str(device), globalPolicyVersion=policy["policyVersion"],
                        hasOverride=overrides is not None,
                        overrides={k:v for k,v in (overrides or {}).items() if k != "allowlistMigration"}, effectivePolicy=effective)

    def claim_transport(self, envelope):
        for attempt in range(4):
            try:
                with self.transaction() as cur:
                    # Unique indexes, not a snapshot read, enforce replay exclusion.
                    cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    cur.execute("INSERT INTO transport_replay VALUES (%s,%s,%s,UTC_TIMESTAMP(6) + INTERVAL 11 MINUTE)",
                                (envelope["keyId"], envelope["requestId"], envelope["nonce"]))
                return True
            except pymysql.err.IntegrityError as exc:
                if exc.args[0] == 1062:
                    return False
                raise
            except pymysql.err.OperationalError as exc:
                # A deadlock transaction is fully rolled back. No business dispatch occurred.
                if exc.args[0] != 1213 or attempt == 3:
                    raise

    def cleanup_transport(self):
        """Bounded cleanup; a database advisory lock coordinates application workers."""
        lock = "endpointai-replay-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
        with self.transaction() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            cur.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                return 0
            try:
                deleted = 0
                for _ in range(8):
                    cur.execute("DELETE FROM transport_replay WHERE expires_at_utc < UTC_TIMESTAMP(6) LIMIT 1000")
                    deleted += cur.rowcount
                    if cur.rowcount < 1000:
                        break
                return deleted
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))

    def replay_expired_age_seconds(self):
        """Age of the oldest expired replay record; zero when no record is expired."""
        with self.transaction() as cur:
            cur.execute("""SELECT GREATEST(0, TIMESTAMPDIFF(SECOND, expires_at_utc, UTC_TIMESTAMP(6))) AS age
                FROM transport_replay ORDER BY expires_at_utc LIMIT 1""")
            row = cur.fetchone()
            return int(row["age"]) if row else 0

    def migrate(self):
        """Migrate exact schema 1/2/3/4 inputs with all application instances stopped."""
        with self.transaction() as cur:
            lock = "endpointai-init-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
            cur.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                raise RuntimeError("Database maintenance already running")
            try:
                cur.execute("SELECT version,checksum FROM schema_migrations")
                rows = cur.fetchall()
                from .credential_rotation import schema_identity
                if rows in ([{"version": SCHEMA_VERSION, "checksum": schema_checksum()}], [schema_identity()]):
                    return "already_migrated"
                if rows not in ([{"version": 1, "checksum": PREVIOUS_CHECKSUM}],
                                [{"version": 2, "checksum": SCHEMA_2_CHECKSUM}],
                                [{"version": 3, "checksum": SCHEMA_3_CHECKSUM}],
                                [{"version": 4, "checksum": SCHEMA_4_CHECKSUM}]):
                    raise RuntimeError("Migration requires an exact supported schema 1, 2, 3 or 4 database")
                statement = next(s for s in schema_statements() if s.startswith("CREATE TABLE transport_replay"))
                # DDL commits in MySQL. An interrupted run can safely resume after CREATE.
                cur.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
                cur.execute("SELECT key_id,request_id,nonce,expires_at_utc FROM transport_replay LIMIT 0")
                cur.execute("SHOW INDEX FROM transport_replay")
                cur.fetchall()
                self._check_replay_constraints(cur)
                statement = next(s for s in schema_statements() if s.startswith("CREATE TABLE device_policy_state"))
                cur.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
                cur.execute("SELECT device_id,base_policy_version,effective_policy_version,overrides_json,effective_policy_json FROM device_policy_state LIMIT 0")
                self._check_device_policy_constraints(cur)
                for table in ("rollout_batches", "rollout_targets", "policy_rollout_batches", "policy_rollout_targets"):
                    statement = next(s for s in schema_statements() if s.startswith("CREATE TABLE " + table + " "))
                    cur.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
                self._check_rollout_constraints(cur)
                cur.execute("UPDATE schema_migrations SET version=%s,checksum=%s,applied_at_utc=%s WHERE version IN (1,2,3,4)",
                            (SCHEMA_VERSION, schema_checksum(), dbtime(utcnow())))
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        self.check_schema()
        return "migrated"

    def _check_rollout_constraints(self, cur):
        for table, expected in (("rollout_batches", {("batch_id",)}),
                                ("rollout_targets", {("batch_id", "device_id"), ("command_id",)}),
                                ("policy_rollout_batches", {("batch_id",)}),
                                ("policy_rollout_targets", {("batch_id", "device_id")})):
            cur.execute(f"SHOW INDEX FROM {table}")
            indexes = {}
            rows = cur.fetchall()
            for row in rows:
                if row["Non_unique"] == 0:
                    if row["Sub_part"] is not None:
                        raise RuntimeError("Rollout unique keys must cover full columns")
                    indexes.setdefault(row["Key_name"], []).append((row["Seq_in_index"], row["Column_name"]))
            if {tuple(col for _, col in sorted(items)) for items in indexes.values()} != expected:
                raise RuntimeError("Rollout unique keys do not match")
            if table == "rollout_targets" and self.cfg.ROLLOUT_MAX_RATE > 20:
                pending = sorted((row for row in rows if row["Key_name"] == "ix_rollout_pending"),
                                 key=lambda row: row["Seq_in_index"])
                if (tuple(row["Column_name"] for row in pending) != ("batch_id", "status", "device_id")
                        or any(row["Sub_part"] is not None or row["Non_unique"] != 1
                               or row["Index_type"].upper() != "BTREE" or row.get("Visible", "YES") != "YES"
                               or row.get("Collation") != "A" for row in pending)):
                    raise RuntimeError("High-rate rollout requires the complete visible pending index")
            if table == "policy_rollout_targets" and self.cfg.POLICY_ROLLOUT_MAX_RATE > 20:
                pending = sorted((row for row in rows if row["Key_name"] == "ix_policy_rollout_pending"),
                                 key=lambda row: row["Seq_in_index"])
                if (tuple(row["Column_name"] for row in pending) != ("batch_id", "status", "device_id")
                        or any(row["Sub_part"] is not None or row["Non_unique"] != 1
                               or row["Index_type"].upper() != "BTREE" or row.get("Visible", "YES") != "YES"
                               or row.get("Collation") != "A" for row in pending)):
                    raise RuntimeError("High-rate policy rollout requires the complete visible pending index")

    def ensure_scale_indexes(self):
        """Add the policy high-water lookup index during explicit maintenance."""
        enabled = self.cfg.EMPLOYEE_INDEX
        self.cfg.EMPLOYEE_INDEX = False
        try:
            self.check_schema()
        finally:
            self.cfg.EMPLOYEE_INDEX = enabled
        with self.transaction() as cur:
            lock = "endpointai-init-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
            cur.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                raise RuntimeError("Database maintenance already running")
            try:
                cur.execute("SHOW INDEX FROM device_policy_state WHERE Key_name='idx_effective_policy_version'")
                rows = cur.fetchall()
                if not rows:
                    cur.execute("ALTER TABLE device_policy_state ADD INDEX idx_effective_policy_version (effective_policy_version)")
                    cur.execute("SHOW INDEX FROM device_policy_state WHERE Key_name='idx_effective_policy_version'")
                    rows = cur.fetchall()
                if (len(rows) != 1 or rows[0]["Column_name"] != "effective_policy_version"
                        or rows[0]["Seq_in_index"] != 1 or rows[0]["Non_unique"] != 1
                        or rows[0]["Sub_part"] is not None or rows[0]["Index_type"].upper() != "BTREE"
                        or rows[0].get("Visible", "YES") != "YES" or rows[0].get("Collation") != "A"):
                    raise RuntimeError("Conflicting policy version index")
                cur.execute("""CREATE TABLE IF NOT EXISTS employee_search_index (
                    device_id CHAR(36) NOT NULL PRIMARY KEY,
                    employees_json JSON NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")
                self._check_employee_index(cur)
                cur.execute("""CREATE TABLE IF NOT EXISTS activity_search_index (
                    device_id CHAR(36) NOT NULL PRIMARY KEY,
                    failure_mask TINYINT UNSIGNED NOT NULL,
                    ever_failure BOOLEAN NOT NULL,
                    observed BOOLEAN NOT NULL,
                    INDEX ix_activity_failure (failure_mask, device_id),
                    INDEX ix_activity_ever (ever_failure, device_id),
                    INDEX ix_activity_observed (observed, failure_mask, device_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")
                self._check_activity_index(cur)
                # Full rebuild is transactional. The operator must stop all writers.
                cur.execute("DELETE FROM employee_search_index")
                after = ""
                while True:
                    cur.execute("SELECT device_id,heartbeat_json FROM device_heartbeats WHERE device_id>%s ORDER BY device_id LIMIT 1000", (after,))
                    batch = cur.fetchall()
                    if not batch:
                        break
                    cur.executemany("INSERT INTO employee_search_index (device_id,employees_json) VALUES (%s,%s)",
                        [(row["device_id"], dumps(employee_ids(decode(row["heartbeat_json"]).get("users")))) for row in batch])
                    after = batch[-1]["device_id"]
                cur.execute("DELETE FROM activity_search_index")
                self._refresh_activity_index(cur)
                cur.connection.commit()
            except Exception:
                cur.connection.rollback()
                raise
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        return "scale_indexes_ready"

    @staticmethod
    def _check_employee_index(cur):
        cur.execute("SELECT device_id,employees_json FROM employee_search_index LIMIT 0")
        cur.execute("SHOW COLUMNS FROM employee_search_index")
        columns = {row["Field"]: (row["Type"].lower(), row["Null"]) for row in cur.fetchall()}
        if columns != {"device_id": ("char(36)", "NO"), "employees_json": ("json", "NO")}:
            raise RuntimeError("Employee search index columns do not match")
        cur.execute("SHOW INDEX FROM employee_search_index")
        keys = [row for row in cur.fetchall() if row["Key_name"] == "PRIMARY"]
        if len(keys) != 1 or keys[0]["Column_name"] != "device_id" or keys[0]["Sub_part"] is not None:
            raise RuntimeError("Employee search index key does not match")

    @staticmethod
    def _check_activity_index(cur):
        cur.execute("SELECT device_id,failure_mask,ever_failure,observed FROM activity_search_index LIMIT 0")
        cur.execute("SHOW COLUMNS FROM activity_search_index")
        columns = {row["Field"]: (row["Type"].lower(), row["Null"]) for row in cur.fetchall()}
        if (set(columns) != {"device_id", "failure_mask", "ever_failure", "observed"}
                or columns["device_id"] != ("char(36)", "NO")
                or not re.fullmatch(r"tinyint(?:\(3\))? unsigned", columns["failure_mask"][0])
                or columns["failure_mask"][1] != "NO"
                or any(not re.fullmatch(r"tinyint(?:\(1\))?", columns[name][0]) or columns[name][1] != "NO"
                       for name in ("ever_failure", "observed"))):
            raise RuntimeError("Activity search index columns do not match")
        cur.execute("SHOW INDEX FROM activity_search_index")
        indexes = {}
        for row in cur.fetchall():
            if row["Sub_part"] is not None:
                raise RuntimeError("Activity search index must cover full columns")
            indexes.setdefault(row["Key_name"], []).append((row["Seq_in_index"], row["Column_name"], row["Non_unique"]))
        expected = {"PRIMARY": [(1, "device_id", 0)],
                    "ix_activity_failure": [(1, "failure_mask", 1), (2, "device_id", 1)],
                    "ix_activity_ever": [(1, "ever_failure", 1), (2, "device_id", 1)],
                    "ix_activity_observed": [(1, "observed", 1), (2, "failure_mask", 1), (3, "device_id", 1)]}
        if {key: sorted(value) for key, value in indexes.items()} != expected:
            raise RuntimeError("Activity search index keys do not match")

    @staticmethod
    def _refresh_activity_index(cur, device=None):
        state = "JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.state'))"
        requests = "COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.requestCountSinceBoot')) AS SIGNED),0)"
        eligible = ("JSON_UNQUOTE(JSON_EXTRACT(e.asset_json,'$.isCurrent'))='true' AND "
                    "JSON_UNQUOTE(JSON_EXTRACT(e.asset_json,'$.routeStatus'))='attached' AND " + requests + ">0")
        masks = " + ".join(f"MAX(CASE WHEN {eligible} AND {state}='{name}' THEN {bit} ELSE 0 END)"
                           for name, bit in (("connectionFailed", 1), ("routeFailed", 2), ("gatewayReachedWithError", 4)))
        ever = "MAX(CASE WHEN COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.failureCountSinceBoot')) AS SIGNED),0)>0 THEN 1 ELSE 0 END)"
        observed = (f"MAX(CASE WHEN {requests}>0 OR "
                    "COALESCE(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.lastRequestAtUtc')),'null'),'')<>'' THEN 1 ELSE 0 END)")
        cur.execute("INSERT INTO activity_search_index (device_id,failure_mask,ever_failure,observed) SELECT h.device_id," +
                    masks + "," + ever + "," + observed + " FROM device_heartbeats h "
                    "LEFT JOIN agent_endpoint_assets e ON e.device_id=h.device_id "
                    "LEFT JOIN proxy_activity a ON a.device_id=e.device_id AND a.asset_id=e.asset_id" +
                    (" WHERE h.device_id=%s" if device is not None else "") + " GROUP BY h.device_id "
                    "ON DUPLICATE KEY UPDATE failure_mask=VALUES(failure_mask),ever_failure=VALUES(ever_failure),observed=VALUES(observed)",
                    (device,) if device is not None else ())

    @staticmethod
    def _check_device_policy_constraints(cur):
        cur.execute("SHOW INDEX FROM device_policy_state")
        indexes = {}
        for row in cur.fetchall():
            if row["Non_unique"] == 0:
                if row["Sub_part"] is not None:
                    raise RuntimeError("Device policy key must cover the full device ID")
                indexes.setdefault(row["Key_name"], []).append((row["Seq_in_index"], row["Column_name"]))
        if {tuple(v for _,v in sorted(cols)) for cols in indexes.values()} != {("device_id",)}:
            raise RuntimeError("Device policy unique key does not match")

    @staticmethod
    def _check_replay_constraints(cur):
        cur.execute("SHOW INDEX FROM transport_replay")
        actual = {}
        for row in cur.fetchall():
            if row["Non_unique"] == 0:
                if row["Sub_part"] is not None:
                    raise RuntimeError("Replay table indexes must cover full columns")
                actual.setdefault(row["Key_name"], []).append((row["Seq_in_index"], row["Column_name"]))
        if {tuple(v for _,v in sorted(cols)) for cols in actual.values()} != {("key_id","request_id"),("key_id","nonce")}:
            raise RuntimeError("Replay table unique constraints do not match")

    @staticmethod
    def _policy_candidate(current, update):
        value = wire(update)
        value.pop("expectedVersion")
        allowlist = value["allowlistedBaseUrls"]
        value["allowlistedBaseUrls"] = current["allowlistedBaseUrls"] if allowlist is None else normalize_allowlist(allowlist)
        for field, normalize in (("allowlistedDomains", normalize_domains), ("routingRules", normalize_routing_rules)):
            value[field] = current.get(field, []) if value[field] is None else normalize(value[field])
        if update.allowlistedBaseUrls is not None and update.allowlistedDomains is None:
            migrated = domain_policy({"allowlistedBaseUrls": value["allowlistedBaseUrls"]})
            value["allowlistedDomains"] = migrated["allowlistedDomains"]
            value["allowlistMigration"] = migrated["allowlistMigration"]
        return {**current, **value}

    @staticmethod
    def _assert_no_policy_rollout(cur):
        cur.execute("SELECT batch_id FROM policy_rollout_batches WHERE status IN ('paused','running','dispatchComplete') LIMIT 1")
        if cur.fetchone():
            raise ApiProblem("POLICY_ROLLOUT_ACTIVE", "Finish or abort the active policy rollout first.", 409)

    def update_policy(self, update, actor="admin-token"):
        with self.transaction() as cur:
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
            current = domain_policy(decode(cur.fetchone()["policy_json"]))
            if current["policyVersion"] != update.expectedVersion:
                return None
            self._assert_no_policy_rollout(cur)
            value = {**self._policy_candidate(current, update),
                     "policyVersion": self._next_policy_version(cur, current), "issuedAtUtc": timestamp(utcnow())}
            self._validate_effective_policy(value)
            cur.execute("SELECT DISTINCT overrides_json FROM device_policy_state WHERE overrides_json IS NOT NULL")
            for row in cur.fetchall():
                self._validate_effective_policy({**value, **domain_policy(decode(row["overrides_json"]), overrides=True)})
            cur.execute("UPDATE control_policy SET policy_version=%s,policy_json=%s WHERE singleton_id=1",
                        (value["policyVersion"], dumps(value)))
            self._audit(cur, actor, "GLOBAL_POLICY_UPDATED", summary=(
                "previousVersion=" + str(current["policyVersion"]) + ";version=" + str(value["policyVersion"])))
            return value

    def enroll(self, request):
        token, now, device = generate_device_token(), utcnow(), str(request.deviceId)
        if request.initialDeviceToken is not None:
            try:
                proposed = base64.b64decode(request.initialDeviceToken, validate=True)
                if len(proposed) != 32 or base64.b64encode(proposed).decode("ascii") != request.initialDeviceToken:
                    raise ValueError("invalid token")
            except (ValueError, binascii.Error):
                raise ApiProblem("DEVICE_ENROLLMENT_INVALID", "The enrollment request is invalid.")
            token = request.initialDeviceToken
        generated_hash = hash_token(token)
        with self.transaction() as cur:
            # Serialize registrations with policy rollout promotion so an existing
            # enrollment cannot be missed by its target-completeness check.
            cur.execute("SELECT policy_version FROM control_policy WHERE singleton_id=1 FOR SHARE")
            cur.fetchone()
            # The duplicate-key path takes the row's exclusive lock directly;
            # INSERT followed by a locking SELECT can deadlock on lock upgrade.
            cur.execute("""INSERT INTO device_credentials
                (device_id,token_hash,enrolled_at_utc,last_authenticated_at_utc,revoked)
                VALUES (%s,%s,%s,NULL,0) ON DUPLICATE KEY UPDATE device_id=VALUES(device_id)""",
                (device, generated_hash, dbtime(now)))
            cur.execute("SELECT token_hash,revoked,enrolled_at_utc FROM device_credentials WHERE device_id=%s FOR UPDATE", (device,))
            row = cur.fetchone()
            from .security import safe_compare
            if row["revoked"]:
                raise ApiProblem("DEVICE_ENROLLMENT_CONFLICT", "Device enrollment requires a valid existing credential or administrative recovery.", 409)
            if not safe_compare(generated_hash, row["token_hash"]):
                if (not request.previousDeviceToken
                        or not safe_compare(hash_token(request.previousDeviceToken), row["token_hash"])):
                    raise ApiProblem("DEVICE_ENROLLMENT_CONFLICT", "Device enrollment requires a valid existing credential or administrative recovery.", 409)
                if request.preserveDeviceToken:
                    # An authenticated retry must not invalidate the only credential
                    # before the response has safely reached the device.
                    token, now = request.previousDeviceToken, row["enrolled_at_utc"]
                else:
                    cur.execute("""UPDATE device_credentials SET token_hash=%s,enrolled_at_utc=%s,
                        last_authenticated_at_utc=NULL WHERE device_id=%s""", (generated_hash, dbtime(now), device))
                    if self._credential_rotation_table:
                        cur.execute("DELETE FROM device_credential_rotations WHERE device_id=%s", (device,))
            else:
                now = row["enrolled_at_utc"]
        return dict(deviceId=device, deviceToken=token, enrolledAtUtc=timestamp(now))

    def recover_device_credential(self, device_id, hostname, reason, actor):
        """Explicit audited administrator recovery; invalidates the previous token."""
        now, token, device = utcnow(), generate_device_token(), str(device_id)
        with self.transaction() as cur:
            cur.execute("SELECT hostname FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (device,))
            heartbeat = cur.fetchone()
            if not heartbeat:
                raise ApiProblem("DEVICE_NOT_FOUND", "Device has no reported identity.", 404)
            if heartbeat["hostname"] != hostname:
                raise ApiProblem("DEVICE_HOSTNAME_MISMATCH", "Device hostname does not match.", 409)
            cur.execute("SELECT device_id FROM device_credentials WHERE device_id=%s FOR UPDATE", (device,))
            if not cur.fetchone():
                raise ApiProblem("DEVICE_CREDENTIAL_NOT_FOUND", "Device credential does not exist.", 404)
            cur.execute("""UPDATE device_credentials SET token_hash=%s,enrolled_at_utc=%s,
                last_authenticated_at_utc=NULL,revoked=0 WHERE device_id=%s""",
                (hash_token(token), dbtime(now), device))
            if self._credential_rotation_table:
                cur.execute("DELETE FROM device_credential_rotations WHERE device_id=%s", (device,))
            self._audit(cur, actor, "DEVICE_CREDENTIAL_RECOVERED", device, summary=reason)
        return dict(deviceId=device, deviceToken=token, enrolledAtUtc=timestamp(now))

    def device_transport_verifier(self, device_id):
        """Fetch only an active device's verifier; never log or return the raw token."""
        with self.transaction() as cur:
            row = self._active_credential(cur, device_id)
            return row["token_hash"] if row else None

    def _active_credential(self, cur, device_id):
        if self._credential_rotation_table:
            cur.execute("""SELECT c.token_hash,c.last_authenticated_at_utc,r.next_token_hash,
                r.previous_token_hash,r.committed_at_utc,r.expires_at_utc
                FROM device_credentials c LEFT JOIN device_credential_rotations r ON r.device_id=c.device_id
                WHERE c.device_id=%s AND c.revoked=0""", (str(device_id),))
        else:
            cur.execute("""SELECT token_hash,last_authenticated_at_utc FROM device_credentials
                WHERE device_id=%s AND revoked=0""", (str(device_id),))
        return cur.fetchone()

    @staticmethod
    def _accepted_credential_hashes(row, now):
        if not row:
            return ()
        from .credential_rotation import alternate_hash
        alternate = alternate_hash(row, now) if row.get('expires_at_utc') is not None else None
        primary = row['token_hash']
        return (primary, alternate) if alternate is not None and alternate != primary else (primary,)

    def device_transport_verifiers(self, device_id):
        with self.transaction() as cur:
            return self._accepted_credential_hashes(self._active_credential(cur, device_id), dbtime(utcnow()))

    def authenticate(self, device_id, token):
        with self.transaction() as cur:
            row = self._active_credential(cur, device_id)
            from .security import safe_compare
            now = dbtime(utcnow())
            supplied = hash_token(token)
            if not any(safe_compare(supplied, value) for value in self._accepted_credential_hashes(row, now)):
                return False
            if row["last_authenticated_at_utc"] is None or now - row["last_authenticated_at_utc"] >= timedelta(minutes=5):
                cur.execute("""UPDATE device_credentials SET last_authenticated_at_utc=%s
                    WHERE device_id=%s AND token_hash=%s AND revoked=0
                    AND (last_authenticated_at_utc IS NULL OR last_authenticated_at_utc<=%s)""",
                    (now, str(device_id), row["token_hash"], now - timedelta(minutes=5)))
            return True

    @staticmethod
    def _replace_inventory(cur, device, table, key_column, json_column, values, key, kind_column=None, kind=None, previous=None):
        if previous is None:
            cur.execute(f"SELECT {key_column},{json_column} FROM {table} WHERE device_id=%s", (device,))
            previous = {row[key_column]: decode(row[json_column]) for row in cur.fetchall()}
        incoming = {}
        for value in values:
            identity = value[key]
            if identity in incoming:
                raise ApiProblem("HEARTBEAT_V2_INVALID", "Duplicate inventory identifiers are not accepted.")
            incoming[identity] = value
        removed = previous.keys() - incoming.keys()
        changed = bool(removed)
        if removed:
            placeholders = ",".join(["%s"] * len(removed))
            cur.execute(f"DELETE FROM {table} WHERE device_id=%s AND {key_column} IN ({placeholders})",
                        (device, *removed))
        updates = [(identity, value) for identity, value in incoming.items() if previous.get(identity) != value]
        if updates:
            changed = True
            if kind_column:
                cur.executemany(f"""INSERT INTO {table} (device_id,{key_column},{kind_column},{json_column})
                    VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
                    {kind_column}=VALUES({kind_column}),{json_column}=VALUES({json_column})""",
                    [(device, identity, value[kind], dumps(value)) for identity, value in updates])
            else:
                cur.executemany(f"""INSERT INTO {table} (device_id,{key_column},{json_column})
                    VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE {json_column}=VALUES({json_column})""",
                    [(device, identity, dumps(value)) for identity, value in updates])
        return changed

    def heartbeat(self, h, interval, source_ip, compact_inventory=False):
        value, device, now = wire(h), str(h.device.deviceId), dbtime(utcnow())
        with self.transaction() as cur:
            if h.schemaVersion == 2 and h.inventoryUnchanged:
                cur.execute("SELECT heartbeat_json FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (device,))
                baseline = cur.fetchone()
                baseline = decode(baseline["heartbeat_json"]) if baseline else None
                if not baseline or baseline.get("schemaVersion") != 2:
                    raise ApiProblem("INVENTORY_BASELINE_MISSING", "Send a full heartbeat before a lightweight heartbeat.", 404)
                if compact_inventory:
                    # Inventory is omitted only on the dedicated negotiated route.
                    # Preserve the acknowledged baseline inside the same row lock.
                    value["users"] = baseline.get("users") or []
                    value["agents"] = baseline.get("agents") or []
            cur.execute("""INSERT INTO device_heartbeats VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE received_at_utc=VALUES(received_at_utc),
                hostname=VALUES(hostname),os_version=VALUES(os_version),
                applied_policy_version=VALUES(applied_policy_version),proxy_state=VALUES(proxy_state),
                heartbeat_json=VALUES(heartbeat_json)""",
                (device, now, h.device.hostname, h.device.osVersion, h.policy.appliedVersion or 0,
                 h.proxy.state.value, dumps(value)))
            new_device = cur.rowcount == 1
            if self.cfg.EMPLOYEE_INDEX and (new_device or h.schemaVersion == 1 or not h.inventoryUnchanged):
                cur.execute("""INSERT INTO employee_search_index (device_id,employees_json) VALUES (%s,%s)
                    ON DUPLICATE KEY UPDATE employees_json=VALUES(employees_json)""",
                    (device, dumps(employee_ids(value["users"]))))
            if h.schemaVersion == 1 or not h.inventoryUnchanged:
                self._replace_inventory(cur, device, "agent_inventory", "instance_id", "inventory_json",
                                        value["agents"], "instanceId", "agent_type", "agentType")
            if h.schemaVersion == 1:
                if self.cfg.EMPLOYEE_INDEX and new_device:
                    self._refresh_activity_index(cur, device)
                return
            cur.execute("""INSERT INTO device_runtime VALUES (%s,2,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE schema_version=2,service_version=VALUES(service_version),
                heartbeat_interval_seconds=VALUES(heartbeat_interval_seconds),
                operation_state=VALUES(operation_state),source_ip=VALUES(source_ip),runtime_json=VALUES(runtime_json)""",
                (device, h.device.serviceVersion, interval, h.runtime.operationState.value, source_ip, dumps(h.runtime)))
            assets_changed = False
            if not h.inventoryUnchanged:
                assets_changed = self._replace_inventory(cur, device, "agent_endpoint_assets", "asset_id", "asset_json",
                                                         value["endpoints"], "assetId", "agent_family", "agentFamily")
            cur.execute("SELECT asset_id,activity_json FROM proxy_activity WHERE device_id=%s", (device,))
            previous = {r["asset_id"]: decode(r["activity_json"]) for r in cur.fetchall()}
            for a in value["activity"]:
                old = previous.get(a["assetId"])
                if a["state"] == "neverObserved" and old and old["state"] != "neverObserved":
                    for key in ("state", "lastRequestAtUtc", "lastSuccessAtUtc", "lastFailureAtUtc",
                                "lastHttpStatusCode", "lastOutcome", "lastErrorCode", "lastGatewayRoundTripMilliseconds"):
                        a[key] = old[key]
            activity_changed = self._replace_inventory(cur, device, "proxy_activity", "asset_id", "activity_json", value["activity"], "assetId", previous=previous)
            if self.cfg.EMPLOYEE_INDEX and (new_device or assets_changed or activity_changed):
                self._refresh_activity_index(cur, device)

    def events(self, batch):
        accepted = duplicates = 0
        with self.transaction() as cur:
            for event in batch.events:
                try:
                    cur.execute("INSERT INTO endpoint_events VALUES (%s,%s,%s,%s,%s)",
                        (str(event.eventId), str(batch.deviceId), dbtime(event.occurredAtUtc), dbtime(utcnow()), dumps(event)))
                    accepted += 1
                except pymysql.err.IntegrityError as exc:
                    if exc.args[0] != 1062:
                        raise
                    duplicates += 1
        return dict(accepted=accepted, duplicates=duplicates, rejected=0, errors=[])

    @staticmethod
    def _summary(row):
        heartbeat = decode(row["heartbeat_json"])
        return dict(deviceId=row["device_id"], lastSeenAtUtc=timestamp(row["received_at_utc"]),
            employeeIds=employee_ids(heartbeat.get("users")),
            supportedPolicySchemaVersion=(heartbeat.get("runtime") or {}).get("supportedPolicySchemaVersion", 1),
            appliedPolicySchemaVersion=(heartbeat.get("policy") or {}).get("appliedSchemaVersion", 1),
            hostname=row["hostname"], osVersion=row["os_version"], agentCount=row["agent_count"],
            appliedPolicyVersion=row["applied_policy_version"], proxyState=row["proxy_state"],
            serviceVersion=row["service_version"], endpointCount=0,
            operationState=row["operation_state"] or "unknown",
            heartbeatIntervalSeconds=row["heartbeat_interval_seconds"] or 60,
            schemaVersion=row["schema_version"] or 1)

    def devices(self, device_id=None):
        with self.transaction() as cur:
            cur.execute("""SELECT h.*,r.service_version,r.operation_state,r.heartbeat_interval_seconds,r.schema_version,
                (SELECT COUNT(*) FROM agent_inventory a WHERE a.device_id=h.device_id
                 AND a.agent_type NOT IN ('ccSwitch','unknownCandidate')) AS agent_count
                FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),1)=2"""
                + (" WHERE h.device_id=%s" if device_id else "") + " ORDER BY h.received_at_utc DESC",
                (str(device_id),) if device_id else ())
            rows = [self._summary(r) for r in cur.fetchall()]
            cur.execute("SELECT device_id,asset_json FROM agent_endpoint_assets" +
                        (" WHERE device_id=%s" if device_id else ""), (str(device_id),) if device_id else ())
            identities = {}
            for row in cur.fetchall():
                a = decode(row["asset_json"])
                if a["isCurrent"]:
                    identities.setdefault(row["device_id"], set()).add((
                        a["userSid"], a["agentFamily"], a["configurationSource"], a["providerId"], a["endpointId"] or ""))
            for row in rows:
                row["endpointCount"] = len(identities.get(row["deviceId"], ())) if row["schemaVersion"] >= 2 else 0
            return rows

    def details(self, device):
        summaries = self.devices(device)
        if not summaries:
            return None
        with self.transaction() as cur:
            result = {"device": summaries[0]}
            for key, table, column, order in (
                ("agents", "agent_inventory", "inventory_json", "agent_type,instance_id"),
                ("endpoints", "agent_endpoint_assets", "asset_json", "agent_family,asset_id"),
                ("activity", "proxy_activity", "activity_json", "asset_id"),
            ):
                if key != "agents" and summaries[0]["schemaVersion"] < 2:
                    result[key] = []
                    continue
                cur.execute(f"SELECT {column} FROM {table} WHERE device_id=%s ORDER BY {order}", (str(device),))
                result[key] = [decode(r[column]) for r in cur.fetchall()]
            cur.execute("SELECT runtime_json FROM device_runtime WHERE device_id=%s", (str(device),))
            runtime = cur.fetchone()
            result["runtime"] = decode(runtime["runtime_json"]) if runtime and summaries[0]["schemaVersion"] >= 2 else None
            return result

    def analytics_snapshot(self):
        """Read policy and all assets from one consistent snapshot, without per-host queries."""
        with self.transaction() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            return self._analytics_snapshot(cur)

    def analytics_aggregate(self, now, scope="online", os=None, partitions=False, observer=None):
        """Aggregate bounded batches in a single consistent database snapshot."""
        from .analytics import build_batches, build_partitions
        with self.transaction() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            _, policy = self._analytics_snapshot(cur, [])
            def batches():
                after = None
                while True:
                    if after is None:
                        cur.execute("SELECT device_id FROM device_heartbeats ORDER BY device_id LIMIT 500")
                    else:
                        cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id > %s ORDER BY device_id LIMIT 500", (after,))
                    ids = [row["device_id"] for row in cur.fetchall()]
                    if not ids:
                        break
                    after = ids[-1]
                    rows, _ = self._analytics_snapshot(cur, ids)
                    yield rows
            if partitions:
                return build_partitions(batches(), policy, now, observer), policy
            return build_batches(batches(), policy, now, scope, os)

    @contextmanager
    def _analytics_search_budget(self, cur, enabled):
        if not enabled:
            yield
            return
        lock = "eai-complex-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode("utf-8")).hexdigest()[:40]
        cur.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock,))
        if cur.fetchone()["acquired"] != 1:
            raise ApiProblem("ANALYTICS_BUSY", "An expensive analytics query is already running; retry later.", 503)
        try:
            yield
        finally:
            cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))

    def analytics_filtered_page(self, now, scope="online", os=None, skip=0, take=50, **filters):
        """Evaluate complex filters in bounded batches and retain only the requested page."""
        from .analytics import drill_down
        skip, take = max(0, skip), min(500, max(1, take))
        selected, total, after = [], 0, None
        with self.transaction() as cur:
            lock = "eai-complex-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode("utf-8")).hexdigest()[:40]
            cur.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                raise ApiProblem("ANALYTICS_BUSY", "A complex analytics query is already running; retry later.", 503)
            try:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
                while True:
                    if after is None:
                        cur.execute("SELECT device_id,received_at_utc FROM device_heartbeats "
                                    "ORDER BY received_at_utc DESC,device_id LIMIT 500")
                    else:
                        cur.execute("SELECT device_id,received_at_utc FROM device_heartbeats "
                                    "WHERE received_at_utc < %s OR (received_at_utc = %s AND device_id > %s) "
                                    "ORDER BY received_at_utc DESC,device_id LIMIT 500", (after[0], after[0], after[1]))
                    page = cur.fetchall()
                    if not page:
                        break
                    after = (page[-1]["received_at_utc"], page[-1]["device_id"])
                    rows, policy = self._analytics_snapshot(cur, [row["device_id"] for row in page])
                    matches = drill_down(rows, policy, now, scope=scope, os=os, take=500, **filters)
                    start = max(0, skip - total)
                    end = min(matches["total"], skip + take - total)
                    if end > start:
                        selected.extend(matches["devices"][start:end])
                    total += matches["total"]
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        return dict(total=total, skip=skip, take=take, updatedAtUtc=timestamp(now), devices=selected)

    def dashboard(self, now):
        """Aggregate legacy dashboard counts without loading device assets."""
        with self.transaction() as cur:
            cur.execute("""SELECT COUNT(*) AS totalDevices,
                COALESCE(SUM(age_us <= (seconds * 2 + 30) * 1000000),0) AS online,
                COALESCE(SUM(age_us > (seconds * 2 + 30) * 1000000 AND
                             age_us <= (seconds * 5 + 30) * 1000000),0) AS stale,
                COALESCE(SUM(age_us > (seconds * 5 + 30) * 1000000),0) AS offline,
                COALESCE(SUM(schema_version < 2),0) AS legacyClients,
                COALESCE(SUM(operation_state = 'disabled'),0) AS proxyDisabled
                FROM (SELECT TIMESTAMPDIFF(MICROSECOND,h.received_at_utc,%s) AS age_us,
                    GREATEST(15,LEAST(3600,COALESCE(NULLIF(r.heartbeat_interval_seconds,0),60))) AS seconds,
                    COALESCE(r.schema_version,1) AS schema_version,
                    COALESCE(r.operation_state,'unknown') AS operation_state
                FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),1)=2) AS devices""",
                (dbtime(now),))
            result = cur.fetchone()
        return {**{key: int(value) for key, value in result.items()}, "updatedAtUtc": timestamp(now)}

    def analytics_page(self, scope, os_filter, now, skip, take, hostname_search=None, employee_search=None,
                       kind=None, key=None, anomaly=None):
        """Page simple inventory queries in the database under the same snapshot."""
        interval = "GREATEST(15,LEAST(3600,COALESCE(NULLIF(r.heartbeat_interval_seconds,0),60)))"
        elapsed = "TIMESTAMPDIFF(MICROSECOND,h.received_at_utc,%s)"
        conditions, args = [], []
        if scope in ("online", "stale", "offline"):
            online = f"({elapsed} <= ({interval}*2+30)*1000000)"
            stale = f"({elapsed} <= ({interval}*5+30)*1000000)"
            if scope == "online":
                conditions.append(online)
                args.append(dbtime(now))
            elif scope == "stale":
                conditions.append(f"NOT {online} AND {stale}")
                args.extend((dbtime(now), dbtime(now)))
            else:
                conditions.append(f"NOT {stale}")
                args.append(dbtime(now))
        elif scope == "legacyclient":
            conditions.append("COALESCE(r.schema_version,1)<2")
        if kind == "online":
            conditions.append(f"({elapsed} <= ({interval}*2+30)*1000000)")
            args.append(dbtime(now))
        # These predicates match analytics.project's per-endpoint semantics. The
        # primary keys ensure each joined asset/activity pair is unique.
        joined = " FROM agent_endpoint_assets e JOIN proxy_activity a ON a.device_id=e.device_id AND a.asset_id=e.asset_id WHERE e.device_id=h.device_id"
        request_count = "COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.requestCountSinceBoot')) AS SIGNED),0)"
        state = "JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.state'))"
        current_failure = (joined + " AND JSON_UNQUOTE(JSON_EXTRACT(e.asset_json,'$.isCurrent'))='true'"
            + " AND JSON_UNQUOTE(JSON_EXTRACT(e.asset_json,'$.routeStatus'))='attached'"
            + f" AND {request_count}>0 AND {state} IN ('connectionFailed','routeFailed','gatewayReachedWithError')")
        ever_failure = joined + " AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.failureCountSinceBoot')) AS SIGNED),0)>0"
        observed = joined + f" AND ({request_count}>0 OR COALESCE(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(a.activity_json,'$.lastRequestAtUtc')),'null'),'')<>'')"
        if kind in ("anomaly", "error", "everAnomaly") or anomaly in ("latest", "ever", "none"):
            conditions.append("r.device_id IS NOT NULL")
        if self.cfg.EMPLOYEE_INDEX:
            def indexed(predicate):
                return "h.device_id IN (SELECT device_id FROM activity_search_index WHERE " + predicate + ")"
            if kind == "anomaly":
                conditions.append(indexed("failure_mask>0"))
            elif kind == "error":
                values = {"connectionfailed": "1,3,5,7", "routefailed": "2,3,6,7",
                          "gatewayreachedwitherror": "4,5,6,7"}.get((key or "").lower())
                conditions.append(indexed("failure_mask IN (" + values + ")") if values else "1=0")
            elif kind == "everAnomaly":
                conditions.append(indexed("ever_failure=1"))
            if anomaly == "latest":
                conditions.append(indexed("failure_mask>0"))
            elif anomaly == "ever":
                conditions.append(indexed("ever_failure=1"))
            elif anomaly == "none":
                conditions.append(indexed("observed=1 AND failure_mask=0"))
        else:
            if kind in ("anomaly", "error"):
                conditions.append("EXISTS (SELECT 1" + current_failure +
                                  (f" AND LOWER({state})=LOWER(%s)" if kind == "error" else "") + ")")
                if kind == "error":
                    args.append(key or "")
            elif kind == "everAnomaly":
                conditions.append("EXISTS (SELECT 1" + ever_failure + ")")
            if anomaly == "latest":
                conditions.append("EXISTS (SELECT 1" + current_failure + ")")
            elif anomaly == "ever":
                conditions.append("EXISTS (SELECT 1" + ever_failure + ")")
            elif anomaly == "none":
                conditions.append("NOT EXISTS (SELECT 1" + current_failure + ")")
                conditions.append("EXISTS (SELECT 1" + observed + ")")
        if os_filter:
            conditions.append("INSTR(LOWER(h.os_version),LOWER(%s))>0")
            args.append(os_filter)
        if hostname_search and hostname_search.strip():
            conditions.append("(INSTR(LOWER(h.hostname),LOWER(%s))>0 OR INSTR(LOWER(h.device_id),LOWER(%s))>0)")
            args.extend((hostname_search, hostname_search))
        if employee_search:
            raw_account = "REGEXP_REPLACE(u.account_name,'^[[:space:]]+|[[:space:]]+$','')"
            account = f"IF(LEFT(LOWER({raw_account}),3)=CONCAT('sf',CHAR(92)),SUBSTRING({raw_account},4),{raw_account})"
            if self.cfg.EMPLOYEE_INDEX:
                conditions.append("""(INSTR(LOWER(h.hostname),LOWER(%s))>0
                    OR INSTR(LOWER(h.device_id),LOWER(%s))>0 OR EXISTS (
                        SELECT 1 FROM employee_search_index ei,
                        JSON_TABLE(ei.employees_json, '$[*]' COLUMNS (
                            account_name LONGTEXT PATH '$')) u
                        WHERE ei.device_id=h.device_id
                        AND INSTR(LOWER(u.account_name) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0))""")
            else:
                conditions.append(f"""(INSTR(LOWER(h.hostname),LOWER(%s))>0
                OR INSTR(LOWER(h.device_id),LOWER(%s))>0 OR EXISTS (
                    SELECT 1 FROM JSON_TABLE(h.heartbeat_json, '$.users[*]' COLUMNS (
                        account_name LONGTEXT PATH '$.accountName' NULL ON EMPTY,
                        sid LONGTEXT PATH '$.sid' NULL ON EMPTY)) u
                    WHERE {account}<>'' AND BINARY {account}<>BINARY COALESCE(u.sid,'')
                    AND NOT REGEXP_LIKE({account}, '^S-[0-9]-', 'i')
                    AND LEFT(LOWER({account}),6)<>'macos:'
                    AND LOWER(SUBSTRING_INDEX({account},CHAR(92),-1)) COLLATE utf8mb4_bin NOT IN
                        ('system','local service','network service','administrator','guest','defaultaccount','wdagutilityaccount','root','daemon')
                    AND INSTR(LOWER({account}) COLLATE utf8mb4_bin,LOWER(%s) COLLATE utf8mb4_bin)>0))""")
            args.extend((employee_search, employee_search, employee_search))
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        source = " FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),1)=2"
        # All-state queries without anomaly filters only reference heartbeat
        # columns (and optional employee lookup tables). Runtime is hydrated
        # for the selected page later; joining it here scans it for every row.
        if scope == "all" and kind in (None, "") and not anomaly:
            source = " FROM device_heartbeats h"
        expensive = bool(employee_search) or (not self.cfg.EMPLOYEE_INDEX and (
            kind in ("anomaly", "error", "everAnomaly") or anomaly in ("latest", "ever", "none")))
        with self.transaction() as cur, self._analytics_search_budget(cur, expensive):
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            # Every allowed interval is at least 15 seconds, so a heartbeat
            # received in the last 60 seconds is unconditionally online. Count
            # that range using the received-time index without joining runtime;
            # the older range still uses the exact per-device predicate. Both
            # branches execute under the same consistent snapshot as the page.
            plain_online = ((scope == "online" and kind in (None, "", "online")) or
                            (scope == "all" and kind == "online")) and not any(
                                (os_filter, hostname_search, employee_search, anomaly))
            if plain_online:
                recent = dbtime(now - timedelta(seconds=60))
                oldest = dbtime(now - timedelta(seconds=7230))
                cur.execute("""SELECT CAST(SUM(recent_n) AS UNSIGNED) AS recent_count,
                    CAST(SUM(older_n) AS UNSIGNED) AS older_count FROM (
                    SELECT COUNT(*) AS recent_n,0 AS older_n FROM device_heartbeats h WHERE h.received_at_utc >= %s
                    UNION ALL SELECT 0 AS recent_n,COUNT(*) AS older_n""" + source +
                    " WHERE h.received_at_utc < %s AND h.received_at_utc >= %s AND " +
                    f"({elapsed} <= ({interval}*2+30)*1000000)) AS online_counts",
                    (recent, recent, oldest, dbtime(now)))
                counts = cur.fetchone()
                recent_count = counts["recent_count"]
                total = recent_count + counts["older_count"]
                ids = []
                if skip < recent_count:
                    cur.execute("""SELECT h.device_id FROM device_heartbeats h
                        WHERE h.received_at_utc >= %s
                        ORDER BY h.received_at_utc DESC,h.device_id LIMIT %s OFFSET %s""",
                        (recent, min(take, recent_count - skip), skip))
                    ids.extend(row["device_id"] for row in cur.fetchall())
                remaining = take - len(ids)
                if remaining > 0 and skip + len(ids) < total:
                    cur.execute("SELECT h.device_id" + source +
                        " WHERE h.received_at_utc < %s AND h.received_at_utc >= %s AND " +
                        f"({elapsed} <= ({interval}*2+30)*1000000)" +
                        " ORDER BY h.received_at_utc DESC,h.device_id LIMIT %s OFFSET %s",
                        (recent, oldest, dbtime(now), remaining, max(0, skip - recent_count)))
                    ids.extend(row["device_id"] for row in cur.fetchall())
            elif employee_search:
                # Search already scans candidates for an exact total. Compute
                # the page and total together under the same snapshot, avoiding
                # a second expensive JSON search when the page is nonempty.
                cur.execute("SELECT h.device_id,COUNT(*) OVER() AS total" + source + where +
                            " ORDER BY h.received_at_utc DESC,h.device_id LIMIT %s OFFSET %s", (*args, take, skip))
                page = cur.fetchall()
                ids = [row["device_id"] for row in page]
                if page:
                    total = page[0]["total"]
                else:
                    # An out-of-range page carries no window row but must
                    # still report the actual total.
                    cur.execute("SELECT COUNT(*) AS total" + source + where, args)
                    total = cur.fetchone()["total"]
            else:
                cur.execute("SELECT COUNT(*) AS total" + source + where, args)
                total = cur.fetchone()["total"]
                cur.execute("SELECT h.device_id" + source + where +
                            " ORDER BY h.received_at_utc DESC,h.device_id LIMIT %s OFFSET %s", (*args, take, skip))
                ids = [row["device_id"] for row in cur.fetchall()]
            rows, policy = self._analytics_snapshot(cur, ids)
            return rows, policy, total

    def _analytics_snapshot(self, cur, device_ids=None):
        cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1")
        policy = domain_policy(decode(cur.fetchone()["policy_json"]))
        if device_ids is not None and not device_ids:
            return [], policy
        clause = "" if device_ids is None else " WHERE device_id IN (" + ",".join(["%s"] * len(device_ids)) + ")"
        heartbeat_clause = "" if device_ids is None else " WHERE h.device_id IN (" + ",".join(["%s"] * len(device_ids)) + ")"
        args = () if device_ids is None else tuple(device_ids)
        cur.execute("""SELECT h.*,r.service_version,r.operation_state,r.heartbeat_interval_seconds,r.schema_version,r.runtime_json,
            (SELECT COUNT(*) FROM agent_inventory a WHERE a.device_id=h.device_id
             AND a.agent_type NOT IN ('ccSwitch','unknownCandidate')) AS agent_count
            FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),1)=2"""
            + heartbeat_clause + " ORDER BY h.received_at_utc DESC,h.device_id", args)
        rows = {}
        for row in cur.fetchall():
            heartbeat = decode(row["heartbeat_json"])
            rows[row["device_id"]] = dict(device=self._summary(row),
                runtime=decode(row["runtime_json"]) if row["runtime_json"] else None,
                _stateless=bool(heartbeat.get("statelessPolicyVersions")),
                agents=heartbeat.get("agents") or [], endpoints=[], activity=[])
        cur.execute("SELECT device_id,base_policy_version,effective_policy_version,overrides_json,effective_policy_json FROM device_policy_state" + clause, args)
        states = {row["device_id"]: row for row in cur.fetchall()}
        for device, detail in rows.items():
            state = states.get(device)
            stateless = detail.pop("_stateless")
            detail["device"]["expectedPolicyVersion"] = (policy["policyVersion"] if state is None or
                (stateless and state["base_policy_version"] != policy["policyVersion"]) else
                state["effective_policy_version"] if state["base_policy_version"] == policy["policyVersion"] else None)
            detail["effectivePolicy"] = (domain_policy(decode(state["effective_policy_json"]))
                if state and state["base_policy_version"] == policy["policyVersion"] else
                {**policy, **(domain_policy(decode(state["overrides_json"]), overrides=True)
                 if state and state["overrides_json"] is not None else {})})
            detail["device"]["expectedPolicySchemaVersion"] = (2 if stateless else decode(state["effective_policy_json"])["schemaVersion"] if state else 1)
        for key, table, column in (("endpoints", "agent_endpoint_assets", "asset_json"),
                                   ("activity", "proxy_activity", "activity_json")):
            cur.execute(f"SELECT device_id,{column} FROM {table}" + clause, args)
            for row in cur.fetchall():
                if row["device_id"] in rows and rows[row["device_id"]]["device"]["schemaVersion"] >= 2:
                    rows[row["device_id"]][key].append(decode(row[column]))
        for detail in rows.values():
            detail["device"]["endpointCount"] = len({(a.get("userSid"), a.get("agentFamily"),
                a.get("configurationSource"), a.get("providerId"), a.get("endpointId") or "")
                for a in detail["endpoints"] if a.get("isCurrent")})
        return list(rows.values()), policy

    @staticmethod
    def _audit(cur, actor, action, device=None, command=None, summary=""):
        cur.execute("INSERT INTO admin_audit_log VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (str(uuid4()), dbtime(utcnow()), actor, action,
                     str(device) if device else None, str(command) if command else None, summary))

    def audit(self, actor, action, device=None, command=None, summary=""):
        with self.transaction() as cur:
            self._audit(cur, actor, action, device, command, summary)

    @staticmethod
    def _expire(cur, device, now):
        cur.execute("""UPDATE remote_commands SET status='expired',completed_at_utc=%s,
            result_code='COMMAND_EXPIRED',result_summary='The command expired before completion.'
            WHERE device_id=%s AND status='pending' AND expires_at_utc<=%s""",
            (now, str(device), now))

    @staticmethod
    def _command(row):
        return dict(commandId=row["command_id"],deviceId=row["device_id"],type=row["command_type"],
            status=row["status"],createdAtUtc=timestamp(row["created_at_utc"]),
            expiresAtUtc=timestamp(row["expires_at_utc"]),createdBy=row["created_by"],reason=row["reason"],
            deliveredAtUtc=timestamp(row["delivered_at_utc"]) if row["delivered_at_utc"] else None,
            startedAtUtc=timestamp(row["started_at_utc"]) if row["started_at_utc"] else None,
            completedAtUtc=timestamp(row["completed_at_utc"]) if row["completed_at_utc"] else None,
            resultCode=row["result_code"],resultSummary=row["result_summary"],deliveryCount=row["delivery_count"])

    def create_command(self, device, request, actor):
        command = str(uuid4())
        with self.transaction() as cur:
            # Device row is the common lock for creation, leasing and cancellation.
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (str(device),))
            if not cur.fetchone():
                return None
            now = dbtime(utcnow())
            self._expire(cur, device, now)
            cur.execute("""SELECT command_id FROM remote_commands WHERE device_id=%s
                AND status IN ('pending','delivered','executing') FOR UPDATE""", (str(device),))
            if cur.fetchone():
                raise ApiProblem("DEVICE_COMMAND_ALREADY_ACTIVE", "The device already has an active command.", 409)
            cur.execute("""INSERT INTO remote_commands
                (command_id,device_id,command_type,status,created_at_utc,expires_at_utc,created_by,reason)
                VALUES (%s,%s,%s,'pending',%s,%s,%s,%s)""",
                (command, str(device), request.type.value, now, now + timedelta(minutes=request.expiresInMinutes), actor, request.reason))
            self._audit(cur, actor, "REMOTE_COMMAND_CREATED", device, command, request.type.name)
            cur.execute("SELECT * FROM remote_commands WHERE command_id=%s", (command,))
            return self._command(cur.fetchone())

    def lease(self, device):
        with self.transaction() as cur:
            # Most heartbeats have no command. A concurrent insertion after
            # this read is picked up on the next heartbeat; actual leasing
            # still locks and rechecks the device and command rows.
            cur.execute("""SELECT 1 FROM remote_commands WHERE device_id=%s
                AND status IN ('pending','delivered','executing') LIMIT 1""", (str(device),))
            if not cur.fetchone():
                return None
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (str(device),))
            if not cur.fetchone():
                return None
            now = dbtime(utcnow())
            self._expire(cur, device, now)
            cur.execute("""SELECT * FROM remote_commands WHERE device_id=%s
                AND status IN ('pending','delivered','executing') ORDER BY created_at_utc LIMIT 1 FOR UPDATE""", (str(device),))
            row = cur.fetchone()
            if row is None:
                return None
            if row["status"] in ("delivered", "executing") and row["expires_at_utc"] <= now:
                # It may have taken effect before the client lost its receipt.
                # Preserve the active slot for manual result-unknown handling,
                # but do not redeliver it to older clients that may rerun it.
                return None
            cur.execute("""UPDATE remote_commands SET status=IF(status='pending','delivered',status),
                delivered_at_utc=COALESCE(delivered_at_utc,%s),delivery_count=delivery_count+1
                WHERE command_id=%s""", (now, row["command_id"]))
            cur.execute("SELECT * FROM remote_commands WHERE command_id=%s", (row["command_id"],))
            return self._command(cur.fetchone())

    def update_command(self, update):
        with self.transaction() as cur:
            # Retries use a new transport envelope after a lost response. Accept the
            # same completed result without replacing the first completion time.
            cur.execute("""SELECT status,result_code,result_summary FROM remote_commands
                WHERE command_id=%s AND device_id=%s FOR UPDATE""",
                        (str(update.commandId), str(update.deviceId)))
            row = cur.fetchone()
            if not row:
                return False
            if row["status"] in ("succeeded", "failed", "expired", "cancelled"):
                return (row["status"] in ("succeeded", "failed")
                        and row["status"] == update.status.value
                        and row["result_code"] == update.resultCode
                        and row["result_summary"] == update.resultSummary)
            late = row["status"] == "resultUnknown"
            if late and update.status.value == "executing":
                return True
            cur.execute("""UPDATE remote_commands SET status=%s,
                started_at_utc=IF(%s='executing',COALESCE(started_at_utc,%s),started_at_utc),
                completed_at_utc=IF(%s IN ('succeeded','failed'),%s,completed_at_utc),
                result_code=%s,result_summary=%s WHERE command_id=%s""",
                (update.status.value, update.status.value, dbtime(update.observedAtUtc),
                 update.status.value, dbtime(update.observedAtUtc), update.resultCode, update.resultSummary, str(update.commandId)))
            if late:
                self._audit(cur, "device-receipt", "REMOTE_COMMAND_LATE_RESULT", update.deviceId,
                            update.commandId, update.status.value)
            return True

    def commands(self, device):
        with self.transaction() as cur:
            cur.execute("SELECT * FROM remote_commands WHERE device_id=%s ORDER BY created_at_utc DESC LIMIT 100", (str(device),))
            return [self._command(row) for row in cur.fetchall()]

    def cancel(self, command, actor):
        with self.transaction() as cur:
            cur.execute("SELECT device_id FROM remote_commands WHERE command_id=%s", (str(command),))
            row = cur.fetchone()
            if not row:
                return False
            device = row["device_id"]
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (device,))
            cur.execute("""UPDATE remote_commands SET status='cancelled',completed_at_utc=%s,
                result_code='COMMAND_CANCELLED',result_summary='Cancelled before delivery.'
                WHERE command_id=%s AND status='pending'""", (dbtime(utcnow()), str(command)))
            if cur.rowcount != 1:
                return False
            self._audit(cur, actor, "REMOTE_COMMAND_CANCELLED", device, command, "Cancelled before delivery.")
            return True

    def resolve_unknown(self, command, actor, reason):
        with self.transaction() as cur:
            cur.execute("SELECT device_id FROM remote_commands WHERE command_id=%s", (str(command),))
            row = cur.fetchone()
            if not row:
                return False
            device = row["device_id"]
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (device,))
            now = dbtime(utcnow())
            cur.execute("""UPDATE remote_commands SET status='resultUnknown',completed_at_utc=%s,
                result_code='RESULT_UNKNOWN',result_summary='Execution outcome requires manual verification.'
                WHERE command_id=%s AND status IN ('delivered','executing') AND expires_at_utc<=%s""",
                (now, str(command), now))
            if cur.rowcount != 1:
                return False
            self._audit(cur, actor, "REMOTE_COMMAND_RESULT_UNKNOWN", device, command, reason)
            return True

    def audits(self, device=None, skip=0, take=100):
        with self.transaction() as cur:
            cur.execute("SELECT * FROM admin_audit_log" + (" WHERE device_id=%s" if device else "") +
                " ORDER BY occurred_at_utc DESC LIMIT %s OFFSET %s",
                ((str(device),) if device else ()) + (take, skip))
            return [dict(auditId=r["audit_id"],occurredAtUtc=timestamp(r["occurred_at_utc"]),
                actor=r["actor"],action=r["action"],deviceId=r["device_id"],
                commandId=r["command_id"],summary=r["summary"]) for r in cur.fetchall()]
