"""MySQL storage. Each operation owns its connection and transaction."""
import hashlib
import json
import re
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pymysql
from pymysql.cursors import DictCursor
from config import ROOT
from .security import dumps, generate_device_token, hash_token, timestamp, utcnow, wire
from .validation import ApiProblem, normalize_allowlist, seed_policy

SCHEMA_PATH = ROOT / "conf" / "endpoint_ai_proxy.sql"
SCHEMA_VERSION = 2
PREVIOUS_CHECKSUM = "26e356840574088656a60eeedd69a319172563e03009864ad61f9a82d1fc0d28"
LEGACY_TABLES = {"server_policy", "devices", "device_users", "agent_inventory",
                 "endpoint_assets", "proxy_activity", "device_runtime", "events",
                 "remote_commands", "audit_log"}


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


class ControlStore:
    def __init__(self, cfg):
        self.cfg = cfg

    def connect(self):
        c = self.cfg
        return pymysql.connect(host=c.MYSQL_HOST, port=c.MYSQL_PORT, user=c.MYSQL_USER,
            password=c.MYSQL_PASSWORD, database=c.MYSQL_DATABASE, charset="utf8mb4",
            cursorclass=DictCursor, autocommit=False, connect_timeout=5, read_timeout=30,
            write_timeout=30, init_command="SET time_zone = '+00:00'")

    @contextmanager
    def transaction(self):
        connection = self.connect()
        try:
            with connection.cursor() as cur:
                yield cur
            connection.commit()
        except BaseException:
            try:
                connection.rollback()
            except pymysql.err.Error:
                pass  # A disconnected server already rolls back its uncommitted transaction.
            raise
        finally:
            connection.close()

    def check_schema(self):
        with self.transaction() as cur:
            cur.execute("SELECT version, checksum FROM schema_migrations")
            rows = cur.fetchall()
            if len(rows) != 1 or rows[0] != {"version": SCHEMA_VERSION, "checksum": schema_checksum()}:
                raise RuntimeError("Database schema mismatch; run the documented database initialization/migration.")
            cur.execute("SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=DATABASE()")
            present = {r["TABLE_NAME"] for r in cur.fetchall()}
            if not schema_tables() <= present:
                raise RuntimeError("Database tables are incomplete")
            self._check_replay_constraints(cur)
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
                known = schema_tables() | LEGACY_TABLES
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

    def policy(self):
        with self.transaction() as cur:
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1")
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Policy not initialized")
            return decode(row["policy_json"])

    def claim_transport(self, envelope):
        for attempt in range(4):
            try:
                with self.transaction() as cur:
                    # Avoid range gap locks between concurrent expiry cleanup and inserts.
                    # Unique indexes, not a snapshot read, enforce replay exclusion.
                    cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    cur.execute("DELETE FROM transport_replay WHERE expires_at_utc < UTC_TIMESTAMP(6) LIMIT 1000")
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

    def migrate(self):
        """Add transport replay protection to the exact 0.1.19 schema, preserving all rows."""
        with self.transaction() as cur:
            lock = "endpointai-init-" + hashlib.sha256(self.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
            cur.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if cur.fetchone()["acquired"] != 1:
                raise RuntimeError("Database maintenance already running")
            try:
                cur.execute("SELECT version,checksum FROM schema_migrations")
                rows = cur.fetchall()
                if rows == [{"version": SCHEMA_VERSION, "checksum": schema_checksum()}]:
                    return "already_migrated"
                if rows != [{"version": 1, "checksum": PREVIOUS_CHECKSUM}]:
                    raise RuntimeError("Migration requires the exact 0.1.19 database")
                statement = next(s for s in schema_statements() if s.startswith("CREATE TABLE transport_replay"))
                # DDL commits in MySQL. An interrupted run can safely resume after CREATE.
                cur.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
                cur.execute("SELECT key_id,request_id,nonce,expires_at_utc FROM transport_replay LIMIT 0")
                cur.execute("SHOW INDEX FROM transport_replay")
                cur.fetchall()
                self._check_replay_constraints(cur)
                cur.execute("UPDATE schema_migrations SET version=%s,checksum=%s,applied_at_utc=%s WHERE version=1",
                            (SCHEMA_VERSION, schema_checksum(), dbtime(utcnow())))
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        self.check_schema()
        return "migrated"

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

    def update_policy(self, update):
        with self.transaction() as cur:
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
            current = decode(cur.fetchone()["policy_json"])
            if current["policyVersion"] != update.expectedVersion:
                return None
            value = wire(update)
            value.pop("expectedVersion")
            allowlist = value["allowlistedBaseUrls"]
            value["allowlistedBaseUrls"] = (current["allowlistedBaseUrls"] if allowlist is None
                                            else normalize_allowlist(allowlist))
            value = {**current, **value, "policyVersion": current["policyVersion"] + 1,
                     "issuedAtUtc": timestamp(utcnow())}
            cur.execute("UPDATE control_policy SET policy_version=%s,policy_json=%s WHERE singleton_id=1",
                        (value["policyVersion"], dumps(value)))
            return value

    def enroll(self, request):
        token, now, device = generate_device_token(), utcnow(), str(request.deviceId)
        with self.transaction() as cur:
            cur.execute("""INSERT INTO device_credentials
                (device_id,token_hash,enrolled_at_utc,last_authenticated_at_utc,revoked)
                VALUES (%s,%s,%s,NULL,0) ON DUPLICATE KEY UPDATE token_hash=VALUES(token_hash),
                enrolled_at_utc=VALUES(enrolled_at_utc),last_authenticated_at_utc=NULL,revoked=0""",
                (device, hash_token(token), dbtime(now)))
        return dict(deviceId=device, deviceToken=token, enrolledAtUtc=timestamp(now))

    def authenticate(self, device_id, token):
        with self.transaction() as cur:
            cur.execute("""SELECT token_hash FROM device_credentials
                WHERE device_id=%s AND revoked=0 FOR UPDATE""", (str(device_id),))
            row = cur.fetchone()
            from .security import safe_compare
            if not row or not safe_compare(hash_token(token), row["token_hash"]):
                return False
            cur.execute("UPDATE device_credentials SET last_authenticated_at_utc=%s WHERE device_id=%s",
                        (dbtime(utcnow()), str(device_id)))
            return True

    def heartbeat(self, h, interval, source_ip):
        value, device, now = wire(h), str(h.device.deviceId), dbtime(utcnow())
        with self.transaction() as cur:
            cur.execute("""INSERT INTO device_heartbeats VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE received_at_utc=VALUES(received_at_utc),
                hostname=VALUES(hostname),os_version=VALUES(os_version),
                applied_policy_version=VALUES(applied_policy_version),proxy_state=VALUES(proxy_state),
                heartbeat_json=VALUES(heartbeat_json)""",
                (device, now, h.device.hostname, h.device.osVersion, h.policy.appliedVersion or 0,
                 h.proxy.state.value, dumps(value)))
            cur.execute("DELETE FROM agent_inventory WHERE device_id=%s", (device,))
            for a in value["agents"]:
                cur.execute("INSERT INTO agent_inventory VALUES (%s,%s,%s,%s)",
                            (device, a["instanceId"], a["agentType"], dumps(a)))
            if h.schemaVersion == 1:
                return
            cur.execute("""INSERT INTO device_runtime VALUES (%s,2,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE schema_version=2,service_version=VALUES(service_version),
                heartbeat_interval_seconds=VALUES(heartbeat_interval_seconds),
                operation_state=VALUES(operation_state),source_ip=VALUES(source_ip),runtime_json=VALUES(runtime_json)""",
                (device, h.device.serviceVersion, interval, h.runtime.operationState.value, source_ip, dumps(h.runtime)))
            cur.execute("DELETE FROM agent_endpoint_assets WHERE device_id=%s", (device,))
            for a in value["endpoints"]:
                cur.execute("INSERT INTO agent_endpoint_assets VALUES (%s,%s,%s,%s)",
                            (device, a["assetId"], a["agentFamily"], dumps(a)))
            cur.execute("SELECT asset_id,activity_json FROM proxy_activity WHERE device_id=%s", (device,))
            previous = {r["asset_id"]: decode(r["activity_json"]) for r in cur.fetchall()}
            cur.execute("DELETE FROM proxy_activity WHERE device_id=%s", (device,))
            for a in value["activity"]:
                old = previous.get(a["assetId"])
                if a["state"] == "neverObserved" and old and old["state"] != "neverObserved":
                    for key in ("state", "lastRequestAtUtc", "lastSuccessAtUtc", "lastFailureAtUtc",
                                "lastHttpStatusCode", "lastOutcome", "lastErrorCode", "lastGatewayRoundTripMilliseconds"):
                        a[key] = old[key]
                cur.execute("INSERT INTO proxy_activity VALUES (%s,%s,%s)", (device, a["assetId"], dumps(a)))

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
                FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id"""
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
                row["endpointCount"] = len(identities.get(row["deviceId"], ()))
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
                cur.execute(f"SELECT {column} FROM {table} WHERE device_id=%s ORDER BY {order}", (str(device),))
                result[key] = [decode(r[column]) for r in cur.fetchall()]
            cur.execute("SELECT runtime_json FROM device_runtime WHERE device_id=%s", (str(device),))
            runtime = cur.fetchone()
            result["runtime"] = decode(runtime["runtime_json"]) if runtime else None
            return result

    def analytics_snapshot(self):
        """Read policy and all assets from one consistent snapshot, without per-host queries."""
        with self.transaction() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1")
            policy = decode(cur.fetchone()["policy_json"])
            cur.execute("""SELECT h.*,r.service_version,r.operation_state,r.heartbeat_interval_seconds,r.schema_version,
                (SELECT COUNT(*) FROM agent_inventory a WHERE a.device_id=h.device_id
                 AND a.agent_type NOT IN ('ccSwitch','unknownCandidate')) AS agent_count
                FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id
                ORDER BY h.received_at_utc DESC,h.device_id""")
            rows = {}
            for row in cur.fetchall():
                heartbeat = decode(row["heartbeat_json"])
                rows[row["device_id"]] = dict(device=self._summary(row),
                    agents=heartbeat.get("agents") or [], endpoints=[], activity=[])
            for key, table, column in (("endpoints", "agent_endpoint_assets", "asset_json"),
                                       ("activity", "proxy_activity", "activity_json")):
                cur.execute(f"SELECT device_id,{column} FROM {table}")
                for row in cur.fetchall():
                    if row["device_id"] in rows:
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
            WHERE device_id=%s AND status IN ('pending','delivered') AND expires_at_utc<=%s""",
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
        now, command = dbtime(utcnow()), str(uuid4())
        with self.transaction() as cur:
            # Device row is the common lock for creation, leasing and cancellation.
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (str(device),))
            if not cur.fetchone():
                return None
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
        now = dbtime(utcnow())
        with self.transaction() as cur:
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (str(device),))
            if not cur.fetchone():
                return None
            self._expire(cur, device, now)
            cur.execute("""SELECT * FROM remote_commands WHERE device_id=%s
                AND status IN ('pending','delivered','executing') ORDER BY created_at_utc LIMIT 1 FOR UPDATE""", (str(device),))
            row = cur.fetchone()
            if row is None:
                return None
            cur.execute("""UPDATE remote_commands SET status=IF(status='pending','delivered',status),
                delivered_at_utc=COALESCE(delivered_at_utc,%s),delivery_count=delivery_count+1
                WHERE command_id=%s""", (now, row["command_id"]))
            cur.execute("SELECT * FROM remote_commands WHERE command_id=%s", (row["command_id"],))
            return self._command(cur.fetchone())

    def update_command(self, update):
        with self.transaction() as cur:
            # Lock/select also treats repeated identical executing reports as accepted.
            cur.execute("""SELECT status FROM remote_commands WHERE command_id=%s AND device_id=%s FOR UPDATE""",
                        (str(update.commandId), str(update.deviceId)))
            row = cur.fetchone()
            if not row or row["status"] in ("succeeded", "failed", "expired", "cancelled"):
                return False
            cur.execute("""UPDATE remote_commands SET status=%s,
                started_at_utc=IF(%s='executing',COALESCE(started_at_utc,%s),started_at_utc),
                completed_at_utc=IF(%s IN ('succeeded','failed'),%s,completed_at_utc),
                result_code=%s,result_summary=%s WHERE command_id=%s""",
                (update.status.value, update.status.value, dbtime(update.observedAtUtc),
                 update.status.value, dbtime(update.observedAtUtc), update.resultCode, update.resultSummary, str(update.commandId)))
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

    def audits(self, device=None, skip=0, take=100):
        with self.transaction() as cur:
            cur.execute("SELECT * FROM admin_audit_log" + (" WHERE device_id=%s" if device else "") +
                " ORDER BY occurred_at_utc DESC LIMIT %s OFFSET %s",
                ((str(device),) if device else ()) + (take, skip))
            return [dict(auditId=r["audit_id"],occurredAtUtc=timestamp(r["occurred_at_utc"]),
                actor=r["actor"],action=r["action"],deviceId=r["device_id"],
                commandId=r["command_id"],summary=r["summary"]) for r in cur.fetchall()]
