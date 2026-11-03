"""Durable, rate-limited batches of existing device commands."""
from datetime import timedelta
from uuid import uuid4

from .database import dbtime
from .security import timestamp, utcnow
from .validation import ApiProblem

TARGET_STATE = "CASE WHEN t.status='issued' AND c.status='pending' THEN 'pendingCommand' WHEN t.status='issued' THEN COALESCE(c.status,'unknown') ELSE t.status END"
TARGET_STATES = {"pending", "dispatchFailed", "pendingCommand", "delivered", "executing",
                 "succeeded", "failed", "expired", "cancelled", "resultUnknown", "unknown"}


def create(store, value, actor):
    ids = [str(device) for device in value.deviceIds]
    if value.maxPerSecond > store.cfg.ROLLOUT_MAX_RATE:
        raise ApiProblem("ROLLOUT_RATE_EXCEEDS_LIMIT", "The requested rate exceeds the configured limit.", 400)
    if (not value.reason.strip() or value.confirmCount != len(ids) or len(set(ids)) != len(ids)
            or any(not device.int for device in value.deviceIds)):
        raise ApiProblem("ROLLOUT_INVALID", "The target count, reason or device IDs are invalid.")
    batch, now = str(uuid4()), dbtime(utcnow())
    with store.transaction() as cur:
        for offset in range(0, len(ids), 500):
            chunk = ids[offset:offset + 500]
            cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id IN (" + ",".join(["%s"] * len(chunk)) + ")", chunk)
            if len(cur.fetchall()) != len(chunk):
                raise ApiProblem("ROLLOUT_DEVICE_NOT_FOUND", "One or more targets are unknown; no batch was created.", 404)
        cur.execute("""INSERT INTO rollout_batches (batch_id,command_type,reason,created_by,created_at_utc,
            expires_in_minutes,max_per_second,next_dispatch_at_utc,status,total_targets)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'paused',%s)""",
            (batch, value.type.value, value.reason.strip(), actor, now, value.expiresInMinutes,
             value.maxPerSecond, now, len(ids)))
        for offset in range(0, len(ids), 1000):
            cur.executemany("INSERT INTO rollout_targets (batch_id,device_id,status) VALUES (%s,%s,%s)",
                            [(batch, device, 'pending') for device in ids[offset:offset + 1000]])
        store._audit(cur, actor, "ROLLOUT_CREATED", summary=f"batch={batch};targets={len(ids)};type={value.type.value}")
    return {"batchId": batch, "status": "paused", "totalTargets": len(ids)}


def change(store, batch, action, reason, actor):
    reason = reason.strip()
    if not reason:
        raise ApiProblem("ROLLOUT_INVALID", "A reason is required.")
    with store.transaction() as cur:
        cur.execute("SELECT status,max_per_second FROM rollout_batches WHERE batch_id=%s FOR UPDATE", (str(batch),))
        row = cur.fetchone()
        if not row:
            raise ApiProblem("ROLLOUT_NOT_FOUND", "Batch not found.", 404)
        status = row["status"]
        if action == "pause" and status == "running":
            next_status, changed = "paused", 0
        elif action == "resume" and status == "paused":
            if row["max_per_second"] > store.cfg.ROLLOUT_MAX_RATE:
                raise ApiProblem("ROLLOUT_RATE_EXCEEDS_LIMIT", "The batch rate exceeds the configured limit.", 409)
            cur.execute("SELECT 1 FROM rollout_targets WHERE batch_id=%s AND status='pending' LIMIT 1", (str(batch),))
            if not cur.fetchone():
                raise ApiProblem("ROLLOUT_NO_PENDING", "No pending targets; retry failures first if appropriate.", 409)
            next_status, changed = "running", 0
        elif action == "retry" and status in ("paused", "dispatchComplete"):
            cur.execute("""UPDATE rollout_targets t LEFT JOIN remote_commands c ON c.command_id=t.command_id
                SET t.status='pending',t.command_id=NULL,t.error_code=NULL
                WHERE t.batch_id=%s AND (t.status='dispatchFailed' OR
                    (t.status='issued' AND c.status IN ('failed','expired','cancelled')))""", (str(batch),))
            changed, next_status = cur.rowcount, "paused"
            if not changed:
                raise ApiProblem("ROLLOUT_NO_RETRYABLE", "No safely retryable failures.", 409)
        else:
            raise ApiProblem("ROLLOUT_STATE_CONFLICT", "Batch state does not allow this action.", 409)
        cur.execute("UPDATE rollout_batches SET status=%s WHERE batch_id=%s", (next_status, str(batch)))
        store._audit(cur, actor, "ROLLOUT_" + action.upper(), summary=f"batch={batch};count={changed};reason={reason}")
    return {"batchId": str(batch), "status": next_status, "retriedTargets": changed}


def dispatch_one(store):
    """Issue one command and advance its batch in the same committed transaction."""
    now = dbtime(utcnow())
    with store.transaction() as cur:
        cur.execute("""SELECT * FROM rollout_batches WHERE status='running' AND next_dispatch_at_utc<=%s
            ORDER BY next_dispatch_at_utc,batch_id LIMIT 1 FOR UPDATE SKIP LOCKED""", (now,))
        batch = cur.fetchone()
        if not batch:
            return False
        batch_id = batch["batch_id"]
        if batch["max_per_second"] > store.cfg.ROLLOUT_MAX_RATE:
            cur.execute("UPDATE rollout_batches SET status='paused' WHERE batch_id=%s", (batch_id,))
            store._audit(cur, "rollout-worker", "ROLLOUT_RATE_SUSPENDED", summary="batch=" + batch_id)
            return True
        if batch["max_per_second"] > 20:
            return _dispatch_batch(store, cur, batch)
        cur.execute("""SELECT device_id FROM rollout_targets WHERE batch_id=%s AND status='pending'
            ORDER BY device_id LIMIT 1 FOR UPDATE""", (batch_id,))
        target = cur.fetchone()
        if not target:
            cur.execute("UPDATE rollout_batches SET status='dispatchComplete' WHERE batch_id=%s", (batch_id,))
            return True
        device = target["device_id"]
        cur.execute("SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (device,))
        exists = cur.fetchone()
        error = None
        command = None
        if not exists:
            error = "DEVICE_NOT_FOUND"
        else:
            now = dbtime(utcnow())
            store._expire(cur, device, now)
            cur.execute("""SELECT command_id FROM remote_commands WHERE device_id=%s
                AND status IN ('pending','delivered','executing') FOR UPDATE""", (device,))
            if cur.fetchone():
                error = "DEVICE_COMMAND_ALREADY_ACTIVE"
            else:
                command = str(uuid4())
                cur.execute("""INSERT INTO remote_commands
                    (command_id,device_id,command_type,status,created_at_utc,expires_at_utc,created_by,reason)
                    VALUES (%s,%s,%s,'pending',%s,%s,%s,%s)""",
                    (command, device, batch["command_type"], now,
                     now + timedelta(minutes=batch["expires_in_minutes"]), batch["created_by"], batch["reason"]))
                store._audit(cur, batch["created_by"], "REMOTE_COMMAND_CREATED", device, command,
                             "rollout=" + batch_id + ";type=" + batch["command_type"])
        cur.execute("""UPDATE rollout_targets SET status=%s,command_id=%s,error_code=%s,attempts=attempts+1
            WHERE batch_id=%s AND device_id=%s""",
            ("dispatchFailed" if error else "issued", command, error, batch_id, device))
        cur.execute("UPDATE rollout_batches SET next_dispatch_at_utc=%s WHERE batch_id=%s",
                    (dbtime(utcnow()) + timedelta(seconds=1 / batch["max_per_second"]), batch_id))
        return True



def _audit_batch(cur, batch, commands, now):
    """Write one auditable event per issued command in the dispatch transaction."""
    if commands:
        cur.executemany("INSERT INTO admin_audit_log VALUES (%s,%s,%s,%s,%s,%s,%s)",
            [(str(uuid4()), now, batch["created_by"], "REMOTE_COMMAND_CREATED", device, command,
              "rollout=" + batch["batch_id"] + ";type=" + batch["command_type"])
             for device, command in commands])


def _dispatch_batch(store, cur, batch):
    """Dispatch a bounded chunk under the batch lock; pause waits for this commit."""
    batch_id = batch["batch_id"]
    limit = min(250, (batch["max_per_second"] + 19) // 20)
    cur.execute("""SELECT device_id FROM rollout_targets FORCE INDEX (ix_rollout_pending)
        WHERE batch_id=%s AND status='pending' ORDER BY device_id LIMIT %s FOR UPDATE""", (batch_id, limit))
    targets = [row["device_id"] for row in cur.fetchall()]
    if not targets:
        cur.execute("UPDATE rollout_batches SET status='dispatchComplete' WHERE batch_id=%s", (batch_id,))
        return True
    slots = ",".join(["%s"] * len(targets))
    # All command creation paths lock the heartbeat row first. Lock devices in
    # primary-key order so overlapping batches follow the same lock order.
    cur.execute("SELECT device_id FROM device_heartbeats FORCE INDEX (PRIMARY) WHERE device_id IN (" + slots + ") ORDER BY device_id FOR UPDATE", targets)
    existing = {row["device_id"] for row in cur.fetchall()}
    now = dbtime(utcnow())
    active = set()
    valid_targets = [device for device in targets if device in existing]
    if valid_targets:
        valid_slots = ",".join(["%s"] * len(valid_targets))
        cur.execute("""UPDATE remote_commands SET status='expired',completed_at_utc=%s,
            result_code='COMMAND_EXPIRED',result_summary='The command expired before completion.'
            WHERE device_id IN (""" + valid_slots + ") AND status='pending' AND expires_at_utc<=%s", (now, *valid_targets, now))
        cur.execute("SELECT device_id FROM remote_commands WHERE device_id IN (" + valid_slots +
            ") AND status IN ('pending','delivered','executing') ORDER BY device_id FOR UPDATE", valid_targets)
        active = {row["device_id"] for row in cur.fetchall()}
    commands, outcomes = [], []
    for device in targets:
        error = "DEVICE_NOT_FOUND" if device not in existing else "DEVICE_COMMAND_ALREADY_ACTIVE" if device in active else None
        command = str(uuid4()) if error is None else None
        outcomes.append((device, command, error))
        if command:
            commands.append((device, command))
    if commands:
        cur.executemany("""INSERT INTO remote_commands
            (command_id,device_id,command_type,status,created_at_utc,expires_at_utc,created_by,reason)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(command, device, batch["command_type"], "pending", now,
              now + timedelta(minutes=batch["expires_in_minutes"]), batch["created_by"], batch["reason"])
             for device, command in commands])
        _audit_batch(cur, batch, commands, now)
    clauses, args = [], []
    for column in ("status", "command_id", "error_code"):
        case = []
        for device, command, error in outcomes:
            value = ("dispatchFailed" if error else "issued") if column == "status" else command if column == "command_id" else error
            case.append("WHEN %s THEN %s")
            args.extend((device, value))
        clauses.append(column + "=CASE device_id " + " ".join(case) + " END")
    cur.execute("UPDATE rollout_targets SET " + ",".join(clauses) + ",attempts=attempts+1 WHERE batch_id=%s AND device_id IN (" + slots + ")",
                (*args, batch_id, *targets))
    if cur.rowcount != len(targets):
        raise RuntimeError("Rollout target update mismatch")
    # Rate is a bounded average with a maximum one-chunk burst. Slow database
    # work does not accumulate credit or cause a catch-up burst.
    cur.execute("UPDATE rollout_batches SET next_dispatch_at_utc=%s WHERE batch_id=%s",
                (dbtime(utcnow()) + timedelta(seconds=len(targets) / batch["max_per_second"]), batch_id))
    return True


def list_batches(store, skip, take):
    with store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS count FROM rollout_batches")
        total = cur.fetchone()["count"]
        cur.execute("""SELECT * FROM rollout_batches ORDER BY created_at_utc DESC,batch_id
            LIMIT %s OFFSET %s""", (take, skip))
        return dict(total=total, skip=skip, take=take, batches=[batch_json(row) for row in cur.fetchall()])


def batch_json(row):
    return dict(batchId=row["batch_id"], type=row["command_type"], reason=row["reason"],
                createdBy=row["created_by"], createdAtUtc=timestamp(row["created_at_utc"]),
                expiresInMinutes=row["expires_in_minutes"], maxPerSecond=row["max_per_second"],
                status=row["status"], totalTargets=row["total_targets"])


def details(store, batch, skip, take, state=None):
    if state and state not in TARGET_STATES:
        raise ApiProblem("ROLLOUT_QUERY_INVALID", "Invalid target status.")
    with store.transaction() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
        cur.execute("SELECT * FROM rollout_batches WHERE batch_id=%s", (str(batch),))
        row = cur.fetchone()
        if not row:
            raise ApiProblem("ROLLOUT_NOT_FOUND", "Batch not found.", 404)
        result = batch_json(row)
        source = " FROM rollout_targets t LEFT JOIN remote_commands c ON c.command_id=t.command_id"
        cur.execute("SELECT " + TARGET_STATE + " AS state,COUNT(*) AS count" + source +
                    " WHERE t.batch_id=%s GROUP BY state", (str(batch),))
        result["counts"] = {item["state"]: item["count"] for item in cur.fetchall()}
        clause = " WHERE t.batch_id=%s" + (" AND " + TARGET_STATE + "=%s" if state else "")
        args = (str(batch), state) if state else (str(batch),)
        # The grouped states cover the same joined rows and snapshot as the
        # page. Reuse them instead of scanning and joining every target again.
        result["filteredTargets"] = result["counts"].get(state, 0) if state else sum(result["counts"].values())
        cur.execute("SELECT t.device_id,t.attempts,t.error_code,t.command_id," + TARGET_STATE + " AS state,c.result_code" +
                    source + clause + " ORDER BY t.device_id LIMIT %s OFFSET %s", (*args, take, skip))
        result["targets"] = [dict(deviceId=item["device_id"], state=item["state"],
            attempts=item["attempts"], errorCode=item["error_code"] or item["result_code"],
            commandId=item["command_id"]) for item in cur.fetchall()]
        result.update(skip=skip, take=take)
        return result


def target_cursor(store, batch, after, take):
    """Read target/command identity with bounded keyset pagination."""
    with store.transaction() as cur:
        cur.execute('SELECT 1 FROM rollout_batches WHERE batch_id=%s', (str(batch),))
        if not cur.fetchone():
            raise ApiProblem('ROLLOUT_NOT_FOUND', 'Batch not found.', 404)
        cur.execute("SELECT t.device_id,t.command_id," + TARGET_STATE + " AS state "
                    "FROM rollout_targets t LEFT JOIN remote_commands c ON c.command_id=t.command_id "
                    "WHERE t.batch_id=%s AND t.device_id>%s ORDER BY t.device_id LIMIT %s",
                    (str(batch), after, take + 1))
        rows = cur.fetchall()
        more = len(rows) > take
        rows = rows[:take]
        return dict(batchId=str(batch), targets=[dict(deviceId=row['device_id'],
                    commandId=row['command_id'], state=row['state']) for row in rows],
                    nextAfter=rows[-1]['device_id'] if more else None)
