"""Rate-limited policy rollout for authenticated v2 devices."""
from datetime import timedelta
from uuid import uuid4
from .database import dbtime, decode
from .security import dumps, timestamp, utcnow, wire
from .validation import ApiProblem, domain_policy, validate_policy

ACTIVE = ("paused", "running", "dispatchComplete")


def _ids(value):
    ids = [str(device) for device in value.deviceIds]
    if not value.reason.strip() or value.confirmCount != len(ids) or len(set(ids)) != len(ids) or any(not d.int for d in value.deviceIds):
        raise ApiProblem("POLICY_ROLLOUT_INVALID", "Invalid targets, count or reason.")
    return ids


def _validate_targets(cur, ids):
    for offset in range(0, len(ids), 500):
        part = ids[offset:offset+500]
        cur.execute("""SELECT h.device_id FROM device_heartbeats h
            JOIN device_runtime r ON r.device_id=h.device_id AND r.schema_version=2
            JOIN device_credentials c ON c.device_id=h.device_id AND c.revoked=0
            WHERE CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED)=2
              AND h.device_id IN (""" + ",".join(["%s"] * len(part)) + ")", part)
        if len(cur.fetchall()) != len(part):
            raise ApiProblem("POLICY_ROLLOUT_TARGET_INVALID", "All targets must be enrolled, active v2 devices.", 409)


def _require_version_index(cur):
    cur.execute("SHOW INDEX FROM device_policy_state WHERE Column_name='effective_policy_version' AND Seq_in_index=1")
    if not any(row["Sub_part"] is None and row["Index_type"].upper() == "BTREE"
               and row.get("Visible", "YES") == "YES" and row.get("Collation") == "A"
               for row in cur.fetchall()):
        raise ApiProblem("POLICY_ROLLOUT_INDEX_REQUIRED", "Build a visible policy version index with services stopped before creating or resuming a rollout.", 409)


def create(store, value, actor):
    ids = _ids(value)
    if value.maxPerSecond > store.cfg.POLICY_ROLLOUT_MAX_RATE:
        raise ApiProblem("POLICY_ROLLOUT_RATE_EXCEEDS_LIMIT", "The requested rate exceeds the configured limit.", 400)
    validate_policy(value.policy)
    now, batch = dbtime(utcnow()), str(uuid4())
    with store.transaction() as cur:
        cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
        base = domain_policy(decode(cur.fetchone()["policy_json"]))
        store._assert_no_policy_rollout(cur)
        _require_version_index(cur)
        if value.policy.expectedVersion != base["policyVersion"]:
            raise ApiProblem("POLICY_VERSION_CONFLICT", "The policy changed; reload and retry.", 409)
        candidate = store._policy_candidate(base, value.policy)
        store._validate_effective_policy(candidate)
        cur.execute("SELECT DISTINCT overrides_json FROM device_policy_state WHERE overrides_json IS NOT NULL")
        for row in cur.fetchall():
            store._validate_effective_policy({**candidate, **domain_policy(decode(row["overrides_json"]), overrides=True)})
        _validate_targets(cur, ids)
        cur.execute("""INSERT INTO policy_rollout_batches VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'paused',%s)""",
            (batch, base["policyVersion"], dumps(candidate), value.reason.strip(), actor, now, value.maxPerSecond, now, len(ids)))
        for offset in range(0, len(ids), 1000):
            cur.executemany("INSERT INTO policy_rollout_targets (batch_id,device_id,status) VALUES (%s,%s,%s)",
                            [(batch, device, 'pending') for device in ids[offset:offset+1000]])
        store._audit(cur, actor, "POLICY_ROLLOUT_CREATED", summary=f"batch={batch};targets={len(ids)};base={base['policyVersion']}")
    return dict(batchId=batch, status="paused", totalTargets=len(ids), baseVersion=base["policyVersion"])


def extend(store, batch_id, value, actor):
    ids = _ids(value)
    with store.transaction() as cur:
        cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
        cur.fetchone()
        cur.execute("SELECT * FROM policy_rollout_batches WHERE batch_id=%s FOR UPDATE", (str(batch_id),))
        batch = cur.fetchone()
        if not batch: raise ApiProblem("POLICY_ROLLOUT_NOT_FOUND", "Batch not found.", 404)
        if batch["status"] not in ("paused", "dispatchComplete") or batch["total_targets"] + len(ids) > 150000:
            raise ApiProblem("POLICY_ROLLOUT_CONFLICT", "Pause the batch and respect the target limit.", 409)
        _validate_targets(cur, ids)
        for offset in range(0, len(ids), 500):
            part = ids[offset:offset+500]
            cur.execute("SELECT device_id FROM policy_rollout_targets WHERE batch_id=%s AND device_id IN ("+
                ",".join(["%s"] * len(part))+")", (str(batch_id), *part))
            if cur.fetchone(): raise ApiProblem("POLICY_ROLLOUT_DUPLICATE", "Target already belongs to the batch.", 409)
        for offset in range(0, len(ids), 1000):
            cur.executemany("INSERT INTO policy_rollout_targets (batch_id,device_id,status) VALUES (%s,%s,%s)",
                            [(str(batch_id), device, 'pending') for device in ids[offset:offset+1000]])
        cur.execute("UPDATE policy_rollout_batches SET status='paused',total_targets=total_targets+%s WHERE batch_id=%s", (len(ids), str(batch_id)))
        store._audit(cur, actor, "POLICY_ROLLOUT_EXTENDED", summary=f"batch={batch_id};targets={len(ids)};reason={value.reason.strip()}")
        return dict(batchId=str(batch_id), status="paused", totalTargets=batch["total_targets"]+len(ids))


def change(store, batch_id, action, reason, actor):
    reason = reason.strip()
    if not reason: raise ApiProblem("POLICY_ROLLOUT_INVALID", "A reason is required.")
    with store.transaction() as cur:
        cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
        base = domain_policy(decode(cur.fetchone()["policy_json"]))
        cur.execute("SELECT * FROM policy_rollout_batches WHERE batch_id=%s FOR UPDATE", (str(batch_id),))
        batch = cur.fetchone()
        if not batch: raise ApiProblem("POLICY_ROLLOUT_NOT_FOUND", "Batch not found.", 404)
        if batch["status"] not in ACTIVE or batch["base_version"] != base["policyVersion"]:
            raise ApiProblem("POLICY_ROLLOUT_CONFLICT", "Batch is not active or its base changed.", 409)
        changed = 0
        if action == "pause" and batch["status"] == "running":
            status = "paused"
        elif action == "resume" and batch["status"] == "paused":
            if batch["max_per_second"] > store.cfg.POLICY_ROLLOUT_MAX_RATE:
                raise ApiProblem("POLICY_ROLLOUT_RATE_EXCEEDS_LIMIT", "The batch rate exceeds the configured limit.", 409)
            _require_version_index(cur)
            cur.execute("SELECT 1 FROM policy_rollout_targets WHERE batch_id=%s AND status='pending' LIMIT 1", (str(batch_id),))
            if not cur.fetchone(): raise ApiProblem("POLICY_ROLLOUT_NO_PENDING", "No pending targets.", 409)
            status = "running"
        elif action == "retry" and batch["status"] in ("paused", "dispatchComplete"):
            cur.execute("UPDATE policy_rollout_targets SET status='pending',error_code=NULL WHERE batch_id=%s AND status='dispatchFailed'", (str(batch_id),))
            changed, status = cur.rowcount, "paused"
            if not changed: raise ApiProblem("POLICY_ROLLOUT_NO_RETRYABLE", "No retryable dispatch failures.", 409)
        elif action == "abort":
            cur.execute("SELECT 1 FROM policy_rollout_targets WHERE batch_id=%s AND status='assigned' LIMIT 1", (str(batch_id),))
            if cur.fetchone():
                rollback = {**base, "policyVersion": store._next_policy_version(cur, base), "issuedAtUtc": timestamp(utcnow())}
                cur.execute("UPDATE control_policy SET policy_version=%s,policy_json=%s WHERE singleton_id=1", (rollback["policyVersion"], dumps(rollback)))
            status = "aborted"
        elif action == "promote" and batch["status"] == "dispatchComplete":
            cur.execute("SELECT 1 FROM policy_rollout_targets WHERE batch_id=%s AND status<>'assigned' LIMIT 1", (str(batch_id),))
            if cur.fetchone(): raise ApiProblem("POLICY_ROLLOUT_INCOMPLETE", "All targets must be assigned before promotion.", 409)
            cur.execute("""SELECT h.device_id FROM device_heartbeats h
                LEFT JOIN device_runtime r ON r.device_id=h.device_id
                LEFT JOIN device_credentials c ON c.device_id=h.device_id
                LEFT JOIN policy_rollout_targets t ON t.batch_id=%s AND t.device_id=h.device_id
                WHERE (c.device_id IS NULL OR c.revoked=0) AND
                  (r.schema_version IS NULL OR r.schema_version<>2 OR
                   COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),0)<>2 OR
                   c.device_id IS NULL OR t.status IS NULL OR t.status<>'assigned') LIMIT 1""", (str(batch_id),))
            if cur.fetchone(): raise ApiProblem("POLICY_ROLLOUT_INCOMPLETE", "All non-revoked devices must be assigned; legacy v1 devices cannot be targeted.", 409)
            cur.execute("""SELECT c.device_id FROM device_credentials c LEFT JOIN device_heartbeats h ON h.device_id=c.device_id
                LEFT JOIN policy_rollout_targets t ON t.batch_id=%s AND t.device_id=c.device_id
                WHERE c.revoked=0 AND (h.device_id IS NULL OR t.status IS NULL OR t.status<>'assigned') LIMIT 1""", (str(batch_id),))
            if cur.fetchone(): raise ApiProblem("POLICY_ROLLOUT_INCOMPLETE", "Every enrolled device needs a heartbeat and assignment before promotion.", 409)
            candidate = domain_policy(decode(batch["candidate_json"]))
            candidate.update(policyVersion=store._next_policy_version(cur, base), issuedAtUtc=timestamp(utcnow()))
            cur.execute("UPDATE control_policy SET policy_version=%s,policy_json=%s WHERE singleton_id=1", (candidate["policyVersion"], dumps(candidate)))
            status = "promoted"
        else:
            raise ApiProblem("POLICY_ROLLOUT_CONFLICT", "Batch state does not allow this action.", 409)
        cur.execute("UPDATE policy_rollout_batches SET status=%s WHERE batch_id=%s", (status, str(batch_id)))
        store._audit(cur, actor, "POLICY_ROLLOUT_" + action.upper(), summary=f"batch={batch_id};count={changed};reason={reason}")
        return dict(batchId=str(batch_id), status=status, retriedTargets=changed)


def dispatch_one(store):
    now = dbtime(utcnow())
    with store.transaction() as cur:
        cur.execute("SELECT 1 FROM policy_rollout_batches WHERE status='running' AND next_dispatch_at_utc<=%s LIMIT 1", (now,))
        if not cur.fetchone(): return False
        cur.execute("SELECT policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE")
        base = domain_policy(decode(cur.fetchone()["policy_json"]))
        cur.execute("""SELECT * FROM policy_rollout_batches WHERE status='running' AND next_dispatch_at_utc<=%s
            ORDER BY next_dispatch_at_utc,batch_id LIMIT 1 FOR UPDATE SKIP LOCKED""", (now,))
        batch = cur.fetchone()
        if not batch: return False
        if batch["base_version"] != base["policyVersion"]: raise RuntimeError("Policy rollout base changed")
        if batch["max_per_second"] > store.cfg.POLICY_ROLLOUT_MAX_RATE:
            cur.execute("UPDATE policy_rollout_batches SET status='paused' WHERE batch_id=%s", (batch["batch_id"],))
            store._audit(cur, "policy-rollout-worker", "POLICY_ROLLOUT_RATE_SUSPENDED", summary="batch=" + batch["batch_id"])
            return True
        if batch["max_per_second"] > 20:
            return _dispatch_batch(store, cur, batch, base)
        cur.execute("SELECT device_id FROM policy_rollout_targets WHERE batch_id=%s AND status='pending' ORDER BY device_id LIMIT 1 FOR UPDATE", (batch["batch_id"],))
        target = cur.fetchone()
        if not target:
            cur.execute("UPDATE policy_rollout_batches SET status='dispatchComplete' WHERE batch_id=%s", (batch["batch_id"],))
            return True
        device = target["device_id"]
        # Credential recovery also locks the heartbeat before the credential.
        cur.execute("SELECT heartbeat_json FROM device_heartbeats WHERE device_id=%s FOR UPDATE", (device,))
        heartbeat = cur.fetchone()
        cur.execute("SELECT revoked FROM device_credentials WHERE device_id=%s FOR UPDATE", (device,))
        credential = cur.fetchone()
        error, version = None, None
        if not credential or credential["revoked"]:
            error = "DEVICE_CREDENTIAL_INACTIVE"
        elif not heartbeat or decode(heartbeat["heartbeat_json"]).get("schemaVersion") != 2:
            error = "DEVICE_PROTOCOL_UNSUPPORTED"
        if not error:
            cur.execute("SELECT * FROM device_policy_state WHERE device_id=%s FOR UPDATE", (device,))
            state = cur.fetchone()
            overrides = domain_policy(decode(state["overrides_json"]), overrides=True) if state and state["overrides_json"] is not None else {}
            previous = decode(state["effective_policy_json"]) if state else base
            version = store._next_policy_version(cur, base)
            effective = {**domain_policy(decode(batch["candidate_json"])), **overrides,
                "schemaVersion": previous["schemaVersion"], "policyVersion": version, "issuedAtUtc": timestamp(utcnow())}
            try:
                store._validate_effective_policy(effective)
            except ApiProblem as exc:
                error, version = exc.code, None
            if not error:
                cur.execute("""INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE base_policy_version=VALUES(base_policy_version),
                    effective_policy_version=VALUES(effective_policy_version),overrides_json=VALUES(overrides_json),
                    effective_policy_json=VALUES(effective_policy_json)""", (device, base["policyVersion"], version,
                    state["overrides_json"] if state else None, dumps(effective)))
        cur.execute("""UPDATE policy_rollout_targets SET status=%s,assigned_version=%s,error_code=%s,attempts=attempts+1
            WHERE batch_id=%s AND device_id=%s""", ("dispatchFailed" if error else "assigned", version, error, batch["batch_id"], device))
        cur.execute("UPDATE policy_rollout_batches SET next_dispatch_at_utc=%s WHERE batch_id=%s",
                    (dbtime(utcnow())+timedelta(seconds=1/batch["max_per_second"]), batch["batch_id"]))
        return True


def _dispatch_batch(store, cur, batch, base):
    """Assign bounded policy chunks under the global policy and batch locks."""
    batch_id = batch["batch_id"]
    limit = min(250, (batch["max_per_second"] + 19) // 20)
    cur.execute("""SELECT device_id FROM policy_rollout_targets FORCE INDEX (ix_policy_rollout_pending)
        WHERE batch_id=%s AND status='pending' ORDER BY device_id LIMIT %s FOR UPDATE""", (batch_id, limit))
    targets = [row["device_id"] for row in cur.fetchall()]
    if not targets:
        cur.execute("UPDATE policy_rollout_batches SET status='dispatchComplete' WHERE batch_id=%s", (batch_id,))
        return True
    slots = ",".join(["%s"] * len(targets))
    # Match credential recovery's heartbeat-before-credential lock order.
    cur.execute("SELECT device_id,heartbeat_json FROM device_heartbeats WHERE device_id IN (" + slots + ") ORDER BY device_id FOR UPDATE", targets)
    heartbeats = {row["device_id"]: row for row in cur.fetchall()}
    cur.execute("SELECT device_id,revoked FROM device_credentials WHERE device_id IN (" + slots + ") ORDER BY device_id FOR UPDATE", targets)
    credentials = {row["device_id"]: row for row in cur.fetchall()}
    cur.execute("SELECT * FROM device_policy_state WHERE device_id IN (" + slots + ") ORDER BY device_id FOR UPDATE", targets)
    states = {row["device_id"]: row for row in cur.fetchall()}
    candidate = domain_policy(decode(batch["candidate_json"]))
    version = None
    updates, outcomes, validation_results = [], [], {}
    for device in targets:
        credential, heartbeat, state = credentials.get(device), heartbeats.get(device), states.get(device)
        error = None
        if not credential or credential["revoked"]:
            error = "DEVICE_CREDENTIAL_INACTIVE"
        elif not heartbeat or decode(heartbeat["heartbeat_json"]).get("schemaVersion") != 2:
            error = "DEVICE_PROTOCOL_UNSUPPORTED"
        assigned = None
        if not error:
            if version is None:
                version = store._next_policy_version(cur, base)
            if version >= 2**63 - 1:
                raise ApiProblem("POLICY_VERSION_EXHAUSTED", "Policy version space exhausted.", 409)
            overrides = domain_policy(decode(state["overrides_json"]), overrides=True) if state and state["overrides_json"] is not None else {}
            previous = decode(state["effective_policy_json"]) if state else base
            effective = {**candidate, **overrides, "schemaVersion": previous["schemaVersion"],
                         "policyVersion": version, "issuedAtUtc": timestamp(utcnow())}
            # Validation depends on the candidate and overrides, while the
            # varying version is already range-checked above. Schema and issue
            # time are not fields in PolicyUpdateRequest. Keep the cache local
            # to this chunk so no decision outlives the locked policy snapshot.
            validation_key = dumps(overrides)
            if validation_key not in validation_results:
                try:
                    store._validate_effective_policy(effective)
                except ApiProblem as exc:
                    validation_results[validation_key] = exc.code
                else:
                    validation_results[validation_key] = None
            error = validation_results[validation_key]
            if not error:
                assigned = version
                version += 1
                updates.append((device, base["policyVersion"], assigned,
                                state["overrides_json"] if state else None, dumps(effective)))
        outcomes.append((device, assigned, error))
    if updates:
        cur.executemany("""INSERT INTO device_policy_state VALUES (%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE base_policy_version=VALUES(base_policy_version),
            effective_policy_version=VALUES(effective_policy_version),overrides_json=VALUES(overrides_json),
            effective_policy_json=VALUES(effective_policy_json)""", updates)
    # JSON_TABLE supplies one typed row per locked target, avoiding three
    # linear CASE searches for every row in a chunk.
    rows = dumps([dict(device=device, version=assigned, error=error,
                       status="dispatchFailed" if error else "assigned") for device, assigned, error in outcomes])
    cur.execute("""UPDATE policy_rollout_targets t JOIN JSON_TABLE(%s, '$[*]' COLUMNS (
        device_id CHAR(36) PATH '$.device', assigned_version BIGINT PATH '$.version',
        error_code LONGTEXT PATH '$.error', status VARCHAR(32) PATH '$.status')) j ON j.device_id COLLATE utf8mb4_bin=t.device_id
        SET t.status=j.status,
        t.assigned_version=j.assigned_version,t.error_code=j.error_code,t.attempts=t.attempts+1
        WHERE t.batch_id=%s""", (rows, batch_id))
    if cur.rowcount != len(targets):
        raise RuntimeError("Policy rollout target update mismatch")
    cur.execute("UPDATE policy_rollout_batches SET next_dispatch_at_utc=%s WHERE batch_id=%s",
                (dbtime(utcnow()) + timedelta(seconds=len(targets) / batch["max_per_second"]), batch_id))
    return True


def list_batches(store, skip, take):
    with store.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS total FROM policy_rollout_batches")
        total = cur.fetchone()["total"]
        cur.execute("SELECT batch_id,status,total_targets,base_version,created_at_utc FROM policy_rollout_batches ORDER BY created_at_utc DESC,batch_id LIMIT %s OFFSET %s", (take, skip))
        return dict(total=total, skip=skip, take=take, maxRate=store.cfg.POLICY_ROLLOUT_MAX_RATE, batches=[dict(batchId=row["batch_id"], status=row["status"],
            totalTargets=row["total_targets"], baseVersion=row["base_version"], createdAtUtc=timestamp(row["created_at_utc"])) for row in cur.fetchall()])


def details(store, batch_id, skip, take, state=None):
    if state and state not in ("pending", "assigned", "dispatchFailed", "applyFailed", "unsupported"):
        raise ApiProblem("POLICY_ROLLOUT_QUERY_INVALID", "Invalid target status.")
    with store.transaction() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
        cur.execute("SELECT * FROM policy_rollout_batches WHERE batch_id=%s", (str(batch_id),))
        batch = cur.fetchone()
        if not batch: raise ApiProblem("POLICY_ROLLOUT_NOT_FOUND", "Batch not found.", 404)
        cur.execute("SELECT status,COUNT(*) AS count FROM policy_rollout_targets WHERE batch_id=%s GROUP BY status", (str(batch_id),))
        counts = {row["status"]: row["count"] for row in cur.fetchall()}
        candidate = domain_policy(decode(batch["candidate_json"]))
        required = 2 if "allowlistedDomains" in candidate or "routingRules" in candidate else 1
        source = " FROM policy_rollout_targets t LEFT JOIN device_heartbeats h ON h.device_id=t.device_id LEFT JOIN device_runtime r ON r.device_id=t.device_id AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),1)=2"
        clause, args = " WHERE t.batch_id=%s", [str(batch_id)]
        support = "COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.runtime.supportedPolicySchemaVersion')) AS UNSIGNED),1)"
        error = "COALESCE(NULLIF(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(r.runtime_json,'$.lastReconcileErrorCode')),'null'),''),'')"
        result = "LOWER(JSON_UNQUOTE(JSON_EXTRACT(r.runtime_json,'$.lastReconcileResult')))"
        if state in ("pending", "assigned", "dispatchFailed"):
            clause += " AND t.status=%s"; args.append(state)
            filtered = counts.get(state, 0)
        elif state in ("applyFailed", "unsupported"):
            if batch["status"] not in ACTIVE:
                clause += " AND 1=0"
            elif state == "unsupported":
                applied_schema = "COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.policy.appliedSchemaVersion')) AS UNSIGNED),1)"
                clause += f" AND t.status='assigned' AND {support}<%s AND NOT COALESCE((t.assigned_version=h.applied_policy_version AND {applied_schema}>=%s AND {result} IN ('success','completed') AND {error}=''),0)"
                args.extend((required, required))
            else:
                clause += f" AND t.status='assigned' AND {support}>=%s AND t.assigned_version=h.applied_policy_version AND ({result}='failed' OR {error}<>'')"
                args.append(required)
            cur.execute("SELECT COUNT(*) AS count" + source + clause, args)
            filtered = cur.fetchone()["count"]
        else:
            filtered = batch["total_targets"]
        cur.execute("""SELECT t.device_id,t.status,t.assigned_version,t.error_code,t.attempts,
            h.received_at_utc,h.applied_policy_version,h.heartbeat_json,r.runtime_json,r.heartbeat_interval_seconds""" +
            source + clause + " ORDER BY t.device_id LIMIT %s OFFSET %s", (*args, take, skip))
        targets = []
        page_rows = cur.fetchall()
        applied_count = None
        if batch["status"] in ACTIVE:
            cur.execute("""SELECT COALESCE(SUM(t.status='assigned' AND h.applied_policy_version=t.assigned_version
                AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.policy.appliedSchemaVersion')) AS UNSIGNED),1)>=%s
                AND LOWER(JSON_UNQUOTE(JSON_EXTRACT(r.runtime_json,'$.lastReconcileResult'))) IN ('success','completed')
                AND COALESCE(NULLIF(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(r.runtime_json,'$.lastReconcileErrorCode')),'null'),''),'')=''),0) AS applied
                FROM policy_rollout_targets t LEFT JOIN device_heartbeats h ON h.device_id=t.device_id
                LEFT JOIN device_runtime r ON r.device_id=t.device_id AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(h.heartbeat_json,'$.schemaVersion')) AS UNSIGNED),1)=2 WHERE t.batch_id=%s""", (required, str(batch_id)))
            applied_count = int(cur.fetchone()["applied"])
        for row in page_rows:
            runtime = decode(row["runtime_json"]) if row["runtime_json"] else {}
            heartbeat = decode(row["heartbeat_json"]) if row["heartbeat_json"] else {}
            result = (runtime.get("lastReconcileResult") or "").lower()
            applied = (row["status"] == "assigned" and row["assigned_version"] == row["applied_policy_version"]
                and (heartbeat.get("policy") or {}).get("appliedSchemaVersion", 1) >= required
                and result in ("success", "completed") and not runtime.get("lastReconcileErrorCode"))
            from .analytics import online_state
            seen = timestamp(row["received_at_utc"]) if row["received_at_utc"] else None
            online = online_state(dict(lastSeenAtUtc=seen, heartbeatIntervalSeconds=row["heartbeat_interval_seconds"]), utcnow()) if seen else "unknown"
            supported = (heartbeat.get("runtime") or {}).get("supportedPolicySchemaVersion", 1)
            if batch["status"] not in ACTIVE:
                application = "historical"
            elif row["status"] != "assigned":
                application = row["status"]
            elif applied:
                application = "applied"
            elif supported < required:
                application = "unsupported"
            elif row["assigned_version"] == row["applied_policy_version"] and (result == "failed" or runtime.get("lastReconcileErrorCode")):
                application = "applyFailed"
            else:
                application = "awaiting"
            targets.append(dict(deviceId=row["device_id"], state=row["status"], assignedVersion=row["assigned_version"],
                applicationState=application, onlineState=online,
                applied=bool(applied) if batch["status"] in ACTIVE else None, reconcileResult=result or None, errorCode=row["error_code"] or runtime.get("lastReconcileErrorCode"),
                lastSeenAtUtc=seen, attempts=row["attempts"]))
        from .models import PolicyUpdateRequest
        candidate_fields = {key: candidate[key] for key in PolicyUpdateRequest.model_fields if key != "expectedVersion" and key in candidate}
        return dict(batchId=str(batch_id), status=batch["status"], baseVersion=batch["base_version"], candidatePolicy=candidate_fields,
            totalTargets=batch["total_targets"], filteredTargets=filtered, counts=counts, appliedTargets=applied_count, skip=skip, take=take, targets=targets,
            createdAtUtc=timestamp(batch["created_at_utc"]), createdBy=batch["created_by"], reason=batch["reason"],
            maxPerSecond=batch["max_per_second"])
