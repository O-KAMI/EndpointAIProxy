"""Bounded synthetic command rollout probe for a disposable loopback MySQL."""
import argparse
import base64
from datetime import datetime, timezone
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sys
import queue
import threading
from tempfile import TemporaryDirectory
import time
from uuid import UUID, uuid4

import pymysql

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import Config
from controlserver.database import ControlStore, dbtime
from controlserver.models import CreateRolloutRequest
from controlserver import rollout


class WorkersNotStopped(RuntimeError):
    pass


@contextmanager
def heartbeat_row_load(port, user, password, database, ids, workers, rate):
    """Generate bounded row-lock traffic, not full heartbeat requests."""
    if not workers:
        yield None
        return
    stop, start = threading.Event(), threading.Event()
    ready = queue.Queue()
    results = [dict(attempted=0, completed=0, missed=0, errors=0, latencies=[]) for _ in range(workers)]

    def run(index):
        conn = None
        result = results[index]
        try:
            conn = pymysql.connect(host='127.0.0.1', port=port, user=user, password=password,
                database=database, autocommit=False, connect_timeout=3, read_timeout=5, write_timeout=5)
            with conn.cursor() as cur:
                cur.execute('SET SESSION innodb_lock_wait_timeout=3')
            ready.put(True)
            start.wait()
            interval = workers / rate
            deadline = time.monotonic() + index / rate
            ordinal = index
            while not stop.is_set():
                delay = deadline - time.monotonic()
                if delay > 0 and stop.wait(delay):
                    break
                now = time.monotonic()
                skipped = max(0, int((now - deadline) / interval))
                result['missed'] += skipped
                deadline += (skipped + 1) * interval
                ordinal += workers * (skipped + 1)
                result['attempted'] += 1
                begin = time.monotonic()
                with conn.cursor() as cur:
                    cur.execute('UPDATE device_heartbeats SET received_at_utc=%s WHERE device_id=%s',
                                (dbtime(datetime.now(timezone.utc)), ids[(ordinal * 7919) % len(ids)]))
                conn.commit()
                result['latencies'].append(time.monotonic() - begin)
                result['completed'] += 1
        except Exception:
            result['errors'] += 1
            ready.put(False)
            stop.set()
        finally:
            if conn is not None:
                conn.close()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    try:
        for _ in threads:
            if not ready.get(timeout=10):
                raise RuntimeError('Synthetic row-load worker failed to start')
        start.set()
        yield results
    finally:
        stop.set()
        start.set()
        for thread in threads:
            thread.join(timeout=10)
        if any(thread.is_alive() for thread in threads):
            raise WorkersNotStopped('Synthetic row-load worker did not stop; test database retained')
    if any(result['errors'] for result in results):
        raise RuntimeError('Synthetic row-load worker failed')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-isolated', action='store_true')
    parser.add_argument('--port', type=int, default=13306)
    parser.add_argument('--devices', type=int, default=2000)
    parser.add_argument('--rate', type=int, default=5000)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--profile', action='store_true', help='Record aggregate database phase durations')
    parser.add_argument('--heartbeat-workers', type=int, default=0)
    parser.add_argument('--heartbeat-rps', type=int, default=0)
    args = parser.parse_args(argv)
    if (not args.confirm_isolated or not 1 <= args.port <= 65535 or not 1 <= args.devices <= 150000
            or not 1 <= args.rate <= 5000 or not 1 <= args.timeout <= 600
            or not 0 <= args.heartbeat_workers <= 32 or not 0 <= args.heartbeat_rps <= 2000
            or bool(args.heartbeat_workers) != bool(args.heartbeat_rps)):
        parser.error('Confirm a disposable isolated MySQL and valid bounds.')
    user = os.environ.get('ENDPOINTAI_TEST_MYSQL_USER', 'root')
    password = os.environ.get('ENDPOINTAI_TEST_MYSQL_PASSWORD', '')
    for key in list(os.environ):
        if key.startswith(('SF_CONTROL_', 'EAI_MYSQL_')) or key in ('APP_ENV', 'APP_CONFIG'):
            os.environ.pop(key)
    name = 'eai_batch_probe_' + uuid4().hex
    assert re.fullmatch(r'eai_batch_probe_[0-9a-f]{32}', name)
    connection = pymysql.connect(host='127.0.0.1', port=args.port, user=user, password=password,
                                 autocommit=True, connect_timeout=3)
    created = False
    try:
        with connection.cursor() as cur:
            cur.execute('CREATE DATABASE `' + name + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
            created = True
        with TemporaryDirectory(prefix='eai-batch-probe-') as temporary:
            cfg = Config(env='sit', conf_dir=Path(temporary))
            cfg.CLIENT_TOKEN, cfg.ADMIN_TOKEN = 'synthetic-client', 'synthetic-admin'
            cfg.HMAC_TEXT = base64.b64encode(bytes(range(32))).decode()
            cfg.TRANSPORT_KEY_TEXT = cfg.HMAC_TEXT
            cfg.MYSQL_HOST, cfg.MYSQL_PORT, cfg.MYSQL_USER, cfg.MYSQL_PASSWORD, cfg.MYSQL_DATABASE = '127.0.0.1', args.port, user, password, name
            cfg.LOG_DIR, cfg.DATA_ROOT = Path(temporary)/'logs', Path(temporary)/'data'
            cfg.BACKUP_DIR = cfg.DATA_ROOT/'backups'
            cfg.ROLLOUT_MAX_RATE = args.rate
            cfg.validate()
            store = ControlStore(cfg)
            store.initialize_empty()
            ids = [str(UUID(int=i+1)) for i in range(args.devices)]
            now = dbtime(datetime.now(timezone.utc))
            payload = json.dumps(dict(schemaVersion=1, users=[], agents=[]), separators=(',',':'))
            with store.transaction() as cur:
                for offset in range(0, len(ids), 1000):
                    cur.executemany('INSERT INTO device_heartbeats VALUES (%s,%s,%s,%s,%s,%s,%s)',
                        [(device, now, 'synthetic', 'synthetic', 0, 'listening', payload) for device in ids[offset:offset+1000]])
            request = CreateRolloutRequest(type='disableProxy', reason='synthetic probe', expiresInMinutes=60,
                maxPerSecond=args.rate, deviceIds=ids, confirmCount=len(ids))
            start = time.monotonic()
            batch = rollout.create(store, request, 'synthetic-operator')['batchId']
            create_seconds = time.monotonic() - start
            rollout.change(store, batch, 'resume', 'synthetic probe', 'synthetic-operator')
            phase_seconds, phase_calls = {}, {}
            if args.profile:
                original = store.transaction
                def phase(sql):
                    normalized = ' '.join(sql.lower().split())
                    for prefix, label in (
                        ('select * from rollout_batches', 'batch_pick'),
                        ('select device_id from rollout_targets', 'target_pick'),
                        ('select device_id from device_heartbeats', 'device_lock'),
                        ('update remote_commands', 'expire'),
                        ('select device_id from remote_commands', 'active_check'),
                        ('insert into remote_commands', 'command_insert'),
                        ('insert into admin_audit_log', 'audit_insert'),
                        ('update rollout_targets', 'target_update'),
                        ('update rollout_batches', 'batch_update'),
                        ('select status from rollout_batches', 'probe_monitor')):
                        if normalized.startswith(prefix): return label
                    return 'other'
                class TimedCursor:
                    def __init__(self, cursor): self.cursor = cursor
                    def __getattr__(self, name): return getattr(self.cursor, name)
                    def _call(self, method, sql, *values):
                        label, started = phase(sql), time.perf_counter()
                        try: return method(sql, *values)
                        finally:
                            phase_seconds[label] = phase_seconds.get(label, 0) + time.perf_counter() - started
                            phase_calls[label] = phase_calls.get(label, 0) + 1
                    def execute(self, sql, *values): return self._call(self.cursor.execute, sql, *values)
                    def executemany(self, sql, values): return self._call(self.cursor.executemany, sql, values)
                @contextmanager
                def profiled():
                    with original() as cur: yield TimedCursor(cur)
                store.transaction = profiled
            start, chunks, target_plan = time.monotonic(), 0, None
            with heartbeat_row_load(args.port, user, password, name, ids, args.heartbeat_workers, args.heartbeat_rps) as heartbeat_results:
              start = time.monotonic()
              while True:
                if heartbeat_results is not None and any(result['errors'] for result in heartbeat_results):
                    raise RuntimeError('Synthetic row-load worker failed')
                if time.monotonic() - start > args.timeout:
                    raise RuntimeError('Synthetic probe timeout; no capacity conclusion')
                dispatched = rollout.dispatch_one(store)
                if dispatched:
                    chunks += 1
                    if args.profile and target_plan is None and chunks >= max(1, (args.devices * 3) // (4 * min(250, max(1, (args.rate + 19) // 20)))):
                        with store.transaction() as cur:
                            cur.execute("""EXPLAIN SELECT device_id FROM rollout_targets FORCE INDEX (ix_rollout_pending)
                                WHERE batch_id=%s AND status='pending' ORDER BY device_id LIMIT 250 FOR UPDATE""", (batch,))
                            row = cur.fetchone()
                            target_plan = {key:row.get(key) for key in ('key', 'rows', 'Extra')}
                    time.sleep(.05)  # Match the application worker's post-dispatch delay.
                else:
                    time.sleep(.01)
                with store.transaction() as cur:
                    cur.execute('SELECT status FROM rollout_batches WHERE batch_id=%s', (batch,))
                    if cur.fetchone()['status'] == 'dispatchComplete':
                        break
            elapsed = time.monotonic() - start
            heartbeat_summary = None
            if heartbeat_results is not None:
                latencies = sorted(value for result in heartbeat_results for value in result['latencies'])
                heartbeat_summary = dict(model='heartbeat_row_update_only', requestedPerSecond=args.heartbeat_rps,
                    attempted=sum(result['attempted'] for result in heartbeat_results),
                    completed=sum(result['completed'] for result in heartbeat_results),
                    effectivePerSecond=round(sum(result['completed'] for result in heartbeat_results)/elapsed, 1),
                    missedSchedule=sum(result['missed'] for result in heartbeat_results),
                    errors=sum(result['errors'] for result in heartbeat_results),
                    p95Seconds=round(latencies[(len(latencies)-1)*95//100], 4) if latencies else None)
            with store.transaction() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM rollout_targets WHERE batch_id=%s AND status='issued'", (batch,))
                issued = cur.fetchone()['n']
                cur.execute("SELECT COUNT(*) AS n FROM admin_audit_log WHERE action='REMOTE_COMMAND_CREATED' AND summary LIKE %s", ('rollout='+batch+';%',))
                audited = cur.fetchone()['n']
                cur.execute("SELECT created_at_utc,COUNT(*) AS n FROM remote_commands WHERE created_by='synthetic-operator' GROUP BY created_at_utc ORDER BY created_at_utc")
                groups = cur.fetchall()
            if issued != args.devices or audited != args.devices:
                raise RuntimeError('Synthetic rollout counts do not match')
            if any((later['created_at_utc']-earlier['created_at_utc']).total_seconds()+0.000001 < earlier['n']/args.rate
                   for earlier, later in zip(groups, groups[1:])):
                raise RuntimeError('Synthetic dispatch exceeded the configured chunk schedule')
            print(json.dumps(dict(devices=args.devices, configuredRate=args.rate, createSeconds=round(create_seconds,3),
                dispatchSeconds=round(elapsed,3), effectivePerSecond=round(issued/elapsed,1), chunks=chunks,
                issued=issued, audited=audited, chunkScheduleObserved=True, includesHttp=False,
                concurrentHeartbeats=False, concurrentRowUpdates=heartbeat_summary, capacityAcceptance='not evaluated',
                phaseSeconds={key:round(value,3) for key,value in phase_seconds.items()}, phaseCalls=phase_calls,
                lateTargetQueryPlan=target_plan)))
    except WorkersNotStopped:
        created = False  # Never drop a database while a worker might still be using it.
        raise
    finally:
        if created:
            with connection.cursor() as cur: cur.execute('DROP DATABASE `' + name + '`')
        connection.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Isolated rollout probe failed: ' + type(error).__name__ + '; capacity not evaluated.', file=sys.stderr)
        sys.exit(1)
