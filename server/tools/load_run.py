"""Bounded synthetic heartbeat and policy runner; not a capacity acceptance tool."""
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import heapq
import hmac
import json
import random
import threading
import time

from controlserver.security import sign_policy
from tools.load_commands import simulate_command
from tools.load_devices import event_batch, heartbeat, legacy_v2_heartbeat, synthetic_id
from tools.load_admin import SyntheticAdmin
from tools.load_schedule import HeartbeatSchedule
from tools.load_transport import FIXTURE_KEY, SyntheticTransport


def rephase_receipts(receipts, recovery, spread, rng):
    """Defer queued receipts until reconnect, including already overdue work."""
    receipts[:] = [(recovery + rng.random() * spread if due < recovery else due, ordinal)
                   for due, ordinal in receipts]
    heapq.heapify(receipts)


def run_heartbeats(origin, tokens, legacy_count, seconds, interval=60, workers=16,
                   full_every=60, seed=0, transport_factory=SyntheticTransport,
                   publish_after=None, admin_factory=SyntheticAdmin, command_after=None,
                   admin_query_interval=None, outage_after=None, outage_seconds=None, reconnect_spread=0,
                   resource_monitor=None, event_devices=0, event_every=60,
                   rollout_after=None, rollout_targets=0, rollout_rate=20,
                   progress_callback=None, progress_seconds=60, full_v2_count=0,
                   startup_spread=None, startup_full=False, ordinal_start=0,
                   publication_observer=None, publication_sink=None, compact_v2=False):
    count = len(tokens)
    if (type(compact_v2) is not bool or type(ordinal_start) is not int or not 0 <= ordinal_start < 150_000
            or not 1 <= count <= 150_000 - ordinal_start or not 0 <= legacy_count <= count or not 0 <= full_v2_count <= count - legacy_count
            or not 1 <= workers <= 128
            or not 0 < seconds <= 86_400 or not 1 <= interval <= 3600 or not 1 <= full_every <= 3600
            or any(not isinstance(token, str) or not token for token in tokens)
            or (publish_after is not None and not 0 <= publish_after < seconds)
            or (publication_observer is not None and publish_after is not None)
            or (publication_sink is not None and publish_after is None)
            or (command_after is not None and (not 0 <= command_after < seconds or legacy_count == count))
            or (admin_query_interval is not None and not 1 <= admin_query_interval <= 3600)
            or ((outage_after is None) != (outage_seconds is None))
            or (outage_after is not None and (outage_after < 0 or outage_seconds <= 0
                or not 0 <= reconnect_spread <= 3600
                or outage_after + outage_seconds + reconnect_spread >= seconds))
            or not 0 <= event_devices <= count or not 1 <= event_every <= 3600
            or not 0 <= rollout_targets <= count - legacy_count or not 1 <= rollout_rate <= 5000
            or ((rollout_after is None) != (rollout_targets == 0))
            or (rollout_after is not None and not 0 <= rollout_after < seconds)
            or (command_after is not None and rollout_targets and rollout_targets >= count - legacy_count)
            or (startup_spread is not None and not 0 <= startup_spread <= 3600)
            or type(startup_full) is not bool
            or not 0.1 <= progress_seconds <= 3600):
        raise ValueError('Invalid synthetic run parameters')
    local = threading.local()
    clients = []
    client_lock = threading.Lock()
    counts, latency_ms = Counter(), Counter()
    policy_latency_ms = Counter()
    admin_latency_ms = Counter()
    event_latency_ms = Counter()
    versions = [1] * count
    operations = ['enabled'] * count
    seen_commands = set()
    converged = [None] * count
    first_applied = [None] * count if publication_observer is not None or publication_sink is not None else None
    publication = None
    publication_evidence = None
    next_publication_check = None
    publication_future = None
    publication_error = False
    command_future = None
    command_created = None
    command_error = False
    command_completions = {}
    target_completions = {}
    rollout_future = None
    rollout_created = None
    rollout_error = False
    inflight = set()
    policy_inflight = set()
    maximum_lag = 0.0
    maximum_policy_lag = 0.0
    started = time.monotonic()
    next_publication_check = started
    deadline = started + seconds
    next_progress = started + progress_seconds
    next_admin_query = started if admin_query_interval is not None else None
    admin_query_future = None
    schedule = HeartbeatSchedule(count, started, interval, seed, startup_spread)
    periodic_count = legacy_count + full_v2_count
    policy_schedule = HeartbeatSchedule(periodic_count, started, interval, seed + 2, startup_spread) if periodic_count else None
    outage_at = started + outage_after if outage_after is not None else None
    recovery = outage_at + outage_seconds if outage_at is not None else None
    pre_outage_expected = None
    pre_outage_policy_expected = None
    offline_suppressed = 0
    offline_policy_suppressed = 0
    reconnect_generation = 0
    receipt_rng = random.Random(seed + 4)
    receipt_due = []
    receipt_expected = 0
    receipt_device_versions = [0] * count

    def get_client():
        client = getattr(local, 'client', None)
        if client is not None and local.generation != reconnect_generation:
            client.close()
            local.client = client = None
        if client is None:
            client = transport_factory(origin)
            try:
                client.verify()
            except Exception:
                client.close()
                raise
            local.client = client
            local.generation = reconnect_generation
            with client_lock:
                clients.append(client)
        return client

    def execute(ordinal, cycle, expedited=False):
        client = get_client()
        legacy = ordinal < legacy_count
        old_v2 = not legacy and ordinal < legacy_count + full_v2_count
        light = not legacy and not old_v2 and cycle % full_every != 0
        # All v2 devices already have a full baseline from seeding. Avoid a
        # synchronized full scan in the first cycle as well.
        if not legacy and not old_v2 and cycle == 0:
            light = not startup_full
        if expedited:
            light = True
        compact = light and compact_v2
        kind = 'v1-full' if legacy else ('v2-legacy-full' if old_v2 else ('v2-compact' if compact else 'v2-light' if light else 'v2-full'))
        path = '/api/v1/heartbeat' if legacy else ('/api/v2/heartbeat/light-compact' if compact else '/api/v2/heartbeat/light' if light else '/api/v2/heartbeat')
        begin = time.monotonic()
        body = legacy_v2_heartbeat(ordinal_start + ordinal) if old_v2 else heartbeat(ordinal_start + ordinal, 1 if legacy else 2, light, compact)
        body['policy']['lastReceivedVersion'] = versions[ordinal]
        body['policy']['appliedVersion'] = versions[ordinal]
        if not legacy:
            body['policy']['appliedSchemaVersion'] = 1 if old_v2 else 2
            body['runtime']['operationState'] = operations[ordinal]
            if operations[ordinal] == 'disabled':
                body['proxy']['state'] = 'stopped'
                body['proxy']['activeRouteCount'] = 0
        response = client.request('POST', path, tokens[ordinal], body)
        heartbeat_finished = time.monotonic()
        elapsed = heartbeat_finished - begin
        policy_result = None
        command_result = None
        event_result = None
        try:
            heartbeat_result = json.loads(response['body']) if response['status'] == 200 else {}
            accepted = heartbeat_result['acceptedPolicyVersion'] if response['status'] == 200 else None
            if accepted is not None and (type(accepted) is not int or accepted < 1):
                raise ValueError('Invalid synthetic heartbeat policy version')
            if not legacy and heartbeat_result.get('command') is not None:
                try:
                    outcome = simulate_command(client, tokens[ordinal], synthetic_id('device', ordinal_start + ordinal),
                                               heartbeat_result['command'], seen_commands)
                    if outcome is not None:
                        operations[ordinal] = outcome
                    command_result = ('command_success' if outcome else 'command_duplicate_ignored',
                                      heartbeat_result['command']['payload']['commandId'], time.monotonic())
                except Exception:
                    command_result = ('command_error', None, time.monotonic())
            refresh = not legacy and not old_v2 and accepted is not None and (accepted != versions[ordinal]
                or (cycle > 0 and cycle % full_every == 0) or (startup_full and cycle == 0))
            if refresh:
                path = '/api/v1/policy' if legacy else f'/api/v2/devices/{synthetic_id("device", ordinal_start + ordinal)}/policy'
                query = '' if legacy else ('policySchemaVersion=1' if old_v2 else 'policySchemaVersion=2&statelessPolicyVersions=1')
                policy_start = time.monotonic()
                try:
                    policy = client.request('GET', path, tokens[ordinal], query=query)
                    latency = time.monotonic() - policy_start
                    signature = policy['headers'].get('X-SF-Policy-Signature', '')
                    valid = policy['status'] == 200 and hmac.compare_digest(signature, sign_policy(policy['body'], FIXTURE_KEY))
                    data = json.loads(policy['body']) if valid else {}
                    version = data.get('policyVersion')
                    valid = valid and type(version) is int and version >= 1 and (accepted is None or version >= accepted)
                    if valid:
                        versions[ordinal] = version
                    prefix = 'startup_policy_' if startup_full and cycle == 0 else 'policy_'
                    policy_result = (prefix + ('success' if valid else 'error'), latency)
                except Exception:
                    prefix = 'startup_policy_' if startup_full and cycle == 0 else 'policy_'
                    policy_result = (prefix + 'error', time.monotonic() - policy_start)
        except (ValueError, KeyError, TypeError):
            policy_result = ('heartbeat_contract_error', 0)
        if not expedited and ordinal < event_devices and cycle % event_every == 0:
            event_start = time.monotonic()
            try:
                path = '/api/v1/events/batch' if legacy else '/api/v2/events/batch'
                event_response = client.request('POST', path, tokens[ordinal], event_batch(ordinal_start + ordinal))
                data = json.loads(event_response['body'])
                valid = (event_response['status'] == 202 and data.get('accepted') == 1
                         and data.get('duplicates') == 0 and data.get('rejected') == 0)
                event_result = ('event_success' if valid else 'event_error', time.monotonic() - event_start)
            except Exception:
                event_result = ('event_error', time.monotonic() - event_start)
        return kind, response['status'], elapsed, policy_result, body['policy']['appliedVersion'], heartbeat_finished, command_result, event_result

    def execute_periodic_policy(ordinal):
        client = get_client()
        legacy = ordinal < legacy_count
        path = '/api/v1/policy' if legacy else f'/api/v2/devices/{synthetic_id("device", ordinal_start + ordinal)}/policy'
        query = '' if legacy else 'policySchemaVersion=1'
        began = time.monotonic()
        try:
            policy = client.request('GET', path, tokens[ordinal], query=query)
            signature = policy['headers'].get('X-SF-Policy-Signature', '')
            valid = policy['status'] == 200 and hmac.compare_digest(signature, sign_policy(policy['body'], FIXTURE_KEY))
            version = json.loads(policy['body']).get('policyVersion') if valid else None
            valid = valid and type(version) is int and version >= versions[ordinal]
            if valid:
                versions[ordinal] = version
            return ('periodic_policy_success' if valid else 'periodic_policy_error', time.monotonic() - began)
        except Exception:
            return ('periodic_policy_error', time.monotonic() - began)

    def launch_rollout():
        admin = admin_factory(origin)
        targets = [synthetic_id('device', ordinal_start + ordinal) for ordinal in range(count - rollout_targets, count)]
        began = time.monotonic()
        batch = admin.create_rollout(targets, rollout_rate)
        result = admin.change_rollout(batch, 'resume')
        if result.get('status') != 'running':
            raise RuntimeError('Synthetic rollout did not resume')
        return dict(batch=batch, started=began, resumed=time.monotonic())

    pending = {}
    resource_report = None
    if resource_monitor is not None:
        resource_monitor.start()
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool, ThreadPoolExecutor(max_workers=2) as admin_pool:
            while time.monotonic() < deadline or pending or admin_query_future is not None:
                now = time.monotonic()
                if outage_at is not None and pre_outage_expected is None and now >= outage_at:
                    pre_outage_expected = schedule.expected_by(outage_at)
                    offline_suppressed = schedule.reconnect(outage_at, recovery, reconnect_spread, seed + 1)
                    rephase_receipts(receipt_due, recovery, reconnect_spread, receipt_rng)
                    if policy_schedule is not None:
                        pre_outage_policy_expected = policy_schedule.expected_by(outage_at)
                        offline_policy_suppressed = policy_schedule.reconnect(outage_at, recovery, reconnect_spread, seed + 3)
                if recovery is not None and now >= recovery:
                    reconnect_generation = 1
                if progress_callback is not None and now >= next_progress and now < deadline:
                    expected_now = ((pre_outage_expected or 0) + schedule.expected_by(now)
                                    + counts['receipt_heartbeat_dispatched'] + counts['receipt_heartbeat_missed_busy']
                                    + sum(due <= now for due, _ in receipt_due))
                    snapshot = dict(elapsedSeconds=now-started, expectedEvents=expected_now,
                        counts=dict(counts), pendingRequests=len(pending),
                        offlineSuppressedEvents=offline_suppressed, maxScheduleLagSeconds=maximum_lag,
                        receiptHeartbeatsScheduled=receipt_expected)
                    if policy_schedule is not None:
                        snapshot['expectedPolicyPolls'] = (pre_outage_policy_expected or 0) + policy_schedule.expected_by(now)
                        snapshot['offlinePolicySuppressed'] = offline_policy_suppressed
                        snapshot['maxPolicyScheduleLagSeconds'] = maximum_policy_lag
                    if resource_monitor is not None and hasattr(resource_monitor, 'latest'):
                        snapshot['resources'] = resource_monitor.latest()
                    progress_callback(snapshot)
                    next_progress = now + progress_seconds
                if now < deadline and publish_after is not None and publication_future is None and now >= started + publish_after:
                    publication_future = admin_pool.submit(lambda: admin_factory(origin).publish_toggle())
                if now < deadline and command_after is not None and command_future is None and now >= started + command_after:
                    command_future = admin_pool.submit(lambda: admin_factory(origin).create_command(
                        synthetic_id('device', ordinal_start + legacy_count), 'disableProxy'))
                if now < deadline and rollout_after is not None and rollout_future is None and now >= started + rollout_after:
                    rollout_future = admin_pool.submit(launch_rollout)
                if admin_query_future is not None and admin_query_future.done():
                    try:
                        elapsed = admin_query_future.result()
                        counts['admin_query_success'] += 1
                        admin_latency_ms[min(int(elapsed * 1000), 60_000)] += 1
                    except Exception:
                        counts['admin_query_error'] += 1
                    admin_query_future = None
                while next_admin_query is not None and next_admin_query <= now and next_admin_query < deadline:
                    if admin_query_future is None and now < deadline:
                        admin_query_future = admin_pool.submit(lambda: admin_factory(origin).query_devices())
                    else:
                        counts['admin_query_missed'] += 1
                    next_admin_query += admin_query_interval
                if publication_future is not None and publication_future.done() and publication is None and not publication_error:
                    try:
                        candidate = publication_future.result()
                        if publication_sink is not None:
                            publication_evidence = publication_sink(candidate)
                        publication = candidate
                        if first_applied is not None:
                            for index, observation in enumerate(first_applied):
                                if (observation is not None and observation[0] >= publication['version']
                                        and publication['completed'] <= observation[1] <= deadline):
                                    converged[index] = observation[1] - publication['started']
                    except Exception:
                        publication_error = True
                if publication_observer is not None and publication is None and now >= next_publication_check:
                    next_publication_check = now + 0.2
                    candidate = publication_observer()
                    if candidate is not None:
                        publication_evidence = candidate.pop('evidence')
                        publication = candidate
                        for index, observation in enumerate(first_applied):
                            if (observation is not None and observation[0] >= publication['version']
                                    and publication['completed'] <= observation[1] <= deadline):
                                converged[index] = observation[1] - publication['started']
                if now < deadline and len(pending) < workers * 2:
                    for _ in range(workers * 2 - len(pending)):
                        heartbeat_due = schedule.next_due()
                        policy_due = policy_schedule.next_due() if policy_schedule is not None else float('inf')
                        expedited_due = receipt_due[0][0] if receipt_due else float('inf')
                        if min(heartbeat_due, policy_due, expedited_due) > now:
                            break
                        if policy_due < min(heartbeat_due, expedited_due):
                            due, ordinal, _ = policy_schedule.pop_due(now, 1)[0]
                            maximum_policy_lag = max(maximum_policy_lag, now - due)
                            if ordinal in policy_inflight:
                                counts['policy_missed_busy'] += 1
                                continue
                            policy_inflight.add(ordinal)
                            pending[pool.submit(execute_periodic_policy, ordinal)] = (ordinal, 'policy')
                        else:
                            expedited = expedited_due < heartbeat_due
                            if expedited:
                                due, ordinal = heapq.heappop(receipt_due)
                                cycle = 1
                            else:
                                due, ordinal, cycle = schedule.pop_due(now, 1)[0]
                            maximum_lag = max(maximum_lag, now - due)
                            if ordinal in inflight:
                                counts['missed_busy'] += 1
                                if expedited:
                                    counts['receipt_heartbeat_missed_busy'] += 1
                                continue
                            inflight.add(ordinal)
                            if expedited:
                                counts['receipt_heartbeat_dispatched'] += 1
                            pending[pool.submit(execute, ordinal, cycle, expedited)] = (ordinal, 'heartbeat')
                if pending:
                    finished, _ = wait(pending, timeout=0.01, return_when=FIRST_COMPLETED)
                    for future in finished:
                        ordinal, job = pending.pop(future)
                        if job == 'policy':
                            policy_inflight.remove(ordinal)
                            try:
                                outcome, elapsed = future.result()
                                counts[outcome] += 1
                                policy_latency_ms[min(int(elapsed * 1000), 60_000)] += 1
                            except Exception:
                                counts['periodic_policy_error'] += 1
                            continue
                        inflight.remove(ordinal)
                        try:
                            kind, status, elapsed, policy_result, applied, finished_at, command_result, event_result = future.result()
                            counts[kind] += 1
                            counts['business_success' if 200 <= status < 300 else 'business_error'] += 1
                            if kind == 'v2-compact':
                                counts['compact_success' if 200 <= status < 300 else 'compact_error'] += 1
                            if finished_at > deadline:
                                counts['heartbeat_completed_after_deadline'] += 1
                            if status == 200 and first_applied is not None:
                                previous = first_applied[ordinal]
                                if previous is None or applied > previous[0]:
                                    first_applied[ordinal] = (applied, finished_at)
                            if (publication is not None and status == 200 and converged[ordinal] is None
                                    and applied >= publication['version']
                                    and publication['completed'] <= finished_at <= deadline):
                                converged[ordinal] = finished_at - publication['started']
                            latency_ms[min(int(elapsed * 1000), 60_000)] += 1
                            if policy_result:
                                counts[policy_result[0]] += 1
                                if policy_result[0] != 'heartbeat_contract_error':
                                    policy_latency_ms[min(int(policy_result[1] * 1000), 60_000)] += 1
                                if (ordinal >= legacy_count + full_v2_count and policy_result[0] in ('policy_success', 'startup_policy_success')
                                        and versions[ordinal] > applied):
                                    due = time.monotonic() + receipt_rng.random() * 5
                                    if outage_at is not None and outage_at <= due < recovery:
                                        due = recovery + receipt_rng.random() * reconnect_spread
                                    if due < deadline:
                                        heapq.heappush(receipt_due, (due, ordinal))
                                        receipt_expected += 1
                                        receipt_device_versions[ordinal] = max(receipt_device_versions[ordinal], versions[ordinal])
                            if command_result:
                                counts[command_result[0]] += 1
                                if command_result[0] == 'command_success':
                                    command_completions[command_result[1]] = command_result[2]
                                    if ordinal >= count - rollout_targets and rollout_targets:
                                        target_completions[synthetic_id('device', ordinal_start + ordinal)] = (command_result[1], command_result[2])
                            if event_result:
                                counts[event_result[0]] += 1
                                event_latency_ms[min(int(event_result[1] * 1000), 60_000)] += 1
                        except Exception:
                            counts['transport_error'] += 1
                elif now < deadline:
                    next_due = min(schedule.next_due(), policy_schedule.next_due() if policy_schedule is not None else float('inf'),
                                   receipt_due[0][0] if receipt_due else float('inf'))
                    time.sleep(min(0.01, max(0, next_due - now)))
                elif admin_query_future is not None:
                    wait([admin_query_future], timeout=0.01)
    finally:
        for client in clients:
            client.close()
        if resource_monitor is not None:
            resource_report = resource_monitor.stop()
    if publish_after is not None and publication_future is None:
        publication_error = True
    if publication_future is not None and publication is None and not publication_error:
        try:
            candidate = publication_future.result()
            if publication_sink is not None:
                publication_evidence = publication_sink(candidate)
            publication = candidate
        except Exception:
            publication_error = True
    if publication_observer is not None and publication is None:
        publication_error = True
    if command_after is not None:
        if command_future is None:
            command_error = True
        else:
            try:
                command_created = command_future.result()
            except Exception:
                command_error = True
    if rollout_after is not None:
        if rollout_future is None:
            rollout_error = True
        else:
            try:
                rollout_created = rollout_future.result()
            except Exception:
                rollout_error = True
    expected = (pre_outage_expected or 0) + schedule.expected_by(deadline) + receipt_expected
    dispatched = sum(counts[k] for k in ('v1-full', 'v2-legacy-full', 'v2-full', 'v2-light', 'v2-compact', 'transport_error'))
    expected_policy = ((pre_outage_policy_expected or 0) + policy_schedule.expected_by(deadline)) if policy_schedule else 0
    dispatched_policy = counts['periodic_policy_success'] + counts['periodic_policy_error']
    observed = sorted(value for value in converged if value is not None)
    convergence = None
    if publication is not None:
        convergence = dict(policyVersion=publication['version'], targetDevices=count,
                           observedDevices=len(observed), missingDevices=count-len(observed),
                           within120Seconds=sum(value <= 120 for value in observed),
                           observationSeconds=max(0, deadline-publication['started']),
                           publicationLatencySeconds=publication['completed']-publication['started'],
                           p99ObservedSeconds=observed[max(0, (99 * len(observed) + 99) // 100 - 1)] if observed else None,
                           timingOrigin=('publication_request_started_external_clock_unverified' if publication_observer is not None
                                         else 'publication_request_started'),
                           scope='simulated applied-version heartbeat; not real client reconciliation')
    simulated_command = None
    if command_created is not None:
        completed = command_completions.get(command_created['commandId'])
        within_window = completed is not None and completed <= deadline
        latency = completed - command_created['started'] if within_window else None
        simulated_command = dict(receiptObserved=within_window, receiptAfterDeadline=completed is not None and not within_window,
                                 completedAfterSeconds=latency,
                                 within120Seconds=latency is not None and latency <= 120,
                                 scope='simulated command receipt; no real configuration change')
    simulated_rollout = None
    if rollout_created is not None:
        simulated_rollout = dict(targetDevices=rollout_targets, observedDevices=None,
            within120Seconds=None, p99ObservedSeconds=None,
            observationSeconds=max(0, deadline-rollout_created['started']),
            timingOrigin='batch_creation_request_started',
            scope='simulated receipts matched against server batch command IDs; no real configuration change')
        try:
            admin = admin_factory(origin)
            details = admin.rollout_details(rollout_created['batch'])
            simulated_rollout['serverStatus'] = details.get('status')
            simulated_rollout['serverCounts'] = details.get('counts')
            observed, target_count = [], 0
            for target in admin.rollout_targets(rollout_created['batch']):
                target_count += 1
                receipt = target_completions.get(target['deviceId'])
                if receipt and target['commandId'] == receipt[0] and rollout_created['started'] <= receipt[1] <= deadline:
                    observed.append(receipt[1] - rollout_created['started'])
            if target_count != rollout_targets:
                raise ValueError('Unexpected synthetic rollout target count')
            observed.sort()
            simulated_rollout.update(observedDevices=len(observed),
                within120Seconds=sum(value <= 120 for value in observed),
                p99ObservedSeconds=observed[max(0, (99 * len(observed) + 99) // 100 - 1)] if observed else None)
        except Exception:
            simulated_rollout['serverStatusError'] = True
    return dict(kind='heartbeat-policy', requestedSeconds=seconds, elapsedSeconds=time.monotonic() - started,
                devices=count, ordinalStart=ordinal_start, legacyDevices=legacy_count, intervalSeconds=interval,
                fullV2Devices=full_v2_count, compactV2=compact_v2,
                startupSpreadSeconds=startup_spread, startupFullV2=startup_full,
                eventDevices=event_devices, eventEveryHeartbeats=event_every,
                expectedEvents=expected, dispatchedEvents=dispatched, missingEvents=expected-dispatched-counts['missed_busy'],
                receiptHeartbeatsScheduled=receipt_expected,
                receiptHeartbeatsMissing=receipt_expected-counts['receipt_heartbeat_dispatched']-counts['receipt_heartbeat_missed_busy'],
                receiptTrafficModel='additive_after_policy_change_v1',
                receiptDevicesAtPublishedVersion=(sum(version >= publication['version'] for version in receipt_device_versions)
                                                  if publication is not None else None),
                expectedPolicyPolls=expected_policy, dispatchedPolicyPolls=dispatched_policy,
                missingPolicyPolls=expected_policy-dispatched_policy-counts['policy_missed_busy'],
                offlineSuppressedEvents=offline_suppressed,
                offlinePolicySuppressed=offline_policy_suppressed,
                maxScheduleLagSeconds=maximum_lag, counts=dict(counts), latencyMilliseconds=dict(latency_ms),
                maxPolicyScheduleLagSeconds=maximum_policy_lag,
                policyLatencyMilliseconds=dict(policy_latency_ms),
                adminLatencyMilliseconds=dict(admin_latency_ms),
                eventLatencyMilliseconds=dict(event_latency_ms),
                publicationFailed=publication_error, simulatedConvergence=convergence,
                publicationEvidence=publication_evidence,
                commandCreationFailed=command_error, simulatedCommand=simulated_command,
                rolloutCreationFailed=rollout_error, simulatedRollout=simulated_rollout,
                resources=resource_report,
                limitations=['Reactive v2 policy fetch follows heartbeat; periodic legacy polling uses an independent schedule',
                             'Policy receipt heartbeats are additive to periodic scheduling and do not model real reconciliation or endpoint scanning',
                             'Command execution is simulated; event rate is an explicit synthetic assumption',
                             'Synthetic events follow heartbeat cycles and do not model independent event bursts',
                             'Optional outage suppresses synthetic client traffic; it does not inject a real network failure',
                             'Synthetic administrator verification can add control traffic outside measured requests',
                             'Latency histograms exclude transport errors and cap individual samples at 60000 ms',
                             'No capacity or rollout acceptance conclusion'])
