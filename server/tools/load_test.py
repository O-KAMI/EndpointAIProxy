"""Run a synthetic loopback-only control workload; never use production credentials."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time

from tools.load_devices import seed_devices
from tools.load_admin import LocalSyntheticAdmin, SyntheticAdmin, local_admin_port
from tools.load_resources import ResourceMonitor
from tools.load_run import run_heartbeats
from tools.load_publication import identity, read_event, write_event
from tools.load_transport import loopback_port


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def percentile(histogram, percent):
    total = sum(histogram.values())
    if not total:
        return None
    rank = (total * percent + 99) // 100
    cumulative = 0
    for bucket, count in sorted(histogram.items(), key=lambda item: int(item[0])):
        cumulative += count
        if cumulative >= rank:
            return int(bucket)
    raise ValueError('Invalid latency histogram')


def wait_for_start(target, clock=time.time, sleeper=time.sleep):
    """Start a pre-seeded partition at a UTC time; reject a missed deadline."""
    now = clock()
    if target <= now:
        raise ValueError('Scheduled start has passed before the partition was ready')
    while now < target:
        sleeper(min(0.5, target - now))
        now = clock()
    return now


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-isolated', action='store_true')
    parser.add_argument('--origin', required=True, help='Explicit loopback HTTP origin with synthetic-only server credentials')
    parser.add_argument('--devices', type=int, required=True)
    parser.add_argument('--online', type=int, required=True)
    parser.add_argument('--ordinal-start', type=int, default=0, help='First synthetic device ordinal for this independent partition; reports cannot be combined for acceptance')
    parser.add_argument('--legacy', type=int, default=0)
    parser.add_argument('--full-v2', type=int, default=0, help='Older v2 clients with full heartbeats and periodic policy polls')
    parser.add_argument('--compact-v2', action='store_true', help='Require and exercise compact heartbeats for newer v2 clients')
    parser.add_argument('--seconds', type=float, required=True)
    parser.add_argument('--workers', type=int, default=16)
    parser.add_argument('--progress-seconds', type=int, default=60)
    parser.add_argument('--heartbeat-seconds', type=float, default=60)
    parser.add_argument('--start-at', help='Optional shared UTC start time, e.g. 2026-11-01T12:00:00Z; seed must finish first')
    parser.add_argument('--startup-spread', type=float, help='Seconds over which the first heartbeat and legacy policy polls start; 0 makes a concentrated spike')
    parser.add_argument('--startup-full', action='store_true', help='Simulate full v2 inventory and initial policy pull on startup')
    parser.add_argument('--event-devices', type=int, default=0)
    parser.add_argument('--event-every', type=int, default=60)
    parser.add_argument('--admin-query-seconds', type=float)
    parser.add_argument('--admin-origin', help='Optional loopback HTTPS local-account admin origin')
    parser.add_argument('--admin-ca', type=Path, help='Trusted test CA certificate for the admin endpoint')
    parser.add_argument('--publish-after', type=float)
    parser.add_argument('--publish-event', type=Path, help='New shared metadata file for the single synthetic publisher')
    parser.add_argument('--follow-event', type=Path, help='Read the shared metadata file as a non-publishing partition')
    parser.add_argument('--coordination-id', help='Shared canonical UUID for the synthetic run')
    parser.add_argument('--command-after', type=float)
    parser.add_argument('--rollout-after', type=float)
    parser.add_argument('--rollout-targets', type=int, default=0)
    parser.add_argument('--rollout-rate', type=int, default=20)
    parser.add_argument('--outage-after', type=float)
    parser.add_argument('--outage-seconds', type=float)
    parser.add_argument('--reconnect-spread', type=float, default=0)
    parser.add_argument('--pid', type=int, action='append', default=[])
    parser.add_argument('--monitor-generator', action='store_true', help='Include this load generator process in Linux samples')
    parser.add_argument('--disk-path', type=Path)
    parser.add_argument('--server-artifact', type=Path, required=True,
                        help='Candidate artifact to hash; operator must independently verify running server identity')
    parser.add_argument('--output', type=Path, required=True, help='New report file in a protected directory')
    args = parser.parse_args(argv)
    try:
        loopback_port(args.origin)
        scheduled_start = None
        if args.start_at is not None:
            scheduled_start = datetime.strptime(args.start_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
            if not time.time() < scheduled_start <= time.time() + 86_400:
                raise ValueError('Scheduled UTC start must be in the next 24 hours')
        if (not args.confirm_isolated or not 0 <= args.ordinal_start < 150_000
                or not 1 <= args.online <= args.devices <= 150_000 - args.ordinal_start
                or not 0 <= args.legacy <= args.online or not 0 < args.seconds <= 86_400
                or not 0 <= args.full_v2 <= args.online - args.legacy
                or not 1 <= args.workers <= 128 or not 1 <= args.heartbeat_seconds <= 3600
                or (args.startup_spread is not None and not 0 <= args.startup_spread <= 3600)
                or not 10 <= args.progress_seconds <= 3600
                or not 0 <= args.event_devices <= args.online or not 1 <= args.event_every <= 3600
                or ((args.pid or args.monitor_generator) and args.disk_path is None)
                or (args.disk_path is not None and not args.pid and not args.monitor_generator)
                or (args.admin_query_seconds is not None and not 1 <= args.admin_query_seconds <= 3600)
                or ((args.admin_origin is None) != (args.admin_ca is None))
                or (args.publish_after is not None and not 0 <= args.publish_after < args.seconds)
                or (args.command_after is not None and (not 0 <= args.command_after < args.seconds or args.legacy == args.online))
                or not 0 <= args.rollout_targets <= args.online - args.legacy or not 1 <= args.rollout_rate <= 5000
                or ((args.rollout_after is None) != (args.rollout_targets == 0))
                or (args.rollout_after is not None and (not 0 <= args.rollout_after < args.seconds or not args.admin_origin))
                or (args.command_after is not None and args.rollout_targets
                    and args.rollout_targets >= args.online - args.legacy)
                or ((args.outage_after is None) != (args.outage_seconds is None))
                or (args.outage_after is None and args.reconnect_spread != 0)
                or (args.outage_after is not None and (args.outage_after < 0 or args.outage_seconds <= 0
                    or not 0 <= args.reconnect_spread <= 3600
                    or args.outage_after + args.outage_seconds + args.reconnect_spread >= args.seconds))):
            raise ValueError('Invalid isolated load parameters')
        coordinated = args.publish_event is not None or args.follow_event is not None
        if ((args.publish_event is not None and args.follow_event is not None)
                or (coordinated and (args.coordination_id is None or args.start_at is None))
                or (not coordinated and args.coordination_id is not None)
                or (args.publish_event is not None and args.publish_after is None)
                or (args.follow_event is not None and args.publish_after is not None)):
            raise ValueError('Invalid synthetic publication coordination parameters')
        event_path = args.publish_event or args.follow_event
        if event_path is not None:
            event_parent = event_path.parent.resolve(strict=True)
            event_path = event_parent / event_path.name
            if event_path.is_symlink() or (args.publish_event is not None and event_path.exists()):
                raise ValueError('Publication event file is linked or already exists')
        if args.admin_origin is not None:
            local_admin_port(args.admin_origin)
            if not args.admin_ca.is_file() or args.admin_ca.is_symlink():
                raise ValueError('A regular test CA certificate is required')
        if not args.server_artifact.is_file() or args.server_artifact.is_symlink():
            raise ValueError('Candidate artifact must be a regular file')
        artifact_sha = digest(args.server_artifact)
        event_identity = identity(args.coordination_id, artifact_sha, args.start_at) if coordinated else None
        parent = args.output.parent.resolve(strict=True)
        if not parent.is_dir() or args.output.name in ('', '.', '..') or (event_path is not None and event_path == parent / args.output.name):
            raise ValueError('A protected existing report directory is required')
    except (OSError, ValueError) as error:
        parser.error(str(error))

    output = parent / args.output.name
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    monitor_pids = args.pid + ([os.getpid()] if args.monitor_generator else [])
    params = dict(devices=args.devices, online=args.online, ordinalStart=args.ordinal_start, legacy=args.legacy, fullV2=args.full_v2, compactV2=args.compact_v2, seconds=args.seconds,
                  workers=args.workers, heartbeatSeconds=args.heartbeat_seconds,
                  startupSpreadSeconds=args.startup_spread, startupFullV2=args.startup_full, scheduledStartUtc=args.start_at,
                  progressSeconds=args.progress_seconds,
                  eventDevices=args.event_devices, eventEveryHeartbeats=args.event_every,
                  adminAuthMode='local-https' if args.admin_origin else 'legacy',
                  generatorPid=os.getpid() if args.monitor_generator else None, monitoredPids=monitor_pids,
                  adminQuerySeconds=args.admin_query_seconds, publishAfter=args.publish_after,
                  coordinationId=args.coordination_id, publicationRole=('publisher' if args.publish_event else 'follower' if args.follow_event else None),
                  commandAfter=args.command_after, outageAfter=args.outage_after,
                  rolloutAfter=args.rollout_after, rolloutTargets=args.rollout_targets, rolloutRate=args.rollout_rate,
                  outageSeconds=args.outage_seconds, reconnectSpread=args.reconnect_spread)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        def emit(record):
            stream.write(json.dumps(record, separators=(',', ':'), allow_nan=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

        emit(dict(status='running', startedUtc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  candidateArtifactSha256=artifact_sha, runningArtifactBinding='operator verification required',
                  parameters=params))
        try:
            monitor = ResourceMonitor(monitor_pids, args.disk_path) if monitor_pids else None
            tokens = seed_devices(args.origin, args.devices, args.legacy, workers=args.workers,
                                  progress_callback=lambda snapshot: emit(dict(status='seeding', snapshot=snapshot)),
                                  full_v2_count=args.full_v2, ordinal_start=args.ordinal_start, compact_v2=args.compact_v2)
            if args.admin_origin:
                admin = LocalSyntheticAdmin(args.origin, args.admin_origin, args.admin_ca)
                admin_factory = lambda origin: admin
            else:
                admin_factory = SyntheticAdmin
            if scheduled_start is not None:
                emit(dict(status='ready', scheduledStartUtc=args.start_at))
                started_at = wait_for_start(scheduled_start)
            else:
                started_at = time.time()
            sink = (lambda publication: write_event(event_path, event_identity, publication)) if args.publish_event else None
            observer = (lambda: read_event(event_path, event_identity)) if args.follow_event else None
            result = run_heartbeats(args.origin, tokens[:args.online], args.legacy, args.seconds,
                interval=args.heartbeat_seconds, workers=args.workers, publish_after=args.publish_after,
                command_after=args.command_after, admin_query_interval=args.admin_query_seconds,
                outage_after=args.outage_after, outage_seconds=args.outage_seconds,
                reconnect_spread=args.reconnect_spread, resource_monitor=monitor,
                event_devices=args.event_devices, event_every=args.event_every, admin_factory=admin_factory,
                rollout_after=args.rollout_after, rollout_targets=args.rollout_targets, rollout_rate=args.rollout_rate,
                progress_callback=lambda snapshot: emit(dict(status='progress', snapshot=snapshot)),
                progress_seconds=args.progress_seconds, full_v2_count=args.full_v2,
                startup_spread=args.startup_spread, startup_full=args.startup_full, ordinal_start=args.ordinal_start,
                publication_observer=observer, publication_sink=sink, compact_v2=args.compact_v2)
            for field, prefix in (('latencyMilliseconds', 'heartbeat'),
                                  ('policyLatencyMilliseconds', 'policy'),
                                  ('eventLatencyMilliseconds', 'event'),
                                  ('adminLatencyMilliseconds', 'admin')):
                result[prefix + 'P95BucketMs'] = percentile(result[field], 95)
                result[prefix + 'P99BucketMs'] = percentile(result[field], 99)
            emit(dict(status='finished', loadStartedUtc=datetime.fromtimestamp(started_at, timezone.utc).isoformat(),
                      startSkewSeconds=(started_at - scheduled_start) if scheduled_start is not None else None,
                      duration8hRequested=args.seconds >= 28_800,
                      duration8hCompleted=args.seconds >= 28_800 and result['elapsedSeconds'] >= 28_800,
                      capacityAcceptance='not evaluated', report=result))
        except Exception as error:
            emit(dict(status='failed', errorType=type(error).__name__, capacityAcceptance='not evaluated'))
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
