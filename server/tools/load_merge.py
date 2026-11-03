"""Inspect coordinated synthetic shard reports without certifying capacity."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path

from tools.load_evaluate import assess
from tools.load_publication import identity, validate_event
from tools.load_test import percentile


def merge(partitions):
    if not isinstance(partitions, list) or not 2 <= len(partitions) <= 256:
        raise ValueError('Two to 256 shard reports are required')
    ranges, params_list, reports, starts = [], [], [], []
    artifact = scheduled = coordination = event = duration = None
    roles = Counter()
    hist = Counter()
    observed = within = 0
    compact_success = compact_error = 0
    checks = []
    for records in partitions:
        if not isinstance(records, list) or not records or records[0].get('status') != 'running' or records[-1].get('status') != 'finished':
            raise ValueError('Shard has no complete run')
        initial, final = records[0], records[-1]
        p, report = initial.get('parameters'), final.get('report')
        if not isinstance(p, dict) or not isinstance(report, dict) or not any(r.get('status') == 'ready' for r in records):
            raise ValueError('Shard has no scheduled readiness evidence')
        ident, digest, start = p.get('coordinationId'), initial.get('candidateArtifactSha256'), p.get('scheduledStartUtc')
        expected = identity(ident, digest, start)
        if not isinstance(start, str):
            raise ValueError('Scheduled start is missing')
        scheduled_epoch = datetime.strptime(start, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
        values = (p.get('ordinalStart'), p.get('devices'), p.get('online'), p.get('legacy'), p.get('fullV2'))
        if (any(type(v) is not int for v in values) or not 0 <= values[0] < 150_000
                or not 1 <= values[2] <= values[1] <= 150_000 - values[0]
                or not 0 <= values[3] <= values[2] or not 0 <= values[4] <= values[2] - values[3]):
            raise ValueError('Invalid shard range or client mix')
        if (report.get('ordinalStart') != values[0] or report.get('devices') != values[2]
                or report.get('legacyDevices') != values[3] or report.get('fullV2Devices') != values[4]
                or type(p.get('compactV2', False)) is not bool or type(report.get('compactV2', False)) is not bool
                or report.get('compactV2', False) != p.get('compactV2', False)):
            raise ValueError('Shard report does not match its parameters')
        current_duration = p.get('seconds')
        if (type(current_duration) not in (int, float) or not math.isfinite(current_duration)
                or not 0 < current_duration <= 86400 or report.get('requestedSeconds') != current_duration):
            raise ValueError('Invalid shard duration')
        if coordination is None:
            coordination, artifact, scheduled, duration = ident, digest, start, current_duration
        elif (ident, digest, start, current_duration) != (coordination, artifact, scheduled, duration):
            raise ValueError('Shards do not belong to one scheduled run')
        role = p.get('publicationRole')
        if role not in ('publisher', 'follower') or (role == 'publisher') != (p.get('publishAfter') is not None):
            raise ValueError('Invalid publication role')
        roles[role] += 1
        proof = report.get('publicationEvidence')
        validate_event(proof, expected)
        if event is None:
            event = proof
        elif event != proof:
            raise ValueError('Publication evidence differs between shards')
        timing = report.get('simulatedConvergence')
        origin = 'publication_request_started' if role == 'publisher' else 'publication_request_started_external_clock_unverified'
        if (report.get('publicationFailed') is not False or not isinstance(timing, dict)
                or timing.get('timingOrigin') != origin or timing.get('policyVersion') != proof['policyVersion']
                or timing.get('targetDevices') != values[2]
                or not scheduled_epoch - 60 <= proof['startedUnixSeconds'] <= scheduled_epoch + current_duration
                or proof['completedUnixSeconds'] > scheduled_epoch + current_duration + 60):
            raise ValueError('Missing coordinated convergence evidence')
        metrics = [timing.get(k) for k in ('observedDevices', 'missingDevices', 'within120Seconds')]
        if (any(type(v) is not int for v in metrics) or not 0 <= metrics[2] <= metrics[0] <= values[2]
                or metrics[0] + metrics[1] != values[2]):
            raise ValueError('Inconsistent convergence counts')
        observed += metrics[0]
        within += metrics[2]
        try:
            actual = datetime.fromisoformat(final['loadStartedUtc'])
            skew = final['startSkewSeconds']
            if actual.tzinfo is None or type(skew) not in (int, float) or not math.isfinite(skew) or skew < 0:
                raise ValueError('Invalid start evidence')
            actual_epoch = actual.timestamp()
            if abs(actual_epoch - scheduled_epoch - skew) > 0.01:
                raise ValueError('Inconsistent start evidence')
        except (KeyError, TypeError, OverflowError):
            raise ValueError('Invalid start evidence') from None
        if not any(r.get('status') == 'ready' and r.get('scheduledStartUtc') == start for r in records):
            raise ValueError('Ready record does not match scheduled start')
        starts.append(actual_epoch)
        evaluation = assess(records)
        checks.append(evaluation['checks'])
        histogram = report.get('latencyMilliseconds')
        counts = report.get('counts')
        if not isinstance(histogram, dict) or not isinstance(counts, dict):
            raise ValueError('Missing heartbeat metrics')
        compact_counts = (counts.get('v2-compact', 0), counts.get('compact_success', 0), counts.get('compact_error', 0))
        if (any(type(v) is not int or v < 0 for v in compact_counts)
                or compact_counts[0] != compact_counts[1] + compact_counts[2]
                or (not p.get('compactV2', False) and compact_counts[0])):
            raise ValueError('Invalid compact heartbeat counters')
        compact_success += compact_counts[1]
        compact_error += compact_counts[2]
        if any(not str(k).isdigit() or type(v) is not int or v < 0 for k, v in histogram.items()):
            raise ValueError('Invalid histogram')
        outcomes = (counts.get('business_success', 0), counts.get('business_error', 0))
        if (any(type(value) is int and compact_counts[i + 1] > value for i, value in enumerate(outcomes))):
            raise ValueError('Invalid compact heartbeat counters')
        if (any(type(value) is not int or value < 0 for value in outcomes)
                or sum(histogram.values()) != sum(outcomes)):
            raise ValueError('Histogram does not match heartbeat responses')
        hist.update({str(k): v for k, v in histogram.items()})
        ranges.append((values[0], values[0] + values[1]))
        params_list.append(p)
        reports.append(report)
    if roles['publisher'] != 1 or roles['follower'] != len(partitions) - 1:
        raise ValueError('Exactly one publisher is required')
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise ValueError('Shard device ranges overlap')
    total_devices = sum(p['devices'] for p in params_list)
    total_online = sum(p['online'] for p in params_list)
    contiguous = ranges[0][0] == 0 and all(left[1] == right[0] for left, right in zip(ranges, ranges[1:]))
    return dict(overall='incomplete', shards=len(partitions), coordinationId=coordination,
        candidateArtifactSha256=artifact, scheduledStartUtc=scheduled,
        devices=total_devices, online=total_online,
        configuredCompactOnline=sum(p['online'] - p['legacy'] - p['fullV2'] for p in params_list if p.get('compactV2', False)),
        compactHeartbeatSuccess=compact_success, compactHeartbeatError=compact_error, ranges=[list(v) for v in ranges],
        inventoryScaleConfiguration=('meets_target' if contiguous and total_devices == 150_000 and total_online >= 100_000 else 'incomplete'),
        requestedSeconds=duration, startSpreadSeconds=max(starts)-min(starts),
        commonScheduledWindowSeconds=max(0, duration-(max(starts)-min(starts))),
        durationCoverage=('met' if all(c.get('duration', {}).get('state') == 'met' for c in checks) else 'incomplete'),
        generatorDelivery=('failed' if any(c.get('generator_delivery', {}).get('state') == 'failed' for c in checks)
                           else 'met' if all(c.get('generator_delivery', {}).get('state') == 'met' for c in checks) else 'incomplete'),
        heartbeatP95BucketMs=percentile(hist, 95), heartbeatP99BucketMs=percentile(hist, 99),
        publicationEvidence=event, simulatedPolicy=dict(targetDevices=total_online, observedDevices=observed,
            within120Seconds=within, state='incomplete', reason='Cross-host clock accuracy and real client receipts require independent verification'),
        note='Synthetic reports and shared event files do not prove clock synchronization, process identity, isolation, real client execution or production capacity.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='+', type=Path)
    args = parser.parse_args(argv)
    try:
        data, total_bytes = [], 0
        for path in args.reports:
            size = path.stat().st_size
            total_bytes += size
            if path.is_symlink() or size > 64 * 1024 * 1024 or total_bytes > 256 * 1024 * 1024:
                raise ValueError('Invalid report file')
            with path.open(encoding='utf-8') as stream:
                data.append([json.loads(line) for line in stream if line.strip()])
        print(json.dumps(merge(data), ensure_ascii=False, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        parser.exit(2, 'Invalid or inconsistent isolated shard reports.\n')


if __name__ == '__main__':
    main()
