"""Conservative evidence checks for an isolated load report; never certifies release."""
import argparse
import json
import math
from pathlib import Path

from tools.load_test import percentile


def assess(records):
    checks = {}
    def check(name, state, reason):
        checks[name] = dict(state=state, reason=reason)

    if not isinstance(records, list) or not records or any(not isinstance(record, dict) for record in records) or records[0].get('status') != 'running':
        raise ValueError('Missing initial record')
    params = records[0].get('parameters', {})
    if not isinstance(params, dict):
        raise ValueError('Invalid test parameters')
    finished = records[-1] if records[-1].get('status') == 'finished' else None
    if finished is None:
        return dict(overall='incomplete', checks={'run': dict(state='incomplete', reason='No completed run record')})
    report = finished.get('report')
    if not isinstance(report, dict):
        raise ValueError('Missing final report')
    def finite_number(value):
        return type(value) in (int, float) and math.isfinite(value)
    elapsed, requested, configured = (report.get('elapsedSeconds'), report.get('requestedSeconds'), params.get('seconds'))
    duration_ok = (finished.get('duration8hCompleted') is True and all(finite_number(v) and v >= 28_800
                   for v in (elapsed, requested, configured)) and requested == configured)
    check('duration', 'met' if duration_ok else 'incomplete', 'Eight-hour duration recorded' if duration_ok else 'Eight hours not recorded')
    scale_ok = (params.get('ordinalStart', 0) == 0 and report.get('ordinalStart', 0) == 0
                and params.get('devices', 0) >= 150_000 and params.get('online', 0) >= 100_000
                and report.get('devices') == params.get('online') and report.get('legacyDevices') == params.get('legacy')
                and report.get('fullV2Devices') == params.get('fullV2')
                and type(params.get('compactV2', False)) is bool and type(report.get('compactV2', False)) is bool
                and report.get('compactV2', False) == params.get('compactV2', False))
    check('inventory_scale', 'met' if scale_ok else 'incomplete', 'Configured 150000 stored and 100000 online' if scale_ok else 'Configured scale below target')
    counts = report.get('counts', {})
    if not isinstance(counts, dict):
        raise ValueError('Invalid workload counters')
    if params.get('compactV2') is True:
        compact_ok = (report.get('compactV2') is True and type(counts.get('v2-compact')) is int
                      and counts['v2-compact'] > 0 and type(counts.get('compact_success')) is int
                      and counts['compact_success'] == counts['v2-compact']
                      and type(counts.get('compact_error', 0)) is int and counts.get('compact_error', 0) == 0
                      and type(counts.get('business_success')) is int and counts['compact_success'] <= counts['business_success'])
        check('compact_heartbeat', 'met' if compact_ok else 'incomplete',
              'Compact requests observed without reported errors' if compact_ok else 'Compact workload not fully observed')
    expected, sent = report.get('expectedEvents'), report.get('dispatchedEvents')
    missing, busy = report.get('missingEvents'), counts.get('missed_busy', 0)
    interval, spread = params.get('heartbeatSeconds'), params.get('startupSpreadSeconds')
    if spread is None:
        spread = interval
    interval_ok = (finite_number(interval) and 1 <= interval <= 60 and finite_number(spread) and 0 <= spread <= 3600
                   and report.get('intervalSeconds') == interval
                   and report.get('startupSpreadSeconds') == params.get('startupSpreadSeconds')
                   and finite_number(configured) and configured > 0 and report.get('requestedSeconds') == configured
                   and params.get('outageAfter') is None and params.get('outageSeconds') is None
                   and type(params.get('online')) is int and params['online'] > 0
                   and report.get('devices') == params['online'])
    cycles = max(0, math.floor((configured - spread) / interval)) if interval_ok else None
    receipt_scheduled = report.get('receiptHeartbeatsScheduled')
    heartbeat_intensity_ok = (cycles is not None and cycles > 0 and type(expected) is int
                              and type(receipt_scheduled) is int and 0 <= receipt_scheduled <= expected
                              and expected - receipt_scheduled >= cycles * params['online'])
    check('heartbeat_workload_intensity', 'met' if heartbeat_intensity_ok else 'incomplete',
          'Heartbeat interval and conservative scheduled volume match the configured online population'
          if heartbeat_intensity_ok else 'Missing baseline schedule evidence or insufficient heartbeat frequency/volume; outage runs are separate')
    if not all(type(value) is int and value >= 0 for value in (expected, sent, missing, busy)) or expected != sent + missing + busy:
        check('generator_delivery', 'incomplete', 'Missing or inconsistent scheduled-event counts')
    elif (any(type(counts.get(key, 0)) is not int or counts.get(key, 0) < 0
              for key in ('business_success', 'business_error', 'transport_error'))
          or sum(counts.get(key, 0) for key in ('business_success', 'business_error', 'transport_error')) != sent):
        check('generator_delivery', 'incomplete', 'Heartbeat response counts do not match dispatched events')
    elif not expected:
        check('generator_delivery', 'incomplete', 'No scheduled events')
    elif missing or busy:
        check('generator_delivery', 'failed', 'Generator missed or skipped scheduled events')
    elif not heartbeat_intensity_ok:
        check('generator_delivery', 'incomplete', 'Scheduled heartbeat volume does not establish the required baseline load')
    else:
        check('generator_delivery', 'met', 'No scheduled heartbeat events missed')

    receipt_expected = report.get('receiptHeartbeatsScheduled')
    receipt_missing = report.get('receiptHeartbeatsMissing')
    receipt_sent = counts.get('receipt_heartbeat_dispatched', 0)
    receipt_busy = counts.get('receipt_heartbeat_missed_busy', 0)
    receipt_devices = report.get('receiptDevicesAtPublishedVersion')
    population = [params.get(key) for key in ('online', 'legacy', 'fullV2')]
    if (report.get('receiptTrafficModel') != 'additive_after_policy_change_v1'
            or not all(type(value) is int and value >= 0 for value in
                       (receipt_expected, receipt_missing, receipt_sent, receipt_busy, receipt_devices, *population))
            or population[1] + population[2] > population[0]
            or receipt_devices > population[0] - population[1] - population[2]
            or receipt_devices > receipt_expected or report.get('publicationFailed') is not False
            or receipt_expected != receipt_sent + receipt_missing + receipt_busy):
        check('receipt_heartbeat_load', 'incomplete', 'Missing or inconsistent policy receipt traffic evidence')
    elif receipt_missing or receipt_busy:
        check('receipt_heartbeat_load', 'failed', 'Generator missed scheduled policy receipt heartbeats')
    elif population[0] - population[1] - population[2] == 0 or receipt_devices < math.ceil((population[0] - population[1] - population[2]) * 0.99):
        check('receipt_heartbeat_load', 'incomplete', 'Fewer than 99% of new-v2 devices scheduled a published-version receipt heartbeat')
    else:
        check('receipt_heartbeat_load', 'met', 'At least 99% of new-v2 devices scheduled published-version receipt traffic without generator omissions; real reconciliation excluded')

    policy_expected = report.get('expectedPolicyPolls')
    policy_sent = report.get('dispatchedPolicyPolls')
    policy_missing = report.get('missingPolicyPolls')
    policy_busy = counts.get('policy_missed_busy', 0)
    legacy_and_full = [params.get('legacy'), params.get('fullV2')]
    policy_intensity_ok = (cycles is not None and cycles > 0 and all(type(v) is int and v >= 0 for v in legacy_and_full)
                           and sum(legacy_and_full) <= params.get('online', 0) and type(policy_expected) is int
                           and policy_expected >= cycles * sum(legacy_and_full))
    if (not all(type(value) is int and value >= 0 for value in (policy_expected, policy_sent, policy_missing, policy_busy))
            or policy_expected != policy_sent + policy_missing + policy_busy
            or policy_sent != counts.get('periodic_policy_success', 0) + counts.get('periodic_policy_error', 0)
            or (params.get('legacy', 0) + params.get('fullV2', 0) > 0 and policy_expected == 0)):
        check('policy_generator_delivery', 'incomplete', 'Missing or inconsistent periodic-policy schedule counts')
    elif policy_missing or policy_busy:
        check('policy_generator_delivery', 'failed', 'Generator missed or skipped scheduled periodic policy polls')
    elif not policy_intensity_ok:
        check('policy_generator_delivery', 'incomplete', 'Periodic policy schedule does not establish the configured legacy/full-v2 load')
    else:
        check('policy_generator_delivery', 'met', 'No scheduled periodic policy polls missed')

    hist = report.get('latencyMilliseconds', {})
    try:
        if (not isinstance(hist, dict) or any(type(v) is not int or v < 0 or not str(k).isdigit() for k, v in hist.items())
                or sum(hist.values()) != counts.get('business_success', 0) + counts.get('business_error', 0)):
            raise ValueError('Invalid histogram')
        p95, p99 = percentile(hist, 95), percentile(hist, 99)
    except (ValueError, TypeError, AttributeError):
        p95 = p99 = None
    if p95 is None or p99 is None:
        check('heartbeat_latency', 'incomplete', 'No usable heartbeat latency samples')
    elif p95 >= 200 or p99 >= 1000:
        check('heartbeat_latency', 'failed', 'Heartbeat p95/p99 bucket exceeds conservative threshold')
    else:
        check('heartbeat_latency', 'met', 'Heartbeat p95 <200ms and p99 <1000ms; transport failures excluded')
    error_values = [counts.get(key, 0) for key in ('business_error', 'transport_error', 'heartbeat_contract_error')]
    errors = sum(error_values) if all(type(value) is int and value >= 0 for value in error_values) else None
    if (type(sent) is not int or sent <= 0 or errors is None or errors > sent
            or counts.get('heartbeat_contract_error', 0) > counts.get('business_success', 0)):
        check('heartbeat_error_rate', 'incomplete', 'Missing or inconsistent heartbeat error counts')
    elif errors / sent >= 0.001:
        check('heartbeat_error_rate', 'failed', 'Heartbeat error rate is at least 0.1%')
    else:
        check('heartbeat_error_rate', 'met', 'Heartbeat error rate is below 0.1%; other endpoints excluded')

    def check_endpoint(name, histogram_key, success_keys, error_keys):
        names = success_keys + error_keys
        values = [counts.get(key, 0) for key in names]
        histogram = report.get(histogram_key, {})
        if (any(type(value) is not int or value < 0 for value in values) or not isinstance(histogram, dict)
                or any(type(value) is not int or value < 0 or not str(key).isdigit() for key, value in histogram.items())):
            check(name, 'incomplete', 'Invalid endpoint counters or histogram')
            return
        attempts = sum(values)
        if attempts == 0 or sum(histogram.values()) != attempts:
            check(name, 'incomplete', 'No endpoint requests or incomplete latency samples')
            return
        p95, p99 = percentile(histogram, 95), percentile(histogram, 99)
        errors = sum(counts.get(key, 0) for key in error_keys)
        if p95 is None or p99 is None:
            check(name, 'incomplete', 'No endpoint latency samples')
        elif p95 >= 200 or p99 >= 1000 or errors / attempts >= 0.001:
            check(name, 'failed', 'Endpoint latency or error rate exceeds the conservative threshold')
        else:
            check(name, 'met', 'Endpoint p95 <200ms, p99 <1000ms and error rate <0.1%')

    check_endpoint('policy_requests', 'policyLatencyMilliseconds',
                   ('periodic_policy_success', 'policy_success', 'startup_policy_success'),
                   ('periodic_policy_error', 'policy_error', 'startup_policy_error'))
    check_endpoint('event_requests', 'eventLatencyMilliseconds', ('event_success',), ('event_error',))

    convergence = report.get('simulatedConvergence')
    if (report.get('publicationFailed') is not False or not isinstance(convergence, dict)
            or convergence.get('timingOrigin') != 'publication_request_started'
            or convergence.get('targetDevices') != params.get('online')
            or type(convergence.get('within120Seconds')) is not int
            or type(convergence.get('observedDevices')) is not int
            or type(convergence.get('missingDevices')) is not int
            or not 0 <= convergence['within120Seconds'] <= convergence['observedDevices'] <= convergence['targetDevices']
            or convergence['missingDevices'] != convergence['targetDevices'] - convergence['observedDevices']):
        check('simulated_policy_120s', 'incomplete', 'Missing publication or complete target denominator')
    elif convergence.get('within120Seconds', 0) < math.ceil(convergence['targetDevices'] * 0.99):
        observed_seconds = convergence.get('observationSeconds')
        if type(observed_seconds) not in (int, float) or observed_seconds < 120:
            check('simulated_policy_120s', 'incomplete', 'Fewer than 99% reported and the observation window was shorter than 120 seconds')
        else:
            check('simulated_policy_120s', 'failed', 'Fewer than 99% of simulated targets reported within 120 seconds')
    else:
        check('simulated_policy_120s', 'met', 'At least 99% simulated version receipts within 120 seconds; real calibration excluded')

    rollout = report.get('simulatedRollout')
    if (report.get('rolloutCreationFailed') is not False or not isinstance(rollout, dict)
            or rollout.get('serverStatusError') is True
            or rollout.get('timingOrigin') != 'batch_creation_request_started'
            or type(rollout.get('targetDevices')) is not int or rollout['targetDevices'] <= 0
            or rollout['targetDevices'] != params.get('rolloutTargets')
            or type(rollout.get('within120Seconds')) is not int
            or type(rollout.get('observedDevices')) is not int
            or not 0 <= rollout['within120Seconds'] <= rollout['observedDevices'] <= rollout['targetDevices']):
        check('simulated_rollout_120s', 'incomplete', 'Missing batch or verified target and receipt counts')
    elif rollout['within120Seconds'] < math.ceil(rollout['targetDevices'] * 0.99):
        observed_seconds = rollout.get('observationSeconds')
        if type(observed_seconds) not in (int, float) or not math.isfinite(observed_seconds) or observed_seconds < 120:
            check('simulated_rollout_120s', 'incomplete', 'Fewer than 99% reported and the observation window was shorter than 120 seconds')
        else:
            check('simulated_rollout_120s', 'failed', 'Fewer than 99% of simulated batch targets reported within 120 seconds')
    else:
        check('simulated_rollout_120s', 'met', 'At least 99% of simulated batch targets reported within 120 seconds; real execution excluded')

    try:
        admin_hist = report.get('adminLatencyMilliseconds', {})
        if (not isinstance(admin_hist, dict) or any(type(v) is not int or v < 0 or not str(k).isdigit() for k, v in admin_hist.items())
                or sum(admin_hist.values()) != counts.get('admin_query_success', 0)):
            raise ValueError('Invalid management histogram')
        admin_p95 = percentile(admin_hist, 95)
    except (ValueError, TypeError, AttributeError):
        admin_p95 = None
    if admin_p95 is None:
        check('management_latency', 'incomplete', 'No usable management query samples')
    elif admin_p95 >= 2000 or counts.get('admin_query_error', 0) or counts.get('admin_query_missed', 0):
        check('management_latency', 'failed', 'Management query latency, errors or omitted queries exceed the check')
    else:
        check('management_latency', 'met', 'Management query p95 <2s without reported errors or omissions')

    resources = report.get('resources')
    pids = params.get('monitoredPids')
    coverage_ok = (duration_ok and isinstance(resources, dict) and resources.get('complete') is True
                   and resources.get('sampleLimitReached') is False and isinstance(pids, list)
                   and bool(pids) and all(type(pid) is int and pid > 0 for pid in pids)
                   and len(set(pids)) == len(pids))
    samples = resources.get('samples') if isinstance(resources, dict) else None
    coverage_ok = coverage_ok and isinstance(samples, list) and len(samples) >= 2
    starts = {}
    times = []
    if coverage_ok:
        for sample in samples:
            if not isinstance(sample, dict) or sample.get('errors') != []:
                coverage_ok = False
                break
            now = sample.get('monotonicSeconds')
            processes, disk = sample.get('processes'), sample.get('disk')
            if (type(now) not in (int, float) or not math.isfinite(now) or not isinstance(processes, list)
                    or not isinstance(disk, dict) or len(processes) != len(pids)
                    or any(not isinstance(p, dict) or type(p.get('pid')) is not int for p in processes)
                    or {p['pid'] for p in processes} != set(pids)
                    or any(type(disk.get(k)) is not int or disk[k] < 0 for k in
                           ('totalBytes', 'availableBytes', 'totalInodes', 'availableInodes'))
                    or disk['totalBytes'] <= 0 or disk['totalInodes'] <= 0 or disk['availableBytes'] > disk['totalBytes']
                    or disk['availableInodes'] > disk['totalInodes']):
                coverage_ok = False
                break
            for proc in processes:
                if (not isinstance(proc, dict) or proc.get('restarted') is not False
                        or any(type(proc.get(k)) is not int or proc[k] <= 0 for k in ('startTicks', 'rssBytes', 'virtualBytes', 'threads'))
                        or any(type(proc.get(k)) is not int or proc[k] < 0 for k in ('cpuTicks', 'openDescriptors'))
                        or proc['virtualBytes'] < proc['rssBytes']
                        or (times and (type(proc.get('cpuPercent')) not in (int, float)
                                      or not math.isfinite(proc['cpuPercent']) or proc['cpuPercent'] < 0))
                        or (proc['pid'] in starts and starts[proc['pid']] != proc['startTicks'])):
                    coverage_ok = False
                    break
                starts[proc['pid']] = proc['startTicks']
            times.append(now)
            if not coverage_ok:
                break
        if (coverage_ok and (times[-1] - times[0] < 28_770
                or any(not 0 < b - a <= 30 for a, b in zip(times, times[1:])))):
            coverage_ok = False
    check('resource_sample_coverage', 'met' if coverage_ok else 'incomplete',
          'Eight-hour process and disk samples present; trends, remote database and thresholds require review'
          if coverage_ok else 'Missing, interrupted or incomplete eight-hour process and disk samples')

    check('remaining_evidence', 'incomplete', 'Running artifact identity, independent polling peaks, real client receipts, Linux and remote database metrics require separate verification')
    return dict(overall='incomplete', checks=checks,
                note='Automated checks are indicative; this report cannot certify capacity or release readiness.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args(argv)
    try:
        with args.report.open(encoding='utf-8') as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        print(json.dumps(assess(records), ensure_ascii=False, indent=2))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        parser.exit(2, 'Invalid or unreadable isolated load report.\n')


if __name__ == '__main__':
    main()
