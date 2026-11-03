from copy import deepcopy

from tools.load_evaluate import assess


def fixture():
    initial = dict(status='running', parameters=dict(devices=150_000, online=100_000, legacy=10_000, fullV2=10_000,
        seconds=28_800, heartbeatSeconds=60, startupSpreadSeconds=None))
    final = dict(status='finished', duration8hCompleted=True, report=dict(
        devices=100_000, legacyDevices=10_000, fullV2Devices=10_000, requestedSeconds=28_800, elapsedSeconds=28_800,
        intervalSeconds=60, startupSpreadSeconds=None, receiptHeartbeatsScheduled=0,
        expectedEvents=48_000_000, dispatchedEvents=48_000_000, missingEvents=0,
        expectedPolicyPolls=9_600_000, dispatchedPolicyPolls=9_600_000, missingPolicyPolls=0,
        counts=dict(business_success=48_000_000, business_error=0, transport_error=0, admin_query_success=5,
                    periodic_policy_success=9_600_000, event_success=10),
        latencyMilliseconds={'50': 47_520_000, '300': 480_000}, adminLatencyMilliseconds={'100': 5},
        policyLatencyMilliseconds={'70': 9_600_000}, eventLatencyMilliseconds={'80': 10}, publicationFailed=False,
        simulatedConvergence=dict(targetDevices=100_000, observedDevices=99_000, missingDevices=1_000,
                                  within120Seconds=99_000, observationSeconds=120,
                                  timingOrigin='publication_request_started')))
    return [initial, final]


def test_synthetic_success_cannot_certify_capacity():
    result = assess(fixture())
    assert result['overall'] == 'incomplete'
    assert result['checks']['duration']['state'] == 'met'
    assert result['checks']['inventory_scale']['state'] == 'met'
    assert result['checks']['simulated_policy_120s']['state'] == 'met'
    assert result['checks']['policy_requests']['state'] == 'met'
    assert result['checks']['event_requests']['state'] == 'met'
    assert result['checks']['remaining_evidence']['state'] == 'incomplete'
    assert result['checks']['simulated_rollout_120s']['state'] == 'incomplete'
    assert result['checks']['receipt_heartbeat_load']['state'] == 'incomplete'
    assert result['checks']['resource_sample_coverage']['state'] == 'incomplete'


def test_baseline_requires_minute_cadence_and_sufficient_scheduled_volume():
    records = fixture()
    assert assess(records)['checks']['heartbeat_workload_intensity']['state'] == 'met'
    report = records[-1]['report']
    report.update(expectedEvents=1000, dispatchedEvents=1000, latencyMilliseconds={'50': 1000})
    report['counts']['business_success'] = 1000
    result = assess(records)['checks']
    assert result['heartbeat_workload_intensity']['state'] == 'incomplete'
    assert result['generator_delivery']['state'] == 'incomplete'

    records = fixture()
    records[0]['parameters']['heartbeatSeconds'] = 3600
    records[-1]['report']['intervalSeconds'] = 3600
    assert assess(records)['checks']['heartbeat_workload_intensity']['state'] == 'incomplete'

    records = fixture()
    records[0]['parameters'].update(outageAfter=60, outageSeconds=60)
    assert assess(records)['checks']['heartbeat_workload_intensity']['state'] == 'incomplete'

    records = fixture()
    report = records[-1]['report']
    report.update(expectedPolicyPolls=100, dispatchedPolicyPolls=100)
    report['counts']['periodic_policy_success'] = 100
    assert assess(records)['checks']['policy_generator_delivery']['state'] == 'incomplete'


def test_nonfinite_duration_is_not_eight_hour_evidence():
    records = fixture()
    records[-1]['report']['elapsedSeconds'] = float('inf')
    assert assess(records)['checks']['duration']['state'] == 'incomplete'


def test_resource_coverage_requires_complete_continuous_eight_hour_samples():
    records = fixture()
    records[0]['parameters']['monitoredPids'] = [42]
    report = records[-1]['report']
    process = dict(pid=42, startTicks=10, rssBytes=100, virtualBytes=200, threads=2,
                   cpuTicks=10, cpuPercent=1.0, openDescriptors=4, restarted=False)
    disk = dict(totalBytes=1000, availableBytes=500, totalInodes=100, availableInodes=50)
    samples = [dict(monotonicSeconds=t, processes=[dict(process)], disk=dict(disk), errors=[])
               for t in range(0, 28_801, 30)]
    samples[0]['processes'][0]['cpuPercent'] = None
    report['resources'] = dict(complete=True, sampleLimitReached=False, samples=samples)
    assert assess(records)['checks']['resource_sample_coverage']['state'] == 'met'
    report['requestedSeconds'] = 1
    assert assess(records)['checks']['resource_sample_coverage']['state'] == 'incomplete'
    report['requestedSeconds'] = 28_800
    report['resources']['samples'][3]['errors'] = ['process_unavailable:42']
    assert assess(records)['checks']['resource_sample_coverage']['state'] == 'incomplete'
    report['resources']['samples'][3]['errors'] = []
    report['resources']['samples'][3]['processes'][0]['startTicks'] = 11
    assert assess(records)['checks']['resource_sample_coverage']['state'] == 'incomplete'
    report['resources']['samples'][3]['processes'][0]['startTicks'] = 10
    del report['resources']['samples'][4]
    assert assess(records)['checks']['resource_sample_coverage']['state'] == 'incomplete'


def test_resource_coverage_rejects_missing_or_invalid_process_data():
    records = fixture()
    records[0]['parameters']['monitoredPids'] = [42]
    records[-1]['report']['resources'] = dict(complete=True, sampleLimitReached=False, samples=[
        dict(monotonicSeconds=t, processes=[dict(pid=[], restarted=False)], disk={}, errors=[])
        for t in (0, 30)])
    assert assess(records)['checks']['resource_sample_coverage']['state'] == 'incomplete'


def test_policy_receipt_load_requires_dispatch_evidence():
    records = fixture()
    report = records[-1]['report']
    report.update(receiptTrafficModel='additive_after_policy_change_v1',
                  receiptHeartbeatsScheduled=80_000, receiptHeartbeatsMissing=0,
                  receiptDevicesAtPublishedVersion=79_200)
    report['counts']['receipt_heartbeat_dispatched'] = 80_000
    assert assess(records)['checks']['receipt_heartbeat_load']['state'] == 'met'
    report['receiptDevicesAtPublishedVersion'] = 1
    assert assess(records)['checks']['receipt_heartbeat_load']['state'] == 'incomplete'
    report['receiptDevicesAtPublishedVersion'] = 79_200
    report['receiptHeartbeatsMissing'] = 1
    report['counts']['receipt_heartbeat_dispatched'] = 79_999
    assert assess(records)['checks']['receipt_heartbeat_load']['state'] == 'failed'
    del report['receiptTrafficModel']
    assert assess(records)['checks']['receipt_heartbeat_load']['state'] == 'incomplete'


def test_batch_receipts_have_separate_target_and_observation_checks():
    records = fixture()
    records[0]['parameters']['rolloutTargets'] = 100
    report = records[-1]['report']
    report['rolloutCreationFailed'] = False
    report['simulatedRollout'] = dict(targetDevices=100, observedDevices=99, within120Seconds=99,
                                      observationSeconds=120, timingOrigin='batch_creation_request_started')
    assert assess(records)['checks']['simulated_rollout_120s']['state'] == 'met'
    report['simulatedRollout']['within120Seconds'] = 98
    assert assess(records)['checks']['simulated_rollout_120s']['state'] == 'failed'
    report['simulatedRollout']['observationSeconds'] = 119
    assert assess(records)['checks']['simulated_rollout_120s']['state'] == 'incomplete'
    report['simulatedRollout']['observationSeconds'] = 120
    report['simulatedRollout']['targetDevices'] = 99
    assert assess(records)['checks']['simulated_rollout_120s']['state'] == 'incomplete'
    report['simulatedRollout']['targetDevices'] = 100
    report['simulatedRollout']['serverStatusError'] = True
    assert assess(records)['checks']['simulated_rollout_120s']['state'] == 'incomplete'


def test_missing_counts_and_excluded_errors_cannot_pass():
    records = fixture()
    report = records[-1]['report']
    report['missingEvents'] = 1
    report['counts']['transport_error'] = 48_000
    report['latencyMilliseconds'] = {'0': 2}
    result = assess(records)
    assert result['checks']['generator_delivery']['state'] == 'incomplete'
    assert result['checks']['heartbeat_latency']['state'] == 'incomplete'
    assert result['checks']['heartbeat_error_rate']['state'] == 'failed'


def test_short_duration_and_incomplete_convergence_never_pass():
    records = fixture()
    records[0]['parameters']['seconds'] = 1
    records[-1]['report']['simulatedConvergence']['within120Seconds'] = 98_999
    result = assess(records)
    assert result['checks']['duration']['state'] == 'incomplete'
    assert result['checks']['simulated_policy_120s']['state'] == 'failed'
    records[-1]['report']['simulatedConvergence']['observationSeconds'] = 30
    assert assess(records)['checks']['simulated_policy_120s']['state'] == 'incomplete'


def test_inconsistent_inventory_and_short_report_are_incomplete():
    records = fixture()
    records[-1]['report']['devices'] = 10
    assert assess(records)['checks']['inventory_scale']['state'] == 'incomplete'
    assert assess(records[:1])['checks']['run']['state'] == 'incomplete'


def test_bucket_boundaries_are_conservative():
    records = fixture()
    report = records[-1]['report']
    report['latencyMilliseconds'] = {'200': 48_000_000}
    assert assess(records)['checks']['heartbeat_latency']['state'] == 'failed'
    report['adminLatencyMilliseconds'] = {'2000': 5}
    assert assess(records)['checks']['management_latency']['state'] == 'failed'


def test_missing_policy_polls_never_count_as_full_load():
    records = fixture()
    records[-1]['report']['dispatchedPolicyPolls'] = 9_599_999
    records[-1]['report']['missingPolicyPolls'] = 1
    records[-1]['report']['counts']['periodic_policy_success'] = 9_599_999
    assert assess(records)['checks']['policy_generator_delivery']['state'] == 'failed'


def test_policy_and_event_require_consistent_samples_and_error_rates():
    records = fixture()
    report = records[-1]['report']
    report['policyLatencyMilliseconds'] = {'70': 99}
    report['counts']['event_success'] = 9
    report['counts']['event_error'] = 1
    result = assess(records)
    assert result['checks']['policy_requests']['state'] == 'incomplete'
    assert result['checks']['event_requests']['state'] == 'failed'


def test_inconsistent_or_failed_publication_cannot_pass_convergence():
    records = fixture()
    records[-1]['report']['simulatedConvergence']['observedDevices'] = 10
    assert assess(records)['checks']['simulated_policy_120s']['state'] == 'incomplete'
    records = fixture()
    records[-1]['report']['simulatedConvergence'].pop('timingOrigin')
    assert assess(records)['checks']['simulated_policy_120s']['state'] == 'incomplete'
    records = fixture()
    records[-1]['report']['publicationFailed'] = True
    assert assess(records)['checks']['simulated_policy_120s']['state'] == 'incomplete'


def test_partition_cannot_be_claimed_as_complete_inventory():
    records = fixture()
    records[0]['parameters']['ordinalStart'] = 10
    records[-1]['report']['ordinalStart'] = 10
    assert assess(records)['checks']['inventory_scale']['state'] == 'incomplete'
    records[0]['parameters']['ordinalStart'] = 0
    assert assess(records)['checks']['inventory_scale']['state'] == 'incomplete'


def test_compact_evidence_requires_mode_match_and_observed_success():
    records = fixture()
    records[0]['parameters']['compactV2'] = True
    records[-1]['report']['compactV2'] = True
    assert assess(records)['checks']['compact_heartbeat']['state'] == 'incomplete'
    counts = records[-1]['report']['counts']
    counts.update({'v2-compact': 5, 'compact_success': 5})
    assert assess(records)['checks']['compact_heartbeat']['state'] == 'met'
    counts['compact_error'] = 1
    assert assess(records)['checks']['compact_heartbeat']['state'] == 'incomplete'
    records[-1]['report']['compactV2'] = 1
    assert assess(records)['checks']['inventory_scale']['state'] == 'incomplete'
