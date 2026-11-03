import copy
import pytest
from tools.load_merge import merge
from tools.load_publication import identity

RUN = 'b63ddd38-45d2-4da4-9032-d5e01a650d6f'
START = '2026-11-01T12:00:00Z'
EVENT = {**identity(RUN, 'a' * 64, START), 'policyVersion': 2,
         'startedUnixSeconds': 1793534401.0, 'completedUnixSeconds': 1793534401.1}


def shard(offset, role, skew=0):
    params = dict(ordinalStart=offset, devices=75000, online=50000, legacy=5000, fullV2=5000,
                  seconds=28800, heartbeatSeconds=60, startupSpreadSeconds=None,
                  coordinationId=RUN, scheduledStartUtc=START, publicationRole=role,
                  publishAfter=1 if role == 'publisher' else None)
    report = dict(ordinalStart=offset, devices=50000, legacyDevices=5000, fullV2Devices=5000,
                  requestedSeconds=28800, elapsedSeconds=28800, publicationFailed=False,
                  publicationEvidence=EVENT, latencyMilliseconds={'10': 21_600_000, '500': 2_400_000},
                  intervalSeconds=60, startupSpreadSeconds=None, receiptHeartbeatsScheduled=0,
                  counts=dict(business_success=24_000_000, business_error=0, transport_error=0),
                  expectedEvents=24_000_000, dispatchedEvents=24_000_000, missingEvents=0,
                  simulatedConvergence=dict(policyVersion=2, targetDevices=50000, observedDevices=49500,
                      missingDevices=500, within120Seconds=49500,
                      timingOrigin=('publication_request_started' if role == 'publisher' else
                                    'publication_request_started_external_clock_unverified')))
    started = '2026-11-01T12:00:00+00:00' if not skew else '2026-11-01T12:00:01+00:00'
    return [dict(status='running', candidateArtifactSha256='a' * 64, parameters=params),
            dict(status='ready', scheduledStartUtc=START),
            dict(status='finished', duration8hCompleted=True, report=report,
                 loadStartedUtc=started, startSkewSeconds=skew)]


def test_merge_recomputes_histogram_and_never_certifies_time_or_capacity():
    result = merge([shard(0, 'publisher'), shard(75000, 'follower', 1)])
    assert result['overall'] == 'incomplete'
    assert result['devices'] == 150000 and result['online'] == 100000
    assert result['inventoryScaleConfiguration'] == 'meets_target' and result['startSpreadSeconds'] == 1
    assert result['heartbeatP95BucketMs'] == 500 and result['generatorDelivery'] == 'met'
    assert result['simulatedPolicy']['within120Seconds'] == 99000
    assert result['simulatedPolicy']['state'] == 'incomplete'


def test_merge_does_not_accept_underscheduled_shards():
    shards = [shard(0, 'publisher'), shard(75000, 'follower')]
    for records in shards:
        report = records[-1]['report']
        report.update(expectedEvents=100, dispatchedEvents=100, latencyMilliseconds={'10': 100})
        report['counts']['business_success'] = 100
    assert merge(shards)['generatorDelivery'] == 'incomplete'


def test_merge_rejects_overlap_different_publication_and_inconsistent_data():
    left, right = shard(0, 'publisher'), shard(75000, 'follower')
    wrong = copy.deepcopy(right); wrong[0]['parameters']['ordinalStart'] = wrong[-1]['report']['ordinalStart'] = 74999
    with pytest.raises(ValueError, match='overlap'):
        merge([left, wrong])
    wrong = copy.deepcopy(right); wrong[-1]['report']['publicationEvidence']['policyVersion'] = 3
    with pytest.raises(ValueError, match='differs'):
        merge([left, wrong])
    wrong = copy.deepcopy(right); wrong[-1]['startSkewSeconds'] = 10
    with pytest.raises(ValueError, match='start evidence'):
        merge([left, wrong])
    wrong = copy.deepcopy(right); wrong[-1]['report']['counts']['business_success'] = 99
    with pytest.raises(ValueError, match='Histogram'):
        merge([left, wrong])
    wrong = copy.deepcopy(right); wrong[-1]['report']['publicationEvidence'] = None
    with pytest.raises(ValueError, match='publication event'):
        merge([left, wrong])


def test_merge_rejects_compact_mode_mismatch():
    left, right = shard(0, 'publisher'), shard(75000, 'follower')
    left[0]['parameters']['compactV2'] = True
    with pytest.raises(ValueError, match='parameters'):
        merge([left, right])
    left[-1]['report']['compactV2'] = 1
    with pytest.raises(ValueError, match='parameters'):
        merge([left, right])


def test_merge_preserves_compact_workload_counts():
    left, right = shard(0, 'publisher'), shard(75000, 'follower')
    left[0]['parameters']['compactV2'] = left[-1]['report']['compactV2'] = True
    left[-1]['report']['counts'].update({'v2-compact': 8, 'compact_success': 7, 'compact_error': 1, 'business_success': 23_999_999, 'business_error': 1})
    result = merge([left, right])
    assert result['configuredCompactOnline'] == 40000
    assert result['compactHeartbeatSuccess'] == 7 and result['compactHeartbeatError'] == 1
    left[-1]['report']['counts']['compact_success'] = 8
    with pytest.raises(ValueError, match='compact heartbeat'):
        merge([left, right])
