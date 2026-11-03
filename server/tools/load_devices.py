"""Synthetic device fixtures for the isolated control-plane load harness."""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from uuid import NAMESPACE_URL, uuid4, uuid5
import json
from threading import Event, Lock

from tools.load_transport import FIXTURE_ENROLLMENT_TOKEN, SyntheticTransport


def synthetic_id(kind, ordinal):
    if kind not in ('device', 'boot', 'agent', 'asset') or not 0 <= ordinal < 300_000:
        raise ValueError('Invalid synthetic identity')
    return str(uuid5(NAMESPACE_URL, f'endpointai-isolated-load/{kind}/{ordinal}'))


def enrollment(ordinal):
    return dict(schemaVersion=2, deviceId=synthetic_id('device', ordinal),
                hostname=f'load-fixture-{ordinal:06d}', serviceVersion='synthetic-load')


def event_batch(ordinal):
    return dict(schemaVersion=1, batchId=str(uuid4()), deviceId=synthetic_id('device', ordinal),
                events=[dict(eventId=str(uuid4()), occurredAtUtc=datetime.now(timezone.utc).isoformat(),
                             severity='info', type='syntheticLoad', code='SYNTHETIC',
                             summary='Synthetic capacity test event')])


def heartbeat(ordinal, version, light=False, compact=False):
    if version not in (1, 2) or (light and version != 2) or (compact and not light):
        raise ValueError('Invalid heartbeat mode')
    at = datetime.now(timezone.utc).isoformat()
    asset_id = synthetic_id('asset', ordinal)
    result = dict(
        schemaVersion=version, heartbeatId=str(uuid4()), observedAtUtc=at,
        device=dict(deviceId=synthetic_id('device', ordinal), hostname=f'load-fixture-{ordinal:06d}',
                    osVersion='synthetic', serviceVersion='synthetic-load', bootId=synthetic_id('boot', ordinal)),
        policy=dict(lastReceivedVersion=1, appliedVersion=1, applyStatus='applied'),
        proxy=dict(state='listening', listenEndpoint='127.0.0.1:18080', activeRouteCount=1, auditState='healthy'),
        users=[dict(sid='synthetic-user', accountName=f'fixture-{ordinal:06d}')],
        agents=[dict(instanceId=synthetic_id('agent', ordinal), userSid='synthetic-user',
                     agentType='claudeCli', displayName='synthetic', version='0', installMethod='npm',
                     discoveryConfidence=100, installed=True, running=True, routeStatus='attached', lastSeenAtUtc=at)],
    )
    if version == 2:
        result.update(
            runtime=dict(serviceStartedAtUtc=at, uptimeSeconds=1, operationState='enabled',
                         proxyListenerAvailable=True, supportedPolicySchemaVersion=2,
                         lastReconcileResult='completed'),
            endpoints=[] if light else [dict(assetId=asset_id, userSid='synthetic-user', agentFamily='claude',
                configurationSource='direct', isCurrent=True, configuredModel='synthetic-model',
                wireApi='anthropicMessages', originalTargetBaseUrl='https://example.invalid',
                allowlistBypassed=False, routeStatus='attached', observedAtUtc=at)],
            activity=[dict(assetId=asset_id, state='succeeded', lastRequestAtUtc=at, lastSuccessAtUtc=at,
                           lastHttpStatusCode=200, lastOutcome='ok', requestCountSinceBoot=1,
                           successCountSinceBoot=1, failureCountSinceBoot=0)],
            statelessPolicyVersions=True,
        )
        if light:
            result['inventoryUnchanged'] = True
        if compact:
            result['compactInventory'] = True
            result['users'], result['agents'] = [], []
    return result


def legacy_v2_heartbeat(ordinal):
    """An older v2 client: full inventory and no stateless-version capability."""
    result = heartbeat(ordinal, 2)
    result.pop('statelessPolicyVersions')
    result['runtime']['supportedPolicySchemaVersion'] = 1
    return result


def register_v2(transport, ordinal, legacy_full=False, compact=False):
    """Enroll one fixture and establish a full inventory before lightweight use."""
    expected = enrollment(ordinal)
    response = transport.request('POST', '/api/v2/enroll', FIXTURE_ENROLLMENT_TOKEN, expected)
    if response['status'] != 200:
        raise RuntimeError('Synthetic enrollment failed')
    data = json.loads(response['body'])
    token = data.get('deviceToken')
    if data.get('deviceId') != expected['deviceId'] or not isinstance(token, str) or not 16 <= len(token) <= 512:
        raise RuntimeError('Invalid synthetic enrollment response')
    initial = legacy_v2_heartbeat(ordinal) if legacy_full else heartbeat(ordinal, 2)
    response = transport.request('POST', '/api/v2/heartbeat', token, initial)
    if response['status'] != 200:
        raise RuntimeError('Synthetic initial heartbeat failed')
    data = json.loads(response['body'])
    if not legacy_full and (data.get('lightweightInventory') is not True or data.get('statelessPolicyVersions') is not True):
        raise RuntimeError('Server did not advertise synthetic fixture capabilities')
    if compact and not legacy_full and data.get('compactInventory') is not True:
        raise RuntimeError('Server did not advertise compact synthetic fixture capability')
    return token


def seed_devices(origin, count, legacy_count, workers=8, transport_factory=SyntheticTransport,
                 progress_callback=None, progress_every=1000, full_v2_count=0, ordinal_start=0, compact_v2=False):
    """Create synthetic v1 and v2 baselines with a bounded number of workers.

    A partially seeded database must be discarded by the isolated test operator;
    re-enrollment is not retried. Tokens remain in memory and must not be logged.
    """
    if (type(compact_v2) is not bool or type(ordinal_start) is not int or not 0 <= ordinal_start < 150_000
            or not 1 <= count <= 150_000 - ordinal_start or not 0 <= legacy_count <= count or not 0 <= full_v2_count <= count - legacy_count
            or not 1 <= workers <= 128
            or not 1 <= progress_every <= 150_000):
        raise ValueError('Invalid synthetic inventory parameters')
    workers = min(workers, count)
    tokens = [None] * count
    stopped = Event()
    progress_lock = Lock()
    completed = 0

    def seed_partition(partition):
        nonlocal completed
        client = transport_factory(origin)
        try:
            client.verify()
            for ordinal in range(partition, count, workers):
                if stopped.is_set():
                    return
                if ordinal < legacy_count:
                    result = client.request('POST', '/api/v1/heartbeat', FIXTURE_ENROLLMENT_TOKEN,
                                            heartbeat(ordinal_start + ordinal, 1))
                    if result['status'] != 200:
                        raise RuntimeError('Synthetic legacy baseline failed')
                    tokens[ordinal] = FIXTURE_ENROLLMENT_TOKEN
                else:
                    tokens[ordinal] = register_v2(client, ordinal_start + ordinal, legacy_full=ordinal < legacy_count + full_v2_count, compact=compact_v2)
                if progress_callback is not None:
                    with progress_lock:
                        completed += 1
                        if completed % progress_every == 0 or completed == count:
                            progress_callback(dict(completedDevices=completed, totalDevices=count))
        except Exception:
            stopped.set()
            raise
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in [pool.submit(seed_partition, i) for i in range(workers)]:
            future.result()
    return tokens
