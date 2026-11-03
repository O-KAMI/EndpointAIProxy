import json
import pytest
from tools.load_publication import identity, read_event, write_event

RUN = 'b63ddd38-45d2-4da4-9032-d5e01a650d6f'

def test_event_is_exclusive_matches_identity_and_maps_clocks(tmp_path):
    path = tmp_path / 'event.json'
    expected = identity(RUN, 'a' * 64, '2026-11-01T12:00:00Z')
    assert read_event(path, expected) is None
    epoch = 1793534400
    event = write_event(path, expected, {'version': 7, 'started': 98, 'completed': 99},
                        wall=lambda: epoch + 1000, monotonic=lambda: 100)
    assert event['startedUnixSeconds'] == epoch + 998 and event['completedUnixSeconds'] == epoch + 999
    observed = read_event(path, expected, wall=lambda: epoch + 1001, monotonic=lambda: 201)
    assert observed['started'] == 198 and observed['completed'] == 199
    assert observed['version'] == 7 and observed['evidence'] == event
    with pytest.raises(FileExistsError):
        write_event(path, expected, {'version': 7, 'started': 98, 'completed': 99}, wall=lambda: epoch + 1000, monotonic=lambda: 100)
    wrong = identity(RUN, 'b' * 64, '2026-11-01T12:00:00Z')
    with pytest.raises(ValueError, match='does not match'):
        read_event(path, wrong)


def test_incomplete_event_waits_and_oversized_or_invalid_event_fails(tmp_path):
    path = tmp_path / 'event.json'
    expected = identity(RUN, 'a' * 64, '2026-11-01T12:00:00Z')
    path.write_text('{', encoding='utf-8')
    assert read_event(path, expected) is None
    path.write_bytes(b'x' * 4097)
    with pytest.raises(ValueError, match='size'):
        read_event(path, expected)
    path.write_text(json.dumps({**expected, 'policyVersion': 0, 'startedUnixSeconds': 2, 'completedUnixSeconds': 3}), encoding='utf-8')
    with pytest.raises(ValueError, match='timing or version'):
        read_event(path, expected)


def test_coordinated_cli_shares_publication_without_credentials(tmp_path, monkeypatch):
    from datetime import datetime, timezone, timedelta
    import time
    from tools import load_test
    scheduled = (datetime.now(timezone.utc) + timedelta(seconds=30)).replace(microsecond=0)
    target = scheduled.timestamp()
    start_text = scheduled.strftime('%Y-%m-%dT%H:%M:%SZ')
    artifact = tmp_path / 'candidate'
    artifact.write_text('fixture', encoding='utf-8')
    event = tmp_path / 'event.json'
    monkeypatch.setattr(load_test, 'seed_devices', lambda origin, devices, legacy, **kwargs: ['secret-test-token'] * devices)
    monkeypatch.setattr(load_test.time, 'time', lambda: target - 60)
    monkeypatch.setattr(load_test, 'wait_for_start', lambda scheduled: scheduled)
    def run(origin, tokens, legacy, seconds, **kwargs):
        now = time.monotonic()
        if kwargs['publication_sink']:
            proof = kwargs['publication_sink']({'version': 2, 'started': now, 'completed': now})
        else:
            proof = kwargs['publication_observer']()['evidence']
        return {'elapsedSeconds': seconds, 'latencyMilliseconds': {}, 'policyLatencyMilliseconds': {},
                'eventLatencyMilliseconds': {}, 'adminLatencyMilliseconds': {}, 'publicationEvidence': proof}
    monkeypatch.setattr(load_test, 'run_heartbeats', run)
    common = ['--confirm-isolated', '--origin', 'http://127.0.0.1:18080', '--devices', '2', '--online', '2',
              '--seconds', '3', '--start-at', start_text, '--coordination-id', RUN,
              '--server-artifact', str(artifact)]
    leader = tmp_path / 'leader.jsonl'
    follower = tmp_path / 'follower.jsonl'
    assert load_test.main(common + ['--publish-after', '1', '--publish-event', str(event), '--output', str(leader)]) == 0
    assert load_test.main(common + ['--ordinal-start', '2', '--follow-event', str(event), '--output', str(follower)]) == 0
    l = [json.loads(x) for x in leader.read_text(encoding='utf-8').splitlines()]
    f = [json.loads(x) for x in follower.read_text(encoding='utf-8').splitlines()]
    assert l[0]['parameters']['publicationRole'] == 'publisher'
    assert f[0]['parameters']['publicationRole'] == 'follower'
    assert l[-1]['report']['publicationEvidence'] == f[-1]['report']['publicationEvidence']
    assert 'secret-test-token' not in leader.read_text(encoding='utf-8') + follower.read_text(encoding='utf-8') + event.read_text(encoding='utf-8')
