import json
import sys
import types
from uuid import uuid4

import pytest

from controlserver.recovery import advance_restored_policy_watermark
from controlserver.validation import ApiProblem


def test_recovery_watermark_advances_above_verified_and_database_versions(mysql_store):
    previous = mysql_store.policy()
    device = str(uuid4())
    newer_device = mysql_store.policy(device, schema_version=2)
    bound = newer_device['policyVersion'] + 100
    result = advance_restored_policy_watermark(mysql_store, bound, 'operator', 'audit-record-123')
    assert result == bound + 1
    current = mysql_store.policy()
    assert current['policyVersion'] == result and current['gatewayOrigin'] == previous['gatewayOrigin']
    assert mysql_store.policy(device, schema_version=2)['policyVersion'] == result
    audit = next(item for item in mysql_store.audits(None, 0, 100)
                 if item['action'] == 'RESTORED_POLICY_WATERMARK_ADVANCED')
    assert audit['actor'] == 'operator'
    assert json.loads(audit['summary'])['verifiedIssuedMax'] == bound
    assert json.loads(audit['summary'])['evidence'] == 'audit-record-123'


def test_recovery_watermark_uses_database_max_when_it_is_higher(mysql_store):
    device = str(uuid4())
    previous = mysql_store.policy(device, schema_version=2)['policyVersion']
    result = advance_restored_policy_watermark(mysql_store, 1, 'operator', 'synthetic-evidence')
    assert result > previous
    assert mysql_store.policy(device, schema_version=2)['policyVersion'] == result


@pytest.mark.parametrize('bound,actor,evidence', [
    (0, 'operator', 'evidence'), (2**63 - 2, 'operator', 'evidence'),
    (True, 'operator', 'evidence'), (1, '', 'evidence'), (1, 'operator', ''),
    (1, 'operator', 'line\nbreak'), (1, 'operator', 'x' * 257),
])
def test_recovery_watermark_rejects_invalid_evidence_before_mutation(mysql_store, bound, actor, evidence):
    before = mysql_store.policy()['policyVersion']
    with pytest.raises(ValueError):
        advance_restored_policy_watermark(mysql_store, bound, actor, evidence)
    assert mysql_store.policy()['policyVersion'] == before


def test_recovery_watermark_audit_failure_rolls_back(mysql_store, monkeypatch):
    before = mysql_store.policy()['policyVersion']
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic audit failure')
    monkeypatch.setattr(mysql_store, '_audit', fail)
    with pytest.raises(RuntimeError, match='synthetic audit failure'):
        advance_restored_policy_watermark(mysql_store, before + 10, 'operator', 'synthetic-evidence')
    assert mysql_store.policy()['policyVersion'] == before


def test_recovery_watermark_refuses_inconsistent_restored_policy(mysql_store):
    before = mysql_store.policy()['policyVersion']
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE control_policy SET policy_version=policy_version+1 WHERE singleton_id=1')
    with pytest.raises(RuntimeError, match='Restored policy version is inconsistent'):
        advance_restored_policy_watermark(mysql_store, before + 10, 'operator', 'synthetic-evidence')
    assert mysql_store.policy()['policyVersion'] == before


def test_recovery_watermark_refuses_active_policy_batch(mysql_store):
    from test_policy_rollout import devices, request
    from controlserver import policy_rollout
    ids = devices(mysql_store, 1)
    before = mysql_store.policy()['policyVersion']
    policy_rollout.create(mysql_store, request(mysql_store, ids), 'admin')
    with pytest.raises(ApiProblem, match='POLICY_ROLLOUT_ACTIVE'):
        advance_restored_policy_watermark(mysql_store, before + 10, 'operator', 'synthetic-evidence')
    assert mysql_store.policy()['policyVersion'] == before


def test_recovery_cli_rejects_source_database(monkeypatch):
    import manage
    import controlserver.database
    cfg = types.SimpleNamespace(APP_ENV='sit', MYSQL_HOST='127.0.0.1', MYSQL_PORT=13306,
                                MYSQL_DATABASE='SourceDB')
    cfg.validate = lambda: cfg
    monkeypatch.setattr(manage, 'Config', lambda *_: cfg)
    monkeypatch.setattr(controlserver.database, 'ControlStore', lambda _: object())
    monkeypatch.setattr(sys, 'argv', ['manage.py', 'advance-restored-watermark', '--env', 'sit',
        '--target-database', 'sourcedb', '--verified-issued-max', '12', '--actor', 'operator',
        '--evidence-reference', 'synthetic', '--service-stopped', '--confirm-restored-target'])
    with pytest.raises(ValueError, match='distinct restored target'):
        manage.main()


@pytest.mark.parametrize('missing', ['--service-stopped', '--confirm-restored-target'])
def test_recovery_cli_requires_both_offline_assertions(monkeypatch, missing):
    import manage
    arguments = ['manage.py', 'advance-restored-watermark', '--env', 'sit',
        '--target-database', 'restored', '--verified-issued-max', '12', '--actor', 'operator',
        '--evidence-reference', 'synthetic', '--service-stopped', '--confirm-restored-target']
    arguments.remove(missing)
    monkeypatch.setattr(sys, 'argv', arguments)
    monkeypatch.setattr(manage, 'Config', lambda *_: pytest.fail('unexpected configuration access'))
    with pytest.raises(SystemExit):
        manage.main()


def test_recovery_cli_uses_distinct_target_and_warns(monkeypatch, capsys):
    import manage
    import controlserver.database
    import controlserver.recovery
    cfg = types.SimpleNamespace(APP_ENV='sit', MYSQL_HOST='127.0.0.1', MYSQL_PORT=13306,
                                MYSQL_DATABASE='source')
    cfg.validate = lambda: cfg
    seen = []
    class Store:
        def __init__(self, value): self.cfg = value
        def check_schema(self): seen.append(('checked', self.cfg.MYSQL_DATABASE))
    monkeypatch.setattr(manage, 'Config', lambda *_: cfg)
    monkeypatch.setattr(controlserver.database, 'ControlStore', Store)
    def advance(store, bound, actor, evidence):
        seen.append((store.cfg.MYSQL_DATABASE, bound, actor, evidence))
        return 13
    monkeypatch.setattr(controlserver.recovery, 'advance_restored_policy_watermark', advance)
    monkeypatch.setattr(sys, 'argv', ['manage.py', 'advance-restored-watermark', '--env', 'sit',
        '--target-database', 'restored', '--verified-issued-max', '12', '--actor', 'operator',
        '--evidence-reference', 'synthetic', '--service-stopped', '--confirm-restored-target'])
    manage.main()
    assert seen == [('checked', 'restored'), ('restored', 12, 'operator', 'synthetic')]
    assert cfg.MYSQL_DATABASE == 'source'
    assert 'does not reconcile credentials, commands, replay state' in capsys.readouterr().out
