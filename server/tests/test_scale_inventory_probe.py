import sys

import pytest

from tools import scale_inventory_probe


@pytest.mark.parametrize('configured', [False, True])
def test_probe_uses_configured_test_account_only(configured, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['scale_inventory_probe', '--isolated-mysql'])
    if configured:
        monkeypatch.setenv('ENDPOINTAI_TEST_MYSQL_USER', 'isolated-user')
        monkeypatch.setenv('ENDPOINTAI_TEST_MYSQL_PASSWORD', 'synthetic-password')
    else:
        monkeypatch.delenv('ENDPOINTAI_TEST_MYSQL_USER', raising=False)
        monkeypatch.delenv('ENDPOINTAI_TEST_MYSQL_PASSWORD', raising=False)

    class StopBeforeConnecting(Exception):
        pass

    def connect(**kwargs):
        assert kwargs['host'] == '127.0.0.1'
        assert kwargs['user'] == ('isolated-user' if configured else 'root')
        assert kwargs['password'] == ('synthetic-password' if configured else '')
        raise StopBeforeConnecting

    monkeypatch.setattr(scale_inventory_probe.pymysql, 'connect', connect)
    with pytest.raises(StopBeforeConnecting):
        scale_inventory_probe.main()


def test_probe_requires_isolation_confirmation_before_connecting(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['scale_inventory_probe'])
    monkeypatch.setattr(scale_inventory_probe.pymysql, 'connect', lambda **kwargs: pytest.fail('unexpected connection'))
    with pytest.raises(SystemExit):
        scale_inventory_probe.main()


@pytest.mark.parametrize('extra', [
    ['--policy-heartbeat-workers', '1'],
    ['--policy-heartbeat-rps', '10'],
    ['--policy-heartbeat-workers', '33', '--policy-heartbeat-rps', '10'],
    ['--policy-heartbeat-workers', '1', '--policy-heartbeat-rps', '2001'],
    ['--policy-heartbeat-workers', '1', '--policy-heartbeat-rps', '10', '--policy-rollout-targets', '25'],
    ['--policy-heartbeat-workers', '1', '--policy-heartbeat-rps', '10', '--policy-respect-rate'],
])
def test_policy_row_load_rejects_unbounded_or_incomplete_options(extra, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['scale_inventory_probe', '--isolated-mysql', *extra])
    monkeypatch.setattr(scale_inventory_probe.pymysql, 'connect', lambda **kwargs: pytest.fail('unexpected connection'))
    with pytest.raises(SystemExit):
        scale_inventory_probe.main()
