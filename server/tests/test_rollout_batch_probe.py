import pytest
from tools import rollout_batch_probe


@pytest.mark.parametrize('args', [[], ['--devices','1'], ['--confirm-isolated','--devices','150001'],
    ['--confirm-isolated','--rate','5001'], ['--confirm-isolated','--port','0'],
    ['--confirm-isolated','--timeout','601'], ['--confirm-isolated','--heartbeat-workers','1'],
    ['--confirm-isolated','--heartbeat-rps','1'],
    ['--confirm-isolated','--heartbeat-workers','33','--heartbeat-rps','1'],
    ['--confirm-isolated','--heartbeat-workers','1','--heartbeat-rps','2001']])
def test_probe_rejects_unconfirmed_or_unbounded_work_before_connect(args, monkeypatch):
    monkeypatch.setattr(rollout_batch_probe.pymysql, 'connect', lambda **kwargs: pytest.fail('unexpected connection'))
    with pytest.raises(SystemExit):
        rollout_batch_probe.main(args)
