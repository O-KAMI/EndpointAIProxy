import importlib.util
import json
from pathlib import Path

import pytest

from config import ROOT
from controlserver.models import HeartbeatV2Request


def module():
    spec = importlib.util.spec_from_file_location('upgrade_snapshot', ROOT.parent / 'deployment/upgrade-snapshot.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_streaming_snapshot_detects_changes_without_exposing_contents(mysql_store):
    fixture = json.loads((ROOT / 'tests/fixtures/dotnet-v0.1.19.json').read_text(encoding='utf-8'))['heartbeat']
    mysql_store.heartbeat(HeartbeatV2Request.model_validate(fixture), 60, '127.0.0.1')
    tables = ['control_policy', 'device_heartbeats', 'device_policy_state']
    first = module().snapshot(mysql_store.cfg, tables)
    assert first == module().snapshot(mysql_store.cfg, list(reversed(tables)))
    assert first['device_heartbeats']['count'] == 1
    assert fixture['device']['hostname'] not in json.dumps(first)
    with mysql_store.transaction() as cur:
        cur.execute('UPDATE device_heartbeats SET hostname=%s', ('changed-fixture',))
    second = module().snapshot(mysql_store.cfg, tables)
    assert second['control_policy'] == first['control_policy']
    assert second['device_heartbeats']['sha256'] != first['device_heartbeats']['sha256']


@pytest.mark.parametrize('tables', [[], ['device_heartbeats', 'device_heartbeats'], ['bad;DROP']])
def test_snapshot_rejects_invalid_table_list(config, tables):
    with pytest.raises(ValueError):
        module().snapshot(config, tables)
