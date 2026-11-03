import sys
import types


def test_restore_cli_does_not_present_schema_check_as_service_readiness(monkeypatch, capsys):
    import manage
    import controlserver.database

    cfg = types.SimpleNamespace(APP_ENV='sit', MYSQL_HOST='127.0.0.1', MYSQL_PORT=13306,
                                MYSQL_DATABASE='synthetic_source')
    cfg.validate = lambda: cfg
    monkeypatch.setattr(manage, 'Config', lambda *_: cfg)
    monkeypatch.setattr(controlserver.database, 'ControlStore', lambda _: object())
    fake_backup = types.ModuleType('controlserver.backup')
    fake_backup.restore_backup = lambda *_: {'policyVersion': 12}
    monkeypatch.setitem(sys.modules, 'controlserver.backup', fake_backup)
    monkeypatch.setattr(sys, 'argv', ['manage.py', 'restore', '--env', 'sit', '--archive', 'synthetic',
                                     '--target-database', 'synthetic_restore', '--service-stopped'])
    manage.main()
    output = capsys.readouterr().out
    assert 'policyVersion=12' in output
    assert 'do not prove recovery is safe to serve' in output
    assert 'policy versions, credentials, commands and replay state' in output
