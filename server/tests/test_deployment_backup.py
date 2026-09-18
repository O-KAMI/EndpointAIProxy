import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4
import pytest


def test_deployment_snapshot_roundtrip(mysql_store,tmp_path):
    source=Path(__file__).resolve().parents[2]/'deployment/deploy.py'
    if not source.exists(): pytest.skip('Deployment coordinator is distributed in the separate deployment bundle')
    spec=importlib.util.spec_from_file_location('deploy_backup_test',source)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    text="中文'\\\nline two; / UTF8 🚚"
    blob=bytes(range(256))*32
    with mysql_store.transaction() as cur:
        cur.execute('CREATE TABLE devices(id INT PRIMARY KEY, payload LONGBLOB, content TEXT, created DATETIME(6))')
        cur.execute('INSERT INTO devices VALUES (1,%s,%s,%s)',(blob,text,'2026-09-14 12:34:56.123456'))
    archive=module.backup_database(mysql_store,tmp_path)
    meta=json.loads((tmp_path/'database-backup.json').read_text())
    assert meta['sha256']==hashlib.sha256(archive.read_bytes()).hexdigest()
    from controlserver.database import ControlStore
    from controlserver.backup import mysql_credentials
    target=copy.copy(mysql_store.cfg)
    target.MYSQL_DATABASE='eai_test_'+uuid4().hex
    with mysql_store.transaction() as cur:
        cur.execute(f'CREATE DATABASE `{target.MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    try:
        binary=Path(os.environ['ENDPOINTAI_TEST_MYSQL_BIN'])/'mysql'
        with mysql_credentials(target) as defaults:
            run=subprocess.run([str(binary),f'--defaults-extra-file={defaults}',target.MYSQL_DATABASE],
                input=gzip.decompress(archive.read_bytes()),capture_output=True)
            assert run.returncode==0,run.stderr
        recovered=ControlStore(target)
        recovered.check_schema()
        assert recovered.policy()==mysql_store.policy()
        with recovered.transaction() as cur:
            cur.execute('SELECT * FROM devices')
            row=cur.fetchone()
            assert row['payload']==blob and row['content']==text and row['created'].microsecond==123456
    finally:
        with mysql_store.transaction() as cur:
            cur.execute(f'DROP DATABASE `{target.MYSQL_DATABASE}`')
