import base64
import os
from uuid import uuid4
import pytest
from config import Config
from controlserver.database import ControlStore


@pytest.fixture
def config(tmp_path):
    c = Config(env="sit", conf_dir=tmp_path / "conf")
    c.CLIENT_TOKEN = "test-enrollment-token"
    c.ADMIN_TOKEN = "test-administrator-token"
    c.HMAC_TEXT = base64.b64encode(bytes(range(32))).decode()
    c.TRANSPORT_KEY_TEXT = base64.b64encode(bytes(range(32))).decode()
    c.MYSQL_HOST = "127.0.0.1"
    c.MYSQL_PORT = int(os.environ.get("ENDPOINTAI_TEST_MYSQL_PORT", "13306"))
    c.MYSQL_USER = "root"
    c.MYSQL_PASSWORD = ""
    c.MYSQL_DATABASE = "eai_test_" + uuid4().hex
    c.LOG_DIR = tmp_path / "logs"
    c.DATA_ROOT = tmp_path / "data"
    c.BACKUP_DIR = c.DATA_ROOT / "backups"
    c.REQUIRE_HTTPS = False
    c.TRUST_PROXY = False
    return c.validate()


@pytest.fixture(autouse=True)
def legacy_business_dispatch(request, monkeypatch):
    """Old handler tests exercise the authenticated internal boundary, not HTTP ingress.

    New test_transport.py and the real HTTP interop tests never receive this marker.
    """
    if request.path.name not in ("test_mysql.py", "test_maintenance.py", "test_contracts.py", "test_http_errors.py"):
        return
    from flask.testing import FlaskClient
    from controlserver.transport import INTERNAL
    original = FlaskClient.__init__
    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.environ_base["endpointai.transport"] = INTERNAL
    monkeypatch.setattr(FlaskClient, "__init__", initialize)


@pytest.fixture
def mysql_store(config):
    if os.environ.get("ENDPOINTAI_TEST_MYSQL") != "1":
        pytest.skip("Set ENDPOINTAI_TEST_MYSQL=1 for isolated local MySQL integration")
    import pymysql
    connection = pymysql.connect(host=config.MYSQL_HOST, port=config.MYSQL_PORT,
        user=config.MYSQL_USER, password=config.MYSQL_PASSWORD, autocommit=True)
    with connection.cursor() as cur:
        cur.execute(f"CREATE DATABASE `{config.MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
    store = ControlStore(config)
    try:
        store.initialize_empty()
        store.check_schema()
        yield store
    finally:
        with connection.cursor() as cur:
            cur.execute(f"DROP DATABASE `{config.MYSQL_DATABASE}`")
        connection.close()
