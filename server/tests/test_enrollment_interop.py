"""Synthetic loopback cross-language test; never uses production state."""
import os
import subprocess
from pathlib import Path
from threading import Thread
import pytest
from werkzeug.serving import make_server
from app import create_app


def test_go_app_retries_lost_first_enrollment_against_python_mysql(mysql_store):
    go = os.environ.get("ENDPOINTAI_TEST_GO")
    if not go:
        pytest.skip("Set ENDPOINTAI_TEST_GO to a local Go toolchain")
    app = create_app(mysql_store.cfg, mysql_store)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    repo = Path(__file__).resolve().parents[2]
    env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", CGO_ENABLED="0",
               ENDPOINTAI_SYNTHETIC_INTEROP_ORIGIN=f"http://127.0.0.1:{server.server_port}")
    try:
        result = subprocess.run([go, "test", "-mod=vendor", "./internal/app", "-run",
                                 "^TestInitialEnrollmentLostResponsePythonInterop$", "-count=1"],
                                cwd=repo / "go-client", env=env, capture_output=True,
                                encoding="utf-8", timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        with mysql_store.transaction() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM device_credentials WHERE revoked=0")
            assert cur.fetchone()["n"] == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
