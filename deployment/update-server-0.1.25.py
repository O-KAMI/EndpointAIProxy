#!/usr/bin/env python3
"""Schema 2 -> 3 update, with a stopped-service backup and a guarded additive rollback."""
import argparse
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location("update_024_base", Path(__file__).with_name("update-server-0.1.24.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.NEW = Path("/app/EndpointAIDLP-Server-0.1.25")
base.CANDIDATES = (Path("/app/EndpointAIDLP-Server-0.1.24"),)
base.state_path = lambda: base.NEW.parent / ".EndpointAIDLP-Server-0.1.25-upgrade.json"


def environment(directory):
    values = {k:v for k,v in os.environ.items() if not k.startswith(("SF_CONTROL_", "EAI_MYSQL_"))
              and k not in ("APP_ENV", "APP_CONFIG", "PYTHONPATH")}
    values.update(base.read_env(directory))
    return values


def database(directory, operation, env=None):
    code = ("import sys,json,hashlib; from pathlib import Path; sys.path.insert(0,'.'); "
            "from config import Config; from controlserver.database import ControlStore; "
            "cfg=Config().validate(); store=ControlStore(cfg)\n" + operation)
    return json.loads(base.run([str(directory / ".venv/bin/python"), "-c", code],
        cwd=directory, env=env or environment(directory)).decode())


def snapshot(directory, env=None):
    return database(directory, """from controlserver.database import schema_tables
with store.transaction() as cur:
    counts={}; contents={}
    for table in sorted(schema_tables()-{'schema_migrations','device_policy_state'}):
        cur.execute('SELECT * FROM `'+table+'`')
        hashes=sorted(hashlib.sha256(json.dumps(row,sort_keys=True,default=lambda value:value.hex() if isinstance(value,bytes) else str(value)).encode()).hexdigest() for row in cur.fetchall())
        counts[table]=len(hashes); contents[table]=hashlib.sha256(''.join(hashes).encode()).hexdigest()
print(json.dumps(dict(counts=counts,contentsSha256=contents,policySha256=hashlib.sha256(json.dumps(store.policy(),sort_keys=True).encode()).hexdigest())))
""", env)


def prepare(archive, old):
    base.require(not base.NEW.exists(), "新版目录已存在；保留现场，不覆盖。")
    base.require(base.processes(old), "旧服务未运行。")
    base.require_unmanaged(old)
    base.health(old)
    database(old, """store.check_schema()
with store.transaction() as cur:
    cur.execute("SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='device_policy_state'")
    assert cur.fetchone()['count']==0, 'Unexpected existing device policy table'
print(json.dumps({'schema':2}))
""")
    base.NEW.mkdir(mode=0o700)
    base.extract(archive, base.NEW)
    # Keep the new canonical SQL. Only deployment configuration is inherited.
    for path in (old / "conf").iterdir():
        base.require(path.is_file() and not path.is_symlink(), "旧配置含链接或目录。")
        if path.name != "endpoint_ai_proxy.sql":
            shutil.copy2(path, base.NEW / "conf" / path.name)
            (base.NEW / "conf" / path.name).chmod(0o600)
    values = base.read_env(old)
    values["APP_CONFIG"] = str(base.NEW / "conf")
    values["SF_CONTROL_LOG_DIR"] = str(base.NEW / "logs")
    # Retain the existing data root and credentials, including backup metadata.
    path = base.NEW / "launch-env.json"
    path.write_text(json.dumps(values)); path.chmod(0o600)
    executable = base.run([str(old / ".venv/bin/python"), "-c",
        "import sys; assert sys.version_info[:3]==(3,13,15); print(sys._base_executable)"]).decode().strip()
    base.run([executable, "-m", "venv", str(base.NEW / ".venv")])
    import platform
    architecture = {"x86_64":"x86_64", "aarch64":"aarch64"}.get(platform.machine())
    base.require(architecture is not None, "不支持当前架构。")
    py = str(base.NEW / ".venv/bin/python")
    base.run([py, "-m", "pip", "install", "--no-index", "--find-links",
        str(base.NEW / "deployment/wheelhouse" / architecture), "-r", str(base.NEW / "requirements.txt")])
    base.run([py, "-m", "pip", "check"])
    base.run([py, "-c", "from config import Config; Config().validate(); import app"],
        cwd=base.NEW, env=environment(base.NEW))


def stopped_backup(old, mysql_bin):
    base.require(not base.processes(old) and not base.processes(base.NEW), "备份前必须停止全部实例。")
    destination = old / "upgrade-backups" / datetime.now(timezone.utc).strftime("0.1.25-%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(parents=True, mode=0o700)
    destination.parent.chmod(0o700)
    shutil.copy2(old / "launch-env.json", destination / "launch-env.json")
    (destination / "launch-env.json").chmod(0o600)
    shutil.copytree(old / "conf", destination / "conf")
    for path in (destination / "conf").rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    result = database(old, """from controlserver.backup import run_backup
cfg.DATA_ROOT=Path(%r)/'metadata'; cfg.DATA_ROOT.mkdir(mode=0o700)
cfg.BACKUP_DIR=Path(%r)/'database'
print(json.dumps({'archive':str(run_backup(cfg,dump_binary=%r))}))
""" % (str(destination), str(destination), str(mysql_bin / "mysqldump")))
    return destination, Path(result["archive"])


def verify_backup(old, destination, archive, mysql_bin, before):
    """Restore real backup only into a local, password-protected disposable server."""
    verify = destination / "restore-verification"
    verify.mkdir(mode=0o700)
    password = secrets.token_urlsafe(32)
    data = verify / "data"
    mysqld = str(mysql_bin / "mysqld")
    args = [mysqld, "--no-defaults", "--basedir=" + str(mysql_bin.parent), "--datadir=" + str(data)]
    base.run(args + ["--initialize-insecure"])
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    init = verify / "init.sql"
    with init.open("x") as stream:
        stream.write("CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '" + password + "';\n")
        stream.write("ALTER USER 'root'@'127.0.0.1' IDENTIFIED BY '" + password + "';\n")
        stream.write("ALTER USER 'root'@'localhost' IDENTIFIED BY '" + password + "';\n")
        stream.write("GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1';\n")
    init.chmod(0o600)
    socket_directory = tempfile.TemporaryDirectory(prefix="eai-restore-", dir=Path.home())
    log = (verify / "mysql.private.log").open("wb")
    process = subprocess.Popen(args + ["--bind-address=127.0.0.1", "--port=" + str(port), "--mysqlx=OFF",
        "--skip-name-resolve", "--skip-log-bin", "--socket=" + str(Path(socket_directory.name) / "mysql.sock"), "--init-file=" + str(init)],
        stdout=log, stderr=log)
    try:
        import pymysql
        deadline = time.monotonic() + 45
        while True:
            base.require(process.poll() is None, "隔离恢复实例启动失败。")
            try:
                connection = pymysql.connect(host="127.0.0.1",port=port,user="root",password=password)
                with connection.cursor() as cur:
                    cur.execute("CREATE DATABASE endpointai_restore_verify CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
                connection.close()
                break
            except pymysql.err.Error:
                base.require(time.monotonic() < deadline, "隔离恢复实例超时。")
                time.sleep(.25)
        init.unlink()
        env = environment(old)
        env.update(EAI_MYSQL_HOST="127.0.0.1", EAI_MYSQL_PORT=str(port), EAI_MYSQL_USERNAME="root",
                   EAI_MYSQL_PASSWORD=password, EAI_MYSQL_DATABASE="endpointai_restore_verify")
        database(old, """from controlserver.backup import restore_backup
restore_backup(cfg,Path(%r),'endpointai_restore_verify',mysql_binary=%r)
print(json.dumps({'restored':True}))
""" % (str(archive), str(mysql_bin / "mysql")), env)
        base.require(snapshot(old, env) == before, "恢复后的策略或记录数量不一致。")
        env["APP_CONFIG"] = str(base.NEW / "conf")
        database(base.NEW, "store.migrate(); print(json.dumps({'migrated':True}))", env)
        base.require(snapshot(base.NEW, env) == before, "恢复副本迁移后策略或记录数量变化。")
        (verify / "report.json").write_text(json.dumps(dict(status="passed", restoredSchema2=True,
            cloneMigratedToSchema3=True, policyAndCountsPreserved=True, productionDatabaseModified=False)))
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=10)
        log.close()
        init.unlink(missing_ok=True)
        socket_directory.cleanup()


def downgrade_unused_schema():
    base.require(not base.processes(base.NEW), "回退前必须停止新版。")
    return database(base.NEW, """from controlserver.database import schema_checksum,SCHEMA_2_CHECKSUM,dbtime
from controlserver.security import utcnow
with store.transaction() as cur:
    cur.execute('SELECT version,checksum FROM schema_migrations'); rows=cur.fetchall()
    assert rows in ([{'version':2,'checksum':SCHEMA_2_CHECKSUM}],[{'version':3,'checksum':schema_checksum()}])
    cur.execute("SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='device_policy_state'")
    if cur.fetchone()['count']:
        store._check_device_policy_constraints(cur)
        cur.execute('SELECT COUNT(*) AS count FROM device_policy_state')
        assert cur.fetchone()['count']==0, 'Scoped versions exist; downgrade forbidden'
        cur.execute('DROP TABLE device_policy_state')
    cur.execute('UPDATE schema_migrations SET version=2,checksum=%s,applied_at_utc=%s',(SCHEMA_2_CHECKSUM,dbtime(utcnow())))
print(json.dumps({'status':'unused-additive-schema-reverted','businessTablesRestoredOrDeleted':False}))
""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, default=Path(__file__).with_name("EndpointAIDLP-Server-0.1.25-update.zip"))
    parser.add_argument("--mysql-bin", type=Path)
    parser.add_argument("--action", choices=("update","status","rollback"), default="update")
    args = parser.parse_args()
    base.require(sys.platform == "linux", "仅用于 Linux。")
    os.umask(0o077)
    lock_path = base.NEW.parent / ".EndpointAIDLP-Server-0.1.25-upgrade.lock"
    base.require(not lock_path.is_symlink(), "升级锁不能是符号链接。")
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = base.CANDIDATES[0]
        if args.action == "status":
            print(json.dumps(dict(oldRunning=bool(base.processes(old)),newRunning=bool(base.processes(base.NEW)))))
            return
        if args.action == "rollback":
            base.require(base.state_path().exists() and base.source_directory() == old, "缺少匹配的升级记录。")
            base.stop(base.NEW)
            try:
                downgrade_unused_schema()
            except Exception:
                base.start(base.NEW)
                raise base.DeploymentError("已有单终端版本或结构不匹配，已恢复新版；禁止回退旧代码。") from None
            base.start(old); base.health(old)
            print("已回退未下发单终端策略的升级，业务表未恢复或删除。")
            return
        base.require(args.mysql_bin is not None and all((args.mysql_bin / n).is_file() for n in ("mysqld","mysql","mysqldump")), "需要兼容的隔离 MySQL 工具目录。")
        base.remember_source(old)
        prepare(args.archive, old)
        stopped = False
        try:
            base.stop(old); stopped = True
            before = snapshot(old)
            destination, archive = stopped_backup(old, args.mysql_bin)
            verify_backup(old, destination, archive, args.mysql_bin, before)
            database(base.NEW, "store.migrate(); print(json.dumps({'schema':3}))")
            base.require(snapshot(base.NEW) == before, "迁移改变了策略或记录数量。")
            base.run([str(base.NEW / ".venv/bin/python"), str(base.NEW / "start.py"), "--check"], cwd=base.NEW)
            base.start(base.NEW); base.health(base.NEW)
        except Exception:
            if stopped:
                base.stop(base.NEW)
                try:
                    downgrade_unused_schema()
                except Exception:
                    base.start(base.NEW)
                    raise base.DeploymentError("无法安全回退结构，已尝试恢复新版；保留备份和版本记录。") from None
                if not base.processes(old):
                    base.start(old)
                base.health(old)
            raise base.DeploymentError("升级未完成；保留备份和目录，未显示私有错误内容。") from None
        print("0.1.25 已启动；单终端策略尚需现场验收。备份：" + str(destination))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.exit(str(exc) if isinstance(exc,base.DeploymentError) else "升级失败：" + type(exc).__name__)
