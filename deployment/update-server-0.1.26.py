#!/usr/bin/env python3
"""Same-account schema 3 -> 5 upgrade; gray execution requires explicit, source-bound qualification."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
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
import urllib.request


spec = importlib.util.spec_from_file_location('update_025_base', Path(__file__).with_name('update-server-0.1.25.py'))
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
base = previous.base
base.NEW = Path('/app/EndpointAIDLP-Server-0.1.26')
base.CANDIDATES = (Path('/app/EndpointAIDLP-Server-0.1.25'),)
base.state_path = lambda: base.NEW.parent / '.EndpointAIDLP-Server-0.1.26-upgrade.json'
SNAPSHOT = Path(__file__).with_name('upgrade-snapshot.py')
MUTATION_VALIDATED = False
spec_gray = importlib.util.spec_from_file_location('gray_qualification', Path(__file__).with_name('gray_qualification.py'))
gray = importlib.util.module_from_spec(spec_gray)
spec_gray.loader.exec_module(gray)


def require_mutation_validated(gray_candidate=False):
    base.require(MUTATION_VALIDATED or gray_candidate,
                 '尚未通过完整发行验收；默认切换动作已禁用。灰度需显式参数和匹配的 Linux 验证记录。')
    return gray.qualified_execution(Path(__file__).parent) if gray_candidate else None


def health(directory):
    values = base.read_env(directory)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for path in ('/health/ready', '/console', '/admin/v1/policy'):
        headers = {'Authorization': 'Bearer ' + values['SF_CONTROL_ADMIN_TOKEN']} if path.startswith('/admin/') else {}
        with opener.open(urllib.request.Request('http://127.0.0.1:8080' + path, headers=headers), timeout=5) as response:
            base.require(response.status == 200, '服务健康检查失败。')


base.health = health


def snapshot(directory, tables, env=None):
    command = [str(directory / '.venv/bin/python'), str(SNAPSHOT), '--server-dir', str(directory),
               '--tables', json.dumps(tables, separators=(',', ':'))]
    return json.loads(base.run(command, cwd=directory, env=env or previous.environment(directory)).decode())


def check_archive(path, expected):
    base.require(path.is_file() and not path.is_symlink(), '更新包缺失或为链接。')
    base.require(len(expected) == 64 and all(c in '0123456789abcdef' for c in expected), '需要独立渠道核对的 SHA-256。')
    with path.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    base.require(actual == expected, '更新包摘要不匹配，未切换服务。')


def check_backup_root(old):
    root = old / 'upgrade-backups'
    base.require(not root.is_symlink(), '备份目录不能是符号链接。')
    if root.exists():
        base.require(root.is_dir() and root.stat().st_uid == os.getuid(), '备份目录无效或不属于当前账户。')


def prepare(archive, old):
    base.require(not base.NEW.exists(), '新版目录已存在；保留现场，不覆盖。')
    base.require(old.is_dir() and not old.is_symlink() and old.stat().st_uid == os.getuid(), '旧目录不属于当前账户或为链接。')
    base.require(base.processes(old), '旧服务未运行。')
    base.require_unmanaged(old)
    values = base.read_env(old)
    base.require(values.get('SF_CONTROL_ROLE', 'all') == 'all', '候选升级器只支持现有单进程角色。')
    base.require(values.get('SF_CONTROL_ADMIN_AUTH_MODE', 'legacy') == 'legacy', '本地账号模式需另行验证升级流程。')
    base.require(values.get('SF_CONTROL_HTTP_PORT', '8080') == '8080', '候选升级器仅支持 8080 入口。')
    health(old)
    previous.database(old, """store.check_schema()
with store.transaction() as cur:
    cur.execute('SELECT version FROM schema_migrations')
    assert cur.fetchone()['version']==3
print(json.dumps({'schema':3}))
""")
    base.NEW.mkdir(mode=0o700)
    base.extract(archive, base.NEW)
    for path in (old / 'conf').iterdir():
        base.require(path.is_file() and not path.is_symlink(), '旧配置含链接或目录。')
        if path.name != 'endpoint_ai_proxy.sql':
            shutil.copy2(path, base.NEW / 'conf' / path.name)
            (base.NEW / 'conf' / path.name).chmod(0o600)
    values['APP_CONFIG'] = str(base.NEW / 'conf')
    values['SF_CONTROL_LOG_DIR'] = str(base.NEW / 'logs')
    # Derived indexes and caches are enabled only after separate maintenance.
    values['SF_CONTROL_EMPLOYEE_INDEX'] = 'false'
    values['SF_CONTROL_ANALYTICS_CACHE'] = 'false'
    values['SF_CONTROL_ANALYTICS_DETAIL_CACHE'] = 'false'
    path = base.NEW / 'launch-env.json'
    path.write_text(json.dumps(values), encoding='utf-8')
    path.chmod(0o600)
    executable = base.run([str(old / '.venv/bin/python'), '-c',
        'import sys; assert sys.version_info[:3]==(3,13,15); print(sys._base_executable)']).decode().strip()
    base.run([executable, '-m', 'venv', str(base.NEW / '.venv')])
    import platform
    architecture = {'x86_64':'x86_64', 'aarch64':'aarch64'}.get(platform.machine())
    base.require(architecture is not None, '不支持当前架构。')
    py = str(base.NEW / '.venv/bin/python')
    base.run([py, '-m', 'pip', 'install', '--no-index', '--find-links',
        str(base.NEW / 'deployment/wheelhouse' / architecture), '-r', str(base.NEW / 'requirements.txt')])
    base.run([py, '-m', 'pip', 'check'])
    base.run([py, '-c', 'from config import Config; Config().validate(); import app'],
             cwd=base.NEW, env=previous.environment(base.NEW))


def verify_backup(old, destination, archive, mysql_bin, tables, before):
    """Restore into a disposable loopback MySQL and rehearse migration there."""
    verify = destination / 'restore-verification'
    verify.mkdir(mode=0o700)
    password = secrets.token_urlsafe(32)
    data = verify / 'data'
    args = [str(mysql_bin / 'mysqld'), '--no-defaults', '--basedir=' + str(mysql_bin.parent), '--datadir=' + str(data)]
    base.run(args + ['--initialize-insecure'])
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    init = verify / 'init.sql'
    process = None
    socket_directory = None
    log = None
    try:
        fd = os.open(init, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write("CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '" + password + "';\n")
            stream.write("ALTER USER 'root'@'127.0.0.1' IDENTIFIED BY '" + password + "';\n")
            stream.write("ALTER USER 'root'@'localhost' IDENTIFIED BY '" + password + "';\n")
            stream.write("GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1';\n")
        socket_directory = tempfile.TemporaryDirectory(prefix='eai-restore-', dir=Path.home())
        log = (verify / 'mysql.private.log').open('wb')
        process = subprocess.Popen(args + ['--bind-address=127.0.0.1', '--port=' + str(port), '--mysqlx=OFF',
            '--skip-name-resolve', '--skip-log-bin', '--socket=' + str(Path(socket_directory.name) / 'mysql.sock'),
            '--init-file=' + str(init)], stdout=log, stderr=log)
        import pymysql
        deadline = time.monotonic() + 45
        while True:
            base.require(process.poll() is None, '隔离恢复实例启动失败。')
            try:
                connection = pymysql.connect(host='127.0.0.1', port=port, user='root', password=password)
                with connection.cursor() as cur:
                    cur.execute('CREATE DATABASE endpointai_restore_verify CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
                connection.close()
                break
            except pymysql.err.Error:
                base.require(time.monotonic() < deadline, '隔离恢复实例超时。')
                time.sleep(.25)
        init.unlink()
        env = previous.environment(old)
        env.update(EAI_MYSQL_HOST='127.0.0.1', EAI_MYSQL_PORT=str(port), EAI_MYSQL_USERNAME='root',
                   EAI_MYSQL_PASSWORD=password, EAI_MYSQL_DATABASE='endpointai_restore_verify')
        previous.database(old, """from controlserver.backup import restore_backup
restore_backup(cfg,Path(%r),'endpointai_restore_verify',mysql_binary=%r)
print(json.dumps({'restored':True}))
""" % (str(archive), str(mysql_bin / 'mysql')), env)
        base.require(snapshot(old, tables, env) == before, '备份恢复后的原始记录不一致。')
        env['APP_CONFIG'] = str(base.NEW / 'conf')
        previous.database(base.NEW, "store.migrate(); print(json.dumps({'migrated':True}))", env)
        base.require(snapshot(base.NEW, tables, env) == before, '恢复副本迁移后原始记录不一致。')
        (verify / 'report.json').write_text(json.dumps(dict(status='passed', restoredSchema=3,
            cloneMigratedToSchema=5, commonRowsPreserved=True, productionDatabaseModified=False)), encoding='utf-8')
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if log is not None:
            log.close()
        init.unlink(missing_ok=True)
        if socket_directory is not None:
            socket_directory.cleanup()


def downgrade_unused_schema(old, gray_candidate=False):
    qualified = require_mutation_validated(gray_candidate)
    if qualified:
        gray.check_files(base.NEW, qualified['runtimeFiles'])
    base.require(not base.processes(base.NEW), '回退前必须停止新版。')
    previous.database(base.NEW, """from controlserver.database import SCHEMA_3_CHECKSUM
with store.transaction() as cur:
    cur.execute('SELECT version,checksum FROM schema_migrations'); rows=cur.fetchall()
if rows != [{'version':3,'checksum':SCHEMA_3_CHECKSUM}]:
    store.revert_unused_rollout_schema()
print(json.dumps({'checked':True}))
""")
    previous.database(old, "store.check_schema(); print(json.dumps({'schema':3}))")


def update(archive, expected_sha256, old, mysql_bin, gray_candidate=False):
    qualified = require_mutation_validated(gray_candidate)
    check_archive(archive, expected_sha256)
    if qualified:
        gray.check_archive(archive, qualified)
    base.require(all((mysql_bin / name).is_file() for name in ('mysqld', 'mysql', 'mysqldump')), '需要兼容 MySQL 工具目录。')
    base.require(old.is_dir() and not old.is_symlink() and old.stat().st_uid == os.getuid(), '旧目录不属于当前账户或为链接。')
    base.require(base.source_directory(old) == old, '旧目录不符合升级约束。')
    check_backup_root(old)
    base.remember_source(old)
    prepare(archive, old)
    tables = previous.database(old, "from controlserver.database import schema_tables; print(json.dumps(sorted(schema_tables()-{'schema_migrations'})))")
    stopped = False
    try:
        stopped = True
        base.stop(old)
        before = snapshot(old, tables)
        destination, backup_archive = previous.stopped_backup(old, mysql_bin)
        base.require(shutil.disk_usage(destination).free >= max(8 << 30, backup_archive.stat().st_size * 4),
                     '隔离恢复空间不足；未迁移数据库。')
        verify_backup(old, destination, backup_archive, mysql_bin, tables, before)
        previous.database(base.NEW, "store.migrate(); print(json.dumps({'schema':5}))")
        base.require(snapshot(base.NEW, tables) == before, '迁移改变了原始记录。')
        base.run([str(base.NEW / '.venv/bin/python'), str(base.NEW / 'start.py'), '--check'], cwd=base.NEW)
        base.start(base.NEW)
        health(base.NEW)
    except Exception:
        if stopped:
            base.stop(base.NEW)
            try:
                downgrade_unused_schema(old, gray_candidate)
            except Exception:
                base.start(base.NEW)
                raise base.DeploymentError('无法安全回退结构；已尝试恢复新版，保留备份及版本记录。') from None
            if not base.processes(old):
                base.start(old)
            health(old)
        raise base.DeploymentError('升级未完成；保留备份和目录，未显示私有错误内容。') from None
    return destination


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, default=Path(__file__).with_name('EndpointAIDLP-Server-0.1.26-update.zip'))
    parser.add_argument('--archive-sha256', default='')
    parser.add_argument('--mysql-bin', type=Path)
    parser.add_argument('--action', choices=('update', 'status', 'rollback'), default='status')
    parser.add_argument('--confirm-exclusive-database', action='store_true')
    parser.add_argument('--gray-candidate', action='store_true', help='Use exact source qualified for an authorized gray trial; not a capacity acceptance')
    args = parser.parse_args()
    base.require(sys.platform == 'linux', '仅用于 Linux。')
    os.umask(0o077)
    old = base.CANDIDATES[0]
    if args.action == 'status':
        print(json.dumps(dict(oldRunning=bool(base.processes(old)), newRunning=bool(base.processes(base.NEW)),
                              mutationEnabled=False)))
        return
    # Do not change this constant until the exact candidate passes isolated
    # Linux migration, backup, rollback, multi-worker and failure-injection tests.
    require_mutation_validated(args.gray_candidate)
    lock_path = base.NEW.parent / '.EndpointAIDLP-Server-0.1.26-upgrade.lock'
    base.require(not lock_path.is_symlink(), '升级锁不能是符号链接。')
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'rollback':
            base.require(base.state_path().exists() and base.source_directory() == old, '缺少匹配的升级记录。')
            base.require_unmanaged(old)
            was_running = bool(base.processes(base.NEW))
            base.stop(base.NEW)
            try:
                downgrade_unused_schema(old, args.gray_candidate)
            except Exception:
                if was_running:
                    base.start(base.NEW)
                raise base.DeploymentError('已有批次数据或结构不匹配，禁止回退旧代码。') from None
            if not base.processes(old):
                base.start(old)
            health(old)
            print('已回退至 schema 3；原始业务表未恢复或删除。')
            return
        base.require(args.confirm_exclusive_database, '必须确认所有其他数据库写入者均已停止。')
        base.require(args.mysql_bin is not None, '需要兼容的 MySQL 工具目录。')
        destination = update(args.archive, args.archive_sha256.lower(), old, args.mysql_bin, args.gray_candidate)
        print('升级完成；备份目录：' + str(destination))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.exit(str(exc) if isinstance(exc, base.DeploymentError) else '升级失败：' + type(exc).__name__)
