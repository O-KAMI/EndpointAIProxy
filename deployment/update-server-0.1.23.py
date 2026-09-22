#!/usr/bin/env python3
"""Offline, same-account update. Never initializes, migrates or deletes MySQL data."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile

CANDIDATES = (Path("/app/EndpointAIDLP-Server-0.1.22"), Path("/app/EndpointAIDLP-Server-0.1.21"))
NEW = Path("/app/EndpointAIDLP-Server-0.1.23")
ARCHIVE = "EndpointAIDLP-Server-0.1.23-update.zip"


def state_path():
    return NEW.parent / ".EndpointAIDLP-Server-0.1.23-upgrade.json"


def source_directory(explicit=None):
    if explicit is not None:
        old = explicit.resolve()
    elif state_path().exists():
        path = state_path()
        require(not path.is_symlink() and path.stat().st_uid == os.getuid()
                and stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, "升级来源记录权限不安全。")
        record = json.loads(path.read_text())
        require(record.get("target") == str(NEW), "升级记录的目标目录不匹配。")
        old = Path(record["source"])
    else:
        active = [p for p in CANDIDATES if p.is_dir() and processes(p)]
        require(len(active) == 1, "无法唯一识别运行的 0.1.21/0.1.22；请使用 --old-dir 指定真实服务目录。")
        old = active[0]
    require(old.is_absolute() and old != NEW and not old.is_symlink()
            and old.is_dir() and old.stat().st_uid == os.getuid(), "旧服务目录无效、与新版相同或不属于当前账户。")
    return old


def remember_source(old):
    path = state_path()
    require(not path.is_symlink(), "升级来源记录不能是符号链接。")
    if path.exists():
        require(source_directory() == old, "已有升级记录指向另一来源；为保证回退安全已中止。")
        return
    with path.open("x") as output:
        output.write(json.dumps({"source": str(old), "target": str(NEW)}))
    path.chmod(0o600)


def systemd_managed_service(cgroup):
    # Only the systemd hierarchy owns lifecycle. Resource hierarchies may retain
    # sshd.service after PAM moves the process into a login session scope.
    for line in cgroup.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        hierarchy, controllers, path = fields
        if not ((hierarchy == "0" and controllers == "")
                or "name=systemd" in controllers.split(",")):
            continue
        units = [part for part in path.split("/")
                 if part.endswith((".service", ".scope"))]
        # A parent user@UID.service owns the user manager, not the application.
        if units and units[-1].endswith(".service"):
            return True
    return False


def require_unmanaged(directory):
    for pid in processes(directory):
        try:
            cgroup = (Path("/proc") / str(pid) / "cgroup").read_text()
        except FileNotFoundError:
            continue
        except OSError:
            raise DeploymentError("无法检查服务托管方式，未停止服务。") from None
        require(not systemd_managed_service(cgroup),
                "检测到 systemd 托管服务，已拒绝切换且未停止进程；请先确认服务单元，按该单元部署流程升级，避免自动重启与本脚本冲突。")


class DeploymentError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def run(args, cwd=None, env=None):
    # Child errors can contain connection strings. Never forward child output.
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=600)
    require(result.returncode == 0, "运行环境或配置检查失败；输出已隐藏以避免泄露凭据。")
    return result.stdout


def backup(old):
    values = read_env(old)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("SF_CONTROL_", "EAI_MYSQL_")) and k not in ("APP_ENV", "APP_CONFIG")}
    env.update(values)
    require(shutil.which("mysqldump", path=env.get("PATH")) is not None,
            "未找到 mysqldump；请由管理员安装兼容的 MySQL 客户端后重试，未切换服务。")
    root = old / "upgrade-backups"
    require(not root.is_symlink(), "备份目录不能是符号链接。")
    root.mkdir(mode=0o700, exist_ok=True)
    require(root.stat().st_uid == os.getuid(), "备份目录不属于当前账户。")
    root.chmod(0o700)
    destination = root / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(mode=0o700)
    shutil.copy2(old / "launch-env.json", destination / "launch-env.json")
    shutil.copytree(old / "conf", destination / "conf")
    for path in destination.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    # Use the old tested backup implementation with inherited runtime credentials.
    # Override output paths only, preserving the original launch config and database.
    code = """import json, os, sys
from pathlib import Path
from config import Config
from controlserver.backup import run_backup
root = Path(sys.argv[1])
cfg = Config(os.environ.get('APP_ENV', 'prd'), os.environ.get('APP_CONFIG')).validate()
cfg.DATA_ROOT = root / 'metadata'
cfg.DATA_ROOT.mkdir(mode=0o700)
cfg.BACKUP_DIR = root / 'database'
print(json.dumps(str(run_backup(cfg))))
"""
    output = run([str(old / ".venv/bin/python"), "-c", code, str(destination)], cwd=old, env=env)
    archive = Path(json.loads(output.decode()))
    require(archive.is_file() and archive.is_relative_to(destination / "database"), "备份结果无效；未切换服务。")
    print("备份目录：" + str(destination))
    print("数据库备份：" + str(archive))


def processes(directory):
    result = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid != os.getuid() or (path / "cwd").resolve() != directory:
                continue
            cmd = (path / "cmdline").read_bytes()
            if b"app.py" not in cmd and b"gunicorn" not in cmd:
                continue
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if fields[0] != "Z":
                result[int(path.name)] = (int(fields[1]), fields[19])
        except (OSError, ValueError):
            continue
    return result


def stop(directory):
    require_unmanaged(directory)
    procs = processes(directory)
    masters = [pid for pid, (parent, _) in procs.items() if parent not in procs]
    require(len(masters) <= 1, "检测到多个独立服务进程，未停止；请检查启动方式。")
    if masters:
        pid = masters[0]
        require(processes(directory).get(pid) == procs[pid], "进程身份发生变化，已中止。")
        os.kill(pid, signal.SIGTERM)
    for _ in range(60):
        if not processes(directory):
            return
        time.sleep(1)
    raise DeploymentError("服务未在 60 秒内退出；没有强制结束进程，请检查后重试。")


def port_free():
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 8080))


def read_env(directory):
    path = directory / "launch-env.json"
    require(path.is_file() and not path.is_symlink(), "缺少独立的 launch-env.json 配置。")
    require(path.stat().st_uid == os.getuid(), "配置文件不属于当前账户。")
    require(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, "请先将 launch-env.json 权限设为 600。")
    values = json.loads(path.read_text())
    require(isinstance(values, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in values.items()), "配置格式无效。")
    require(values.get("SF_CONTROL_ADMIN_TOKEN"), "缺少管理员认证配置。")
    return values


def health(directory):
    values = read_env(directory)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    paths = ["/health/ready", "/console", "/admin/v1/policy", "/admin/v1/devices"]
    if directory == NEW:
        paths += ["/admin/v1/analytics", "/admin/v1/analytics/devices?take=1"]
    for path in paths:
        headers = {"Authorization": "Bearer " + values["SF_CONTROL_ADMIN_TOKEN"]} if path.startswith("/admin/") else {}
        with opener.open(urllib.request.Request("http://127.0.0.1:8080" + path, headers=headers), timeout=3) as response:
            require(response.status == 200, "服务健康检查失败。")


def start(directory):
    require(not processes(directory), "目标服务已经在运行。")
    port_free()
    with (directory / "console.log").open("ab") as log:
        child = subprocess.Popen([str(directory / ".venv/bin/python"), str(directory / "start.py")],
                                 cwd=directory, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
    (directory / "server.pid").write_text(str(child.pid) + "\n")
    for _ in range(45):
        if child.poll() is not None:
            break
        try:
            if processes(directory):
                health(directory)
                return
        except Exception:
            pass
        time.sleep(1)
    raise DeploymentError("新版启动或管理接口检查失败。")


def extract(archive, destination):
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        require(len(names) == len(set(names)), "压缩包存在重复文件。")
        require(all(not Path(n).is_absolute() and ".." not in Path(n).parts for n in names), "压缩包路径不安全。")
        require(all(not stat.S_ISLNK(i.external_attr >> 16) for i in z.infolist()), "压缩包包含符号链接。")
        manifest = json.loads(z.read("manifest.json"))
        require(set(names) == set(manifest) | {"manifest.json"}, "压缩包清单不匹配。")
        require({"app.py", "start.py", "requirements.txt"}.issubset(manifest), "缺少服务启动文件或离线依赖清单。")
        require(all(hashlib.sha256(z.read(n)).hexdigest() == digest for n, digest in manifest.items()), "压缩包校验失败。")
        z.extractall(destination)


def prepare(archive, old):
    require(not NEW.exists(), "新版目录已存在；为防覆盖不会继续，请检查上次更新结果。")
    require(old.is_dir() and old.stat().st_uid == os.getuid(), "旧服务目录不存在或不属于当前账户。")
    values = read_env(old)
    require(processes(old), "旧服务没有运行；请先确认服务状态。")
    require_unmanaged(old)
    health(old)
    NEW.mkdir(mode=0o700)
    try:
        extract(archive, NEW)
        # Bundle stores service source at its root; wheelhouse is only for offline install.
        shutil.copytree(old / "conf", NEW / "conf", dirs_exist_ok=True)
        if (old / "var").exists():
            shutil.copytree(old / "var", NEW / "var", dirs_exist_ok=True)
        for key, value in list(values.items()):
            if value == str(old) or value.startswith(str(old) + "/"):
                values[key] = str(NEW) + value[len(str(old)):]
        values["APP_CONFIG"] = str(NEW / "conf")
        require(values.get("SF_CONTROL_HTTP_PORT", "8080") == "8080", "当前脚本只支持现有 8080 端口部署。")
        values["SF_CONTROL_LOG_DIR"] = str(NEW / "logs")
        (NEW / "launch-env.json").write_text(json.dumps(values))
        (NEW / "launch-env.json").chmod(0o600)
        base = run([str(old / ".venv/bin/python"), "-c", "import sys; assert sys.version_info[:3] == (3,13,15); print(sys._base_executable)"]).decode().strip()
        run([base, "-m", "venv", str(NEW / ".venv")])
        py = str(NEW / ".venv/bin/python")
        machine = platform.machine().lower()
        architecture = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(machine)
        require(architecture is not None, "仅支持 Linux x86_64 / aarch64 离线升级。")
        wheelhouse = NEW / "deployment/wheelhouse" / architecture
        require(wheelhouse.is_dir(), "缺少当前架构的离线依赖。")
        run([py, "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), "-r", str(NEW / "requirements.txt")])
        run([py, "-m", "pip", "check"])
        run([py, str(NEW / "start.py"), "--check"], cwd=NEW)
    except Exception:
        # Keep failed directory for diagnosis; never touch old runtime or tables.
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, default=Path(__file__).resolve().parent / ARCHIVE)
    parser.add_argument("--action", choices=("update", "rollback", "start", "stop", "status", "backup"), default="update")
    parser.add_argument("--old-dir", type=Path, help="覆盖自动识别的旧服务目录；首次更新后来源记录用于回退")
    args = parser.parse_args()
    require(sys.platform == "linux", "仅用于 Linux 生产服务器。")
    os.umask(0o077)
    lock_path = NEW.parent / ".EndpointAIDLP-Server-0.1.23-upgrade.lock"
    require(not lock_path.is_symlink(), "升级锁不能是符号链接。")
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = source_directory(args.old_dir)
        if state_path().exists():
            require(source_directory() == old, "--old-dir 与持久化升级来源不一致；未进行任何服务切换。")
        if args.action == "status":
            print("回退来源：" + str(old) + "；运行中：" + str(bool(processes(old))))
            print("0.1.23 运行中：" + str(bool(processes(NEW))))
            return
        if args.action == "backup":
            backup(old)
            return
        if args.action == "stop":
            stop(NEW)
            print("0.1.23 已停止。")
            return
        if args.action == "start":
            require(state_path().is_file(), "缺少升级来源记录，未启动新版。")
            start(NEW)
            print("0.1.23 已启动并通过检查。")
            return
        if args.action == "rollback":
            require(state_path().is_file(), "缺少升级来源记录，未执行回退。")
            read_env(old)
            require((old / "start.py").is_file(), "旧版启动文件缺失，未停止新版。")
            require_unmanaged(old)
            stop(NEW)
            if not processes(old):
                start(old)
            health(old)
            print("已回退到 " + str(old) + "；数据库及策略保持不变。")
            return
        require(args.archive.is_file(), "找不到更新 ZIP，请与脚本放在同一目录或使用 --archive。")
        print("正在准备新版及离线依赖；旧服务继续运行。", flush=True)
        require(not NEW.exists(), "新版目录已存在；不会覆盖，请先查看 --action status。")
        require_unmanaged(old)
        remember_source(old)
        prepare(args.archive, old)
        print("准备检查通过，正在切换服务。", flush=True)
        try:
            stop(old)
            port_free()
            start(NEW)
        except Exception:
            stop(NEW)
            if not processes(old):
                start(old)
            health(old)
            raise DeploymentError("更新未完成，旧服务已恢复；数据库未重建。") from None
        print("更新成功：http://10.220.22.112:8080/console")
        print("目录：" + str(NEW) + "；启动日志：console.log；业务日志：logs/app.log")
        print("旧目录保留用于回退；未配置开机自启动。")
        print("本脚本支持 --action status / stop / start / rollback。")


if __name__ == "__main__":
    try:
        main()
    except DeploymentError as exc:
        sys.exit(str(exc))
    except Exception as exc:
        sys.exit("操作未完成，错误类型：" + type(exc).__name__ + "；未显示配置或密码。")
