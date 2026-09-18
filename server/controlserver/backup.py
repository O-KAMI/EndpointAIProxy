"""Independent consistent MySQL backups; never started from a WSGI worker."""
import fcntl
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4
from .database import ControlStore, schema_tables
from .security import timestamp, utcnow


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_backup_state(cfg):
    try:
        value = json.loads((cfg.DATA_ROOT / "backup-state.json").read_text())
        return {"lastSucceededAtUtc": value["lastSucceededAtUtc"], "lastError": value["lastError"]}
    except FileNotFoundError:
        return {"lastSucceededAtUtc": None, "lastError": "BACKUP_NOT_RUN"}
    except (OSError, ValueError, KeyError, TypeError):
        return {"lastSucceededAtUtc": None, "lastError": "BACKUP_STATE_UNREADABLE"}


@contextmanager
def mysql_credentials(cfg):
    """The password is neither an argument nor an environment variable passed to tools."""
    def escape(value):
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="endpointai-mysql-", suffix=".cnf") as file:
        file.write("[client]\n")
        for key, value in (("host", cfg.MYSQL_HOST), ("port", cfg.MYSQL_PORT),
                           ("user", cfg.MYSQL_USER), ("password", cfg.MYSQL_PASSWORD)):
            file.write(f'{key}="{escape(value)}"\n')
        file.flush()
        yield file.name


def run_backup(cfg, retention=7, dump_binary="mysqldump"):
    if retention < 1:
        raise ValueError("Retention must be positive")
    cfg.BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (cfg.BACKUP_DIR / ".backup.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Backup already running") from None
        state = read_backup_state(cfg)
        temporary = None
        try:
            ControlStore(cfg).check_schema()
            name = utcnow().strftime("control-%Y%m%dT%H%M%S") + "-" + uuid4().hex[:8] + ".sql.gz"
            output = cfg.BACKUP_DIR / name
            fd, temporary = tempfile.mkstemp(dir=cfg.BACKUP_DIR, prefix=".incomplete-")
            with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
                with mysql_credentials(cfg) as defaults, tempfile.TemporaryFile() as errors:
                    command = [dump_binary, f"--defaults-extra-file={defaults}", "--single-transaction",
                        "--quick", "--skip-lock-tables", "--no-tablespaces", "--set-gtid-purged=OFF",
                        "--hex-blob", "--default-character-set=utf8mb4", cfg.MYSQL_DATABASE, *sorted(schema_tables())]
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors)
                    try:
                        shutil.copyfileobj(process.stdout, compressed)
                    except BaseException:
                        # A full disk or interrupted writer must not leave mysqldump
                        # running after its credential file and lock are released.
                        if process.poll() is None:
                            process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        raise
                    finally:
                        process.stdout.close()
                    if process.wait() != 0:
                        raise RuntimeError("MYSQLDUMP_FAILED")
            # Validate the entire stream before publication, including the gzip CRC.
            with gzip.open(temporary, "rb") as stream:
                while stream.read(1024 * 1024):
                    pass
            digest = digest_file(temporary)
            os.replace(temporary, output)
            temporary = None
            try:
                atomic_json(output.with_suffix(output.suffix + ".json"), {
                    "formatVersion": 1, "sha256": digest, "database": cfg.MYSQL_DATABASE,
                    "tables": sorted(schema_tables()), "createdAtUtc": timestamp(utcnow()),
                })
            except Exception:
                # Archives without a manifest cannot be restored or retained safely.
                output.unlink(missing_ok=True)
                raise
            state = {"lastSucceededAtUtc": timestamp(utcnow()), "lastError": None}
            atomic_json(cfg.DATA_ROOT / "backup-state.json", state)
            # Random suffixes do not order backups made in the same second.
            # Keep this successful backup first, then older completed manifests.
            newest = Path(str(output) + ".json")
            completed = [newest] + sorted(
                (p for p in cfg.BACKUP_DIR.glob("control-*.sql.gz.json") if p != newest),
                key=lambda p: p.stat().st_mtime_ns, reverse=True)
            for manifest in completed[retention:]:
                archive = Path(str(manifest)[:-5])
                archive.unlink(missing_ok=True)
                manifest.unlink()
            return output
        except Exception as exc:
            state["lastError"] = type(exc).__name__
            atomic_json(cfg.DATA_ROOT / "backup-state.json", state)
            raise
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)


def digest_file(path):
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def restore_backup(cfg, archive, target_database, mysql_binary="mysql"):
    """Restore trusted, generated backups only into an explicitly named empty database."""
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", target_database):
        raise ValueError("Target database must contain only letters, digits and underscore")
    archive = Path(archive)
    manifest = json.loads(Path(str(archive) + ".json").read_text())
    if (manifest.get("formatVersion") != 1 or set(manifest.get("tables", [])) != schema_tables()
            or digest_file(archive) != manifest.get("sha256")):
        raise ValueError("Backup manifest/checksum mismatch")
    # Decompress fully first. A corrupt backup must not partially modify the target.
    with tempfile.TemporaryFile() as sql:
        with gzip.open(archive, "rb") as source:
            shutil.copyfileobj(source, sql)
        sql.seek(0)
        import copy
        target = copy.copy(cfg)
        target.MYSQL_DATABASE = target_database
        control = ControlStore(target)
        with control.transaction() as cur:
            cur.execute("SHOW FULL TABLES")
            if cur.fetchall():
                raise RuntimeError("Restore target must be an empty database")
        with mysql_credentials(target) as defaults, tempfile.TemporaryFile() as errors:
            process = subprocess.run([mysql_binary, f"--defaults-extra-file={defaults}",
                "--binary-mode", "--default-character-set=utf8mb4", target_database],
                stdin=sql, stdout=subprocess.DEVNULL, stderr=errors, check=False)
            if process.returncode:
                raise RuntimeError("MYSQL_RESTORE_FAILED; target may be partially restored; do not start service")
        control.check_schema()
        return control.policy()
