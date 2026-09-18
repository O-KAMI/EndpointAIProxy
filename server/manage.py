"""Explicit maintenance commands. WSGI startup never calls these operations."""
import argparse
import json
import logging
import os
import base64
import secrets
from pathlib import Path
from config import Config


def main():
    parser = argparse.ArgumentParser(description="EndpointAIDLP maintenance")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check-db", "init-db", "migrate-db", "backup", "restore"):
        command = sub.add_parser(name)
        command.add_argument("--env", choices=("sit", "prd"), required=True)
        command.add_argument("--config-dir")
        if name in ("init-db", "migrate-db"):
            command.add_argument("--service-stopped", action="store_true", required=True,
                                 help="Assert that all application instances are stopped")
        if name == "backup":
            command.add_argument("--mysqldump", default="mysqldump")
        if name == "restore":
            command.add_argument("--archive", required=True)
            command.add_argument("--target-database", required=True)
            command.add_argument("--mysql", default="mysql")
            command.add_argument("--service-stopped", action="store_true", required=True)
    cert = sub.add_parser("certificate")
    cert.add_argument("--directory", required=True)
    cert.add_argument("--ip", default="10.220.22.112")
    cert.add_argument("--days", type=int, default=365)
    cert_check = sub.add_parser("certificate-check")
    cert_check.add_argument("--directory", required=True)
    cert_check.add_argument("--ip", default="10.220.22.112")
    cert_check.add_argument("--warn-days", type=int, default=30)
    secret = sub.add_parser("secrets")
    secret.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "certificate-check":
        from cryptography import x509
        from controlserver.certificates import certificate_info
        from controlserver.security import utcnow
        certificate = x509.load_pem_x509_certificate((Path(args.directory)/"server.crt").read_bytes())
        info = certificate_info(certificate, args.ip)
        remaining = (certificate.not_valid_after_utc - utcnow()).days
        print(json.dumps(dict(info,daysRemaining=remaining,renewalRequired=remaining <= args.warn_days),indent=2))
        if remaining <= args.warn_days:
            raise SystemExit(2)
        return
    if args.command == "secrets":
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write("SF_CONTROL_CLIENT_TOKEN=" + secrets.token_hex(32) + "\n")
            file.write("SF_CONTROL_ADMIN_TOKEN=" + secrets.token_hex(32) + "\n")
            file.write("SF_CONTROL_POLICY_HMAC_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
            file.write("SF_CONTROL_TRANSPORT_KEY_ID=production-2026-01\n")
            file.write("SF_CONTROL_TRANSPORT_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
        print(f"Secrets created at {path}; values not printed. Existing files are never overwritten.")
        return
    if args.command == "certificate":
        from controlserver.certificates import ensure_certificate
        print(json.dumps(ensure_certificate(args.directory, args.ip, args.days), indent=2))
        return
    cfg = Config(args.env, args.config_dir).validate()
    print(f"Environment={cfg.APP_ENV} MySQL={cfg.MYSQL_HOST}:{cfg.MYSQL_PORT} Database={cfg.MYSQL_DATABASE}")
    from controlserver.database import ControlStore
    store = ControlStore(cfg)
    if args.command == "check-db":
        store.check_schema()
        with store.transaction() as cur:
            cur.execute("SELECT VERSION() AS version")
            print(json.dumps(cur.fetchone()))
    elif args.command == "init-db":
        print(store.initialize_empty())
        store.check_schema()
    elif args.command == "migrate-db":
        print(store.migrate())
    elif args.command == "backup":
        from controlserver.backup import run_backup
        print(run_backup(cfg, dump_binary=args.mysqldump))
    elif args.command == "restore":
        from controlserver.backup import restore_backup
        policy = restore_backup(cfg, args.archive, args.target_database, args.mysql)
        print(f"Restore validated: target={args.target_database} policyVersion={policy['policyVersion']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logging.basicConfig(level=logging.ERROR)
        logging.exception("Maintenance failed")
        raise SystemExit(1)
