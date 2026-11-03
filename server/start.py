"""Load the deployment-only configuration, then run app.py or a read-only check."""
import json
import os
from pathlib import Path
import sys
import argparse

root = Path(__file__).resolve().parent
for name in list(os.environ):
    if name.startswith(("SF_CONTROL_", "EAI_MYSQL_")) or name in ("APP_ENV", "APP_CONFIG"):
        os.environ.pop(name)
os.environ.update(json.loads((root / "launch-env.json").read_text()))
parser = argparse.ArgumentParser()
action = parser.add_mutually_exclusive_group()
action.add_argument("--check", action="store_true")
action.add_argument("--refresh-analytics-cache", action="store_true")
parser.add_argument("--role", choices=("all", "client", "admin"))
parser.add_argument("--port", type=int)
args = parser.parse_args()
if args.role:
    os.environ["SF_CONTROL_ROLE"] = args.role
if args.port is not None:
    os.environ["SF_CONTROL_HTTP_PORT"] = str(args.port)
os.chdir(root)
if args.refresh_analytics_cache:
    from config import Config
    env = Config().APP_ENV
    os.execv(str(root / ".venv/bin/python"), [str(root / ".venv/bin/python"), str(root / "manage.py"), "refresh-analytics-cache", "--env", env])
elif args.check:
    from app import create_app
    create_app()
else:
    os.execv(str(root / ".venv/bin/python"), [str(root / ".venv/bin/python"), str(root / "app.py")])
