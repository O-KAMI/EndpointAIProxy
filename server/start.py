"""Load the deployment-only configuration, then run app.py or a read-only check."""
import json
import os
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
for name in list(os.environ):
    if name.startswith(("SF_CONTROL_", "EAI_MYSQL_")) or name in ("APP_ENV", "APP_CONFIG"):
        os.environ.pop(name)
os.environ.update(json.loads((root / "launch-env.json").read_text()))
os.chdir(root)
if sys.argv[1:] == ["--check"]:
    from app import create_app
    create_app()
else:
    os.execv(str(root / ".venv/bin/python"), [str(root / ".venv/bin/python"), str(root / "app.py")])
