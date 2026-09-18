"""UI-only local development entry. Only explicit disposable eai_test_* databases."""
import argparse
import base64
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app
from config import Config

parser = argparse.ArgumentParser()
parser.add_argument("--database",required=True)
parser.add_argument("--mysql-port",type=int,default=13306)
parser.add_argument("--http-port",type=int,default=18081)
args = parser.parse_args()
if not args.database.startswith("eai_test_"):
    parser.error("Only disposable eai_test_* databases are allowed")
c = Config("sit",conf_dir=Path(__file__).resolve().parents[1]/"artifacts/ui-empty-conf")
c.MYSQL_HOST,c.MYSQL_PORT,c.MYSQL_DATABASE = "127.0.0.1",args.mysql_port,args.database
c.MYSQL_USER,c.MYSQL_PASSWORD = "root",""
c.CLIENT_TOKEN,c.ADMIN_TOKEN = "test-enrollment-token","test-administrator-token"
c.HMAC_TEXT = base64.b64encode(bytes(range(32))).decode()
c.TRANSPORT_KEY_TEXT = base64.b64encode(bytes(range(32))).decode()
c.REQUIRE_HTTPS,c.TRUST_PROXY = False,False
c.LOG_DIR = Path(__file__).resolve().parents[1]/"artifacts/ui-logs"
create_app(c).run(host="127.0.0.1",port=args.http_port,debug=False)
