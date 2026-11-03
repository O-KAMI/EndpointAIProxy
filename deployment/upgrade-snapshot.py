#!/usr/bin/env python3
"""Hash ordered database rows in a consistent snapshot without retaining tables."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import pymysql
from pymysql.cursors import SSDictCursor


def snapshot(cfg, tables):
    if not tables or len(tables) != len(set(tables)) or any(not re.fullmatch(r'[a-z_][a-z0-9_]*', table) for table in tables):
        raise ValueError('Invalid snapshot table list')
    connection = pymysql.connect(host=cfg.MYSQL_HOST, port=cfg.MYSQL_PORT, user=cfg.MYSQL_USER,
        password=cfg.MYSQL_PASSWORD, database=cfg.MYSQL_DATABASE, charset='utf8mb4', autocommit=False,
        connect_timeout=5, read_timeout=60, write_timeout=30, init_command="SET time_zone = '+00:00'")
    try:
        keys = {}
        with connection.cursor(pymysql.cursors.DictCursor) as cur:
            for table in sorted(tables):
                cur.execute(f'SHOW INDEX FROM `{table}` WHERE Key_name=\'PRIMARY\'')
                columns = sorted(cur.fetchall(), key=lambda row: row['Seq_in_index'])
                if not columns or any(not re.fullmatch(r'[a-z_][a-z0-9_]*', row['Column_name']) for row in columns):
                    raise RuntimeError('A snapshot table has no valid primary key')
                keys[table] = [row['Column_name'] for row in columns]
            connection.commit()
            cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            cur.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
        result = {}
        with connection.cursor(SSDictCursor) as cur:
            for table in sorted(tables):
                order = ','.join('`' + column + '`' for column in keys[table])
                cur.execute(f'SELECT * FROM `{table}` ORDER BY {order}')
                digest, count = hashlib.sha256(), 0
                for row in cur:
                    encoded = json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(',', ':'),
                        default=lambda value: value.hex() if isinstance(value, bytes) else str(value)).encode('utf-8')
                    digest.update(len(encoded).to_bytes(8, 'big'))
                    digest.update(encoded)
                    count += 1
                result[table] = {'count': count, 'sha256': digest.hexdigest()}
        connection.commit()
        return result
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-dir', required=True)
    parser.add_argument('--tables', required=True, help='JSON array of table names, never credentials')
    args = parser.parse_args()
    root = Path(args.server_dir).resolve(strict=True)
    sys.path.insert(0, str(root))
    from config import Config
    cfg = Config().validate()
    print(json.dumps(snapshot(cfg, json.loads(args.tables)), sort_keys=True))


if __name__ == '__main__':
    main()
