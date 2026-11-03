"""Opt-in, transactional credential renewal; only token verifiers are stored."""
import base64
import hashlib
from datetime import timedelta

from .database import dbtime, schema_checksum
from .security import hash_token, safe_compare, timestamp, utcnow
from .validation import ApiProblem

TABLE = 'device_credential_rotations'
SCHEMA_VERSION = 6
MIN_AGE = timedelta(days=30)
PREPARE_TTL = timedelta(days=1)
GRACE = timedelta(days=1)
DDL = """CREATE TABLE IF NOT EXISTS device_credential_rotations (
    device_id CHAR(36) NOT NULL PRIMARY KEY,
    rotation_id CHAR(36) NOT NULL,
    next_token_hash CHAR(64) NOT NULL,
    previous_token_hash CHAR(64) NULL,
    prepared_at_utc DATETIME(6) NOT NULL,
    committed_at_utc DATETIME(6) NULL,
    expires_at_utc DATETIME(6) NOT NULL,
    INDEX ix_credential_rotation_expires (expires_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"""


def schema_identity():
    return {'version': SCHEMA_VERSION, 'checksum': hashlib.sha256((schema_checksum() + '\n' + DDL).encode()).hexdigest()}


def check_table(cur):
    cur.execute('SELECT ENGINE AS engine FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (TABLE,))
    engine = cur.fetchone()
    if not engine or engine['engine'] != 'InnoDB':
        raise RuntimeError('Credential rotation requires an InnoDB table')
    cur.execute('SHOW COLUMNS FROM device_credential_rotations')
    columns = {row['Field']: (row['Type'].lower(), row['Null']) for row in cur.fetchall()}
    if columns != dict(device_id=('char(36)', 'NO'), rotation_id=('char(36)', 'NO'),
            next_token_hash=('char(64)', 'NO'), previous_token_hash=('char(64)', 'YES'),
            prepared_at_utc=('datetime(6)', 'NO'), committed_at_utc=('datetime(6)', 'YES'),
            expires_at_utc=('datetime(6)', 'NO')):
        raise RuntimeError('Credential rotation columns do not match')
    cur.execute('SHOW INDEX FROM device_credential_rotations')
    indexes = cur.fetchall()
    for name, column, unique in [('PRIMARY', 'device_id', 0),
                                ('ix_credential_rotation_expires', 'expires_at_utc', 1)]:
        rows = [r for r in indexes if r['Key_name'] == name]
        if (len(rows) != 1 or rows[0]['Column_name'] != column or rows[0]['Non_unique'] != unique
                or rows[0]['Sub_part'] is not None or rows[0]['Index_type'] != 'BTREE'
                or rows[0].get('Visible', 'YES') != 'YES' or rows[0]['Collation'] != 'A'):
            raise RuntimeError('Credential rotation indexes do not match')


def ensure_table(store):
    enabled, employee_index = store.cfg.CREDENTIAL_ROTATION, store.cfg.EMPLOYEE_INDEX
    store.cfg.CREDENTIAL_ROTATION = False
    store.cfg.EMPLOYEE_INDEX = False
    try:
        store.check_schema()
    finally:
        store.cfg.CREDENTIAL_ROTATION = enabled
        store.cfg.EMPLOYEE_INDEX = employee_index
    lock = 'endpointai-init-' + hashlib.sha256(store.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
    with store.transaction() as cur:
        cur.execute('SELECT GET_LOCK(%s,0) AS acquired', (lock,))
        if cur.fetchone()['acquired'] != 1:
            raise RuntimeError('Database maintenance already running')
        try:
            cur.execute(DDL)
            check_table(cur)
            identity = schema_identity()
            cur.execute('SELECT version,checksum FROM schema_migrations FOR UPDATE')
            current = cur.fetchall()
            if current not in ([{'version': 5, 'checksum': schema_checksum()}], [identity]):
                raise RuntimeError('Credential renewal requires the current schema 5 or 6 database')
            cur.execute('UPDATE schema_migrations SET version=%s,checksum=%s,applied_at_utc=%s',
                        (identity['version'], identity['checksum'], dbtime(utcnow())))
        finally:
            cur.execute('SELECT RELEASE_LOCK(%s)', (lock,))
    store._credential_rotation_table = True
    return 'Credential rotation storage ready'


def alternate_hash(row, now):
    if not row or row['expires_at_utc'] <= now:
        return None
    return row['previous_token_hash'] if row['committed_at_utc'] is not None else row['next_token_hash']


def _locked(cur, device):
    # Match the heartbeat/credential order used by recovery and policy dispatch.
    cur.execute('SELECT device_id FROM device_heartbeats WHERE device_id=%s FOR UPDATE', (device,))
    if not cur.fetchone():
        raise ApiProblem('DEVICE_NOT_FOUND', 'Device has no heartbeat.', 404)
    cur.execute('SELECT token_hash,enrolled_at_utc,revoked FROM device_credentials WHERE device_id=%s FOR UPDATE', (device,))
    credential = cur.fetchone()
    if not credential or credential['revoked']:
        raise ApiProblem('UNAUTHORIZED', 'Unauthorized', 401)
    cur.execute('SELECT * FROM device_credential_rotations WHERE device_id=%s FOR UPDATE', (device,))
    return credential, cur.fetchone()


def _result(device, rotation, state, expires, enrolled=None):
    return dict(deviceId=device, rotationId=rotation, state=state,
                expiresAtUtc=timestamp(expires) if expires is not None else None,
                enrolledAtUtc=timestamp(enrolled) if enrolled is not None else None)


def prepare(store, device, rotation, token, next_token):
    if not store._credential_rotation_table:
        raise ApiProblem('CREDENTIAL_ROTATION_UNAVAILABLE', 'Credential renewal is not enabled.', 503)
    try:
        raw = base64.b64decode(next_token, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode('ascii') != next_token:
            raise ValueError()
    except (ValueError, TypeError):
        raise ApiProblem('CREDENTIAL_ROTATION_INVALID', 'Invalid renewal credential.') from None
    device, rotation = str(device), str(rotation)
    now, current_hash, next_hash = dbtime(utcnow()), hash_token(token), hash_token(next_token)
    with store.transaction() as cur:
        credential, row = _locked(cur, device)
        primary = safe_compare(current_hash, credential['token_hash'])
        alternate = alternate_hash(row, now)
        if not primary and (alternate is None or not safe_compare(current_hash, alternate)):
            raise ApiProblem('UNAUTHORIZED', 'Unauthorized', 401)
        if safe_compare(next_hash, credential['token_hash']):
            expires = row['expires_at_utc'] if row and row['rotation_id'] == rotation and row['committed_at_utc'] else None
            return _result(device, rotation, 'active', expires, credential['enrolled_at_utc'])
        if not primary:
            raise ApiProblem('UNAUTHORIZED', 'Renewal requires the active primary credential.', 401)
        if row:
            if row['rotation_id'] == rotation and not safe_compare(row['next_token_hash'], next_hash):
                raise ApiProblem('CREDENTIAL_ROTATION_CONFLICT', 'Renewal identity has different material.', 409)
            if row['expires_at_utc'] > now:
                if row['rotation_id'] == rotation and row['committed_at_utc'] is None:
                    return _result(device, rotation, 'prepared', row['expires_at_utc'])
        if not store.cfg.CREDENTIAL_ROTATION:
            raise ApiProblem('CREDENTIAL_ROTATION_UNAVAILABLE', 'Credential renewal is not enabled.', 503)
        if row and row['expires_at_utc'] > now:
            raise ApiProblem('CREDENTIAL_ROTATION_CONFLICT', 'A renewal or overlap window is active.', 409)
        if now - credential['enrolled_at_utc'] < MIN_AGE:
            raise ApiProblem('CREDENTIAL_ROTATION_NOT_DUE', 'Credential renewal is not due.', 409)
        expires = now + PREPARE_TTL
        cur.execute('''INSERT INTO device_credential_rotations VALUES (%s,%s,%s,NULL,%s,NULL,%s)
            ON DUPLICATE KEY UPDATE rotation_id=VALUES(rotation_id),next_token_hash=VALUES(next_token_hash),
            previous_token_hash=NULL,prepared_at_utc=VALUES(prepared_at_utc),committed_at_utc=NULL,
            expires_at_utc=VALUES(expires_at_utc)''', (device, rotation, next_hash, now, expires))
        store._audit(cur, 'device:' + device, 'DEVICE_CREDENTIAL_ROTATION_PREPARED', device, None, 'rotationId=' + rotation)
        return _result(device, rotation, 'prepared', expires)


def commit(store, device, rotation, token):
    # Disabling new preparations must not strand an already prepared client.
    if not store._credential_rotation_table:
        raise ApiProblem('CREDENTIAL_ROTATION_UNAVAILABLE', 'Credential renewal storage is unavailable.', 503)
    device, rotation = str(device), str(rotation)
    now, supplied = dbtime(utcnow()), hash_token(token)
    with store.transaction() as cur:
        credential, row = _locked(cur, device)
        if safe_compare(supplied, credential['token_hash']):
            if row and row['committed_at_utc'] is None:
                raise ApiProblem('CREDENTIAL_ROTATION_CONFLICT', 'The prepared credential must confirm activation.', 409)
            expires = row['expires_at_utc'] if row and row['rotation_id'] == rotation else None
            return _result(device, rotation, 'active', expires, credential['enrolled_at_utc'])
        if (not row or row['rotation_id'] != rotation or row['committed_at_utc'] is not None
                or row['expires_at_utc'] <= now or not safe_compare(supplied, row['next_token_hash'])):
            raise ApiProblem('UNAUTHORIZED', 'Unauthorized', 401)
        expires = now + GRACE
        cur.execute('''UPDATE device_credentials SET token_hash=%s,enrolled_at_utc=%s,
            last_authenticated_at_utc=NULL WHERE device_id=%s''', (supplied, now, device))
        cur.execute('''UPDATE device_credential_rotations SET previous_token_hash=%s,
            committed_at_utc=%s,expires_at_utc=%s WHERE device_id=%s''', (credential['token_hash'], now, expires, device))
        store._audit(cur, 'device:' + device, 'DEVICE_CREDENTIAL_ROTATION_COMMITTED', device, None, 'rotationId=' + rotation)
        return _result(device, rotation, 'active', expires, now)


def cleanup(store):
    if not getattr(store, '_credential_rotation_table', False):
        return 0
    lock = 'endpointai-renewal-' + hashlib.sha256(store.cfg.MYSQL_DATABASE.encode()).hexdigest()[:32]
    with store.transaction() as cur:
        cur.execute('SELECT GET_LOCK(%s,0) AS acquired', (lock,))
        if cur.fetchone()['acquired'] != 1:
            return 0
        try:
            cur.execute('''DELETE FROM device_credential_rotations WHERE expires_at_utc<=%s
                ORDER BY expires_at_utc LIMIT 1000''', (dbtime(utcnow()),))
            return cur.rowcount
        finally:
            cur.execute('SELECT RELEASE_LOCK(%s)', (lock,))
