"""Explicit offline recovery helpers; never called by request handlers."""
from .database import decode
from .security import dumps, timestamp, utcnow
from .validation import ApiProblem, domain_policy


def advance_restored_policy_watermark(store, verified_issued_max, actor, evidence):
    """Advance a restored policy above an independently verified issued bound."""
    if (isinstance(verified_issued_max, bool) or not isinstance(verified_issued_max, int)
            or not 1 <= verified_issued_max < 2**63 - 2):
        raise ValueError('Verified issued maximum is outside the supported range')
    actor, evidence = actor.strip(), evidence.strip()
    if (not actor or len(actor) > 64 or not evidence or len(evidence) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in actor + evidence)):
        raise ValueError('An operator and a non-sensitive evidence reference are required')
    with store.transaction() as cur:
        cur.execute('SELECT policy_version,policy_json FROM control_policy WHERE singleton_id=1 FOR UPDATE')
        row = cur.fetchone()
        if not row:
            raise RuntimeError('Policy not initialized')
        policy = domain_policy(decode(row['policy_json']))
        if policy['policyVersion'] != row['policy_version']:
            raise RuntimeError('Restored policy version is inconsistent')
        store._assert_no_policy_rollout(cur)
        next_version = max(store._next_policy_version(cur, policy), verified_issued_max + 1)
        if next_version >= 2**63 - 1:
            raise ApiProblem('POLICY_VERSION_EXHAUSTED', 'Policy version space exhausted.', 409)
        updated = {**policy, 'policyVersion': next_version, 'issuedAtUtc': timestamp(utcnow())}
        store._validate_effective_policy(updated)
        cur.execute('UPDATE control_policy SET policy_version=%s,policy_json=%s WHERE singleton_id=1',
                    (next_version, dumps(updated)))
        store._audit(cur, actor, 'RESTORED_POLICY_WATERMARK_ADVANCED', summary=dumps(dict(
            previousVersion=policy['policyVersion'], verifiedIssuedMax=verified_issued_max,
            newVersion=next_version, evidence=evidence)))
    return next_version
