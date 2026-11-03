"""Publication metadata exchange for manually coordinated synthetic partitions.

This file carries public test metadata only. A shared file is not an authenticated
coordination channel; clock identity, integrity and isolation need independent review.
"""
from datetime import datetime, timezone
import json
import math
import os
import time
from uuid import UUID

PROTOCOL = 'synthetic-publication-v1'
MAX_EVENT_BYTES = 4096


def identity(run_id, artifact_sha, scheduled_start):
    if str(UUID(run_id)) != run_id:
        raise ValueError('Invalid synthetic coordination identifier')
    datetime.strptime(scheduled_start, '%Y-%m-%dT%H:%M:%SZ')
    if len(artifact_sha) != 64 or any(c not in '0123456789abcdef' for c in artifact_sha):
        raise ValueError('Invalid artifact digest')
    return dict(protocol=PROTOCOL, runId=run_id, candidateArtifactSha256=artifact_sha,
                scheduledStartUtc=scheduled_start)


def write_event(path, expected, publication, wall=time.time, monotonic=time.monotonic):
    # The synthetic policy publisher reports times on its process monotonic clock.
    # A local wall/monotonic anchor allows other hosts to estimate those times.
    anchor_mono = monotonic()
    anchor_wall = wall()
    event = dict(**expected, policyVersion=publication['version'],
                 startedUnixSeconds=anchor_wall + publication['started'] - anchor_mono,
                 completedUnixSeconds=anchor_wall + publication['completed'] - anchor_mono)
    validate_event(event, expected)
    data = json.dumps(event, separators=(',', ':'), allow_nan=False).encode('utf-8')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return event


def validate_event(event, expected):
    if not isinstance(event, dict) or set(event) != set(expected) | {'policyVersion', 'startedUnixSeconds', 'completedUnixSeconds'}:
        raise ValueError('Invalid publication event')
    if any(event[key] != value for key, value in expected.items()):
        raise ValueError('Publication event does not match the coordinated run')
    start, end, version = event['startedUnixSeconds'], event['completedUnixSeconds'], event['policyVersion']
    if (type(version) is not int or version < 1 or type(start) not in (int, float) or type(end) not in (int, float)
            or not math.isfinite(start) or not math.isfinite(end) or not 0 <= end - start <= 3600):
        raise ValueError('Invalid publication timing or version')
    scheduled = datetime.strptime(expected['scheduledStartUtc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    if not scheduled - 60 <= start <= scheduled + 86_400:
        raise ValueError('Publication time is outside the scheduled run window')


def read_event(path, expected, wall=time.time, monotonic=time.monotonic):
    try:
        flags = os.O_RDONLY
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError('Publication event exceeds size limit')
    # The exclusive-create writer may still be flushing; retry incomplete JSON.
    try:
        event = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    validate_event(event, expected)
    anchor_wall = wall()
    anchor_mono = monotonic()
    return dict(version=event['policyVersion'],
                started=anchor_mono + event['startedUnixSeconds'] - anchor_wall,
                completed=anchor_mono + event['completedUnixSeconds'] - anchor_wall,
                evidence=event)
