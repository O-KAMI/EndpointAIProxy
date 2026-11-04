"""Bind explicit gray upgrades to reviewed native evidence and exact source inputs."""
import hashlib
import json
from pathlib import Path
import platform
import sys
import zipfile


def qualification(deployment):
    path = Path(deployment) / 'gray-upgrade-0.1.26.json'
    if path.is_symlink():
        raise RuntimeError('Linked gray qualification')
    result = json.loads(path.read_text(encoding='utf-8'))
    if (result.get('version') != '0.1.26' or result.get('channel') != 'gray-candidate'
            or result.get('fullRolloutAccepted') is not False
            or result.get('targetSchema') != 5 or not result.get('runtimeFiles') or not result.get('upgraderFiles')):
        raise RuntimeError('Invalid gray qualification')
    return result


def check_files(root, expected):
    root = Path(root).resolve()
    for name, digest in expected.items():
        path = root / name
        if (not path.resolve().is_relative_to(root) or path.is_symlink() or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise RuntimeError('Gray qualification source mismatch')


def qualified_source(server, deployment):
    result = qualification(deployment)
    check_files(server, result['runtimeFiles'])
    check_files(deployment, result['upgraderFiles'])
    return result


def qualified_execution(deployment):
    result = qualification(deployment)
    if sys.platform != 'linux' or platform.machine() not in result.get('validatedLinuxArchitectures', []):
        raise RuntimeError('Gray upgrade has not been qualified for this platform')
    check_files(deployment, result['upgraderFiles'])
    return result


def check_archive(archive, result):
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError('Duplicate gray archive inputs')
        for name, digest in result['runtimeFiles'].items():
            if name not in names or hashlib.sha256(source.read(name)).hexdigest() != digest:
                raise RuntimeError('Gray archive does not match native qualification')
