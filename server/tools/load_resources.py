"""Unprivileged Linux process samples for an isolated load test.

Samples are numeric only. Remote MySQL and host-wide metrics require their own
collector; this module never treats missing data as zero or as a passed gate.
"""
import os
from pathlib import Path
import threading
import time


def process_sample(pid, proc_root=Path('/proc')):
    if type(pid) is not int or pid <= 0:
        raise ValueError('Invalid process ID')
    directory = proc_root / str(pid)
    stat = (directory / 'stat').read_text(encoding='utf-8')
    close = stat.rfind(')')
    if close < 0:
        raise ValueError('Invalid process stat')
    fields = stat[close + 2:].split()
    if len(fields) < 20:
        raise ValueError('Incomplete process stat')
    status = {}
    for line in (directory / 'status').read_text(encoding='utf-8').splitlines():
        key, sep, value = line.partition(':')
        if sep and key in ('VmRSS', 'VmSize', 'Threads'):
            status[key] = value.strip()
    def kib(key):
        value = status.get(key)
        if value is None:
            return None
        parts = value.split()
        if len(parts) != 2 or parts[1] != 'kB':
            raise ValueError('Invalid process memory unit')
        return int(parts[0]) * 1024
    try:
        descriptor_count = sum(1 for _ in (directory / 'fd').iterdir())
    except (OSError, PermissionError):
        descriptor_count = None
    return dict(pid=pid, startTicks=int(fields[19]), cpuTicks=int(fields[11]) + int(fields[12]),
                rssBytes=kib('VmRSS'), virtualBytes=kib('VmSize'),
                threads=int(status['Threads']) if 'Threads' in status else None,
                openDescriptors=descriptor_count)


def disk_sample(path):
    stats = os.statvfs(path)
    return dict(totalBytes=stats.f_blocks * stats.f_frsize,
                availableBytes=stats.f_bavail * stats.f_frsize,
                totalInodes=stats.f_files, availableInodes=stats.f_favail)


def sample(pids, disk_path, previous=None, proc_root=Path('/proc'), clock_ticks=None):
    now = time.monotonic()
    ticks = clock_ticks if clock_ticks is not None else os.sysconf('SC_CLK_TCK')
    result = dict(monotonicSeconds=now, processes=[], disk=None, errors=[])
    old = {item['pid']: item for item in (previous or {}).get('processes', [])}
    for pid in pids:
        try:
            item = process_sample(pid, proc_root)
            item['cpuPercent'] = None
            item['restarted'] = False
            prior = old.get(pid)
            if prior:
                item['restarted'] = item['startTicks'] != prior['startTicks']
                elapsed = now - previous['monotonicSeconds']
                delta = item['cpuTicks'] - prior['cpuTicks']
                if not item['restarted'] and elapsed > 0 and delta >= 0:
                    item['cpuPercent'] = 100 * delta / ticks / elapsed
            result['processes'].append(item)
        except (OSError, ValueError, IndexError):
            result['errors'].append(f'process_unavailable:{pid}')
    try:
        result['disk'] = disk_sample(disk_path)
    except OSError:
        result['errors'].append('disk_unavailable')
    return result


class ResourceMonitor:
    def __init__(self, pids, disk_path, interval=10, sampler=sample):
        if (not 1 <= len(pids) <= 32 or len(set(pids)) != len(pids)
                or any(type(pid) is not int or pid <= 0 for pid in pids)
                or not 10 <= interval <= 3600):
            raise ValueError('Invalid resource monitor parameters')
        self.pids, self.disk_path, self.interval, self.sampler = list(pids), disk_path, interval, sampler
        self.samples = []
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if self.thread is not None:
            raise RuntimeError('Resource monitor already started')

        def collect():
            previous = None
            while not self.stop_event.is_set() and len(self.samples) < 8641:
                try:
                    current = self.sampler(self.pids, self.disk_path, previous=previous)
                except Exception:
                    current = dict(monotonicSeconds=time.monotonic(), processes=[], disk=None,
                                   errors=['resource_sampler_failed'])
                self.samples.append(current)
                previous = current
                if self.stop_event.wait(self.interval):
                    break

        self.thread = threading.Thread(target=collect, name='synthetic-resource-monitor', daemon=True)
        self.thread.start()

    def stop(self):
        if self.thread is None:
            raise RuntimeError('Resource monitor not started')
        self.stop_event.set()
        self.thread.join(timeout=5)
        return dict(samples=list(self.samples), complete=not self.thread.is_alive(),
                    sampleLimitReached=len(self.samples) >= 8641,
                    limitations=['Remote database resources are not sampled',
                                 'Samples are not a capacity or availability verdict'])

    def latest(self):
        return self.samples[-1] if self.samples else None
