from pathlib import Path

import pytest
from tools import load_resources


def write_process(root, pid, cpu=20, start=300, rss='123 kB'):
    directory = root / str(pid)
    directory.mkdir(exist_ok=True)
    fields = ['S'] + ['0'] * 19
    fields[11], fields[12], fields[19] = str(cpu), '5', str(start)
    (directory / 'stat').write_text(f'{pid} (fixture name with ) bracket) ' + ' '.join(fields), encoding='utf-8')
    (directory / 'status').write_text(f'Name: fixture\nVmRSS: {rss}\nVmSize: 456 kB\nThreads: 3\n', encoding='utf-8')
    (directory / 'fd').mkdir(exist_ok=True)
    (directory / 'fd' / '1').touch()
    return directory


def test_process_and_cpu_deltas_and_pid_reuse(tmp_path, monkeypatch):
    root = tmp_path / 'proc'
    root.mkdir()
    write_process(root, 123)
    times = iter([10.0, 12.0, 14.0])
    monkeypatch.setattr(load_resources.time, 'monotonic', lambda: next(times))
    monkeypatch.setattr(load_resources, 'disk_sample', lambda path: {'availableBytes': 100})
    first = load_resources.sample([123], tmp_path, proc_root=root, clock_ticks=100)
    assert first['processes'][0]['rssBytes'] == 123 * 1024
    assert first['processes'][0]['openDescriptors'] == 1
    assert first['processes'][0]['cpuPercent'] is None
    write_process(root, 123, cpu=220)
    second = load_resources.sample([123], tmp_path, previous=first, proc_root=root, clock_ticks=100)
    assert second['processes'][0]['cpuPercent'] == 100
    write_process(root, 123, cpu=2, start=999)
    third = load_resources.sample([123], tmp_path, previous=second, proc_root=root, clock_ticks=100)
    assert third['processes'][0]['restarted'] is True
    assert third['processes'][0]['cpuPercent'] is None


def test_missing_process_and_disk_are_not_treated_as_zero(tmp_path, monkeypatch):
    def fail_disk(path):
        raise OSError('synthetic failure')
    monkeypatch.setattr(load_resources, 'disk_sample', fail_disk)
    sample = load_resources.sample([456], tmp_path, proc_root=tmp_path, clock_ticks=100)
    assert sample['processes'] == [] and sample['disk'] is None
    assert set(sample['errors']) == {'process_unavailable:456', 'disk_unavailable'}


def test_invalid_units_and_pid_rejected(tmp_path):
    write_process(tmp_path, 12, rss='42 MB')
    with pytest.raises(ValueError):
        load_resources.process_sample(12, tmp_path)
    with pytest.raises(ValueError):
        load_resources.process_sample(0, tmp_path)


def test_monitor_reports_samples_and_sampler_failures(tmp_path):
    def broken(*args, **kwargs):
        raise OSError('unavailable')
    monitor = load_resources.ResourceMonitor([123], tmp_path, sampler=broken)
    monitor.start()
    monitor.thread.join(timeout=0.05)
    result = monitor.stop()
    assert result['complete'] is True
    assert result['samples'][0]['errors'] == ['resource_sampler_failed']
    assert monitor.latest()['errors'] == ['resource_sampler_failed']
    with pytest.raises(ValueError):
        load_resources.ResourceMonitor([123, 123], tmp_path)
