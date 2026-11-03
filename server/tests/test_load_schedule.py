from collections import Counter

import pytest

from tools.load_schedule import HeartbeatSchedule


def test_100k_devices_have_one_event_per_cycle_and_stable_phases():
    schedule = HeartbeatSchedule(100_000, start=1000, interval=60, seed=17)
    first = schedule.pop_due(1060, 100_001)
    second = schedule.pop_due(1120, 100_001)
    assert len(first) == len(second) == 100_000
    assert len({ordinal for _, ordinal, _ in first}) == 100_000
    assert all(cycle == 0 for _, _, cycle in first)
    assert all(cycle == 1 for _, _, cycle in second)
    first_by_device = {ordinal: due for due, ordinal, _ in first}
    assert all(abs(due - first_by_device[ordinal] - 60) < 1e-9 for due, ordinal, _ in second)
    per_second = Counter(int(due - 1000) for due, _, _ in first)
    assert len(per_second) == 60
    assert max(per_second.values()) < 2000


def test_limited_reads_preserve_overdue_events_without_silent_loss():
    schedule = HeartbeatSchedule(100, 0, interval=60, seed=3)
    chunks = [schedule.pop_due(60, 7) for _ in range(15)]
    events = [event for chunk in chunks for event in chunk]
    assert len(events) == 100
    assert len({ordinal for _, ordinal, _ in events}) == 100
    assert schedule.next_due() > 60


def test_schedules_are_reproducible_and_validate_bounds():
    first = HeartbeatSchedule(10, 5, seed=42)
    second = HeartbeatSchedule(10, 5, seed=42)
    assert first.pop_due(65, 10) == second.pop_due(65, 10)
    with pytest.raises(ValueError):
        HeartbeatSchedule(150_001, 0)
    with pytest.raises(ValueError):
        first.pop_due(65, 0)


def test_outage_rephases_every_device_with_bounded_reconnect_spread():
    schedule = HeartbeatSchedule(1000, 0, interval=60, seed=1)
    prior = schedule.pop_due(30, 1000)
    suppressed = schedule.reconnect(30, 90, spread=5, seed=4)
    assert suppressed == 1000
    assert schedule.pop_due(89.9, 1000) == []
    resumed = schedule.pop_due(95, 1000)
    assert len(resumed) == len({event[1] for event in resumed}) == 1000
    assert all(90 <= due <= 95 for due, _, _ in resumed)
    assert len(prior) + schedule.expected_by(95) == len(prior) + 1000


def test_concentrated_startup_emits_all_100k_at_once():
    schedule = HeartbeatSchedule(100_000, start=1000, interval=60, seed=9, initial_spread=0)
    initial = schedule.pop_due(1000, 100_000)
    assert len(initial) == 100_000
    assert all(due == 1000 and cycle == 0 for due, _, cycle in initial)
    assert schedule.next_due() == 1060
