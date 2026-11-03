"""Bounded, reproducible heartbeat schedule for isolated load tests."""
import heapq
import math
import random


class HeartbeatSchedule:
    def __init__(self, count, start, interval=60.0, seed=0, initial_spread=None):
        if (not 1 <= count <= 150_000 or not 1 <= interval <= 3600
                or (initial_spread is not None and not 0 <= initial_spread <= 3600)):
            raise ValueError('Invalid synthetic schedule')
        self.interval = float(interval)
        spread = self.interval if initial_spread is None else initial_spread
        rng = random.Random(seed)
        self.heap = [(float(start) + rng.random() * spread, ordinal, 0)
                     for ordinal in range(count)]
        self.phases = [entry[0] for entry in self.heap]
        heapq.heapify(self.heap)

    def pop_due(self, now, limit):
        """Return at most limit events, preserving overdue events for later processing."""
        if limit < 1:
            raise ValueError('Limit must be positive')
        result = []
        while self.heap and self.heap[0][0] <= now and len(result) < limit:
            due, ordinal, cycle = heapq.heappop(self.heap)
            result.append((due, ordinal, cycle))
            heapq.heappush(self.heap, (due + self.interval, ordinal, cycle + 1))
        return result

    def next_due(self):
        return self.heap[0][0]

    def expected_by(self, deadline):
        return sum(0 if first > deadline else int((deadline - first) // self.interval) + 1
                   for first in self.phases)

    def reconnect(self, outage_start, recovery, spread, seed=0):
        """Rephase every device at recovery and count scheduled offline events."""
        if recovery <= outage_start or not 0 <= spread <= 3600:
            raise ValueError('Invalid reconnect window')
        rng = random.Random(seed)
        entries = []
        suppressed = 0
        for due, ordinal, cycle in self.heap:
            before = max(0, math.ceil((outage_start - due) / self.interval))
            first_offline = due + before * self.interval
            offline = max(0, math.ceil((recovery - first_offline) / self.interval))
            suppressed += offline
            entries.append((recovery + rng.random() * spread, ordinal, cycle + before + offline))
        self.heap = entries
        self.phases = [entry[0] for entry in entries]
        heapq.heapify(self.heap)
        return suppressed
