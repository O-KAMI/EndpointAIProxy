"""Local synthetic checks; never starts the endpoint client or uses production credentials."""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from benchmark import sample
from soak import check_sample_continuity, control_event_queue_sample, control_stats, control_sync_fresh, protect_fixture_root, start_control, terminate


class SoakContinuityTests(unittest.TestCase):
    def test_event_queue_samples_are_bounded_and_do_not_copy_payloads(self):
        queue = dict(memoryDepth=3, persistedDepth=2, capacity=1000,
                     memoryBaselineLoaded=True, persistedReadStatus='available', payload='synthetic-private-event')
        sample = control_event_queue_sample({'controlEventQueue': queue})
        self.assertEqual(sample['memoryDepth'], 3)
        self.assertEqual(sample['persistedDepth'], 2)
        self.assertNotIn('payload', sample)
        queue['memoryDepth'] = 2000
        self.assertEqual(control_event_queue_sample({'controlEventQueue': queue})['memoryDepth'], 2000)
        queue.update(persistedReadStatus='unavailable', persistedDepth=None)
        self.assertIsNone(control_event_queue_sample({'controlEventQueue': queue})['persistedDepth'])
        self.assertIsNone(control_event_queue_sample({}))
        for field, value in (('memoryDepth', True), ('memoryDepth', 2001), ('capacity', 999),
                             ('persistedReadStatus', 'synthetic-secret-status'), ('memoryBaselineLoaded', 1)):
            with self.subTest(field=field):
                damaged = dict(queue); damaged[field] = value
                self.assertIsNone(control_event_queue_sample({'controlEventQueue': damaged}))

    def test_control_sync_must_be_recent_and_well_formed(self):
        now = datetime(2026, 11, 3, tzinfo=timezone.utc)
        for seconds, expected in ((0, True), (600, True), (601, False), (-60, True), (-61, False)):
            with self.subTest(seconds=seconds):
                status = {"lastControlSyncAtUtc": (now - timedelta(seconds=seconds)).isoformat()}
                self.assertEqual(control_sync_fresh(status, now), expected)
        for status in ({}, {"lastControlSyncAtUtc": None}, {"lastControlSyncAtUtc": "bad"},
                       {"lastControlSyncAtUtc": "2026-11-03T00:00:00"},
                       {"lastControlSyncAtUtc": now.isoformat(), "lastControlErrorCode": "SYNC_FAILED"}):
            with self.subTest(status=status):
                self.assertFalse(control_sync_fresh(status, now))

    def test_regular_samples_include_start_and_end(self):
        result = check_sample_continuity([(0, 1000), (10, 1010), (20, 1020), (30, 1030)], 10)
        self.assertEqual(result["max_gap_seconds"], 10)
        self.assertEqual(result["allowed_gap_seconds"], 70)

    def test_long_gap_and_missing_end_sampling_fail(self):
        with self.assertRaisesRegex(RuntimeError, "Sampling gap"):
            check_sample_continuity([(0, 1000), (10, 1010), (81, 1081)], 10)

    def test_suspend_or_clock_change_fails(self):
        for points in ([(0, 1000), (10, 1100)], [(0, 1000), (10, 990)]):
            with self.subTest(points=points), self.assertRaisesRegex(RuntimeError, "clock changed"):
                check_sample_continuity(points, 10)


@unittest.skipUnless(os.name == "nt", "Windows-only resource and ACL checks")
class WindowsSoakSupportTests(unittest.TestCase):
    def test_sample_current_synthetic_process(self):
        rss, cpu = sample(os.getpid())
        self.assertGreater(rss, 0)
        self.assertGreaterEqual(cpu, 0)

    def test_private_fixture_key_is_accepted_by_helper(self):
        helper = os.environ.get("ENDPOINTAI_SOAK_TEST_HELPER")
        if not helper:
            self.skipTest("Synthetic control helper path not supplied")
        with tempfile.TemporaryDirectory(prefix="endpointai-helper-test-") as temporary:
            root = Path(temporary).resolve()
            protect_fixture_root(root)
            process, log, origin, _ = start_control(Path(helper), root, "http://127.0.0.1:1")
            try:
                self.assertIsInstance(control_stats(origin), dict)
            finally:
                terminate(process, log)


if __name__ == "__main__":
    unittest.main()
