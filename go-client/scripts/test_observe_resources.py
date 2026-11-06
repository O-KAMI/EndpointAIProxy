import tempfile
from pathlib import Path
import unittest

from observe_resources import DirectoryScanner


class ResourceAccountingTests(unittest.TestCase):
    def test_totals_and_unavailable_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "captures/nested").mkdir(parents=True)
            (root / "captures/body.gz").write_bytes(b"1234")
            (root / "captures/nested/body.partial").write_bytes(b"567")
            (root / "state").write_bytes(b"not a directory")
            scanner = DirectoryScanner(root)
            try:
                usage = scanner.sample()
                captures = usage["groups"]["captures"]
                self.assertEqual((captures["fileCount"], captures["totalBytes"]), (2, 7))
                self.assertEqual((captures["partialBytes"], captures["compressedBytes"]), (3, 4))
                self.assertEqual(usage["groups"]["state"]["status"], "unavailable")
                self.assertIsNone(usage["groups"]["state"]["totalBytes"])
                self.assertEqual(usage["groups"]["diagnostics"]["totalBytes"], 0)
                self.assertFalse(usage["scanComplete"])
            finally:
                scanner.close()

    def test_budget_exhaustion_does_not_report_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            scanner = DirectoryScanner(temporary)
            try:
                usage = scanner.sample(budget_seconds=0)
                self.assertFalse(usage["scanComplete"])
                self.assertIsNone(usage["groups"]["captures"]["totalBytes"])
                usage = scanner.sample()
                self.assertTrue(usage["scanComplete"])
            finally:
                scanner.close()


if __name__ == "__main__":
    unittest.main()
