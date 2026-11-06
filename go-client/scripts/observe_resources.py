"""Read-only directory accounting companion for native client soak tests (Python 3.9+).

Reports metadata only. Run alongside business/health observation; this tool cannot
establish an acceptance pass. Each minute continues a bounded metadata scan.
"""
import argparse
from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import time

GROUPS = {"captures": "captures", "serviceLogs": "logs", "state": "state",
          "configBackups": "config-backups", "diagnostics": "diagnostics"}


class DirectoryScanner:
    def __init__(self, root):
        self.root = Path(root)
        self.items = []
        self.next = 0
        self.reset()

    def reset(self):
        self.close()
        self.items = [dict(name=name, pending=deque([self.root / relative]), iterator=None,
                           status="scanning", fileCount=0, totalBytes=0, partialFileCount=0,
                           partialBytes=0, compressedFileCount=0, compressedBytes=0)
                      for name, relative in GROUPS.items()]
        self.started = datetime.now(timezone.utc).isoformat()

    def close(self):
        for item in self.items:
            if item["iterator"] is not None:
                item["iterator"].close()
                item["iterator"] = None

    def sample(self, budget_seconds=2):
        started = time.monotonic()
        while time.monotonic() - started < budget_seconds:
            if not any(i["status"] == "scanning" for i in self.items):
                break
            item = self.items[self.next]
            self.next = (self.next + 1) % len(self.items)
            if item["status"] != "scanning":
                continue
            try:
                if item["iterator"] is None:
                    if not item["pending"]:
                        item["status"] = "complete"
                        continue
                    directory = item["pending"].popleft()
                    try:
                        mode = directory.lstat().st_mode
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                        raise OSError("Unsafe or unavailable directory")
                    item["iterator"] = os.scandir(directory)
                entry = next(item["iterator"], None)
                if entry is None:
                    item["iterator"].close()
                    item["iterator"] = None
                    continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if len(item["pending"]) >= 4096:
                        raise OSError("Directory budget exceeded")
                    item["pending"].append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    item["fileCount"] += 1
                    item["totalBytes"] += info.st_size
                    for suffix, prefix in ((".partial", "partial"), (".gz", "compressed")):
                        if entry.name.endswith(suffix):
                            item[prefix + "FileCount"] += 1
                            item[prefix + "Bytes"] += info.st_size
                else:
                    raise OSError("Unsupported directory entry")
            except OSError:
                item["status"] = "unavailable"
                if item["iterator"] is not None:
                    item["iterator"].close()
                    item["iterator"] = None
        groups = {}
        for item in self.items:
            complete = item["status"] == "complete"
            groups[item["name"]] = dict(status=item["status"], complete=complete,
                                        partialScanFileCount=item["fileCount"])
            for key in ("fileCount", "totalBytes", "partialFileCount", "partialBytes",
                        "compressedFileCount", "compressedBytes"):
                groups[item["name"]][key] = item[key] if complete else None
        return dict(cycleStartedAtUtc=self.started, groups=groups,
                    scanComplete=all(i["status"] == "complete" for i in self.items),
                    scanElapsedMilliseconds=round((time.monotonic() - started) * 1000, 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--output", required=True, help="New JSONL file outside the client data root")
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--hours", type=float, default=8)
    args = parser.parse_args()
    if (len(args.package_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in args.package_sha256)
            or not 0 < args.hours <= 72):
        parser.error("Supply a SHA-256 digest and a duration in (0, 72] hours")
    root, output = Path(args.data_root).resolve(), Path(args.output).resolve()
    if output == root or root in output.parents or not root.is_dir():
        parser.error("The data root must exist; output must be outside it")
    scanner = DirectoryScanner(root)
    started = time.monotonic()
    os.umask(0o077)
    try:
        with output.open("x", encoding="utf-8") as stream:
            while True:
                elapsed = time.monotonic() - started
                usage = scanner.sample()
                sample = dict(atUtc=datetime.now(timezone.utc).isoformat(), elapsedSeconds=round(elapsed, 3),
                              packageSha256=args.package_sha256.lower(), directoryUsage=usage,
                              diskFreeBytes=shutil.disk_usage(root).free, resourceAccountingOnly=True)
                stream.write(json.dumps(sample) + "\n")
                stream.flush()
                if elapsed >= args.hours * 3600:
                    break
                time.sleep(min(60, max(0, args.hours * 3600 - (time.monotonic() - started))))
                if not any(i["status"] == "scanning" for i in scanner.items):
                    scanner.reset()
    finally:
        scanner.close()


if __name__ == "__main__":
    main()
