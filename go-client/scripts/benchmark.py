#!/usr/bin/env python3
"""Isolated native/SDK-host comparison. Never installs or attaches real Agent configs."""
import argparse
import concurrent.futures
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROUTE = "abcdefghijklmnopqrstuv"
PORT = 18080

def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))

class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True
    def log_message(self, *args):
        pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path.startswith("/v1/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for value in (b'data: {"text":"synthetic"}\n\n', b'data: [DONE]\n\n'):
                    self.wfile.write(value)
                    self.wfile.flush()
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
        else:
            response = json.dumps({"synthetic": True, "bytes": len(body)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

def ensure_free():
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", PORT))
        except OSError:
            raise RuntimeError("Port 18080 is in use; stop without modifying the running service.") from None

def isolated_env(root, upstream, auto_attach=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SF_PROXY_")}
    profile = root / "profile"
    profile.mkdir(parents=True, exist_ok=True)
    (profile / ".endpointai-e2e-profile").touch()
    if auto_attach:
        (profile / ".claude").mkdir(exist_ok=True)
        config = profile / ".claude/settings.json"
        if not config.exists():
            config.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://synthetic.example.invalid/v1"}}))
    env.update(SF_PROXY_CONTROL_ORIGIN="", SF_PROXY_AUTO_ATTACH=str(auto_attach).lower(), SF_PROXY_DATA_ROOT=str(root / "data"),
               SF_PROXY_E2E_PROFILE_ROOT=str(profile), SF_PROXY_BOOTSTRAP_UPSTREAM=upstream, SF_PROXY_BOOTSTRAP_ROUTE_ID=ROUTE,
               DOTNET_ENVIRONMENT="Development", ASPNETCORE_ENVIRONMENT="Development", SF_PROXY_ENVIRONMENT="Development",
               DOTNET_CLI_HOME=str(root / "dotnet-home"), DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
    return env

def health():
    with opener().open(f"http://127.0.0.1:{PORT}/healthz", timeout=1) as response:
        return json.load(response)

def start(command, root, upstream, auto_attach=False):
    ensure_free()
    log = (root / "process.log").open("wb")
    began = time.perf_counter()
    proc = subprocess.Popen([str(x) for x in command], env=isolated_env(root, upstream, auto_attach), stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Candidate exited before readiness; inspect isolated process.log locally.")
            try:
                value = health()
                if value.get("status") == "ok":
                    return proc, log, (time.perf_counter() - began) * 1000, value
            except (urllib.error.URLError, OSError, ValueError):
                pass
            time.sleep(0.02)
        raise RuntimeError("Candidate readiness timed out.")
    except BaseException:
        stop(proc, log)
        raise

def stop(proc, log):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    log.close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            ensure_free()
            return
        except RuntimeError:
            time.sleep(0.05)
    raise RuntimeError("Listener did not release port 18080.")

def cpu_seconds(text):
    days = 0
    if "-" in text:
        d, text = text.split("-", 1)
        days = int(d)
    total = 0.0
    for value in text.split(":"):
        total = total * 60 + float(value)
    return total + days * 86400

def sample(pid):
    fields = subprocess.check_output(["ps", "-p", str(pid), "-o", "rss=", "-o", "time="], text=True).split()
    if len(fields) != 2:
        raise RuntimeError("Process resource counters unavailable.")
    return int(fields[0]), cpu_seconds(fields[1])

def request(path, direct=None):
    base = direct if direct else f"http://127.0.0.1:{PORT}/r/{ROUTE}"
    req = urllib.request.Request(base + path, data=b'{"model":"synthetic","messages":[{"role":"user","content":"fixture"}]}',
                                 headers={"Content-Type": "application/json"}, method="POST")
    began = time.perf_counter()
    with opener().open(req, timeout=10) as response:
        first = response.read(1)
        first_ms = (time.perf_counter() - began) * 1000
        rest = response.read()
        if response.status != 200 or not first:
            raise RuntimeError("Synthetic request failed.")
    return {"first_byte_ms": first_ms, "complete_ms": (time.perf_counter() - began) * 1000, "bytes": len(first) + len(rest)}

def p95(values):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * 0.95))]

def scenario(concurrency, count, stream=False, direct=None):
    path = "/stream" if stream else "/chat/completions"
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        rows = list(pool.map(lambda _: request(path, direct), range(count)))
    return {"concurrency": concurrency, "requests": len(rows), "stream": stream,
            "p95_first_byte_ms": p95([r["first_byte_ms"] for r in rows]),
            "p95_complete_ms": p95([r["complete_ms"] for r in rows])}

def measure(name, command, upstream, idle_seconds, count):
    with tempfile.TemporaryDirectory(prefix="endpointai-benchmark-") as temp:
        root = Path(temp).resolve()
        proc, log, startup, status = start(command, root, upstream)
        try:
            time.sleep(2)
            before = sample(proc.pid)
            rss = []
            began = time.monotonic()
            while time.monotonic() - began < idle_seconds:
                rss.append(sample(proc.pid)[0])
                time.sleep(0.2)
            after = sample(proc.pid)
            idle_duration = time.monotonic() - began
            cases = []
            for concurrency in (1, 8, 32):
                cases.append(scenario(concurrency, count))
                cases.append(scenario(concurrency, max(16, count // 2), stream=True))
            expected = sum(case["requests"] for case in cases)
            deadline = time.monotonic() + 10
            while True:
                records = []
                for path in (root / "data/captures").rglob("*.jsonl*"):
                    reader = gzip.open if path.suffix == ".gz" else open
                    with reader(path, "rt") as stream:
                        for line in stream:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass  # A writer may still be finishing its final line.
                if len(records) >= expected or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            degraded = sum(bool(record.get("CaptureDegraded")) for record in records)
            if len(records) != expected or degraded:
                raise RuntimeError("Capture evidence is incomplete or degraded; comparison is invalid.")
            return {"implementation": name, "version": status.get("clientVersion"), "startup_ms": startup,
                    "idle_seconds": idle_duration, "median_idle_rss_kib": statistics.median(rss),
                    "idle_cpu_percent": max(0, after[1] - before[1]) / idle_duration * 100, "scenarios": cases,
                    "completed_capture_records": len(records), "degraded_capture_records": degraded,
                    "data": "temporary synthetic fixtures; control disabled; auto-attach=false"}
        finally:
            stop(proc, log)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--go", required=True, type=Path)
    ap.add_argument("--dotnet", type=Path)
    ap.add_argument("--dotnet-dll", type=Path)
    ap.add_argument("--idle-seconds", type=float, default=15)
    ap.add_argument("--requests", type=int, default=128)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    if bool(args.dotnet) != bool(args.dotnet_dll) or args.requests < 16 or args.idle_seconds <= 0:
        ap.error("Provide both .NET paths, at least 16 requests, and positive idle time.")
    ensure_free()
    class MockServer(http.server.ThreadingHTTPServer):
        request_queue_size = 128
        daemon_threads = True
    mock = MockServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    upstream = f"http://127.0.0.1:{mock.server_port}/v1"
    try:
        results = []
        if args.dotnet:
            results.append(measure("dotnet-sdk-host", [args.dotnet, args.dotnet_dll], upstream, args.idle_seconds, args.requests))
        failure = None
        try:
            results.append(measure("go-native", [args.go], upstream, args.idle_seconds, args.requests))
        except RuntimeError as error:
            failure = str(error)
        result = {"kind": "isolated-local-benchmark", "measured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "go_binary_sha256": hashlib.sha256(args.go.read_bytes()).hexdigest(),
                  "limitations": ["Single host; not native installation/IOA acceptance", ".NET launched through trusted SDK host, not standalone apphost", "4-hour soak not included"], "results": results, "candidate_failure": failure}
        if len(results) == 2:
            old, new = results
            result["idle_rss_reduction_percent"] = (1 - new["median_idle_rss_kib"] / old["median_idle_rss_kib"]) * 100
            result["p95_latency_deltas_ms"] = [{"concurrency": n["concurrency"], "stream": n["stream"], "first_byte": n["p95_first_byte_ms"] - o["p95_first_byte_ms"], "complete": n["p95_complete_ms"] - o["p95_complete_ms"]} for o, n in zip(old["scenarios"], new["scenarios"])]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"report": str(args.output), "implementations": len(results), "status": "blocked" if failure else "measured"}))
        if failure:
            raise SystemExit(1)
    finally:
        mock.shutdown()
        mock.server_close()

if __name__ == "__main__":
    main()
