#!/usr/bin/env python3
"""Isolated four-hour signed-client gate; shorter runs are smoke tests only."""
import argparse
import base64
import concurrent.futures
import gzip
import http.server
import json
import os
from pathlib import Path
import re
import signal
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import hashlib

from benchmark import Upstream, ensure_free, health, isolated_env, opener, p95, sample, stop


def write_json(path, value):
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def terminate(proc, log):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if log is not None:
        log.close()


def fixtures(root, upstream, dsh_runtime=None):
    profile = root / "profile"
    profile.mkdir(mode=0o700)
    (profile / ".endpointai-e2e-profile").touch()
    (profile / ".claude").mkdir()
    (profile / ".codex").mkdir()
    (profile / ".claude/settings.json").write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": upstream}, "fixture": "preserved"}))
    (profile / ".codex/config.toml").write_text(f'openai_base_url = "{upstream}"\nmodel = "synthetic"\n')
    for command, package in (("claude", "@anthropic-ai/claude-code"), ("codex", "@openai/codex"), ("qoder", "@qoder-ai/qodercli")):
        command_path = profile / ".local/bin" / command
        command_path.parent.mkdir(parents=True, exist_ok=True)
        command_path.write_text("#!/bin/sh\nexit 0\n")
        command_path.chmod(0o700)
        manifest = profile / ".local/bin/node_modules" / package / "package.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"name": package, "version": "0.0.0-soak"}))
    if dsh_runtime is not None:
        dsh = profile / ".dsh/profiles/web"
        dsh.mkdir(parents=True)
        (dsh / "package.json").write_text(json.dumps({"dsh": {"profile": {"bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"]}}}))
        (dsh / "cordis.patch.yml").write_text(json.dumps([{"id": "llm-deepseek", "config": {"baseURL": upstream, "apiKeyEnv": "ENDPOINTAI_DSH_TEST_KEY"}}]))
        for package in ("@deepseek-ai/dsh", "@deepseek-ai/dsh-llm-pi-ai", "@earendil-works/pi-ai"):
            manifest = profile / ".local/bin/node_modules" / package / "package.json"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_bytes((dsh_runtime / "node_modules" / package / "package.json").read_bytes())
    expired = []
    for scope, name in (("captures/retention-fixture", "expired.md"), ("logs/service", "expired.jsonl")):
        path = root / "data" / scope / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic expired evidence\n")
        old = time.time() - 8 * 86400
        os.utime(path, (old, old))
        expired.append(path)
    fresh = root / "data/captures/retention-fixture/retained-fresh.md"
    fresh.write_text("synthetic retained evidence\n")
    return profile, expired, fresh


def routes(profile):
    claude = json.loads((profile / ".claude/settings.json").read_text())["env"]["ANTHROPIC_BASE_URL"]
    codex = re.search(r'^\s*openai_base_url\s*=\s*"([^"]+)"', (profile / ".codex/config.toml").read_text(), re.MULTILINE)
    if codex is None:
        raise RuntimeError("Isolated Codex endpoint missing.")
    values = [claude, codex.group(1)]
    dsh = profile / ".dsh/profiles/web/cordis.patch.yml"
    if dsh.exists():
        match = re.search(r'baseURL["\s]*:["\s]*(http://127\.0\.0\.1:18080/r/[A-Za-z0-9_-]{22})', dsh.read_text())
        if match is None:
            raise RuntimeError("Isolated DSH endpoint was not attached.")
        values.append(match.group(1))
    if any(re.fullmatch(r"http://127\.0\.0\.1:18080/r/[A-Za-z0-9_-]{22}", value) is None for value in values):
        raise RuntimeError("Isolated Agent configuration was not attached.")
    return values


def start_client(candidate, root, env):
    ensure_free()
    log = (root / "process.log").open("ab")
    proc = subprocess.Popen([str(candidate)], env=env, stdout=log, stderr=log)
    status = {}
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Signed candidate exited before readiness.")
            try:
                status = health()
                if status.get("status") == "ok" and status.get("policyVersion") == 2 and status.get("lastControlSyncAtUtc") and not status.get("lastControlErrorCode"):
                    routes(root / "profile")
                    return proc, log, status
            except (urllib.error.URLError, OSError, ValueError, RuntimeError):
                pass
            time.sleep(0.1)
        evidence = {name: status.get(name) for name in ("status", "policyVersion", "routeCount", "auditState", "lastControlErrorCode")}
        raise RuntimeError("Client readiness/configuration/control recovery timed out: " + json.dumps(evidence))
    except BaseException:
        stop(proc, log)
        raise


def start_control(helper, root, gateway_origin):
    key = os.urandom(32)
    path = root / "control.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key)
    ready = root / "control-ready.json"
    log = (root / "control.log").open("wb")
    proc = subprocess.Popen([str(helper), "--key-file", str(path), "--ready-file", str(ready), "--gateway-origin", gateway_origin], stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Isolated control helper exited before readiness.")
            if ready.exists():
                try:
                    origin = json.loads(ready.read_text())["origin"]
                    if re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", origin) is None:
                        raise RuntimeError("Control helper address must be loopback.")
                    control_stats(origin)
                    return proc, log, origin, base64.b64encode(key).decode()
                except (ValueError, urllib.error.URLError, OSError):
                    pass
            time.sleep(0.05)
        raise RuntimeError("Isolated control helper readiness timed out.")
    except BaseException:
        terminate(proc, log)
        raise


def control_stats(origin):
    with opener().open(origin + "/stats", timeout=3) as response:
        return json.load(response)


def load_request(base, stream):
    path = "/stream" if stream else "/chat/completions"
    request = urllib.request.Request(base + path, data=b'{"model":"synthetic","messages":[{"role":"user","content":"soak fixture"}]}',
                                     headers={"Content-Type": "application/json", "User-Agent": "endpointai-soak-fixture"}, method="POST")
    began = time.monotonic()
    with opener().open(request, timeout=10) as response:
        request_id = response.headers.get("x-request-id", "")
        if str(uuid.UUID(request_id)) != request_id:
            raise RuntimeError("Gateway response request ID is missing or malformed.")
        first = response.read(1)
        first_ms = (time.monotonic() - began) * 1000
        body = first + response.read()
        if response.status != 200 or not body:
            raise RuntimeError("Synthetic concurrent request failed.")
        if stream and b"data: [DONE]" not in body:
            raise RuntimeError("Synthetic SSE ended without its final event.")
        if not stream and json.loads(body).get("synthetic") is not True:
            raise RuntimeError("Synthetic JSON response was changed.")
    return {"stream": stream, "first_ms": first_ms, "complete_ms": (time.monotonic() - began) * 1000, "request_id": request_id}


def disk_sample(root):
    total = files = compressed = 0
    for directory, children, names in os.walk(root, followlinks=False):
        children[:] = [name for name in children if not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            try:
                if path.is_symlink():
                    continue
                total += path.stat().st_size
                files += 1
                if name.endswith(".md.gz") and name != "retained-fresh.md.gz":
                    compressed += 1
            except FileNotFoundError:
                pass  # Concurrent atomic compression/retention.
    return {"bytes": total, "files": files, "compressed_captures": compressed}


def capture_results(data, expected_ids):
    total = degraded = 0
    outcomes = {}
    ids = set()
    for path in (data / "captures/summary").glob("*.jsonl*"):
        reader = gzip.open if path.suffix == ".gz" else open
        with reader(path, "rt") as stream:
            for line in stream:
                record = json.loads(line)
                if record["RequestId"] in ids:
                    raise RuntimeError("Duplicate capture request ID.")
                ids.add(record["RequestId"])
                total += 1
                degraded += bool(record.get("CaptureDegraded"))
                outcome = record.get("Outcome", "unknown")
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
    if ids != expected_ids:
        raise RuntimeError("Gateway and capture request IDs are inconsistent.")
    return {"completed_records": total, "degraded_records": degraded, "outcomes": outcomes, "request_id_correlation_passed": True}


def trend(samples, field):
    if len(samples) < 2:
        return {"assessment": "insufficient samples"}
    width = max(1, len(samples) // 4)
    first = statistics.median(row[field] for row in samples[:width])
    last = statistics.median(row[field] for row in samples[-width:])
    return {"first_quarter_median": first, "last_quarter_median": last, "delta": last - first,
            "assessment": "measured; disk includes retained synthetic capture evidence" if field == "disk_bytes" else "measured across scheduled restarts"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--go", required=True, type=Path, help="Signed native client executable inside its development app")
    ap.add_argument("--control-helper", required=True, type=Path, help="Built cmd/soak-control helper; never a deployment payload")
    ap.add_argument("--dsh-runtime", type=Path, help="Installed fixed DSH npm fixture; adds a DSH route to the same four-hour gate")
    ap.add_argument("--hours", type=float, default=4)
    ap.add_argument("--sample-seconds", type=float, default=10)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--requests-per-round", type=int, default=16)
    ap.add_argument("--restarts", type=int, default=3)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--progress", type=Path, help="Compact running summary; defaults beside output")
    ap.add_argument("--progress-seconds", type=float, default=30)
    args = ap.parse_args()
    if args.hours <= 0 or args.sample_seconds <= 0 or args.progress_seconds <= 0 or args.restarts < 0 or args.concurrency < 2 or args.requests_per_round < 4:
        ap.error("Positive durations, at least two workers/four requests, and nonnegative restarts are required.")
    args.go, args.control_helper = args.go.resolve(), args.control_helper.resolve()
    if not args.go.is_file() or not args.control_helper.is_file():
        ap.error("Client and built control helper must exist.")
    args.output = args.output.resolve()
    args.progress = args.progress.resolve() if args.progress else args.output.with_name(args.output.stem + "-progress.json")
    timeline_path = args.output.with_suffix(".jsonl")
    if len({args.output, args.progress, timeline_path}) != 3 or any(path.exists() for path in (args.output, args.progress, timeline_path)):
        ap.error("Choose distinct unused output/progress/timeline paths; historical reports are preserved.")
    for path in (args.output, args.progress):
        path.parent.mkdir(parents=True, exist_ok=True)
    ensure_free()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    gateway_ids = set()
    gateway_lock = threading.Lock()
    class CheckedUpstream(Upstream):
        def do_POST(self):
            request_id = self.headers.get("x-request-id", "")
            try:
                valid = str(uuid.UUID(request_id)) == request_id
            except ValueError:
                valid = False
            if not valid or not self.headers.get("x-sf-userid") or self.headers.get("X-SF-AI-Request-Id") is not None or self.headers.get("X-SF-AI-User-Id") is not None:
                self.send_error(400, "Synthetic gateway metadata check failed")
                return
            with gateway_lock:
                if request_id in gateway_ids:
                    self.send_error(400, "Duplicate synthetic request ID")
                    return
                gateway_ids.add(request_id)
            super().do_POST()
        def end_headers(self):
            self.send_header("x-request-id", self.headers.get("x-request-id", ""))
            super().end_headers()
    class Mock(http.server.ThreadingHTTPServer):
        request_queue_size = 128
        daemon_threads = True
    mock = Mock(("127.0.0.1", 0), CheckedUpstream)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    upstream = f"http://127.0.0.1:{mock.server_port}/v1"
    report = {"kind": "isolated-soak" if args.hours >= 4 else "isolated-smoke", "requested_hours": args.hours,
              "status": "running", "duration_4h_completed": False, "elapsed_seconds": 0, "samples": 0, "restarts": 0,
              "requested_restarts": args.restarts, "concurrency": args.concurrency, "requests_per_round": args.requests_per_round,
              "native_installation_ioa_validation": "not performed", "failure": None,
              "binary_sha256": hashlib.sha256(args.go.read_bytes()).hexdigest(),
              "limitations": ["Temporary Agent profile and data; no service registration or real-user configuration", "Loopback encrypted mock control and synthetic upstream", "No production IOA, native installer or real Intel Mac acceptance"]}
    write_json(args.output, report)
    write_json(args.progress, report)
    proc = log = helper = helper_log = None
    rows, timings = [], {False: [], True: []}
    began = None
    cpu_completed = 0.0
    request_count = 0
    stats = {}
    failure = None
    with tempfile.TemporaryDirectory(prefix="endpointai-soak-") as temporary:
        root = Path(temporary).resolve()
        try:
            original = "https://synthetic.example.invalid/v1"
            profile, expired, fresh = fixtures(root, original, args.dsh_runtime)
            helper, helper_log, origin, key = start_control(args.control_helper, root, f"http://127.0.0.1:{mock.server_port}")
            env = isolated_env(root, upstream, auto_attach=True)
            for name in ("SF_PROXY_BOOTSTRAP_UPSTREAM", "SF_PROXY_BOOTSTRAP_ROUTE_ID"):
                env.pop(name, None)
            env.update(SF_PROXY_CONTROL_ORIGIN=origin, SF_PROXY_CONTROL_TOKEN="isolated-soak-enrollment",
                       SF_PROXY_CONTROL_HMAC_KEY=key, SF_PROXY_CONTROL_TRANSPORT_KEY=key, SF_PROXY_CONTROL_TRANSPORT_KEY_ID="soak")
            management_token = base64.urlsafe_b64encode(os.urandom(32)).decode()
            env.update(SF_PROXY_ENABLE_MANAGEMENT_API="true", SF_PROXY_MANAGEMENT_TOKEN=management_token)
            if args.dsh_runtime is not None:
                env["SF_PROXY_ENABLE_DSH"] = "true"
                report["dsh_included"] = True
                report["limitations"].append("DSH route stress uses synthetic HTTP calls; real DSH SDK parity has a separate report")
            del key
            proc, log, status = start_client(args.go, root, env)
            identity = status.get("deviceId")
            if not identity:
                raise RuntimeError("Persistent identity missing.")
            if any(path.exists() for path in expired):
                raise RuntimeError("Expired synthetic capture/log evidence was not cleaned.")
            report["retention_expired_capture_and_log_removed"] = True
            began, next_progress = time.monotonic(), time.monotonic()
            with timeline_path.open("x", encoding="utf-8") as timeline, concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                while time.monotonic() - began < args.hours * 3600:
                    round_began = time.monotonic()
                    status = health()
                    if proc.poll() is not None or helper.poll() is not None or status.get("status") != "ok" or status.get("deviceId") != identity or status.get("auditState") != "Healthy" or status.get("lastControlErrorCode"):
                        report["failure_evidence"] = {
                            "client_exit_code": proc.poll(), "helper_exit_code": helper.poll(),
                            "identity_unchanged": status.get("deviceId") == identity,
                            "health": {name: status.get(name) for name in ("status", "auditState", "policyVersion", "lastControlErrorCode")},
                        }
                        raise RuntimeError("Client/helper health, audit, control sync or persistent identity changed unexpectedly.")
                    bases = routes(profile)
                    futures = [pool.submit(load_request, bases[index % len(bases)], (index // len(bases)) % 2 == 1) for index in range(args.requests_per_round)]
                    for future in futures:
                        value = future.result()
                        timings[value["stream"]].append(value)
                        request_count += 1
                    rss, cpu = sample(proc.pid)
                    disk = disk_sample(root / "data")
                    previous = rows[-1] if rows else None
                    elapsed = time.monotonic() - began
                    total_cpu = cpu_completed + cpu
                    row = {"elapsed_seconds": elapsed, "rss_kib": rss, "cpu_seconds_total": total_cpu, "cpu_percent": None,
                           "disk_bytes": disk["bytes"], "disk_files": disk["files"], "compressed_captures": disk["compressed_captures"],
                           "audit_state": status.get("auditState"), "restart_index": report["restarts"], "completed_requests": request_count}
                    if previous:
                        row["cpu_percent"] = max(0, total_cpu - previous["cpu_seconds_total"]) / max(0.001, elapsed - previous["elapsed_seconds"]) * 100
                    rows.append(row)
                    timeline.write(json.dumps(row) + "\n")
                    timeline.flush()
                    report.update(elapsed_seconds=elapsed, samples=len(rows), completed_requests=request_count, latest=row)
                    if time.monotonic() >= next_progress:
                        stats = control_stats(origin)
                        report["control"] = stats
                        write_json(args.output, report)
                        write_json(args.progress, report)
                        next_progress = time.monotonic() + args.progress_seconds
                    if report["restarts"] < args.restarts and elapsed >= (report["restarts"] + 1) * args.hours * 3600 / (args.restarts + 1):
                        cpu_completed += sample(proc.pid)[1]
                        stop(proc, log)
                        proc = log = None
                        proc, log, restarted_status = start_client(args.go, root, env)
                        report["restarts"] += 1
                        if restarted_status.get("deviceId") != identity:
                            raise RuntimeError("Device identity changed across restart.")
                    pause = min(args.sample_seconds - (time.monotonic() - round_began), args.hours * 3600 - (time.monotonic() - began))
                    if pause > 0:
                        time.sleep(pause)
            stop(proc, log)
            proc = log = None
            stats = control_stats(origin)
            with gateway_lock:
                captures = capture_results(root / "data", gateway_ids)
            disk = disk_sample(root / "data")
            if captures["completed_records"] != request_count or captures["degraded_records"] or captures["outcomes"].get("SUCCESS", 0) != request_count or not disk["compressed_captures"]:
                raise RuntimeError("Completed capture evidence is incomplete, degraded or uncompressed.")
            if not fresh.exists() and not fresh.with_suffix(".md.gz").exists():
                raise RuntimeError("Fresh synthetic evidence was removed by retention.")
            counts = stats["counts"]
            if any(counts.get(name, 0) < 1 for name in ("enroll", "policy", "heartbeat", "assets", "events")) or stats["distinct_device_ids"] != 1 or counts["enroll"] != 1 or stats["max_agents"] < 2 or stats["max_endpoint_assets"] < 2 or stats["attached_endpoint_assets"] < 2:
                raise RuntimeError("Encrypted enrollment, policy, heartbeat, discovery/assets or event coverage is incomplete.")
            if report["restarts"] != args.restarts:
                raise RuntimeError("Requested restart coverage was not completed.")
            # Maintenance CLI correctly requires an administrator. Exercise the
            # authenticated management API against only our own temporary data,
            # with auto-attach disabled so restoration cannot race reattachment.
            env["SF_PROXY_AUTO_ATTACH"] = "false"
            proc, log, _ = start_client(args.go, root, env)
            detach = urllib.request.Request("http://127.0.0.1:18080/management/detach", data=b"", method="POST",
                                            headers={"Authorization": "Bearer " + management_token})
            with opener().open(detach, timeout=30) as response:
                detached = json.load(response)
            stop(proc, log)
            proc = log = None
            restored_claude = json.loads((profile / ".claude/settings.json").read_text())
            restored_codex = (profile / ".codex/config.toml").read_text()
            if detached.get("failures") or restored_claude["env"]["ANTHROPIC_BASE_URL"] != original or restored_claude.get("fixture") != "preserved" or f'openai_base_url = "{original}"' not in restored_codex:
                raise RuntimeError("Isolated configuration detach/restore did not complete.")
            if args.dsh_runtime is not None:
                restored_dsh = (profile / ".dsh/profiles/web/cordis.patch.yml").read_text()
                if original not in restored_dsh or "http://127.0.0.1:18080/r/" in restored_dsh:
                    raise RuntimeError("Isolated DSH detach/restore did not complete.")
                report["dsh_configuration_attach_restore"] = True
            report.update(captures=captures, control=stats, configuration_attach_restore=True,
                          restore_validation="authenticated management API, auto-attach disabled; administrator maintenance CLI not exercised",
                          identity_and_credential_survived_restarts=True, retained_fresh_evidence=True,
                          final_disk=disk, rss_min_kib=min(row["rss_kib"] for row in rows), rss_max_kib=max(row["rss_kib"] for row in rows),
                          disk_max_bytes=max(row["disk_bytes"] for row in rows), rss_trend=trend(rows, "rss_kib"), disk_trend=trend(rows, "disk_bytes"),
                          latency=[{"stream": stream, "requests": len(values), "p95_first_byte_ms": p95([value["first_ms"] for value in values]), "p95_complete_ms": p95([value["complete_ms"] for value in values])} for stream, values in timings.items() if values])
        except BaseException as error:
            failure = "Interrupted" if isinstance(error, KeyboardInterrupt) else f"{type(error).__name__}: {error}"
        finally:
            cleanup_failures = []
            if proc is not None:
                try:
                    stop(proc, log)
                except BaseException:
                    cleanup_failures.append("client_cleanup_failed")
            if helper is not None:
                try:
                    terminate(helper, helper_log)
                except BaseException:
                    cleanup_failures.append("control_helper_cleanup_failed")
            mock.shutdown()
            mock.server_close()
            if cleanup_failures:
                failure = failure or ", ".join(cleanup_failures)
    elapsed = time.monotonic() - began if began else 0
    report.update(elapsed_seconds=elapsed, failure=failure, status="failed" if failure else "passed",
                  duration_4h_completed=elapsed >= 4 * 3600 and failure is None,
                  completed_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), all_children_cleaned_up=True)
    write_json(args.output, report)
    write_json(args.progress, report)
    print(json.dumps({"report": str(args.output), "status": report["status"], "duration_4h_completed": report["duration_4h_completed"]}))
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
