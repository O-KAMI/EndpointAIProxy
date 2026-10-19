#!/usr/bin/env python3
"""Balanced Go candidate comparison with unchanged synchronous capture semantics."""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import threading
import time
import benchmark as bench

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline', required=True, type=Path)
p.add_argument('--candidate', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--requests', type=int, default=128)
p.add_argument('--idle-seconds', type=float, default=10)
a = p.parse_args()
if a.requests < 16 or a.idle_seconds <= 0 or a.output.exists():
    p.error('At least 16 requests, positive idle duration and a new output path required')
bench.ensure_free()
class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True
server = Server(('127.0.0.1', 0), bench.Upstream)
threading.Thread(target=server.serve_forever, daemon=True).start()
report = {'kind': 'balanced-go-comparison', 'measured_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
          'binary_sha256': {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in [('baseline', a.baseline), ('candidate', a.candidate)]},
          'limitations': ['Single host, synthetic upstream; all fixes compared together, not logging-only attribution',
                          'CPU and RSS sampled during idle only; load CPU/RSS budget remains pending',
                          'Two balanced rounds are exploratory, not a stable release performance gate'], 'rounds': []}
try:
    for order in [('baseline', 'candidate'), ('candidate', 'baseline')]:
        measured = {}
        for name in order:
            measured[name] = bench.measure(name, [getattr(a, name).resolve()], f'http://127.0.0.1:{server.server_port}/v1', a.idle_seconds, a.requests)
        old, new = measured['baseline'], measured['candidate']
        report['rounds'].append({'order': list(order), 'results': measured,
            'idle_rss_delta_mib': (new['median_idle_rss_kib'] - old['median_idle_rss_kib']) / 1024,
            'idle_cpu_delta_percentage_points': new['idle_cpu_percent'] - old['idle_cpu_percent'],
            'p95_complete_deltas_ms': [{'concurrency': n['concurrency'], 'stream': n['stream'], 'delta': n['p95_complete_ms'] - o['p95_complete_ms']} for o, n in zip(old['scenarios'], new['scenarios'])]})
except Exception as error:
    report['failure_class'] = type(error).__name__
    raise
finally:
    server.shutdown()
    server.server_close()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
