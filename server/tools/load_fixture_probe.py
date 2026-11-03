"""Measure synthetic request construction only; never connects to a server."""
import argparse
import base64
import json
import time
from uuid import uuid4

from controlserver.transport import seal
from tools.load_devices import heartbeat
from tools.load_transport import FIXTURE_ENROLLMENT_TOKEN, FIXTURE_KEY, FIXTURE_KEY_ID


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=5000)
    args = parser.parse_args(argv)
    if not 1 <= args.requests <= 150_000:
        parser.error('Request count must be between 1 and 150000')
    started, cpu = time.perf_counter(), time.process_time()
    total_bytes = 0
    for ordinal in range(args.requests):
        body = json.dumps(heartbeat(ordinal, 2, True), separators=(',', ':')).encode()
        inner = dict(method='POST', path='/api/v2/heartbeat/light', query='',
                     token=FIXTURE_ENROLLMENT_TOKEN, body=base64.b64encode(body).decode())
        envelope = seal(FIXTURE_KEY, FIXTURE_KEY_ID, str(uuid4()), inner, 'request')
        total_bytes += len(json.dumps(envelope, separators=(',', ':')).encode())
    elapsed = time.perf_counter() - started
    print(json.dumps(dict(requests=args.requests, wallSeconds=elapsed, cpuSeconds=time.process_time()-cpu,
                          requestsPerSecond=args.requests/elapsed, meanWireBytes=total_bytes/args.requests,
                          scope='single process construction only; no HTTP, response, database or capacity verdict')))


if __name__ == '__main__':
    main()
