"""Smoke-test the published native service without installing or auto-attaching."""
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request


def check(binary, dotnet=None):
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 18080))
        except OSError:
            raise RuntimeError('Port 18080 is occupied; no existing service was stopped.') from None
    with tempfile.TemporaryDirectory(prefix='native-smoke-', dir='/private/tmp/endpointai-mac-build') as temp:
        root = Path(temp)
        profiles = root/'isolated-profiles'
        profiles.mkdir()
        marker = profiles/'untouched.txt'
        marker.write_text('fixture')
        env = {k:v for k,v in os.environ.items() if not k.startswith('SF_PROXY_')}
        env.update(SF_PROXY_DATA_ROOT=str(root/'data'), SF_PROXY_E2E_PROFILE_ROOT=str(profiles),
                   SF_PROXY_AUTO_ATTACH='false', SF_PROXY_CONTROL_ORIGIN='')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with (root/'service.log').open('wb') as log:
            binary=Path(binary).resolve()
            command=[str(binary)] if dotnet is None else [str(Path(dotnet).resolve()),str(binary)+'.dll']
            process = subprocess.Popen(command+['--auto-attach=false'],
                                       env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic()+20
                health = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError('Isolated service exited before becoming healthy.')
                    try:
                        with opener.open('http://127.0.0.1:18080/healthz', timeout=1) as response:
                            health=json.load(response)
                        break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                assert health and health['status']=='ok' and health['clientVersion']=='0.1.22'
                assert health['routeCount']==0 and marker.read_text()=='fixture'
                executable=subprocess.check_output(['/bin/ps','-ww','-p',str(process.pid),'-o','comm='],text=True).strip()
                expected=str(binary) if dotnet is None else str(Path(dotnet).resolve())
                assert executable==expected, 'Process path format differs from expected host.'
                assert (root/'data/state/client.db').exists()
                mode='native apphost' if dotnet is None else 'SDK-hosted managed service (not standalone apphost validation)'
                print(f'PASS: {mode}, health version 0.1.22, SQLite, exact process path, no attachment/control network.')
            except Exception:
                log.flush()
                shutil.copyfile(root/'service.log', '/private/tmp/endpointai-mac-build/native-service-failure.log')
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)


if __name__ == '__main__':
    check(sys.argv[1], sys.argv[2] if len(sys.argv)>2 else None)
