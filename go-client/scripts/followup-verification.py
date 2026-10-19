#!/usr/bin/env python3
"""Run the four-hour functional gate after the exclusive-port performance suite."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ('performance-report','go','control-helper','dsh-runtime','soak-output','output'):p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
if a.output.exists() or a.soak_output.exists():p.error('Historical verification outputs are immutable')
report={'status':'running','phase':'waiting-for-performance','binary_sha256':hashlib.sha256(a.go.read_bytes()).hexdigest(),'performance_report':a.performance_report.name,'soak_report':a.soak_output.name}
def save():a.output.write_text(json.dumps(report,indent=2)+'\n')
save();deadline=time.monotonic()+7200
try:
    while True:
        if a.performance_report.exists():
            try:performance=json.loads(a.performance_report.read_text())
            except json.JSONDecodeError:performance={}
            status=performance.get('status')
            if status=='failed':raise RuntimeError('PERFORMANCE_EXECUTION_FAILED')
            if status=='measured':
                if performance.get('hashes',{}).get('candidate')!=report['binary_sha256']:raise RuntimeError('CANDIDATE_HASH_CHANGED')
                report['performance_gate']=performance.get('dotnet_5ms_gate');break
        if time.monotonic()>deadline:raise RuntimeError('PERFORMANCE_WAIT_EXPIRED')
        time.sleep(30)
    report['phase']='four-hour-soak';save()
    cmd=['python3',str(Path(__file__).with_name('soak.py')),'--go',str(a.go),'--control-helper',str(a.control_helper),'--dsh-runtime',str(a.dsh_runtime),'--hours','4','--sample-seconds','10','--restarts','3','--output',str(a.soak_output)]
    result=subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if result.returncode:raise RuntimeError('SOAK_EXECUTION_FAILED')
    soak=json.loads(a.soak_output.read_text())
    if not soak.get('duration_4h_completed') or soak.get('status')!='passed' or soak.get('binary_sha256')!=report['binary_sha256']:raise RuntimeError('SOAK_NOT_PASSED')
    report.update(status='completed',phase='finished',functional_soak='passed',release_acceptance='pending native Windows/Mac and independent observability budget; see performance gate')
except Exception as e:report.update(status='failed',failure_code=str(e) if str(e).isupper() else type(e).__name__);raise
finally:save()
