#!/usr/bin/env python3
"""Balanced, persistent-connection synthetic benchmark; no installed service is changed."""
import argparse,gzip,hashlib,json,statistics,subprocess,tempfile,threading,time,shutil
from pathlib import Path
import benchmark as old

def captures(root,expected):
    deadline=time.monotonic()+60
    while True:
        rows=[]
        for path in (root/'data/captures/summary').glob('*.jsonl*'):
            if path.suffix not in ('.jsonl','.gz'):continue
            reader=gzip.open if path.suffix=='.gz' else open
            try:
                with reader(path,'rt') as stream:
                    for line in stream:
                        try:rows.append(json.loads(line))
                        except json.JSONDecodeError:pass
            except FileNotFoundError:continue
        if len(rows)>=expected or time.monotonic()>deadline:break
        time.sleep(.2)
    if len(rows)!=expected or any(x.get('CaptureDegraded') for x in rows) or len({x['RequestId'] for x in rows})!=expected:
        raise RuntimeError('CAPTURE_COMPLETENESS_FAILED')
    return {'completed':len(rows),'degraded':0,'distinct_request_ids':expected}

def load(a,url,scenario,c,*,duration=0,requests=None,warmup=None,rps=0):
    command=[str(a.lab),'--mode=load','--url='+url,'--scenario='+scenario,'--concurrency='+str(c),'--requests='+str(requests or a.requests),'--warmup='+str(a.warmup if warmup is None else warmup),'--duration='+str(duration)+'s','--rps='+str(rps)]
    done=subprocess.run(command,capture_output=True,text=True,timeout=max(180,duration+120))
    if done.returncode:
        failure={'scenario':scenario,'concurrency':c,'returncode':done.returncode,'stdout':done.stdout[-8192:],'stderr':done.stderr[-8192:]}
        a.output.with_suffix('.load-failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        raise RuntimeError('SYNTHETIC_LOAD_FAILED')
    result=json.loads(done.stdout)
    if result['failures'] or result['requests']<(requests or a.requests):raise RuntimeError('SYNTHETIC_REQUESTS_FAILED')
    return result

def measure(a,name,command,origin):
    # Preserve isolated synthetic evidence on failure; no real profiles or credentials.
    temporary=tempfile.mkdtemp(prefix='endpointai-stable-')
    completed=False
    try:
        root=Path(temporary).resolve();proc,log,startup,health=old.start(command,root,origin)
        halt=threading.Event();samples=[]
        def sample_loop():
            while not halt.is_set():
                try:samples.append((time.monotonic(),*old.sample(proc.pid)))
                except (OSError,subprocess.SubprocessError):pass
                halt.wait(1)
        sampler=threading.Thread(target=sample_loop);sampler.start()
        try:
            target=f'http://127.0.0.1:18080/r/{old.ROUTE}'
            # Sustained activity reaches the candidate's busy-compression threshold.
            busy=load(a,target,'json',8,duration=a.busy_seconds,requests=max(100,a.busy_seconds*32),warmup=100,rps=32)
            expected=busy['requests']+busy['warmup_requests']
            load_began=time.monotonic();cpu_start=old.sample(proc.pid)[1]
            cases=[]
            for c in (1,8,32):
                for scenario in ('json','sse','large'):
                    row=load(a,target,scenario,c);cases.append(row);expected+=row['requests']+row['warmup_requests']
            elapsed=time.monotonic()-load_began;cpu_end=old.sample(proc.pid)[1]
            evidence=captures(root,expected)
            result={'name':name,'version':health.get('clientVersion'),'startup_ms':startup,'cases':cases,'sustained_busy':busy,'load_cpu_percent':max(0,cpu_end-cpu_start)/elapsed*100,'rss_median_mib':statistics.median(x[1] for x in samples)/1024,'rss_peak_mib':max(x[1] for x in samples)/1024,'capture_validation':evidence,'capture_settings':'production defaults; synchronous body finalization and per-record write-through summary'}
            completed=True
            return result
        except Exception:
            evidence=a.output.with_suffix('.service-failure.json')
            evidence.write_text(json.dumps({'implementation':name,'scenario_root':str(root),'process_exit':proc.poll(),'completed_cases':cases if 'cases' in locals() else []},indent=2)+'\n')
            raise
        finally:
            halt.set();sampler.join();old.stop(proc,log)
    finally:
        if completed:shutil.rmtree(temporary)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('candidate','baseline','dotnet','dotnet-dll','lab','output'):p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--rounds',type=int,default=5);p.add_argument('--requests',type=int,default=1000);p.add_argument('--warmup',type=int,default=100);p.add_argument('--busy-seconds',type=int,default=65)
    a=p.parse_args()
    if a.output.exists() or a.requests<16 or a.rounds<1 or a.warmup<0 or a.busy_seconds<0:p.error('Invalid limits or existing output')
    old.ensure_free();server=subprocess.Popen([str(a.lab),'--mode=serve'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    report={'kind':'balanced-persistent-go-load','status':'running','rounds':[],'requests_per_case_minimum':a.requests,'full_measurement':a.rounds>=5 and a.requests>=1000 and a.busy_seconds>60,'hashes':{n:hashlib.sha256(getattr(a,n).read_bytes()).hexdigest() for n in ('candidate','baseline','dotnet_dll','lab')},'limitations':['Synthetic loopback, SDK-hosted .NET; no native Windows/IOA or production gateway','Includes all candidate changes; not a logging-only isolation','Byte-delivery latency and capture completion are checked separately','Small-RPS soak is independent of this load benchmark']}
    def save():
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    try:
        origin=json.loads(server.stdout.readline())['origin']
        baseline_failed=False
        for number in range(a.rounds):
            direct=[load(a,origin,s,c) for c in (1,8,32) for s in ('json','sse','large')]
            order=['dotnet','baseline','candidate'] if number%2==0 else ['candidate','baseline','dotnet']
            result={'index':number+1,'direct':direct,'order':order,'implementations':{}}
            report['rounds'].append(result);save()
            for name in order:
                command=[a.dotnet,a.dotnet_dll] if name=='dotnet' else [getattr(a,name)]
                if name=='baseline' and baseline_failed:
                    result['implementations'][name]={'status':'skipped-after-reference-failure'};save();continue
                try:
                    result['implementations'][name]=measure(a,name,command,origin)
                except RuntimeError:
                    if name!='baseline':raise
                    # A broken historical Go reference does not invalidate the
                    # independently measured candidate-versus-.NET gate.
                    baseline_failed=True
                    result['implementations'][name]={'status':'failed','evidence':a.output.with_suffix('.service-failure.json').name}
                save()
            candidate=result['implementations']['candidate'];baseline=result['implementations']['baseline'];dotnet=result['implementations']['dotnet']
            result['deltas']=[{'scenario':n['scenario'],'concurrency':n['concurrency'],'candidate_minus_dotnet_p95_ms':n['p95_last_byte_ms']-d['p95_last_byte_ms'],'candidate_minus_baseline_go_p95_ms':n['p95_last_byte_ms']-b['p95_last_byte_ms'] if b else None} for n,b,d in zip(candidate['cases'],baseline.get('cases',[None]*len(candidate['cases'])),dotnet['cases'])];save()
        report['status']='measured'
        deltas=[x['candidate_minus_dotnet_p95_ms'] for r in report['rounds'] for x in r['deltas']]
        report['dotnet_5ms_gate']='passed' if report['full_measurement'] and max(deltas)<=5 else 'not-passed-or-incomplete'
        report['max_dotnet_p95_delta_ms']=max(deltas);report['observability_isolated_budget']='not established by all-changes comparison'
    except Exception as e:report['status']='failed';report['failure_type']=type(e).__name__;raise
    finally:
        server.terminate()
        try:server.wait(timeout=5)
        except subprocess.TimeoutExpired:server.kill();server.wait()
        save()
if __name__=='__main__':main()
