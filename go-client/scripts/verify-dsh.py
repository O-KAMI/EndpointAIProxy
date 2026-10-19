#!/usr/bin/env python3
"""Real DSH SDK request parity with synthetic credentials, temporary profiles and loopback upstream."""
import argparse,hashlib,http.server,json,os,re,shutil,subprocess,tempfile,threading,time,urllib.request
from pathlib import Path
from benchmark import ensure_free,health,isolated_env,opener,stop

class Mock(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    rows=[]
    lock=threading.Lock()
    def log_message(self,*args):pass
    def reply(self,value,status=200):
        data=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def record(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length','0')))
        with self.lock:self.rows.append({'method':self.command,'path':self.path,'body':raw,'headers':{k.lower():v for k,v in self.headers.items()}})
        return raw
    def do_GET(self):
        self.record()
        if '/files/' in self.path:self.reply(file())
        elif '/files' in self.path:self.reply({'data':[file()],'has_more':False,'first_id':'file-fixture','last_id':'file-fixture'})
        else:self.reply({'data':[]})
    def do_DELETE(self):self.record();self.reply({'id':'file-fixture','type':'file_deleted'})
    def do_POST(self):
        raw=self.record()
        if self.path.endswith('/files'):self.reply(file());return
        data=json.loads(raw)
        messages=data.get('messages',data.get('input',[]))
        if any('error' in str(m.get('content','')) for m in messages):self.reply({'error':{'type':'api_error','message':'synthetic upstream failure'}},500);return
        if any('cancel' in str(m.get('content','')) for m in messages):time.sleep(.6)
        if any(t.get('name')=='web_search' for t in data.get('tools',[])):
            self.reply({'content':[{'type':'web_search_tool_result','tool_use_id':'tool-fixture','content':[{'type':'web_search_result','url':'https://example.invalid/fixture','title':'fixture','encrypted_content':'fixture'}]}]});return
        self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Connection','close');self.end_headers();self.close_connection=True
        tool=bool(data.get('tools'))
        if self.path.endswith('/chat/completions'):
            delta={'tool_calls':[{'index':0,'id':'call-fixture','type':'function','function':{'name':'fixture_tool','arguments':'{"value":"hello"}'}}]} if tool else {'content':'hello'}
            events=[{'choices':[{'delta':{'role':'assistant'},'index':0,'finish_reason':None}]},{'choices':[{'delta':delta,'index':0,'finish_reason':None}]},{'choices':[{'delta':{},'index':0,'finish_reason':'tool_calls' if tool else 'stop'}],'usage':{'prompt_tokens':3,'completion_tokens':1}}]
            wire=''.join('data: '+json.dumps(e)+'\n\n' for e in events)+'data: [DONE]\n\n'
        elif self.path.endswith('/responses'):
            item={'type':'function_call','id':'fc_fixture','call_id':'call-fixture','name':'fixture_tool','arguments':'{"value":"hello"}'} if tool else {'type':'message','id':'msg_fixture','role':'assistant','content':[{'type':'output_text','text':'hello','annotations':[]}]}
            events=[{'type':'response.created','response':{'id':'resp_fixture'}},{'type':'response.output_item.added','output_index':0,'item':item},{'type':'response.output_item.done','output_index':0,'item':item},{'type':'response.completed','response':{'id':'resp_fixture','status':'completed','output':[item],'usage':{'input_tokens':3,'output_tokens':1,'total_tokens':4}}}]
            wire=''.join('event: '+e['type']+'\ndata: '+json.dumps(e)+'\n\n' for e in events)
        else:
            block={'type':'tool_use','id':'call-fixture','name':'fixture_tool','input':{}} if tool else {'type':'text','text':''}
            delta={'type':'input_json_delta','partial_json':'{"value":"hello"}'} if tool else {'type':'text_delta','text':'hello'}
            events=[{'type':'message_start','message':{'id':'msg_fixture','type':'message','role':'assistant','model':'fixture','content':[],'stop_reason':None,'stop_sequence':None,'usage':{'input_tokens':3,'output_tokens':0}}},{'type':'content_block_start','index':0,'content_block':block},{'type':'content_block_delta','index':0,'delta':delta},{'type':'content_block_stop','index':0},{'type':'message_delta','delta':{'stop_reason':'tool_use' if tool else 'end_turn','stop_sequence':None},'usage':{'output_tokens':1}},{'type':'message_stop'}]
            wire=''.join('event: '+e['type']+'\ndata: '+json.dumps(e)+'\n\n' for e in events)
        try:self.wfile.write(wire.encode());self.wfile.flush()
        except (BrokenPipeError,ConnectionResetError):pass

def file():return {'id':'file-fixture','type':'file','size_bytes':3,'created_at':'2026-10-17T00:00:00.000Z','filename':'fixture.png','mime_type':'image/png'}
def sdk(runtime,mock,mode,config,provider='fixture',action=None):
    value={'runtime':str(runtime),'mockOrigin':mock,'originalOrigin':'https://synthetic.example.invalid','mode':mode,'config':config,'provider':provider,'action':action}
    done=subprocess.run(['node',str(Path(__file__).with_name('dsh-sdk-fixture.mjs'))],input=json.dumps(value),text=True,capture_output=True,timeout=30)
    try:result=json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError,IndexError):raise RuntimeError('DSH_SDK_RUNNER_OUTPUT_INVALID') from None
    if action in ('error','cancel'):
        if result['status']!='failed':raise RuntimeError('DSH_SDK_EXPECTED_FAILURE_MISSING')
        expected={'SERVER'} if action=='error' else {'ABORTED','TIMEOUT'}
        if result.get('errorCode') not in expected:raise RuntimeError('DSH_SDK_FAILURE_CLASS_CHANGED')
    elif result['status']!='passed':raise RuntimeError('DSH_SDK_'+result.get('errorCode','FAILED'))
    return result

def parse_patch(runtime,path):
    code="const fs=require('fs');const y=require(process.argv[1]);process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[2],'utf8'))));"
    return json.loads(subprocess.check_output(['node','-e',code,str(runtime/'node_modules/js-yaml'),str(path)],text=True))
def inputs(rows):
    out={'deepseek':next(r['config'] for r in rows if r['id']=='llm-deepseek'),'search':next(r['config'] for r in rows if r['id']=='web-search-deepseek')}
    out.update(next(r['config']['providers'] for r in rows if r['id']=='llm-pi-ai'))
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--go',required=True,type=Path);p.add_argument('--runtime',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--baseline-only',action='store_true');a=p.parse_args()
    a.runtime=a.runtime.resolve();a.go=a.go.resolve()
    if a.output.exists():p.error('Choose a new evidence output path')
    ensure_free();server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mock);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();origin=f'http://127.0.0.1:{server.server_port}'
    report={'kind':'real-dsh-sdk-parity','dsh_version':json.loads((a.runtime/'node_modules/@deepseek-ai/dsh/package.json').read_text())['version'],'pi_ai_version':json.loads((a.runtime/'node_modules/@earendil-works/pi-ai/package.json').read_text())['version'],'binary_sha256':hashlib.sha256(a.go.read_bytes()).hexdigest(),'cases':[],'status':'running','limitations':['Synthetic credentials and mock upstream only','SDK/plugin calls; not native Desktop or IOA acceptance','No DeepSeek account login'],'npm_lock_sha256':hashlib.sha256((a.runtime/'package-lock.json').read_bytes()).hexdigest()}
    proc=log=None
    try:
        with tempfile.TemporaryDirectory(prefix='endpointai-dsh-e2e-') as name:
            root=Path(name);profile=root/'profile';profile.mkdir();(profile/'.endpointai-e2e-profile').touch()
            patch=profile/'.dsh/profiles/web/cordis.patch.yml';patch.parent.mkdir(parents=True)
            (patch.parent/'package.json').write_text(json.dumps({'dsh':{'profile':{'bundles':['@deepseek-ai/dsh-base','@deepseek-ai/dsh-web-app']}}}))
            rows=[{'id':'llm-deepseek','config':{'baseURL':'https://synthetic.example.invalid/anthropic/v1','apiKeyEnv':'ENDPOINTAI_DSH_TEST_KEY','models':[{'id':'fixture','contextWindow':8192,'maxTokens':256}]}},{'id':'web-search-deepseek','config':{'baseURL':'https://synthetic.example.invalid/anthropic/v1','apiKeyEnv':'ENDPOINTAI_DSH_TEST_KEY'}},{'id':'llm-pi-ai','config':{'providers':{}}}]
            for name,api in [('chat','openai-completions'),('responses','openai-responses'),('messages','anthropic-messages')]:
                rows[-1]['config']['providers'][name]={'baseURL':f'https://synthetic.example.invalid/{name}/v1','api':api,'apiKeyEnv':'ENDPOINTAI_DSH_TEST_KEY','models':[{'id':'fixture','contextWindow':8192,'maxTokens':256}],'retryPolicy':{'mode':'normal','maxRetries':0}}
            patch.write_text(json.dumps(rows));before=inputs(rows)
            for package in ['@deepseek-ai/dsh','@deepseek-ai/dsh-llm-pi-ai','@earendil-works/pi-ai']:
                target=profile/'.local/bin/node_modules'/package/'package.json';target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(a.runtime/'node_modules'/package/'package.json',target)
            command=profile/'.local/bin/dsh';command.write_text('#!/bin/sh\nexit 0\n');command.chmod(0o700)
            baseline={}
            for name in ['deepseek','chat','responses','messages','search','files']:
                mode=name if name in ['deepseek','search','files'] else 'pi';config=before['deepseek' if name=='files' else name]
                start=len(Mock.rows);result=sdk(a.runtime,origin,mode,config,name);baseline[name]=Mock.rows[start:]
                report['cases'].append({'name':name,'baseline':result,'requests':len(baseline[name])})
            if a.baseline_only:report['status']='baseline-passed';return
            env=isolated_env(root,origin,auto_attach=True)
            for key in ('SF_PROXY_BOOTSTRAP_UPSTREAM','SF_PROXY_BOOTSTRAP_ROUTE_ID'):env.pop(key,None)
            token=os.urandom(32).hex()
            env.update(SF_PROXY_ENABLE_DSH='true',SF_PROXY_ROUTE_MODE='fixedGateway',SF_PROXY_GATEWAY_ORIGIN=origin,SF_PROXY_ALLOW_INSECURE_GATEWAY='true',SF_PROXY_ENABLE_MANAGEMENT_API='true',SF_PROXY_MANAGEMENT_TOKEN=token)
            log=(root/'client.log').open('wb');proc=subprocess.Popen([str(a.go)],env=env,stdout=log,stderr=log)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if proc.poll() is not None:raise RuntimeError('DSH_CLIENT_START_FAILED')
                try:
                    health();after=inputs(parse_patch(a.runtime,patch))
                    if all(v['baseURL'].startswith('http://127.0.0.1:18080/r/') for v in after.values()):break
                except (OSError,ValueError,KeyError):pass
                time.sleep(.2)
            else:raise RuntimeError('DSH_CONFIG_NOT_ATTACHED')
            for case in report['cases']:
                name=case['name'];mode=name if name in ['deepseek','search','files'] else 'pi';start=len(Mock.rows)
                case['proxied']=sdk(a.runtime,origin,mode,after['deepseek' if name=='files' else name],name)
                actual=Mock.rows[start:];expected=baseline[name]
                assert len(actual)==len(expected),'DSH_REQUEST_COUNT_CHANGED'
                for old,new in zip(expected,actual):
                    assert (old['method'],old['path'])==(new['method'],new['path']),'DSH_PATH_CHANGED'
                    if name!='files':assert old['body']==new['body'],'DSH_BODY_CHANGED'
                    else:assert (b'\x01\x02\x03' in old['body'])==(b'\x01\x02\x03' in new['body']),'DSH_FILE_BYTES_CHANGED'
                    for header in ['authorization','x-api-key','anthropic-beta','anthropic-version']:
                        assert old['headers'].get(header)==new['headers'].get(header),'DSH_CREDENTIAL_OR_PROTOCOL_HEADER_CHANGED'
                    assert new['headers'].get('x-sf-ai-agent')=='DeepSeekHarness','DSH_AGENT_MISCLASSIFIED'
                    assert new['headers'].get('x-sf-userid') and new['headers'].get('x-request-id'),'DSH_ATTRIBUTION_MISSING'
                case['wire_parity']='passed'
            for action in ['tool','error','cancel']:
                for name in ['deepseek','chat','responses','messages']:
                    mode='deepseek' if name=='deepseek' else 'pi';result=sdk(a.runtime,origin,mode,after[name],name,action)
                    report['cases'].append({'name':name+'-'+action,'proxied':result})
            stop(proc,log);proc=log=None
            env['SF_PROXY_AUTO_ATTACH']='false'
            log=(root/'restore.log').open('wb');proc=subprocess.Popen([str(a.go)],env=env,stdout=log,stderr=log)
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                try:health();break
                except (OSError,ValueError):time.sleep(.1)
            else:raise RuntimeError('DSH_RESTORE_CLIENT_NOT_READY')
            request=urllib.request.Request('http://127.0.0.1:18080/management/detach',data=b'',method='POST',headers={'Authorization':'Bearer '+token})
            with opener().open(request,timeout=20) as response:detached=json.load(response)
            if detached.get('failures') or inputs(parse_patch(a.runtime,patch)) != before:raise RuntimeError('DSH_CONFIG_RESTORE_CHANGED')
            report['configuration_attach_restore']=True
            stop(proc,log);proc=log=None
            restored=subprocess.run([str(a.go),'--maintenance=detach-all','--auto-attach=false'],env=env,capture_output=True,timeout=20)
            # Maintenance is admin-only; ordinary-user checks must not claim uninstall acceptance.
            report['maintenance_exit_code']=restored.returncode
            report['maintenance_native_acceptance']='pending admin device' if restored.returncode==5 else 'fixture-only'
            report['status']='passed'
    except Exception as error:
        report['status']='failed';report['failure_code']=str(error) if re.fullmatch('[A-Z0-9_]+',str(error)) else type(error).__name__;raise
    finally:
        if proc is not None:stop(proc,log)
        server.shutdown();server.server_close();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
