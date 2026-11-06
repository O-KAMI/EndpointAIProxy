from app import create_app


def test_console_served_without_credentials_but_not_cached(config):
    client = create_app(config, check_database=False).test_client()
    response = client.get("/console")
    assert response.status_code == 200
    assert response.content_type == "text/html; charset=utf-8"
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert config.ADMIN_TOKEN not in response.text
    assert config.TRANSPORT_KEY_TEXT not in response.text
    assert client.get("/").headers["Location"] == "/console"


def test_console_version_has_four_views_and_production_transport_guidance(config):
    html = create_app(config, check_database=False).test_client().get("/console").text
    for page in ("analytics", "policy", "assets", "rollouts"):
        assert f'data-page="{page}"' in html
    assert 'data-page="analytics" aria-current="page"' in html
    assert "EndpointAIDLP 0.1.26" in html
    assert "LLM 当前目标服务分布" in html
    assert "providerMode" not in html
    assert "已观测代理请求" not in html
    assert "AES-GCM" in html
    assert "HTTP 地址需显式允许 HTTP 网关" in html


def test_console_dsh_has_independent_family_label(config):
    html = create_app(config, check_database=False).test_client().get("/console").text
    assert "if(t==='deepseekharness')return'deepseekHarness'" in html
    assert "deepseekHarness:'DSH'" in html


def test_search_waits_for_explicit_submission_and_resets_page():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const line=html.split('\n').find(line=>line.includes('function refreshAssets()'));
const elements={},el=id=>elements[id] ||= {value:'',textContent:'',placeholder:''};
let calls=0,prevented=false;
const sandbox={$:el,assetSkip:50,assetRevision:0,loadAssetPage:()=>calls++};
vm.createContext(sandbox);vm.runInContext(line,sandbox);
el('searchMode').value='general';
for(const value of ['a','ab','abc']){el('search').value=value;el('search').oninput()}
if(calls!==0||!el('assetFreshness').textContent.includes('回车')||!vm.runInContext('assetSearchDirty',sandbox))throw Error('typing submitted a search');
el('search').onkeydown({key:'Enter',preventDefault:()=>prevented=true});
if(calls!==1||sandbox.assetSkip!==0||!prevented||vm.runInContext('assetSearchDirty',sandbox))throw Error('Enter did not submit the first page');
el('searchMode').value='employee';el('searchMode').onchange();
if(calls!==1||!el('search').placeholder.includes('完整账号'))throw Error('mode change submitted a pending search');
if(!html.includes("$('refreshList').onclick=refreshAssets;"))throw Error('button must submit from the first page');
if(!html.includes("if(activePage==='assets'&&!assetSearchDirty)loadAssetPage();"))throw Error('automatic refresh must wait for a pending search');
if(!html.includes("if(assetSearchDirty){refreshAssets();return}assetSkip=skip;loadAssetPage()"))throw Error('paging a pending search must start at page one');
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_batch_creation_confirmations_explain_dispatch_lower_bound():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the console JavaScript behavior check")
    html = Path(__file__).resolve().parents[1] / "controlserver/templates/console.html"
    script = r'''
const fs=require('fs'),vm=require('vm');
const lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
const code=lines.filter(line=>line.includes('function rolloutMinimumTime(')||line.includes('function policyTimingNotice(')||line.includes("$('createRollout').onclick=")||line.includes("$('policyBatchCreate').onclick=")).join('\n');
const elements={}, prompts=[];
const el=id=>elements[id] ||= {value:'',textContent:''};
Object.assign(el('rolloutDevices'),{value:Array.from({length:100000},(_,i)=>'device-'+i).join(',')});
el('rolloutRate').value='20';el('rolloutExpiry').value='60';el('rolloutReason').value='test';
const sandbox={$:el,rolloutWritable:()=>true,rolloutBusy:false,rolloutMaxRate:20,policyBatchBusy:false,policyBatchMaxRate:20,authMode:'local',adminRole:'admin',
 currentPolicy:{policyVersion:1},policyBatchInput:()=>({deviceIds:['one','two'],reason:'test'}),
 gatewayPayload:()=>({gatewayOrigin:'example'}),readRules:()=>[],allowlistDraft:[],
 confirm:text=>{prompts.push(text);return false}};
el('policyBatchRate').value='1';vm.runInNewContext(code,sandbox);
(async()=>{await el('createRollout').onclick();await el('policyBatchCreate').onclick();
 if(!prompts[0].includes('4999 秒')||!prompts[1].includes('1 秒')||prompts.some(x=>!x.includes('不含终端生效和回执')))throw Error(prompts.join('\n'));
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, "-e", script, str(html)], capture_output=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr


def test_high_rate_policy_requires_configured_limit_and_warns():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
const code=lines.filter(line=>line.includes('function rolloutMinimumTime(')||line.includes('function policyTimingNotice(')||line.includes("$('policyBatchCreate').onclick=")).join('\n');
const elements={},prompts=[],el=id=>elements[id] ||= {value:'',textContent:''};
el('policyBatchRate').value='1000';
const sandbox={$:el,policyBatchBusy:false,policyBatchMaxRate:20,authMode:'local',adminRole:'admin',currentPolicy:{policyVersion:1},
 policyBatchInput:()=>({deviceIds:['one','two'],reason:'test'}),gatewayPayload:()=>({enabled:true,heartbeatIntervalSeconds:60}),
 readRules:()=>[],allowlistDraft:[],confirm:text=>{prompts.push(text);return false}};
vm.runInNewContext(code,sandbox);
(async()=>{await el('policyBatchCreate').onclick();
 if(prompts.length||!el('policyBatchMessage').textContent.includes('20'))throw Error('default limit not enforced');
 sandbox.policyBatchMaxRate=1000;await el('policyBatchCreate').onclick();
 if(prompts.length!==1||!prompts[0].includes('高速策略下发')||!prompts[0].includes('隔离容量验证'))throw Error('high-rate warning missing');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_disabling_policy_warns_before_global_or_batch_publication():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the console JavaScript behavior check")
    html = Path(__file__).resolve().parents[1] / "controlserver/templates/console.html"
    script = r'''
const fs=require('fs'),vm=require('vm');
const lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
const code=lines.filter(line=>line.includes('function rolloutMinimumTime(')||line.includes('function policyTimingNotice(')||line.includes('async function savePolicy()')||line.includes("$('policyBatchCreate').onclick=")).join('\n');
const elements={}, prompts=[];let calls=0;
const el=id=>elements[id] ||= {value:'',textContent:''};el('policyBatchRate').value='1';
const sandbox={$:el,policySaving:false,policyBatchBusy:false,policyBatchMaxRate:20,authMode:'local',adminRole:'admin',currentPolicy:{policyVersion:1},
 policyWritable:()=>true,gatewayPayload:()=>({enabled:false,routeMode:'passthroughOriginal',gatewayOrigin:'',pollIntervalSeconds:60,heartbeatIntervalSeconds:60}),
 readRules:()=>[],allowlistDraft:[],policyBatchInput:()=>({deviceIds:['one'],reason:'test'}),
 confirm:text=>{prompts.push(text);return false},api:()=>{calls++;throw Error('unexpected request')}};
vm.runInNewContext(code,sandbox);
(async()=>{await sandbox.savePolicy();await el('policyBatchCreate').onclick();
 if(calls || prompts.length!==2 || prompts.some(text=>!text.includes('拒绝代理请求')||!text.includes('不会自动恢复')))throw Error('missing warning or unexpected request');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, "-e", script, str(html)], capture_output=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr


def test_long_heartbeat_interval_warns_before_policy_publication():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the console JavaScript behavior check")
    html = Path(__file__).resolve().parents[1] / "controlserver/templates/console.html"
    script = r'''
const fs=require('fs'),vm=require('vm');
const lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
const code=lines.filter(line=>line.includes('function rolloutMinimumTime(')||line.includes('function policyTimingNotice(')||line.includes('async function savePolicy()')||line.includes("$('policyBatchCreate').onclick=")).join('\n');
const elements={},prompts=[];let calls=0;
const el=id=>elements[id] ||= {value:'',textContent:''};el('policyBatchRate').value='1';
const sandbox={$:el,policySaving:false,policyBatchBusy:false,policyBatchMaxRate:20,authMode:'local',adminRole:'admin',currentPolicy:{policyVersion:1},
 policyWritable:()=>true,gatewayPayload:()=>({enabled:true,routeMode:'passthroughOriginal',gatewayOrigin:'',pollIntervalSeconds:60,heartbeatIntervalSeconds:120}),
 readRules:()=>[],allowlistDraft:[],policyBatchInput:()=>({deviceIds:['one'],reason:'test'}),
 confirm:text=>{prompts.push(text);return false},api:()=>{calls++;throw Error('unexpected request')}};
vm.runInNewContext(code,sandbox);
(async()=>{if(sandbox.policyTimingNotice(60)!==''||!sandbox.policyTimingNotice(61).includes('120 秒'))throw Error('threshold');
 await sandbox.savePolicy();await el('policyBatchCreate').onclick();
 if(calls||prompts.length!==2||prompts.some(text=>!text.includes('120 秒')))throw Error('missing timing warning');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, "-e", script, str(html)], capture_output=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr


def test_device_policy_state_recognizes_go_and_dotnet_reconciliation():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the console JavaScript behavior check")
    html = Path(__file__).resolve().parents[1] / "controlserver/templates/console.html"
    script = r'''
const fs = require('fs'), vm = require('vm');
const lines = fs.readFileSync(process.argv[1], 'utf8').split('\n');
const code = lines.filter(line => line.includes('function reconcileSucceeded(') || line.includes('function deviceApplyState(')).join('\n');
const sandbox = {currentDevice:{supportedPolicySchemaVersion:2,appliedPolicyVersion:7,appliedPolicySchemaVersion:2}, currentDetail:{runtime:{}}};
vm.runInNewContext(code, sandbox);
for (const value of ['completed','SUCCESS']) {
  sandbox.currentDetail.runtime = {lastReconcileResult:value};
  if (sandbox.deviceApplyState({effectivePolicy:{policyVersion:7}}) !== '终端已应用') process.exit(1);
}
sandbox.currentDetail.runtime = {lastReconcileResult:'failed',lastReconcileErrorCode:'CONFIG_ERROR'};
if (!sandbox.deviceApplyState({effectivePolicy:{policyVersion:7}}).includes('CONFIG_ERROR')) process.exit(2);
'''
    result = subprocess.run([node, "-e", script, str(html)], capture_output=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr


def test_unknown_command_resolution_requires_reason_and_hostname():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the console JavaScript behavior check")
    html = Path(__file__).resolve().parents[1] / "controlserver/templates/console.html"
    script = r'''
const fs = require('fs'), vm = require('vm');
const code = fs.readFileSync(process.argv[1], 'utf8').split('\n').find(line => line.includes('async function resolveUnknownCommand('));
const answers = ['verified offline', 'fixture-host'], calls = [];
const sandbox = {currentDevice:{hostname:'fixture-host'}, commandCreateInFlight:false,
  prompt:()=>answers.shift(), alert:()=>{throw Error('unexpected alert')},
  api:async (path, options)=>{calls.push({path, body:JSON.parse(options.body)})},
  commandWritable:()=>true,updateCommandButtons:()=>{}, setAppMessage:()=>{}, fetchDetail:async()=>{}};
vm.runInNewContext(code, sandbox);
(async()=>{await sandbox.resolveUnknownCommand({commandId:'fixture-id'});
if(calls.length!==1 || calls[0].path!=='/admin/v1/commands/fixture-id/resolve-unknown' || calls[0].body.reason!=='verified offline') process.exit(1);
if(sandbox.commandCreateInFlight) process.exit(2)})().catch(()=>process.exit(3));
'''
    result = subprocess.run([node, "-e", script, str(html)], capture_output=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr


def test_expired_delivered_and_executing_commands_offer_review():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const code=fs.readFileSync(process.argv[1],'utf8').split('\n').find(line=>line.includes('function commandNeedsReview('));
const sandbox={}; vm.runInNewContext(code,sandbox);
for(const status of ['delivered','executing']) {
  if(!sandbox.commandNeedsReview({status,expiresAtUtc:'2000-01-01T00:00:00Z'})) throw Error('missing review');
  if(sandbox.commandNeedsReview({status,expiresAtUtc:'2999-01-01T00:00:00Z'})) throw Error('premature review');
}
if(sandbox.commandNeedsReview({status:'pending',expiresAtUtc:'2000-01-01T00:00:00Z'})) throw Error('pending command offered review');
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_detail_refresh_notices_command_expiry_without_new_heartbeat():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm'),lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
let now=Date.parse('2026-01-01T00:00:00Z');
const clock={parse:Date.parse,now:()=>now}, sandbox={Date:clock};
vm.runInNewContext(lines.find(line=>line.includes('function commandNeedsReview(')),sandbox);
vm.runInNewContext(lines.find(line=>line.includes('function detailRevision(')),sandbox);
const command={commandId:'x',status:'delivered',expiresAtUtc:'2026-01-01T00:00:01Z'};
const before=sandbox.detailRevision({},[command],[]);now+=2000;
if(before===sandbox.detailRevision({},[command],[]))throw Error('expiry did not invalidate detail view');
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_policy_batch_filter_requests_selected_state_and_ignores_stale_results():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs = require('fs'), vm = require('vm');
const code = fs.readFileSync(process.argv[1], 'utf8').split('\n').find(line => line.includes('async function loadPolicyBatchDetail('));
const elements = {}, calls = [];
function element(id) { return elements[id] ||= {value:'',textContent:'',classList:{remove(){}},replaceChildren(){this.children=[]},append(item){(this.children ||= []).push(item)}} }
const sandbox = {policyBatchSelected:'batch', policyBatchDetailRevision:0, policyBatchSkip:0,
  $:element, api:path=>new Promise((resolve,reject)=>calls.push({path,resolve,reject})),
  node:(_tag,_class,text)=>({textContent:text,append(){}}),
  statusLabel:x=>x, value:(x,f)=>x||f, localTime:x=>x, rolloutPager:()=>{}, policyBatchControls:()=>{}};
vm.runInNewContext(code, sandbox);
const response = name=>({status:name,candidatePolicy:{enabled:true,routeMode:'fixed',gatewayOrigin:'example',pollIntervalSeconds:60,heartbeatIntervalSeconds:60},totalTargets:1,filteredTargets:1,counts:{},appliedTargets:0,maxPerSecond:1,targets:[]});
(async()=>{
 element('policyBatchFilter').value='applyFailed'; const older=sandbox.loadPolicyBatchDetail();
 element('policyBatchFilter').value='unsupported'; const newer=sandbox.loadPolicyBatchDetail();
 if(!calls[0].path.endsWith('&state=applyFailed') || !calls[1].path.endsWith('&state=unsupported')) throw Error('filter missing');
 calls[1].resolve(response('new')); await newer;
 calls[0].resolve(response('old')); await older;
 if(!element('policyBatchTitle').textContent.includes('new')) throw Error('stale result replaced current selection');
 element('policyBatchFilter').value=''; const all=sandbox.loadPolicyBatchDetail();
 if(!calls[2].path.endsWith('&state=')) throw Error('all filter missing');
 calls[2].resolve(response('all')); await all;
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_drawer_warns_when_cached_details_may_differ_from_summary():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const code=fs.readFileSync(process.argv[1],'utf8').split('\n').find(line=>line.includes('async function loadDrawer('));
const elements={};
const element=id=>elements[id] ||= {textContent:'',replaceChildren(){},append(){}};
let response={total:0,devices:[],updatedAtUtc:'snapshot-time',cacheAgeSeconds:400,cacheStale:true};
const sandbox={drawerRevision:0,drawerFilter:{},drawerSkip:0,pageSize:25,$:element,
  api:async()=>response,queryString:()=>'',localTime:x=>x,node:()=>({}),renderPager:()=>{}};
vm.runInNewContext(code,sandbox);
(async()=>{await sandbox.loadDrawer();
const text=element('drawerContext').textContent;
if(!text.includes('snapshot-time')||!text.includes('超过 5 分钟')||!text.includes('不同刷新批次')) throw Error('cached context is incomplete');
response={total:0,devices:[],updatedAtUtc:'live'};await sandbox.loadDrawer();
if(!element('drawerContext').textContent.includes('明细为实时查询')) throw Error('live context missing');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_policy_statistics_ignore_older_results_and_errors():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const code=fs.readFileSync(process.argv[1],'utf8').split('\n').find(line=>line.includes('async function loadPolicyStats('));
const requests=[],elements={};
const sandbox={policyStatsRevision:0,policyStats:null,$:id=>elements[id] ||= {textContent:''},
  api:()=>new Promise((resolve,reject)=>requests.push({resolve,reject})),localTime:x=>x,
  fillOptions:()=>{},renderAllowlist:()=>{}};
vm.runInNewContext(code,sandbox);
const response=version=>({policy:{version,appliedDevices:0,pendingDevices:0},updatedAtUtc:'fixture'});
(async()=>{const old=sandbox.loadPolicyStats(),fresh=sandbox.loadPolicyStats();
 requests[1].resolve(response(2));await fresh;requests[0].resolve(response(1));await old;
 if(sandbox.policyStats.policy.version!==2||!elements.policySummary.textContent.includes('v2'))throw Error('stale result replaced new');
 if(!elements.policySummary.textContent.includes('最后上报校准成功')||!elements.policySummary.textContent.includes('未确认校准成功')||!elements.policySummary.textContent.includes('离线设备为最后上报状态')||elements.policySummary.textContent.includes('待同步'))throw Error('policy status wording misrepresents last reported results');
 const failing=sandbox.loadPolicyStats(),latest=sandbox.loadPolicyStats();
 requests[3].resolve(response(3));await latest;requests[2].reject(new Error('old failure'));await failing;
 if(!elements.policySummary.textContent.includes('v3'))throw Error('stale error replaced new');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_rollout_pages_ignore_older_responses():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
const code=lines.filter(line=>['async function loadRollouts()','async function loadRolloutDetail()','async function loadPolicyBatches()'].some(name=>line.includes(name))).join('\n');
const requests=[],elements={},pagers=[],messages=[];
const sandbox={rolloutSelected:'batch',rolloutListSkip:0,rolloutSkip:0,rolloutListRevision:0,rolloutDetailRevision:0,
 policyBatchListSkip:0,policyBatchListRevision:0,policyBatchSelected:'',
 $:id=>elements[id] ||= {value:'',textContent:'',classList:{remove(){}},replaceChildren(){},append(){}},
 api:path=>new Promise((resolve,reject)=>requests.push({path,resolve,reject})),
 node:()=>({append(){}}),rolloutControls:()=>{},policyBatchControls:()=>{},
 rolloutPager:(id,total,skip)=>pagers.push({id,total,skip}),setAppMessage:message=>messages.push(message),localTime:x=>x,statusLabel:x=>x};
vm.runInNewContext(code,sandbox);
const list=total=>({total,batches:[]});
const detail=status=>({batchId:'batch',status,totalTargets:26,counts:{},maxPerSecond:1,filteredTargets:26,targets:[]});
(async()=>{
 for(const [fn,skip,kind] of [['loadRollouts','rolloutListSkip','list'],['loadPolicyBatches','policyBatchListSkip','list'],['loadRolloutDetail','rolloutSkip','detail']]){
   const start=requests.length,old=sandbox[fn]();sandbox[skip]=25;const fresh=sandbox[fn]();
   requests[start+1].resolve(kind==='list'?list(26):detail('new'));await fresh;
   requests[start].resolve(kind==='list'?list(1):detail('old'));await old;
   if(kind==='list' && (pagers.at(-1).total!==26 || pagers.at(-1).skip!==25))throw Error('old list replaced new');
   if(kind==='detail' && !elements.rolloutTitle.textContent.includes('new'))throw Error('old detail replaced new');
   const next=requests.length,stale=sandbox[fn](),latest=sandbox[fn]();
   requests[next+1].resolve(kind==='list'?list(26):detail('latest'));await latest;
   requests[next].reject(new Error('old error'));await stale;
   if(messages.length || (elements.policyBatchMessage && elements.policyBatchMessage.textContent))throw Error('stale error displayed');
 }
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_command_batch_filter_is_sent_to_backend_and_recovers_out_of_range_page():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const code=fs.readFileSync(process.argv[1],'utf8').split('\n').find(line=>line.includes('async function loadRolloutDetail('));
const paths=[],elements={},pagers=[];
const sandbox={rolloutSelected:'batch',rolloutSkip:25,rolloutDetailRevision:0,rolloutStatus:'',
 $:id=>elements[id] ||= {value:id==='rolloutFilter'?'resultUnknown':'',textContent:'',classList:{remove(){}},replaceChildren(){},append(){}},
 api:async path=>{paths.push(path);return {batchId:'batch',status:'paused',totalTargets:30,filteredTargets:1,counts:{resultUnknown:1},maxPerSecond:5,targets:[]}},
 rolloutPager:(id,total,skip)=>pagers.push({total,skip}),rolloutControls:()=>{},statusLabel:s=>s,setAppMessage:()=>{}};
vm.runInNewContext(code,sandbox);
(async()=>{await sandbox.loadRolloutDetail();
if(paths.length!==2 || !paths[0].includes('skip=25') || !paths[1].includes('skip=0') || paths.some(p=>!p.includes('state=resultUnknown')))throw Error('filter or page reset lost');
if(pagers.length!==1||pagers[0].total!==1||pagers[0].skip!==0)throw Error('incorrect filtered pagination');
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr


def test_rollout_ui_uses_server_rate_limit_and_warns_for_high_rate():
    import shutil
    import subprocess
    from pathlib import Path
    import pytest
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the console JavaScript behavior check')
    html = Path(__file__).resolve().parents[1] / 'controlserver/templates/console.html'
    script = r'''
const fs=require('fs'),vm=require('vm');
const lines=fs.readFileSync(process.argv[1],'utf8').split('\n');
const code=lines.filter(line=>line.includes('async function loadRollouts()')||line.includes('function rolloutMinimumTime(')||line.includes("$('createRollout').onclick=")).join('\n');
const elements={},prompts=[];
const el=id=>elements[id] ||= {value:'',textContent:'',replaceChildren(){},append(){}};
el('rolloutDevices').value='one,two,three';el('rolloutRate').value='100';el('rolloutExpiry').value='60';el('rolloutReason').value='test';
const sandbox={$:el,rolloutListRevision:0,rolloutListSkip:0,rolloutBusy:false,rolloutMaxRate:20,rolloutWritable:()=>true,rolloutControls:()=>{},rolloutPager:()=>{},node:()=>({append(){}}),api:async()=>({maxRate:100,total:0,batches:[]}),confirm:text=>{prompts.push(text);return false}};
vm.runInNewContext(code,sandbox);
(async()=>{await sandbox.loadRollouts();if(sandbox.rolloutMaxRate!==100||el('rolloutRate').max!=='100')throw Error('rate limit not loaded');
 await el('createRollout').onclick();if(prompts.length!==1||!prompts[0].includes('高速批量下发'))throw Error('missing high rate warning');
 el('rolloutRate').value='101';await el('createRollout').onclick();if(prompts.length!==1||!el('rolloutCreateMessage').textContent)throw Error('rate limit not enforced');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', script, str(html)], capture_output=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stderr
