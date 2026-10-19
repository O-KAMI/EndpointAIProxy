// Real, fixed DSH packages; synthetic credentials and loopback-only network.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const root = path.resolve(input.runtime, 'node_modules');
const load = name => import(pathToFileURL(path.join(root, name, 'lib/index.js')).href);
const originalFetch = globalThis.fetch;
globalThis.fetch = (request, init) => {
  const original = new URL(typeof request === 'string' || request instanceof URL ? request : request.url);
  const destination = new URL(original);
  if (original.origin === input.originalOrigin) {
    const mock = new URL(input.mockOrigin);
    destination.protocol = mock.protocol; destination.host = mock.host;
  } else if (!['127.0.0.1', 'localhost', '[::1]'].includes(original.hostname)) {
    throw new Error('FIXTURE_NETWORK_BOUNDARY');
  }
  return originalFetch(request instanceof Request ? new Request(destination, request) : destination, init);
};
process.env.ENDPOINTAI_DSH_TEST_KEY = 'synthetic-fixture-not-a-production-key';
process.env.DSH_TELEMETRY_DISABLED = '1';
let context;
try {
  const llm = await load('@deepseek-ai/dsh-llm');
  const deepseek = await load('@deepseek-ai/dsh-llm-deepseek');
  const baseURL = input.config.baseURL;
  let result;
  if (input.mode === 'files') {
    const client = new deepseek.DeepSeekFilesClient({baseURL, headers: {'x-api-key': process.env.ENDPOINTAI_DSH_TEST_KEY}});
    const file = await client.upload({data: Uint8Array.of(1,2,3), mediaType:'image/png', filename:'fixture.png', expiresAfterSeconds:3600});
    await client.list({limit:2}); await client.retrieve(file.id); await client.delete(file.id);
    result = {operations:4};
  } else if (input.mode === 'search') {
    const search = await load('@deepseek-ai/dsh-web-search-deepseek');
    const provider = new search.DeepSeekSearchProvider(() => ({...input.config, apiKey:process.env.ENDPOINTAI_DSH_TEST_KEY, model:'fixture', apiVersion:'2023-06-01', maxTokens:256, maxUses:1}));
    const output = await provider.search({query:'synthetic fixture'});
    result = {sources:output.sources?.length ?? 0};
    if(result.sources !== 1) throw new Error('FIXTURE_SEARCH_RESULTS_MISSING');
  } else {
    let stream;
    const options = {provider:input.provider ?? 'deepseek-official',model:'fixture',maxTokens:256,
      messages:[{role:'user',content:[{type:'text',text:input.action ?? 'synthetic fixture'}]}]};
    if (input.action === 'tool') options.tools=[{name:'fixture_tool',description:'Synthetic fixture',parameters:{type:'object',properties:{value:{type:'string'}},required:['value']}}];
    if (input.mode === 'deepseek') {
      const adapter = new deepseek.DeepSeekAdapter({options:()=>deepseek.resolveAdapterOptions({...input.config, thinking:'disabled', reasoningEffort:'off'}),
        resolveAuth:async()=>({headers:{'x-api-key':process.env.ENDPOINTAI_DSH_TEST_KEY}}),resolveUserId:()=> 'fixture-user', prepareExtensions:async()=>({fields:{},accept:async()=>{}})});
      if(input.action==='cancel') options.signal=AbortSignal.timeout(150);
      stream = adapter.stream(options);
    } else {
      const cordis=await load('@deepseek-ai/cordis');
      const pi=await load('@deepseek-ai/dsh-llm-pi-ai');
      context=new cordis.Context(); await context.plugin(llm.default);
      await context.plugin(pi,{providers:{[options.provider]:input.config}});
      if(input.action==='cancel') options.signal=AbortSignal.timeout(150);
      stream=context.llm.stream(options);
    }
    const chunks=[];
    for await (const chunk of stream) chunks.push(chunk);
    const finish=chunks.findLast(c=>c.type==='finish');
    if (!finish) throw new Error('FIXTURE_STREAM_NOT_FINISHED');
    if(['error','aborted'].includes(finish.reason?.kind)) throw Object.assign(new Error('FIXTURE_PROVIDER_FAILURE'), {code:finish.reason.failure?.code ?? 'FIXTURE_FAILED'});
    if(input.action==='tool' && finish.reason?.kind!=='tool-calls') throw Object.assign(new Error('FIXTURE_TOOL_CALL_MISSING'),{code:'FIXTURE_TOOL_CALL_MISSING'});
    result={chunks:chunks.length,finish:finish.reason ?? finish.finishReason ?? finish.kind};
  }
  console.log(JSON.stringify({status:'passed',...result}));
} catch(error) {
  console.log(JSON.stringify({status:'failed',errorClass:error.name,errorCode:typeof error.code==='string'?error.code:'FIXTURE_FAILED'}));
  process.exitCode=1;
} finally {
  if(context) await context.fiber.dispose();
}
