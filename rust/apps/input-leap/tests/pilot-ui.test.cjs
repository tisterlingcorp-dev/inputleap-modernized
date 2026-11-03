const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname,'../ui/pilot.html'),'utf8');
const code = fs.readFileSync(path.join(__dirname,'../ui/pilot.js'),'utf8');
const settle = () => new Promise(resolve=>setImmediate(resolve));
class Element {
  constructor(){this.disabled=false;this.checked=false;this.hidden=false;this.textContent='';this.value='';this.events={};this.children=[];}
  addEventListener(name,fn){this.events[name]=fn;}
  replaceChildren(){this.children=[];}
  append(node){this.children.push(node);}
  async fire(name='click'){if(!this.disabled || name!=='click')this.events[name]?.();await settle();await settle();}
}
const pending = (id='attempt-1',capabilities=1) => ({pairing_id:id,phase:'awaiting_local_confirmation',comparison_code:'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF',peer_device_id:'synthetic-peer',peer_fingerprint:'a'.repeat(64),capabilities});
const status = pairing => ({version:3,status:{version:3,state:'awaiting_pairing',error_code:null,security:{persistence_healthy:true,device_id:'synthetic-local',fingerprint:'b'.repeat(64),peers:[],pairing}}});
async function app(initial, bridge=true){
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],new Element()]));
  const calls=[]; let response=initial, failure=null, interval;
  const context={document:{hidden:false,getElementById:id=>{assert.ok(elements[id],id);return elements[id];},createElement:()=>new Element()},window:{confirm:()=>true},setInterval:fn=>{interval=fn;}};
  if(bridge)context.window.__TAURI__={core:{invoke:async(name,args)=>{assert.equal(name,'pilot_command');calls.push(args.payload);if(failure)throw failure;return structuredClone(response);}}};
  vm.runInNewContext(code,context);await settle();await settle();
  return {elements,calls,set:value=>{response=value;},fail:()=>{failure=new Error('synthetic unavailable');},tick:async()=>{interval();await settle();await settle();}};
}
test('approval requires explicit comparison and never auto-confirms on poll',async()=>{
  const a=await app(status(pending()));
  assert.equal(a.elements.approve.disabled,true);
  await a.tick();assert.ok(a.calls.every(call=>call.type==='status'));
  a.elements.compared.checked=true;await a.elements.compared.fire('change');
  assert.equal(a.elements.approve.disabled,false);
  await a.elements.approve.fire();assert.equal(a.calls.at(-1).type,'confirm_pairing');assert.equal(a.calls.at(-1).matches,true);
});
test('new attempts or changed rights/code discard old consent',async()=>{
  const a=await app(status(pending()));
  for(const next of [pending('attempt-2'),pending('attempt-2',7),{...pending('attempt-2',7),comparison_code:'1111-2222-3333-4444-5555-6666'}]){
    a.elements.compared.checked=true;await a.elements.compared.fire('change');
    a.set(status(next));await a.tick();assert.equal(a.elements.compared.checked,false);assert.equal(a.elements.approve.disabled,true);
  }
});
test('unavailable service clears old codes and no browser demo pretends connected',async()=>{
  const a=await app(status(pending()));a.fail();await a.tick();assert.equal(a.elements.code.textContent,'');assert.equal(a.elements.approve.disabled,true);assert.equal(a.elements.pending.hidden,true);
  const browser=await app(status(pending()),false);assert.match(browser.elements.connection.textContent,/Abra esta tela/);assert.equal(browser.calls.length,0);
});
test('rights are unchecked by default and explicit in begin request',async()=>{
  const a=await app(status(null));a.elements.address.value='127.0.0.1:24920';await a.elements.listen.fire();assert.ok(a.calls.every(call=>call.type==='status'));
  a.elements['input-right'].checked=true;await a.elements.listen.fire();assert.equal(a.calls.at(-1).type,'listen_pairing');assert.equal(a.calls.at(-1).capabilities,1);
});
test('reject while waiting for the remote cancels instead of duplicate approval',async()=>{
  const p=pending();p.phase='awaiting_peer_confirmation';const a=await app(status(p));await a.elements.reject.fire();assert.equal(a.calls.at(-1).type,'stop');
});
test('failed revocation persistence is never labeled a completed durable revocation',async()=>{
  const response=status(null);response.status.security.persistence_healthy=false;
  response.status.security.peers=[{device_id:'synthetic-peer',fingerprint:'c'.repeat(64),revoked:true,capabilities:1}];
  const a=await app(response);const label=a.elements.peers.children[0].children[0].textContent;
  assert.match(label,/gravação pendente/);assert.doesNotMatch(label,/persistido/);assert.equal(a.elements.approve.disabled,true);
});
