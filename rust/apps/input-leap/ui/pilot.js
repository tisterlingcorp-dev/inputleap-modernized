'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let busy = false, querying = false, pairingId = null, consentKey = null, canApprove = false;
  const errors = { pairing_busy:'Já existe uma tentativa. Cancele ou aguarde.', pairing_failed:'Pareamento não concluído. Confira o endereço e tente novamente.', pairing_expired:'A janela de pareamento expirou.', pairing_rejected:'Pareamento recusado.', pairing_session_changed:'O login Windows mudou. Inicie outra tentativa.', pairing_rate_limited:'Aguarde dois segundos antes de tentar novamente.', security_persistence_failed:'Não foi possível salvar a segurança. A autorização permanece bloqueada.', pairing_persistence_failed:'O pareamento não foi salvo. Nenhum sucesso foi confirmado.', revocation_failed:'Revogação não gravada. Resolva o problema e tente novamente.', authenticated_runtime_not_ready:'Serviço piloto disponível. Compartilhamento Rust ainda não habilitado.' };
  const buttons = ['listen','connect','stop','approve','reject'];
  function enable() { for(const id of buttons) $(id).disabled = busy || querying || (id === 'approve' && (!canApprove || !$('compared').checked)); $('compared').disabled = busy || querying || !canApprove; }
  function resetConsent() { pairingId = null; consentKey = null; canApprove = false; $('compared').checked = false; $('pending').hidden = true; $('code').textContent = ''; enable(); }
  function text(id, value) { $(id).textContent = value || '—'; }
  function render(response) {
    if(response.version !== 3 || response.status?.version !== 3) throw new Error('Versão do piloto incompatível. Atualize os dois dispositivos.');
    const status = response.status, security = status.security;
    text('connection', errors[status.error_code] || status.error_code || status.state);
    if(!security) { resetConsent(); text('device'); text('fingerprint'); $('peers').replaceChildren(); return; }
    text('device', security.device_id); text('fingerprint', security.fingerprint);
    if(!security.persistence_healthy) text('message', errors.security_persistence_failed);
    const pending = security.pairing;
    if(!pending) resetConsent();
    else {
      const nextConsent = JSON.stringify([pending.pairing_id,pending.comparison_code,pending.peer_device_id,pending.peer_fingerprint,pending.capabilities]);
      if(consentKey !== nextConsent) { resetConsent(); pairingId = pending.pairing_id; consentKey = nextConsent; }
      $('pending').hidden = false;
      const phases = {listening:'Aguardando conexão por tempo limitado…',connecting:'Estabelecendo canal autenticado…',awaiting_local_confirmation:'Confira o código completo antes de autorizar.',awaiting_peer_confirmation:'Aguardando confirmação na outra tela…'};
      text('phase', phases[pending.phase]); text('peer-id', pending.peer_device_id); text('peer-fingerprint', pending.peer_fingerprint); text('code', pending.comparison_code || 'Aguardando código');
      const rights = ['Teclado/mouse','Texto/imagens','Arquivos'].filter((_,i)=>pending.capabilities & (1<<i));
      text('rights', 'Direitos negociados: '+(rights.join(', ') || 'nenhum'));
      canApprove = pending.phase === 'awaiting_local_confirmation' && !!pending.comparison_code && security.persistence_healthy;
      if(!canApprove) $('compared').checked = false;
    }
    $('peers').replaceChildren();
    for(const peer of security.peers) {
      const item = document.createElement('li'), info = document.createElement('span');
      const peerState = peer.revoked ? (security.persistence_healthy ? 'revogado (persistido)' : 'bloqueado nesta sessão; gravação pendente') : 'pareado';
      info.textContent = peer.device_id+' · '+peerState+' · '+peer.fingerprint; item.append(info);
      const revoke = document.createElement('button'); revoke.textContent = peer.revoked ? 'Repetir revogação' : 'Revogar'; revoke.disabled = busy;
      revoke.addEventListener('click',()=>{if(window.confirm('Revogar a autorização deste dispositivo?')) action({type:'revoke',device_id:peer.device_id});});
      item.append(revoke); $('peers').append(item);
    }
    enable();
  }
  async function invoke(command) {
    const bridge = window.__TAURI__?.core?.invoke;
    if(!bridge) throw new Error('Abra esta tela pelo aplicativo com --rust-pilot. Nenhum resultado de demonstração será usado.');
    return bridge('pilot_command',{payload:command});
  }
  async function refresh() {
    if(busy || querying) return;
    querying = true; enable();
    try { render(await invoke({type:'status'})); }
    catch(error) { resetConsent(); text('connection',String(error.message || error)); text('device'); text('fingerprint'); $('peers').replaceChildren(); }
    finally { querying = false; enable(); }
  }
  async function action(command) {
    if(busy || querying) return;
    busy = true; enable(); $('message').textContent = '';
    try { const response = await invoke(command); render(response); if(response.status.error_code) text('message', errors[response.status.error_code] || response.status.error_code); }
    catch(error) { resetConsent(); text('message',String(error.message || error)); }
    finally { busy = false; enable(); }
  }
  function start(listen) {
    const capabilities = ['input-right','clipboard-right','files-right'].reduce((bits,id,i)=>bits | ($(id).checked ? 1<<i : 0),0);
    if(!capabilities) { text('message','Escolha conscientemente ao menos um direito.'); return; }
    action({type:listen?'listen_pairing':'begin_pairing',address:$('address').value.trim(),capabilities});
  }
  $('listen').addEventListener('click',()=>start(true)); $('connect').addEventListener('click',()=>start(false));
  $('stop').addEventListener('click',()=>action({type:'stop'})); $('refresh').addEventListener('click',refresh); $('compared').addEventListener('change',enable);
  $('approve').addEventListener('click',()=>{if(canApprove && $('compared').checked && pairingId) action({type:'confirm_pairing',pairing_id:pairingId,matches:true});});
  $('reject').addEventListener('click',()=>{if(pairingId) action(canApprove ? {type:'confirm_pairing',pairing_id:pairingId,matches:false} : {type:'stop'});});
  refresh(); setInterval(()=>{if(!document.hidden) refresh();},1000);
})();
