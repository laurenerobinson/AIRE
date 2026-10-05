'use strict';

const state = {
  bootstrap: null,
  binaryId: null,
  binaryMeta: null,
  sessionId: null,
  currentFunctionId: null,
  busy: false,
  toolsCollapsed: false,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function renderMarkdown(text) {
  const blocks = [];
  const codeBlock = (code, lang = '') => {
    const token = `@@AIRE_CODE_${blocks.length}@@`;
    blocks.push(`<pre><code data-lang="${escapeHtml(lang.trim())}">${code.replace(/^\n|\n$/g,'')}</code></pre>`);
    return token;
  };
  let safe = escapeHtml(text || '').replace(/```([^\n`]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    return codeBlock(code, lang);
  });
  // The existing agent's CLI answer uses labelled plain-text code sections.
  // Format those sections here so stored transcripts and live answers match.
  safe = safe.replace(/(^|\n)(Decompiled text:)\n([\s\S]*?)(?=\nAssembly:\n)/g,
    (_, prefix, label, code) => `${prefix}### ${label}\n${codeBlock(code, 'c')}`);
  safe = safe.replace(/(^|\n)(Assembly:)\n([\s\S]*?)(?=\nText is bounded;)/g,
    (_, prefix, label, code) => `${prefix}### ${label}\n${codeBlock(code, 'asm')}`);
  safe = safe.replace(/(^|\n)((decompiled_text|assembly) for [^\n]+:)\n([\s\S]*?)(?=\n(?:Retrieved code evidence \[|Connectivity ranking by |get_callers \(|get_callees \(|Bounded stored call path:|Stored binary-level artifacts \(|Deterministic security rule evaluations \(|Text was truncated;)|$)/g,
    (_, prefix, label, field, code) => `${prefix}### ${label}\n${codeBlock(code, field === 'assembly' ? 'asm' : 'c')}`);
  safe = safe.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  const lines = safe.split('\n');
  const out = [];
  let list = null;
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (let line of lines) {
    const codeToken = line.match(/^@@AIRE_CODE_(\d+)@@$/);
    if (codeToken && blocks[Number(codeToken[1])] !== undefined) { closeList(); out.push(blocks[Number(codeToken[1])]); continue; }
    let match;
    if ((match = line.match(/^(#{1,3})\s+(.+)$/))) { closeList(); const n = match[1].length; out.push(`<h${n}>${match[2]}</h${n}>`); continue; }
    if (/^(A\.I\.R\.E\. Analysis|A\.I\.R\.E\. stored graph results|Summary \(model interpretation\)|Verified stored facts|Model interpretation|Uncertainty|Evidence provenance|Retrieved tool facts|Retrieved code evidence \[.*)$/.test(line)) {
      closeList(); out.push(`<h3>${line}</h3>`); continue;
    }
    if ((match = line.match(/^[-*]\s+(.+)$/))) { if (list !== 'ul') { closeList(); list = 'ul'; out.push('<ul>'); } out.push(`<li>${match[1]}</li>`); continue; }
    if ((match = line.match(/^\d+[.)]\s+(.+)$/))) { if (list !== 'ol') { closeList(); list = 'ol'; out.push('<ol>'); } out.push(`<li>${match[1]}</li>`); continue; }
    closeList();
    if (!line.trim()) { out.push(''); continue; }
    line = line.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    out.push(`<p>${line}</p>`);
  }
  closeList();
  return out.join('\n');
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: options.body ? {'Content-Type':'application/json', ...(options.headers || {})} : (options.headers || {}),
  });
  let payload;
  try { payload = await response.json(); } catch { payload = {message: `HTTP ${response.status}`}; }
  if (!response.ok) throw new Error(payload.message || payload.error || `HTTP ${response.status}`);
  return payload;
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.add('hidden'), 3200);
}

function autoSize(textarea) {
  textarea.style.height = 'auto';
  textarea.style.height = `${Math.min(textarea.scrollHeight, 160)}px`;
}

function setBusy(value) {
  state.busy = value;
  $$('.send-button').forEach(button => button.disabled = value);
  $$('#newChatBtn, [data-nav], #binarySelect, .tool-card, .tool-row, .recent-card').forEach(control => control.disabled = value);
}

function displayName(binary) {
  if (!binary) return 'Unknown binary';
  const path = binary.path || '';
  return binary.program_name || path.split(/[\\/]/).pop() || binary.binary_id.slice(0, 12);
}

function formatSha(value) {
  return value ? `${value.slice(0,8)}…${value.slice(-6)}` : 'unknown';
}

function renderBinaryContext(metadata) {
  state.binaryMeta = metadata;
  const b = metadata?.binary || {};
  const c = metadata?.counts || {};
  $('#binaryStats').innerHTML = [
    ['Format', b.format || 'unknown'],
    ['Arch', b.architecture || 'unknown'],
    ['Functions', c.functions ?? '—'],
    ['SHA-256', formatSha(b.sha256), b.sha256],
  ].map(([label,value,full]) => `<span class="stat-chip" title="${escapeHtml(full || value)}"><strong>${escapeHtml(label)}</strong> ${escapeHtml(value)}</span>`).join('');
}

function populateBinaries(binaries) {
  const select = $('#binarySelect');
  select.innerHTML = binaries.map(binary => `<option value="${escapeHtml(binary.binary_id)}">${escapeHtml(displayName(binary))}</option>`).join('');
  select.value = state.binaryId;
}

function setActiveNav(name) {
  $$('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.nav === name));
}

function showView(name) {
  const map = {home:'#homeView', chat:'#chatView', recent:'#recentView', about:'#aboutView'};
  Object.entries(map).forEach(([key, selector]) => $(selector).classList.toggle('hidden', key !== name));
  setActiveNav(name === 'chat' ? 'home' : name);
  $('#collapseToolsTop').classList.toggle('hidden', name !== 'chat');
  if (name === 'recent') loadRecent();
  if (name === 'about') checkHealth();
}

function resetChat() {
  state.sessionId = null;
  state.currentFunctionId = null;
  $('#messages').innerHTML = '';
  $('#chatInput').value = '';
  $('#selectedFunctionChip').classList.add('hidden');
  $('#toolResult').classList.add('hidden');
  $$('.tool-card').forEach(card => card.classList.remove('active'));
  showView('home');
  $('#homeInput').focus();
}

async function ensureSession() {
  if (state.sessionId) return state.sessionId;
  const created = await api('/api/sessions', {method:'POST', body:JSON.stringify({binary_id: state.binaryId})});
  state.sessionId = created.session_id;
  state.currentFunctionId = created.current_function_id || null;
  return state.sessionId;
}

function updateSelectedFunction(functionData) {
  if (!functionData) return;
  state.currentFunctionId = functionData.function_id;
  const chip = $('#selectedFunctionChip');
  chip.textContent = `${functionData.current_name} · ${functionData.address}`;
  chip.title = functionData.function_id;
  chip.classList.remove('hidden');
}

function userMessage(text) {
  const row = document.createElement('div');
  row.className = 'message-row user';
  const bubble = document.createElement('div');
  bubble.className = 'user-bubble';
  bubble.textContent = text;
  row.appendChild(bubble);
  $('#messages').appendChild(row);
  return row;
}

function assistantShell() {
  const row = document.createElement('div');
  row.className = 'message-row assistant';
  row.innerHTML = `<div class="assistant-message"><div class="assistant-avatar">A</div><div class="assistant-content"><div class="activity-live"><span class="activity-spinner"></span><span class="activity-text">Starting analysis…</span></div><div class="answer-body"></div><details class="activity-log hidden"><summary>Analysis activity</summary><div class="activity-items"></div></details></div></div>`;
  $('#messages').appendChild(row);
  return row;
}

function appendEvent(shell, event) {
  const live = $('.activity-text', shell);
  const tool = event.tool_name ? `${event.tool_name}: ` : '';
  live.textContent = `${tool}${event.message}`;
  const log = $('.activity-log', shell);
  const items = $('.activity-items', shell);
  log.classList.remove('hidden');
  const item = document.createElement('div');
  item.className = 'activity-item';
  item.innerHTML = `<span class="event-kind">${escapeHtml(event.event_type.replace(/_.*/,''))}</span><span>${escapeHtml(tool + event.message)}</span>`;
  items.appendChild(item);
  if (event.function_id) updateSelectedFunction({function_id:event.function_id, current_name:event.function_name, address:event.function_address});
}

function finishAssistant(shell, result) {
  $('.activity-live', shell).classList.add('hidden');
  $('.answer-body', shell).innerHTML = renderMarkdown(result.answer || 'No answer returned.');
  const log = $('.activity-log', shell);
  if (!log.classList.contains('hidden')) {
    const summary = $('summary', log);
    const count = $$('.activity-item', log).length;
    summary.textContent = `Analysis activity · ${count} event${count === 1 ? '' : 's'} · ${result.status}`;
  }
}

async function sendQuestion(text) {
  text = String(text || '').trim();
  if (!text || state.busy) return;
  setBusy(true);
  try {
    await ensureSession();
    showView('chat');
    userMessage(text);
    const shell = assistantShell();
    $('#messages').scrollTop = $('#messages').scrollHeight;
    const response = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session_id:state.sessionId, question:text})});
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.message || `HTTP ${response.status}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let final = null;
    while (true) {
      const {value, done} = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), {stream: !done});
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const packet = JSON.parse(line);
        if (packet.type === 'event') appendEvent(shell, packet.data);
        if (packet.type === 'result') final = packet.data;
        if (packet.type === 'error') throw new Error(packet.data.message || packet.data.error);
      }
      $('#messages').scrollTop = $('#messages').scrollHeight;
      if (done) break;
    }
    if (!final && buffer.trim()) {
      const packet = JSON.parse(buffer);
      if (packet.type === 'result') final = packet.data;
      if (packet.type === 'error') throw new Error(packet.data.message || packet.data.error);
    }
    if (!final) throw new Error('A.I.R.E. ended the request without a result');
    finishAssistant(shell, final);
    $('#messages').scrollTop = $('#messages').scrollHeight;
    const session = await api(`/api/sessions/${state.sessionId}`);
    state.currentFunctionId = session.current_function_id || null;
    if (!state.currentFunctionId) $('#selectedFunctionChip').classList.add('hidden');
    await refreshRecent(false);
  } catch (error) {
    toast(error.message);
    const shell = $$('.message-row.assistant').at(-1);
    if (shell && !$('.activity-live', shell).classList.contains('hidden')) {
      $('.activity-live', shell).classList.add('hidden');
      $('.answer-body', shell).innerHTML = `<p>Request failed: ${escapeHtml(error.message)}</p>`;
    }
  } finally {
    setBusy(false);
    $('#chatInput').focus();
  }
}

async function refreshRecent(render = true) {
  const data = await api(`/api/sessions?binary_id=${encodeURIComponent(state.binaryId)}`);
  if (state.bootstrap) state.bootstrap.sessions = data.sessions;
  if (render) renderRecent(data.sessions);
  return data.sessions;
}

function renderRecent(sessions) {
  const root = $('#recentList');
  if (!sessions.length) {
    root.innerHTML = '<div class="empty-state">No saved conversations for this binary yet.</div>';
    return;
  }
  root.innerHTML = '';
  for (const item of sessions) {
    const button = document.createElement('button');
    button.className = 'recent-card';
    button.innerHTML = `<strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.preview)}</p><small>${escapeHtml(new Date(item.updated_at).toLocaleString())}</small>`;
    button.addEventListener('click', () => openSession(item.session_id));
    root.appendChild(button);
  }
}

async function loadRecent() {
  try { renderRecent(await refreshRecent(false)); } catch (error) { toast(error.message); }
}

async function openSession(sessionId) {
  try {
    const data = await api(`/api/sessions/${sessionId}`);
    if (data.binary_id !== state.binaryId) {
      await switchBinary(data.binary_id);
    }
    state.sessionId = sessionId;
    state.currentFunctionId = data.current_function_id || null;
    $('#messages').innerHTML = '';
    for (const message of data.messages || []) {
      if (message.role === 'user') userMessage(message.text);
      else {
        const shell = assistantShell();
        $('.activity-live', shell).classList.add('hidden');
        $('.answer-body', shell).innerHTML = renderMarkdown(message.text);
      }
    }
    if (state.currentFunctionId) {
      const result = await runTool('get_function', {function:state.currentFunctionId}, false);
      if (result?.ok) updateSelectedFunction(result.data.function);
    } else $('#selectedFunctionChip').classList.add('hidden');
    showView('chat');
    $('#messages').scrollTop = $('#messages').scrollHeight;
  } catch (error) { toast(error.message); }
}

async function runTool(tool, args = {}, announce = true) {
  await ensureSession();
  try {
    const result = await api('/api/tool', {method:'POST', body:JSON.stringify({session_id:state.sessionId, tool, arguments:args})});
    if (announce && !result.ok) toast(result.error?.message || `${tool} failed`);
    return result;
  } catch (error) {
    if (announce) toast(error.message);
    return {ok:false, error:{message:error.message}};
  }
}

function openToolResult(title, content) {
  const root = $('#toolResult');
  root.classList.remove('hidden');
  root.innerHTML = `<div class="tool-result-head"><h4>${escapeHtml(title)}</h4><button aria-label="Close tool result">×</button></div><div class="tool-result-body"></div>`;
  $('.tool-result-body', root).append(content);
  $('button', root).addEventListener('click', () => root.classList.add('hidden'));
}

function rowsContainer() { const el = document.createElement('div'); el.className = 'tool-list'; return el; }
function infoRow(html, asButton = false) { const el = document.createElement(asButton ? 'button' : 'div'); el.className = 'tool-row'; el.innerHTML = html; return el; }

async function showFunctions() {
  const result = await runTool('list_functions', {limit:40, offset:0});
  if (!result.ok) return;
  const list = rowsContainer();
  for (const item of result.data.items) {
    const f = item.function;
    const row = infoRow(`<strong>${escapeHtml(f.current_name)}</strong><div class="tool-meta">${escapeHtml(f.address)} · ${escapeHtml(f.signature || 'signature unavailable')}</div>`, true);
    row.addEventListener('click', async () => {
      try {
        const selected = await api(`/api/sessions/${state.sessionId}/select-function`, {method:'POST', body:JSON.stringify({function:f.function_id})});
        updateSelectedFunction(selected.selected_function);
        toast(`Selected ${selected.selected_function.current_name}`);
      } catch (error) { toast(error.message); }
    });
    list.appendChild(row);
  }
  openToolResult('Functions', list);
}

async function showArtifacts(kind, label) {
  const result = await runTool('get_artifacts', {kind, limit:50});
  if (!result.ok) return;
  const list = rowsContainer();
  for (const item of result.data.items) {
    const a = item.artifact || item;
    list.appendChild(infoRow(`<strong>${escapeHtml(a.value)}</strong><div class="tool-meta">${escapeHtml(a.address || 'no address')} · ${escapeHtml(a.type || kind)}</div>`));
  }
  if (!result.data.items.length) list.appendChild(infoRow('No stored artifacts of this type.'));
  openToolResult(label, list);
}

async function showCallGraph() {
  if (!state.currentFunctionId) { toast('Select a function from Functions first.'); return showFunctions(); }
  const [callers, callees] = await Promise.all([
    runTool('get_callers', {function:'it', limit:30}, false),
    runTool('get_callees', {function:'it', limit:30}, false),
  ]);
  const root = document.createElement('div'); root.className = 'tool-list';
  const section = (name, result, direction) => {
    root.appendChild(infoRow(`<strong>${escapeHtml(name)}</strong>`));
    if (!result.ok) { root.appendChild(infoRow(escapeHtml(result.error?.message || 'Query failed'))); return; }
    for (const edge of result.data.items) {
      const f = direction === 'caller' ? edge.caller.function : edge.callee.function;
      root.appendChild(infoRow(`<strong>${escapeHtml(f.current_name)}</strong><div class="tool-meta">${escapeHtml(f.address)} · callsite ${escapeHtml(edge.callsite_address)}</div>`));
    }
    if (!result.data.items.length) root.appendChild(infoRow('No matching stored CALL edges.'));
  };
  section('Callers', callers, 'caller'); section('Callees', callees, 'callee');
  openToolResult('Call Graph', root);
}

async function showFindings() {
  const result = await runTool('security_findings', {});
  if (!result.ok) return;
  const list = rowsContainer();
  for (const evaluation of result.data.evaluations || []) {
    list.appendChild(infoRow(`<strong>${escapeHtml(evaluation.rule_id)} · ${escapeHtml(evaluation.status)}</strong><div class="tool-meta">${escapeHtml(evaluation.message)}</div>`));
  }
  for (const finding of result.data.findings || []) {
    list.appendChild(infoRow(`<strong>${escapeHtml(finding.cwe_id || finding.rule_id || 'Finding')}</strong><div class="tool-meta">${escapeHtml(finding.message || '')}</div>`));
  }
  if (!(result.data.evaluations || []).length) list.appendChild(infoRow('No rule evaluations returned.'));
  openToolResult('Findings', list);
}

async function showDecompiled() {
  if (!state.currentFunctionId) { toast('Select a function from Functions first.'); return showFunctions(); }
  const result = await runTool('get_decompiled_text', {function:'it', max_chars:8000});
  if (!result.ok) return;
  updateSelectedFunction(result.data.function);
  const pre = document.createElement('pre'); pre.className = 'code-view'; pre.textContent = result.data.text || 'Decompiled text unavailable in the stored analysis.';
  openToolResult(`Decompiled · ${result.data.function.current_name}`, pre);
}

async function showToolView(name) {
  $$('.tool-card').forEach(card => card.classList.toggle('active', card.dataset.toolView === name));
  if (name === 'functions') return showFunctions();
  if (name === 'strings') return showArtifacts('STRING', 'Strings');
  if (name === 'imports') return showArtifacts('IMPORT', 'Imports');
  if (name === 'callgraph') return showCallGraph();
  if (name === 'findings') return showFindings();
  if (name === 'decompiled') return showDecompiled();
}

function toggleTools() {
  state.toolsCollapsed = !state.toolsCollapsed;
  $('.chat-layout').classList.toggle('tools-collapsed', state.toolsCollapsed);
  $('#collapseTools').textContent = state.toolsCollapsed ? '‹' : '›';
  $('#toolsPanel').inert = state.toolsCollapsed;
  $('#collapseToolsTop').setAttribute('aria-expanded', String(!state.toolsCollapsed));
}

async function switchBinary(binaryId) {
  if (!binaryId || binaryId === state.binaryId) return;
  try {
    const data = await api(`/api/bootstrap?binary_id=${encodeURIComponent(binaryId)}`);
    state.bootstrap = data;
    state.binaryId = data.selected_binary_id;
    state.sessionId = null;
    state.currentFunctionId = null;
    populateBinaries(data.binaries);
    renderBinaryContext(data.binary_metadata);
    resetChat();
    toast(`Loaded ${displayName(data.binary_metadata.binary)}`);
  } catch (error) { toast(error.message); $('#binarySelect').value = state.binaryId; }
}

async function checkHealth() {
  const card = $('#healthCard');
  try {
    const health = await api('/api/health');
    const dot = $('.status-dot', card);
    dot.style.background = health.ok ? 'var(--success)' : 'var(--warning)';
    $('span:last-child', card).textContent = health.ok
      ? `Ollama connected · ${health.selected_model || 'no model selected'}`
      : `Ollama unavailable · ${health.message || 'connection failed'}`;
  } catch (error) { $('span:last-child', card).textContent = `Model check failed · ${error.message}`; }
}

function wireEvents() {
  $$('[data-nav]').forEach(button => button.addEventListener('click', () => {
    const target = button.dataset.nav;
    if (target === 'home') resetChat(); else showView(target);
  }));
  $('#newChatBtn').addEventListener('click', resetChat);
  $('#binarySelect').addEventListener('change', event => switchBinary(event.target.value));
  $$('.prompt-card').forEach(card => card.addEventListener('click', () => {
    $('#homeInput').value = card.dataset.prompt;
    autoSize($('#homeInput'));
    $('#homeInput').focus();
  }));
  $('#homeComposer').addEventListener('submit', event => { event.preventDefault(); if (state.busy) return; const value = $('#homeInput').value; $('#homeInput').value = ''; autoSize($('#homeInput')); sendQuestion(value); });
  $('#chatComposer').addEventListener('submit', event => { event.preventDefault(); if (state.busy) return; const value = $('#chatInput').value; $('#chatInput').value = ''; autoSize($('#chatInput')); sendQuestion(value); });
  [$('#homeInput'), $('#chatInput')].forEach(input => {
    input.addEventListener('input', () => autoSize(input));
    input.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); input.closest('form').requestSubmit(); }
    });
  });
  $$('.tool-card').forEach(card => card.addEventListener('click', () => showToolView(card.dataset.toolView)));
  $('#collapseTools').addEventListener('click', toggleTools);
  $('#collapseToolsTop').addEventListener('click', toggleTools);
}

async function init() {
  wireEvents();
  if (window.matchMedia('(max-width: 820px)').matches) toggleTools();
  try {
    const data = await api('/api/bootstrap');
    state.bootstrap = data;
    state.binaryId = data.selected_binary_id;
    populateBinaries(data.binaries);
    renderBinaryContext(data.binary_metadata);
    $('#modelName').textContent = data.model ? `Ollama · ${data.model}` : 'Ollama · model not selected';
    renderRecent(data.sessions || []);
    showView('home');
  } catch (error) {
    document.body.innerHTML = `<main style="max-width:760px;margin:80px auto;padding:24px;font-family:system-ui;color:#fff"><h1>A.I.R.E. could not start</h1><p style="color:#9aa9ba">${escapeHtml(error.message)}</p><p>Verify that the selected analysis database exists and contains a persisted binary index.</p></main>`;
  }
}

document.addEventListener('DOMContentLoaded', init);
