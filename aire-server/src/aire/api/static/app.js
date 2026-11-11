'use strict';

const state = {
  bootstrap: null,
  binaryId: null,
  binaryMeta: null,
  sessionId: null,
  currentFunctionId: null,
  busy: false,
  toolsCollapsed: false,
  uploadId: null,
  analysisJob: null,
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
  const map = {home:'#homeView', chat:'#chatView', recent:'#recentView', about:'#aboutView', library:'#libraryView'};
  Object.entries(map).forEach(([key, selector]) => $(selector).classList.toggle('hidden', key !== name));
  setActiveNav(name === 'chat' ? 'home' : name);
  $('#collapseToolsTop').classList.toggle('hidden', name !== 'chat');
  if (name === 'recent') loadRecent();
  if (name === 'about') checkHealth();
  if (name === 'library') loadLibrary();
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
  if (!state.binaryId) throw new Error('Upload or select a repository binary first.');
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
  $('.workspace-preview', shell)?.remove();
  renderAnswer(shell, result.answer || 'No answer returned.', result.presentation);
  const log = $('.activity-log', shell);
  if (!log.classList.contains('hidden')) {
    const summary = $('summary', log);
    const count = $$('.activity-item', log).length;
    summary.textContent = `Analysis activity · ${count} event${count === 1 ? '' : 's'} · ${result.status}`;
  }
}

function renderAnswer(shell, answer, presentation) {
  const body = $('.answer-body', shell);
  body.innerHTML = renderMarkdown(answer);
  if (!presentation) return;
  if (presentation.interpretation) {
    const label = document.createElement('div');
    label.className = 'interpretation-label'; label.textContent = 'AI interpretation · grounded in stored evidence';
    body.prepend(label);
  }
  const footer = document.createElement('p'); footer.className = 'analysis-footer';
  footer.textContent = presentation.footer; body.appendChild(footer);
  const section = (title, rows, raw = false) => {
    const details = document.createElement('details'); details.className = 'analysis-details';
    const summary = document.createElement('summary'); summary.textContent = title; details.appendChild(summary);
    if (raw) {
      const pre = document.createElement('pre'); pre.textContent = JSON.stringify(rows, null, 2); details.appendChild(pre);
    } else for (const row of rows) {
      const p = document.createElement('p'); p.textContent = row.label || ''; details.appendChild(p);
      const pre = document.createElement('pre'); pre.textContent = JSON.stringify(row, null, 2); details.appendChild(pre);
    }
    body.appendChild(details);
  };
  section('Evidence · Verified stored facts', presentation.evidence || []);
  section('Call Relationships', presentation.relationships || []);
  section('Security Checks', presentation.security || [], true);
  section('Raw Analysis Details', presentation.raw, true);
}

function previewAnswer(shell, data) {
  const body = $('.answer-body', shell);
  body.innerHTML = '';
  const label = document.createElement('div'); label.className = 'interpretation-label';
  label.textContent = 'AI interpretation · generating, validation pending';
  const text = document.createElement('p'); text.textContent = data.text;
  body.append(label, text);
}

function previewContext(shell, data) {
  let context = $('.workspace-preview', shell);
  if (!context) {
    context = document.createElement('div'); context.className = 'workspace-preview';
    $('.answer-body', shell).before(context);
  }
  context.textContent = 'Verified stored facts\n' + data.text;
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
        if (packet.type === 'text') previewAnswer(shell, packet.data);
        if (packet.type === 'context') previewContext(shell, packet.data);
        if (packet.type === 'result') final = packet.data;
        if (packet.type === 'error') throw new Error(packet.data.message || packet.data.error);
      }
      $('#messages').scrollTop = $('#messages').scrollHeight;
      if (done) break;
    }
    if (!final && buffer.trim()) {
      const packet = JSON.parse(buffer);
      if (packet.type === 'result') final = packet.data;
      if (packet.type === 'text') previewAnswer(shell, packet.data);
      if (packet.type === 'context') previewContext(shell, packet.data);
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
        renderAnswer(shell, message.text, message.presentation);
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
  root.scrollIntoView({block:'nearest', behavior:'smooth'});
}

function rowsContainer() { const el = document.createElement('div'); el.className = 'tool-list'; return el; }
function infoRow(html, asButton = false) { const el = document.createElement(asButton ? 'button' : 'div'); el.className = 'tool-row'; el.innerHTML = html; return el; }

async function showFunctions(offset = 0) {
  const result = await runTool('list_functions', {limit:40, offset});
  if (!result.ok) return;
  const list = rowsContainer();
  const lookup = document.createElement('form'); lookup.className = 'function-lookup';
  const input = document.createElement('input'); input.placeholder = 'Exact function name or address'; input.setAttribute('aria-label', 'Function name or address');
  const select = document.createElement('button'); select.textContent = 'Select'; select.type = 'submit';
  lookup.append(input, select);
  lookup.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const selected = await api(`/api/sessions/${state.sessionId}/select-function`, {method:'POST', body:JSON.stringify({function:input.value.trim()})});
      updateSelectedFunction(selected.selected_function);
      toast(`Selected ${selected.selected_function.current_name}`);
    } catch (error) { toast(error.message); }
  });
  list.appendChild(lookup);
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
  if (offset > 0) { const prev = infoRow('Previous 40 functions', true); prev.addEventListener('click', () => showFunctions(Math.max(0, offset-40))); list.appendChild(prev); }
  if (result.data.items.length === 40) { const next = infoRow('Next 40 functions', true); next.addEventListener('click', () => showFunctions(offset+40)); list.appendChild(next); }
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

async function showCrypto() {
  // Deterministic crypto API evidence: exact callsites, identifier strings, callers.
  const result = await runTool('crypto_evidence', {limit:50});
  if (!result.ok) return;
  const data = result.data, list = rowsContainer();
  list.appendChild(infoRow(`<strong>${data.summary.functions_with_crypto_calls} function(s) with crypto API calls</strong><div class="tool-meta">${data.summary.crypto_api_imports_called}/${data.summary.crypto_api_imports} crypto imports called · families: ${escapeHtml(data.summary.families.join(', ') || 'none')}</div>`));
  for (const f of data.functions) {
    const calls = f.callsites.map(c => `${escapeHtml(c.address)} → ${escapeHtml(c.api)} (${escapeHtml(c.operation)})`).join('<br>');
    const ids = f.identifier_strings.map(s => `${escapeHtml(s.address)} → "${escapeHtml(s.value)}" (${escapeHtml(s.meaning)})`).join('<br>');
    const callers = f.callers.map(c => `${escapeHtml(c.name)} @ ${escapeHtml(c.callsite)}`).join(', ');
    const row = infoRow(`<strong>${escapeHtml(f.name)} · ${escapeHtml(f.address)} · ${escapeHtml(f.primary_operations.join(', ') || f.operations.join(', '))}</strong>`
      + `<div class="tool-meta">${calls}${ids ? '<br>Identifiers:<br>' + ids : ''}${callers ? '<br>Called by: ' + callers : ''}</div>`, true);
    row.addEventListener('click', async () => {
      try {
        const selected = await api(`/api/sessions/${state.sessionId}/select-function`, {method:'POST', body:JSON.stringify({function:f.function_id})});
        updateSelectedFunction(selected.selected_function);
        toast(`Selected ${selected.selected_function.current_name}`);
      } catch (error) { toast(error.message); }
    });
    list.appendChild(row);
  }
  if (!data.functions.length) list.appendChild(infoRow('No stored crypto API callsites. Absence covers only recognized imported APIs.'));
  list.appendChild(infoRow(`<div class="tool-meta">${data.limitations.map(escapeHtml).join('<br>')}</div>`));
  openToolResult('Crypto evidence', list);
}

async function showDecompiled() {
  if (!state.currentFunctionId) { toast('Select a function from Functions first.'); return showFunctions(); }
  const result = await runTool('get_decompiled_text', {function:'it', max_chars:8000});
  if (!result.ok) return;
  updateSelectedFunction(result.data.function);
  const missing = result.data.incomplete ? `Decompilation INCOMPLETE for this function (${result.data.incomplete.reason}): ${result.data.incomplete.message}` : 'Decompiled text unavailable in the stored analysis.';
  const pre = document.createElement('pre'); pre.className = 'code-view'; pre.textContent = result.data.text || missing;
  openToolResult(`Decompiled · ${result.data.function.current_name}`, pre);
}

async function showToolView(name) {
  $$('.tool-card').forEach(card => card.classList.toggle('active', card.dataset.toolView === name));
  if (name === 'functions') return showFunctions();
  if (name === 'strings') return showArtifacts('STRING', 'Strings');
  if (name === 'imports') return showArtifacts('IMPORT', 'Imports');
  if (name === 'callgraph') return showCallGraph();
  if (name === 'findings') return showFindings();
  if (name === 'crypto') return showCrypto();
  if (name === 'decompiled') return showDecompiled();
  if (['assembly', 'xrefs', 'thunks', 'crosscheck'].includes(name)) {
    if (!state.currentFunctionId) { toast('Select a function first.'); return showFunctions(); }
    const tool = {assembly:'get_assembly', xrefs:'get_xrefs', thunks:'get_thunk_target', crosscheck:'crosscheck_function'}[name];
    const result = await runTool(tool, {function:'it'});
    if (!result.ok) return;
    if (name === 'crosscheck') {
      const root = document.createElement('div');
      const report = result.data;
      const families = {integer_multiplication:'Integer multiplication', scalar_double_multiplication:'Scalar double-precision floating-point multiplication', scalar_float_multiplication:'Scalar single-precision floating-point multiplication'};
      const observations = report.assembly_observations.filter(row => row.same_operand && families[row.operation_family]);
      for (const row of observations) {
        const p = document.createElement('p');
        p.textContent = `${families[row.operation_family]} of a locally tracked value by itself (likely squaring), at ${row.address}.`;
        root.appendChild(p);
      }
      const note = document.createElement('p');
      note.textContent = `${report.cross_check_status}: ${observations.length ? 'Local arithmetic observation only.' : 'No same-value multiplication established by the local recognizer.'} Original source parameter types and full function equivalence are not established.`;
      root.appendChild(note);
      const source = document.createElement('small'); source.textContent = `Evidence: ${report.provenance.source_table} · ${report.provenance.source_id}`;
      root.appendChild(source);
      const raw = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Full instruction / decompiler report';
      const pre = document.createElement('pre'); pre.textContent = JSON.stringify(report, null, 2); raw.append(summary, pre); root.appendChild(raw);
      openToolResult('Arithmetic evidence', root);
      return;
    }
    const pre = document.createElement('pre'); pre.className = 'code-view';
    pre.textContent = name === 'assembly' ? result.data.text : JSON.stringify(result.data, null, 2);
    if (name === 'xrefs') {
      const strings = await runTool('get_function_strings', {function:'it'});
      pre.textContent += '\n\nFunction-owned string references:\n' + JSON.stringify(strings.data || strings.error, null, 2);
    }
    openToolResult(name, pre);
  }
}

async function loadLibrary() {
  try {
    const data = await api('/api/library');
    const root = $('#fixtureList'); root.innerHTML = '';
    const analyzer = data.analyzer || {};
    const analyzerText = {ready: `Analyzer ready (pre-warmed in ${(analyzer.seconds || 0).toFixed(1)} s)`, warming: 'Analyzer warming up in the background…', running: 'Analyzer running', failed: `Analyzer pre-warm failed (${analyzer.error || 'unknown'}); it will start on the first analysis`, not_started: 'Analyzer starts on the first analysis', stopped: 'Analyzer stopped; it restarts on the next analysis'}[analyzer.status];
    if (analyzerText) { const note = document.createElement('p'); note.className = 'tool-meta'; note.textContent = analyzerText; root.appendChild(note); }
    for (const fixture of data.fixtures) {
      const row = document.createElement('div'); row.className = 'fixture-row';
      const text = document.createElement('div');
      const name = document.createElement('strong'); name.textContent = fixture.name;
      const detail = document.createElement('p');
      detail.textContent = `${fixture.collection} · ${fixture.format || 'unknown'} · ${fixture.architecture || 'unknown'} ${fixture.bits || ''} · ${fixture.cached ? 'Cached' : fixture.indexed ? 'Indexed; refresh required' : 'Not indexed'}${fixture.negative_fixture ? ' · Negative fixture' : ''}`;
      const level = fixture.analysis_level || fixture.validation?.analysis_level;
      if (level) detail.textContent += ` · ${{full: 'Structure valid', partial: 'Damaged: partial analysis', none: 'Invalid: rejected'}[level] || level}`;
      const path = document.createElement('small'); path.textContent = fixture.error || fixture.binary_path;
      text.append(name, detail, path);
      const report = fixture.validation || (level && level !== 'full' ? fixture : null);
      if (report) {
        const more = document.createElement('details'); more.className = 'structure-report';
        const summary = document.createElement('summary'); summary.textContent = `${report.structure_issue_count || 0} structure issue(s)`;
        const body = document.createElement('pre'); body.textContent = structureText(report);
        more.append(summary, body); text.appendChild(more);
      }
      row.appendChild(text);
      const button = document.createElement('button'); button.textContent = !fixture.available ? 'Unavailable' : fixture.cached ? 'Open cached analysis' : 'Analyze & open';
      button.disabled = !fixture.available || !!state.analysisJob;
      button.addEventListener('click', () => startAnalysis({fixture_id:fixture.fixture_id})); row.appendChild(button);
      root.appendChild(row);
    }
  } catch (error) { toast(error.message); }
}

function structureText(report) {
  // Static PE/ELF structure report from the server; never inferred client-side.
  if (!report || !report.analysis_level) return '';
  const level = {full: 'Full analysis possible', partial: 'Partial analysis only', none: 'No analysis possible'}[report.analysis_level] || report.analysis_level;
  const validity = report.pe_valid === null || report.pe_valid === undefined ? '' : ` · PE structure ${report.pe_valid ? 'valid' : 'INVALID'}`;
  const lines = [`Structure: ${report.structure_summary || ''}${validity} · ${level}`];
  for (const issue of report.structure_issues || []) {
    lines.push(`  [${issue.severity}] ${issue.code}: ${issue.message}${issue.offset === null || issue.offset === undefined ? '' : ` (file offset 0x${issue.offset.toString(16)})`}`);
  }
  const hidden = (report.structure_issue_count || 0) - (report.structure_issues || []).length;
  if (hidden > 0) lines.push(`  … ${hidden} more issue(s)`);
  return lines.join('\n');
}

async function validateUpload() {
  const file = $('#binaryFile').files[0];
  state.uploadId = null; $('#analyzeUpload').disabled = true;
  if (!file) return;
  $('#uploadDetails').textContent = `${file.name} · ${file.size} bytes · validating…`;
  try {
    if (!file.size || file.size > 32*1024*1024) throw new Error('Select a nonempty binary up to 32 MiB.');
    const response = await fetch(`/api/uploads?filename=${encodeURIComponent(file.name)}`, {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:file});
    let data;
    try { data = await response.json(); } catch { throw new Error(`Upload failed (HTTP ${response.status})`); }
    if (!response.ok) {
      const failure = new Error(data.message || 'Upload failed');
      failure.validation = data.validation;
      throw failure;
    }
    if ($('#binaryFile').files[0] !== file) return;
    state.uploadId = data.upload_id;
    $('#uploadDetails').textContent = `${data.filename} · ${data.format} · ${data.architecture} ${data.bits}-bit · ${data.size} bytes\nSHA-256 ${data.sha256}\n${structureText(data)}`;
    $('#analyzeUpload').disabled = !!state.analysisJob;
  } catch (error) {
    const report = error.validation;
    const known = report && (report.format || report.architecture) ? `\nDetected: ${report.format || 'unknown format'} · ${report.architecture || 'unknown architecture'}${report.bits ? ` ${report.bits}-bit` : ''}` : '';
    $('#uploadDetails').textContent = `Validation failed: ${error.message}${known}${report ? '\n' + structureText(report) : ''}\nThe file was not analyzed or executed. Choose another binary.`;
  }
}

async function startAnalysis(selection) {
  if (state.analysisJob) return;
  try {
    const job = await api('/api/analysis', {method:'POST', body:JSON.stringify(selection)});
    state.analysisJob = job.job_id;
    $('#analyzeUpload').disabled = true;
    $('#binaryFile').disabled = true;
    await loadLibrary();
    await pollAnalysis(job.job_id);
  } catch (error) { $('#analysisStatus').textContent = `Analysis failed: ${error.message}`; }
  finally {
    state.analysisJob = null;
    $('#binaryFile').disabled = false;
    $('#analyzeUpload').disabled = !state.uploadId;
    await loadLibrary();
  }
}

async function pollAnalysis(id) {
  for (;;) {
    const job = await api(`/api/analysis/${id}`);
    $('#analysisStatus').textContent = `${job.filename} · ${job.status} · ${job.phase} · ${job.elapsed_seconds.toFixed(2)} s elapsed\n` +
      job.events.map(event => `${event.seconds.toFixed(2)} s · ${event.phase}`).join('\n');
    if (job.status === 'failed') throw new Error(job.error);
    if (job.status === 'completed') {
      $('#analysisStatus').textContent += `\n${job.cache_hit ? 'Persisted cache reused' : 'Fresh static analysis'} · processing ${job.analysis_seconds.toFixed(3)} s · queue ${job.queue_seconds.toFixed(3)} s · total ${job.total_seconds.toFixed(3)} s · SHA-256 ${job.sha256}`;
      const warningCount = job.warning_count ?? job.warnings?.length ?? 0;
      if (warningCount) $('#analysisStatus').textContent += `\n${warningCount} analyzer warnings recorded.`;
      if (job.decompile_retry?.retried) $('#analysisStatus').textContent += `\n${job.decompile_retry.retried} decompilation timeout(s) retried serially; ${job.decompile_retry.recovered} recovered.`;
      if (job.decompilation_incomplete_count) $('#analysisStatus').textContent += `\nINCOMPLETE: ${job.decompilation_incomplete_count} function(s) have no decompiled text (see Decompiled View for the reason). Evidence for them is limited to assembly and references.`;
      if (job.analysis_level === 'partial') $('#analysisStatus').textContent += `\n${structureText(job)}\nEvidence may be incomplete: damaged regions could not be analyzed.`;
      await switchBinary(job.binary_id, true);
      await ensureSession(); showView('chat'); await showFunctions();
      toast(`${job.cache_hit ? 'Cached analysis opened' : 'Analysis completed'} in ${job.analysis_seconds.toFixed(3)} s`);
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
}

function toggleTools() {
  state.toolsCollapsed = !state.toolsCollapsed;
  $('.chat-layout').classList.toggle('tools-collapsed', state.toolsCollapsed);
  $('#collapseTools').textContent = state.toolsCollapsed ? '‹' : '›';
  $('#toolsPanel').inert = state.toolsCollapsed;
  $('#collapseToolsTop').setAttribute('aria-expanded', String(!state.toolsCollapsed));
}

async function switchBinary(binaryId, force = false) {
  if (!binaryId || (binaryId === state.binaryId && !force)) return;
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
  $('#binaryFile').addEventListener('change', validateUpload);
  $('#uploadForm').addEventListener('submit', event => { event.preventDefault(); if (state.uploadId) startAnalysis({upload_id:state.uploadId}); });
  $('#refreshLibrary').addEventListener('click', loadLibrary);
  $('#investigateBtn').addEventListener('click', async () => {
    try { await ensureSession(); showView('chat'); await showFunctions(); } catch (error) { toast(error.message); showView('library'); }
  });
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
    showView(state.binaryId ? 'home' : 'library');
  } catch (error) {
    document.body.innerHTML = `<main style="max-width:760px;margin:80px auto;padding:24px;font-family:system-ui;color:#fff"><h1>A.I.R.E. could not start</h1><p style="color:#9aa9ba">${escapeHtml(error.message)}</p><p>Verify that the selected analysis database exists and contains a persisted binary index.</p></main>`;
  }
}

document.addEventListener('DOMContentLoaded', init);
