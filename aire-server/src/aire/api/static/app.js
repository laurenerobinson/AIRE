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
  const inline = value => value.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s).,;:]|$)/g, '$1<em>$2</em>');
  const lines = safe.split('\n');
  const out = [];
  let list = null;
  let table = null;
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  const closeTable = () => { if (table) { out.push('</tbody></table></div>'); table = null; } };
  const cells = row => row.trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map(c => inline(c.trim().replace(/\\\|/g, '|')));
  for (let line of lines) {
    if (/^\s*\|.*\|\s*$/.test(line)) {
      closeList();
      if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue;  // header separator row
      if (!table) { table = true; out.push(`<div class="table-wrap"><table class="fact-table"><thead><tr>${cells(line).map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>`); continue; }
      out.push(`<tr>${cells(line).map(c => `<td>${c}</td>`).join('')}</tr>`);
      continue;
    }
    closeTable();
    const codeToken = line.match(/^@@AIRE_CODE_(\d+)@@$/);
    if (codeToken && blocks[Number(codeToken[1])] !== undefined) { closeList(); out.push(blocks[Number(codeToken[1])]); continue; }
    let match;
    if ((match = line.match(/^(#{1,3})\s+(.+)$/))) { closeList(); const n = match[1].length; out.push(`<h${n}>${match[2]}</h${n}>`); continue; }
    if (/^(A\.I\.R\.E\. Analysis|A\.I\.R\.E\. stored graph results|Summary \(model interpretation\)|Verified stored facts|Model interpretation|Uncertainty|Evidence provenance|Retrieved tool facts|Retrieved code evidence \[.*)$/.test(line)) {
      closeList(); out.push(`<h3>${line}</h3>`); continue;
    }
    if ((match = line.match(/^[-*]\s+(.+)$/))) { if (list !== 'ul') { closeList(); list = 'ul'; out.push('<ul>'); } out.push(`<li>${inline(match[1])}</li>`); continue; }
    if ((match = line.match(/^\d+[.)]\s+(.+)$/))) { if (list !== 'ol') { closeList(); list = 'ol'; out.push('<ol>'); } out.push(`<li>${inline(match[1])}</li>`); continue; }
    closeList();
    if (!line.trim()) { out.push(''); continue; }
    out.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  closeTable();
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

function shortId(value) {
  const text = String(value ?? '');
  return text.length > 28 ? `…${text.slice(-12)}` : text;
}

function renderAnswer(shell, answer, presentation) {
  const body = $('.answer-body', shell);
  body.innerHTML = renderMarkdown(answer);
  if (!presentation) return;
  const badge = document.createElement('div');
  if (presentation.verified) {
    badge.className = 'answer-badge verified';
    badge.textContent = 'Verified stored facts · deterministic · no AI model';
  } else if (presentation.interpretation) {
    badge.className = 'answer-badge interpretation';
    badge.textContent = 'AI interpretation · grounded in stored evidence, not verified fact';
  }
  if (badge.className) body.prepend(badge);
  const footer = document.createElement('p'); footer.className = 'analysis-footer';
  footer.textContent = presentation.footer || ''; body.appendChild(footer);
  const section = (title, count, build) => {
    if (!count) return;
    const details = document.createElement('details'); details.className = 'analysis-details';
    const summary = document.createElement('summary'); summary.textContent = `${title} (${count})`; details.appendChild(summary);
    build(details);
    body.appendChild(details);
  };
  const evidence = presentation.evidence || [];
  section('Evidence · verified stored facts', evidence.length, details => {
    const list = document.createElement('ul'); list.className = 'evidence-list';
    for (const row of evidence) {
      const item = document.createElement('li');
      const label = document.createElement('span'); label.textContent = row.label || '';
      const source = document.createElement('span'); source.className = 'tool-meta';
      const table = row.provenance?.source_table || 'source';
      source.textContent = ` · ${table} · ${shortId(row.evidence_id || row.provenance?.source_id)}`;
      source.title = String(row.evidence_id || row.provenance?.source_id || '');
      const raw = document.createElement('details'); raw.className = 'provenance';
      const rawSummary = document.createElement('summary'); rawSummary.textContent = 'provenance';
      const pre = document.createElement('pre'); pre.textContent = JSON.stringify(row, null, 2);
      raw.append(rawSummary, pre);
      item.append(label, source, raw); list.appendChild(item);
    }
    details.appendChild(list);
  });
  const relationships = presentation.relationships || [];
  section('Call relationships', relationships.length, details => {
    const list = document.createElement('ul'); list.className = 'evidence-list';
    for (const row of relationships) {
      const item = document.createElement('li'); item.textContent = row.label || '';
      item.title = String(row.provenance?.source_id || ''); list.appendChild(item);
    }
    details.appendChild(list);
  });
  const limitations = presentation.limitations || [];
  section('Limitations', limitations.length, details => {
    const list = document.createElement('ul');
    for (const text of limitations) { const item = document.createElement('li'); item.textContent = text; list.appendChild(item); }
    details.appendChild(list);
  });
  section('Tool output · full identifiers', presentation.tool_facts ? 1 : 0, details => {
    const pre = document.createElement('pre'); pre.textContent = presentation.tool_facts; details.appendChild(pre);
  });
  const security = presentation.security || [];
  section('Security checks', security.length, details => {
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(security, null, 2); details.appendChild(pre);
  });
  section('Raw analysis record', presentation.raw ? 1 : 0, details => {
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(presentation.raw, null, 2); details.appendChild(pre);
  });
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

// ---------------------------------------------------------------- M10 Function explorer
const explorerCache = new Map();
async function explorerTool(tool, args) {
  const key = `${state.currentFunctionId}|${tool}|${JSON.stringify(args)}`;
  if (explorerCache.has(key)) return explorerCache.get(key);
  const result = await runTool(tool, {function:'it', ...args});
  if (result.ok) { explorerCache.set(key, result); while (explorerCache.size > 64) explorerCache.delete(explorerCache.keys().next().value); }
  return result;
}
function addr(a) { return `<button class="addr-link" data-addr="${escapeHtml(a)}">0x${escapeHtml(a)}</button>`; }
function badge(text, kind = '') { return `<span class="badge ${kind}">${escapeHtml(text)}</span>`; }
function verdictKind(v) { return v === 'CONSISTENT' ? 'ok' : v === 'POTENTIAL DISCREPANCY' ? 'warn' : 'muted'; }

async function showExplorer(tab = 'overview') {
  if (!state.currentFunctionId) { toast('Select a function first.'); return showFunctions(); }
  let root = $('#explorer');
  if (!root) {
    root = document.createElement('section'); root.id = 'explorer'; root.className = 'explorer';
    root.setAttribute('role', 'dialog'); root.setAttribute('aria-label', 'Function explorer');
    document.body.appendChild(root);
  }
  root.classList.remove('hidden');
  root.innerHTML = `<div class="explorer-head"><h3 id="explorerTitle">Function explorer</h3>
    <nav class="explorer-tabs">${['overview','assembly','cfg','dataflow','decompiler'].map(t =>
      `<button data-tab="${t}" class="${t === tab ? 'active' : ''}">${{overview:'Overview', assembly:'Assembly', cfg:'Control flow', dataflow:'Data flow', decompiler:'Decompiled vs assembly'}[t]}</button>`).join('')}</nav>
    <button class="explorer-close" aria-label="Close explorer">×</button></div><div class="explorer-body" aria-live="polite">Loading…</div>`;
  $('.explorer-close', root).addEventListener('click', () => root.classList.add('hidden'));
  $$('.explorer-tabs button', root).forEach(b => b.addEventListener('click', () => showExplorer(b.dataset.tab)));
  const body = $('.explorer-body', root);
  body.addEventListener('click', event => {
    const link = event.target.closest('.addr-link');
    if (link) { event.preventDefault(); showExplorerAssembly(body, link.dataset.addr); }
  });
  try {
    if (tab === 'overview') await showExplorerOverview(body);
    else if (tab === 'assembly') await showExplorerAssembly(body);
    else if (tab === 'cfg') await showExplorerCfg(body);
    else if (tab === 'dataflow') await showExplorerDataflow(body);
    else await showExplorerDecompiler(body);
  } catch (error) { body.textContent = `Explorer failed: ${error.message}`; }
}

function explorerHeader(data) {
  const f = data.function, b = data.binary, c = data.coverage || {};
  $('#explorerTitle').textContent = `${f.name} · 0x${f.address}`;
  const warn = data.evidence_source !== 'ghidra_pcode' ? `<p class="warning">${escapeHtml(c.note || 'Lower-confidence evidence (assembly text only).')}</p>`
    : c.truncated ? `<p class="warning">Instruction facts truncated at ${c.instructions} instructions.</p>` : '';
  return `<p class="tool-meta">${escapeHtml(b.name || '')} · ${escapeHtml(b.architecture || '')} · SHA-256 ${escapeHtml((b.sha256 || '').slice(0, 16))}… · ${c.instructions ?? '?'} instructions · ${c.blocks ?? '?'} blocks · evidence: ${data.evidence_source === 'ghidra_pcode' ? 'Ghidra P-code' : 'assembly text'}</p>${warn}`;
}

async function showExplorerOverview(body) {
  const [ev, cv] = await Promise.all([explorerTool('function_evidence', {}), explorerTool('crossvalidate_function', {})]);
  if (!ev.ok) { body.textContent = ev.error?.message || 'Unavailable'; return; }
  const d = ev.data, report = cv.ok ? cv.data.crossvalidation : null;
  const list = (items, render) => items.length ? `<ul>${items.map(render).join('')}</ul>` : '<p class="tool-meta">None.</p>';
  body.innerHTML = explorerHeader(d) +
    (report ? `<p>Decompiler cross-check: ${badge(report.verdict, verdictKind(report.verdict))}</p>` : '') +
    `<h4>Calls</h4>${list(d.calls, c => `<li>${addr(c.address)} → ${escapeHtml(c.name || c.target || 'indirect')}</li>`)}
     <h4>Conditions</h4>${list(d.conditional_branches, b => `<li>${addr(b.address)} <code>${escapeHtml(b.text)}</code> → 0x${escapeHtml(b.target)} when ${escapeHtml(b.condition || 'flag condition')}</li>`)}
     <h4>Loops</h4>${list(d.loops, l => `<li>header ${addr(l.header)} · back-edge from ${addr(l.back_edge_from)} · exits ${l.exits.map(addr).join(', ')}</li>`)}
     <h4>Strings</h4>${list(d.strings, s => `<li>${addr(s.address)} “${escapeHtml(s.value.slice(0, 80))}”</li>`)}
     <h4>Writes outside the stack frame</h4>${list(d.non_stack_memory_writes, w => `<li>${addr(w.address)} <code>${escapeHtml(w.text)}</code></li>`)}
     <h4>Parameters read</h4>${list(d.parameter_use, p => `<li>${escapeHtml(p.location)}${p.parameter ? ` (parameter ${p.parameter.ordinal} ${escapeHtml(p.parameter.name)})` : ''} first read at ${addr(p.first_reads[0])}</li>`)}
     <p class="tool-meta">Deterministic evidence from stored Ghidra facts. Purpose is not asserted here; ask “What does this function do?” for a hedged, cited summary.</p>`;
}

async function showExplorerAssembly(body, focus = null, start = null) {
  const result = await explorerTool('explain_instructions', {limit:200, ...(start ? {start} : {})});
  if (!result.ok) { body.textContent = result.error?.message || 'Unavailable'; return; }
  const d = result.data;
  let block = null;
  const rows = d.instructions.map(r => {
    const sep = r.block !== block ? `<tr class="block-sep"><td colspan="3">block 0x${escapeHtml(r.block || '?')}</td></tr>` : '';
    block = r.block;
    // Trace targets: data registers (not address-forming base/index registers) and frame-pointer stack slots read.
    const mem = r.reads.memory || {};
    const addressRegs = new Set([mem.base, mem.index, (r.writes.memory || {}).base, (r.writes.memory || {}).index].filter(Boolean));
    const reads = (r.reads.registers || []).filter(x => !/^(RIP|RSP|ESP)$/.test(x) && !addressRegs.has(x));
    if (mem.kind === 'frame' && mem.base) reads.unshift(`[${mem.base}${mem.disp < 0 ? '-' : '+'}0x${Math.abs(mem.disp).toString(16)}]`);
    const actions = [r.category === 'branch_conditional' ? `<button class="mini" data-branch="${escapeHtml(r.address)}">paths</button>` : '',
      ...reads.slice(0, 3).map(x => `<button class="mini" data-trace="${escapeHtml(r.address)}" data-loc="${escapeHtml(x)}" title="Where does this value come from?">${escapeHtml(x)}?</button>`)].join(' ');
    return sep + `<tr id="ins-${escapeHtml(r.address)}" class="${r.address === focus ? 'focus' : ''} cat-${escapeHtml(r.category)}"><td>${addr(r.address)}</td><td><code>${escapeHtml(r.text)}</code></td>
      <td>${escapeHtml(r.explanation)}${r.confidence !== 'high' ? ` ${badge('confidence ' + r.confidence, 'muted')}` : ''} ${actions}<div class="detail" id="detail-${escapeHtml(r.address)}"></div></td></tr>`;
  }).join('');
  body.innerHTML = explorerHeader(d) + `<table class="asm-table"><tbody>${rows}</tbody></table>` +
    (d.window.more ? `<button class="mini" id="asmMore">Next instructions</button>` : '');
  if (d.window.more) $('#asmMore').addEventListener('click', () => {
    const last = d.instructions[d.instructions.length - 1].address;
    const next = (parseInt(last, 16) + 1).toString(16).padStart(8, '0');
    showExplorerAssembly(body, null, d.instructions[d.instructions.length - 1].address);
  });
  $$('[data-branch]', body).forEach(b => b.addEventListener('click', async () => {
    const r = await explorerTool('branch_paths', {address:b.dataset.branch});
    const p = r.data?.paths; const out = $(`#detail-${b.dataset.branch}`);
    out.innerHTML = !r.ok || p.error ? escapeHtml(p?.error || 'Unavailable') : ['when_true', 'when_false'].map(k =>
      `<p><strong>${escapeHtml(p[k].label)}</strong> → 0x${escapeHtml(p[k].start || '?')}: ${escapeHtml(p[k].outcome)}${p[k].calls.length ? '; calls ' + p[k].calls.map(c => escapeHtml(c.name || c.target)).join(', ') : ''}</p>`).join('');
  }));
  $$('[data-trace]', body).forEach(b => b.addEventListener('click', async () => {
    const r = await explorerTool('trace_value', {address:b.dataset.trace, location:b.dataset.loc});
    const out = $(`#detail-${b.dataset.trace}`);
    out.innerHTML = r.ok ? `<ul class="trace">${renderTrace(r.data.trace)}</ul><p class="tool-meta">${escapeHtml(r.data.limits)}</p>` : escapeHtml(r.error?.message || 'Unavailable');
  }));
  if (focus) $(`#ins-${focus}`, body)?.scrollIntoView({block:'center'});
}

function renderTrace(node, depth = 0) {
  if (depth > 6) return '';
  if (!node.definitions) return `<li>${escapeHtml(node.location)} at 0x${escapeHtml(node.at)}: ${escapeHtml(node.note || node.origin)}</li>`;
  return node.definitions.map(d => {
    if (!d.address) return `<li>${escapeHtml(node.location)}: ${escapeHtml(d.note)}</li>`;
    const what = {constant:`constant ${d.value}`, call_result:`result of call to ${d.call?.target_name || d.call?.target}`,
      stack_slot:'loaded from a stack slot', stored_value:'stored value', global_memory:'global memory', memory:'loaded through a pointer'}[d.origin] || d.origin;
    const children = [d.from, d.pointer, ...(d.inputs || [])].filter(Boolean).map(c => renderTrace(c, depth + 1)).join('');
    return `<li>${escapeHtml(node.location)} ← ${addr(d.address)} <code>${escapeHtml(d.text)}</code>: ${escapeHtml(what)}${children ? `<ul>${children}</ul>` : ''}</li>`;
  }).join('');
}

async function showExplorerCfg(body) {
  const r = await explorerTool('function_cfg', {});
  if (!r.ok) { body.textContent = r.error?.message || 'Unavailable'; return; }
  const g = r.data.cfg, loopHeads = new Set(g.loops.map(l => l.header));
  body.innerHTML = explorerHeader(r.data) + `<p>${g.blocks.length} blocks · ${g.loops.length} loop(s) · ${g.unreachable_blocks.length} unreachable</p>
    <table class="asm-table"><thead><tr><th>Block</th><th>Branch</th><th>Successors</th></tr></thead><tbody>` +
    g.blocks.map(b => `<tr class="${b.reachable ? '' : 'muted'}"><td>${addr(b.start)}${loopHeads.has(b.start) ? ' ' + badge('loop header', 'ok') : ''}</td>
      <td>${b.branch ? `${addr(b.branch.address)} when ${escapeHtml(b.branch.condition || '?')}` : ''}</td>
      <td>${b.successors.map(e => `${addr(e.to)} <span class="tool-meta">${escapeHtml(e.kind)}</span>`).join('<br>')}${b.leaves_function.length ? '<br><span class="tool-meta">leaves function</span>' : ''}</td></tr>`).join('') +
    '</tbody></table><p class="tool-meta">Loops are natural loops found from dominator back-edges.</p>';
}

async function showExplorerDataflow(body) {
  const [params, usage] = await Promise.all([explorerTool('parameter_use', {}), explorerTool('return_usage', {})]);
  const p = params.ok ? params.data : null, u = usage.ok ? usage.data : null;
  body.innerHTML = (p ? explorerHeader(p) : '') + '<h4>Parameters read before written</h4>' +
    (p && p.parameter_use.length ? '<ul>' + p.parameter_use.map(x => `<li>${escapeHtml(x.location)}${x.parameter ? ` = parameter ${x.parameter.ordinal} <code>${escapeHtml(x.parameter.name)}</code> (${escapeHtml(x.parameter.storage)})` : ' (not a Ghidra-recovered parameter)'} · first read ${x.first_reads.map(addr).join(', ')}</li>`).join('') + '</ul>' : '<p class="tool-meta">None.</p>') +
    `<h4>How callers use the return value</h4><p class="tool-meta">Return storage: ${escapeHtml(u?.return_storage?.storage || '?')} (${escapeHtml(u?.return_storage?.type || '?')})</p>` +
    (u && u.callsites.length ? '<ul>' + u.callsites.map(c => `<li><strong>${escapeHtml(c.caller)}</strong> call at 0x${escapeHtml(c.callsite)}: ${c.uses.length ? c.uses.map(x => `${escapeHtml(x.use)} at 0x${escapeHtml(x.address)}${x.then ? ' → ' + escapeHtml(x.then) : ''}`).join('; ') : escapeHtml(c.note)}</li>`).join('') + '</ul>' : '<p class="tool-meta">No stored direct callers.</p>') +
    '<p class="tool-meta">Click a register button in the Assembly tab to trace where a value comes from.</p>';
}

async function showExplorerDecompiler(body) {
  const [cv, dec] = await Promise.all([explorerTool('crossvalidate_function', {}), runTool('get_decompiled_text', {function:'it', max_chars:8000}, false)]);
  if (!cv.ok) { body.textContent = cv.error?.message || 'Unavailable'; return; }
  const report = cv.data.crossvalidation;
  const findings = report.findings.map(f => `<li>${badge(f.status, verdictKind(f.status))} <strong>${escapeHtml(f.check)}</strong>: ${escapeHtml(f.summary)}${f.notes.length ? `<br><span class="tool-meta">${escapeHtml(f.notes[0])}</span>` : ''}</li>`).join('');
  const text = dec.ok ? (dec.data.text || (dec.data.incomplete ? `Decompilation INCOMPLETE: ${dec.data.incomplete.message}` : 'No decompiled text stored.')) : 'Unavailable';
  body.innerHTML = explorerHeader(cv.data) + `<p>Verdict: ${badge(report.verdict, verdictKind(report.verdict))}</p><ul>${findings}</ul>` +
    (report.decompiler_warnings.length ? `<p class="warning">Ghidra warnings: ${escapeHtml(report.decompiler_warnings.join('; '))}</p>` : '') +
    `<pre class="code-view">${escapeHtml(text)}</pre><p class="tool-meta">${escapeHtml(report.verdict_basis || '')}</p>`;
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
  if (name === 'explorer') return showExplorer();
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
