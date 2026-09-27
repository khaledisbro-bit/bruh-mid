'use strict';
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

const state = { filePath: null, outDir: null, harness: null, analysis: null, finalSource: null, history: [] };

// ---- navigation ----
$$('.nav button').forEach(b => b.addEventListener('click', () => {
  $$('.nav button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  const page = b.dataset.page;
  $$('.page').forEach(p => p.classList.remove('active'));
  $('#page-' + page).classList.add('active');
  $('#pageTitle').textContent = b.textContent.trim();
}));
$$('.tabs button[data-tab]').forEach(b => b.addEventListener('click', () => {
  const grp = b.closest('.tabs');
  grp.querySelectorAll('button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  const pane = b.dataset.tab;
  $$('.tabpane').forEach(p => p.classList.remove('active'));
  $('#tab-' + pane).classList.add('active');
}));

// ---- lua highlighter (lightweight) ----
const LUA_KW = new Set(('and break do else elseif end false for function if in local nil not or repeat return then true until while'
  + ' goto continue self').split(' '));
function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function highlightLua(code) {
  let out = ''; let i = 0; const n = code.length;
  while (i < n) {
    const c = code[i];
    // comments
    if (c === '-' && code[i+1] === '-') {
      let j = i + 2;
      if (code[j] === '[' && code[j+1] === '[') { const e = code.indexOf(']]', j); j = e < 0 ? n : e + 2; }
      else { const e = code.indexOf('\n', j); j = e < 0 ? n : e; }
      out += `<span class="tok-com">${esc(code.slice(i, j))}</span>`; i = j; continue;
    }
    // strings
    if (c === '"' || c === "'") {
      let j = i + 1; while (j < n && code[j] !== c) { if (code[j] === '\\') j++; j++; }
      j++; out += `<span class="tok-str">${esc(code.slice(i, j))}</span>`; i = j; continue;
    }
    if (c === '[' && code[i+1] === '[') { const e = code.indexOf(']]', i + 2); const j = e < 0 ? n : e + 2; out += `<span class="tok-str">${esc(code.slice(i, j))}</span>`; i = j; continue; }
    // numbers
    if (/[0-9]/.test(c)) { let j = i; while (j < n && /[0-9a-fA-FxX.]/.test(code[j])) j++; out += `<span class="tok-num">${esc(code.slice(i, j))}</span>`; i = j; continue; }
    // identifiers / keywords
    if (/[A-Za-z_]/.test(c)) {
      let j = i; while (j < n && /[A-Za-z0-9_]/.test(code[j])) j++;
      const w = code.slice(i, j);
      if (LUA_KW.has(w)) out += `<span class="tok-kw">${w}</span>`;
      else if (code[j] === '(') out += `<span class="tok-fn">${esc(w)}</span>`;
      else out += esc(w);
      i = j; continue;
    }
    if ('+-*/%^#=~<>(){}.,:;'.includes(c)) { out += `<span class="tok-op">${esc(c)}</span>`; i++; continue; }
    out += esc(c); i++;
  }
  return out;
}
function showSource(el, code) {
  if (!code) { el.classList.add('empty'); el.textContent = 'Nothing yet.'; return; }
  el.classList.remove('empty'); el.innerHTML = highlightLua(code);
}

// ---- stages ----
function setStage(name, cls, text) {
  const el = $(`.stage[data-st="${name}"]`);
  el.classList.remove('run', 'done'); if (cls) el.classList.add(cls);
  if (text != null) el.querySelector('.s').textContent = text;
  el.querySelector('.pill').textContent = cls === 'done' ? 'done' : (cls === 'run' ? 'running' : '');
}
function resetStages() { ['detect','static','harness','audit'].forEach(s => setStage(s, '', '-')); }

// ---- file flow ----
const drop = $('#drop');
drop.addEventListener('click', async () => { const f = await window.vm.pickFile(); if (f) analyzeFile(f); });
['dragover','dragenter'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('hot'); }));
['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('hot'); }));
drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) analyzeFile(f.path); });

async function analyzeFile(filePath) {
  state.filePath = filePath; state.harness = null; state.finalSource = null;
  $('#dropFile').textContent = filePath;
  $('#pageSub').textContent = filePath.split(/[\\/]/).pop();
  resetStages();
  setStage('detect', 'run', 'analyzing...');
  const r = await window.vm.analyze(filePath).catch(e => ({ code: -1, stderr: String(e) }));
  state.outDir = r.outDir; state.harness = r.harness; state.analysis = r.analysis;
  fillStructure(r);

  const family = (r.stages && r.stages.detect) || '';
  const universal = /unknown/i.test(family);
  if (!r.harness) {
    // engine could not even build a harness (e.g. crash, missing python/zstandard)
    setStage('detect', '', family || 'failed');
    setStage('static', '', 'stopped');
    const why = (r.stderr && r.stderr.trim()) || (r.stdout || '').trim() || 'engine produced no harness';
    $('#finalLbl').textContent = 'Could not process this file';
    $('#finalCode').classList.remove('empty');
    $('#finalCode').textContent =
      'Detect: ' + (family || 'unknown') + '\n\n' +
      'The engine could not build a harness.\n\n' +
      'Checklist:\n' +
      ' 1) Is python + zstandard installed?  (pip install zstandard)\n' +
      ' 2) Is the pipeline folder up to date (pipeline/universal.lua present)?\n\n' +
      '--- engine output ---\n' + why;
    return;
  }

  if (universal) {
    setStage('detect', 'done', 'unknown family');
    setStage('static', 'done', 'universal dynamic trace');
    setStage('harness', 'run', 'ready (behavior mode)');
    $('#finalLbl').textContent = 'Universal mode: recovering behavior (no static plugin for this family)';
  } else {
    setStage('detect', 'done', family);
    setStage('static', 'done', r.stages.static || 'unwrapped');
    setStage('harness', 'run', 'ready');
  }
  autoRun(); // full auto in both modes
}

function fillStructure(r) {
  const a = r.analysis; const kv = $('#structKv'); const pills = $('#classPills');
  $('#structRaw').textContent = r.vmStructure || '(none)';
  if (!a || !a.inner_vm) { kv.innerHTML = '<div class="empty" style="grid-column:1/3">Not the base85+Zstd family.</div>'; pills.innerHTML = ''; return; }
  const vm = a.inner_vm, l1 = a.layer1 || {};
  const rows = [
    ['Family', 'base85 + Zstd Luau VM'],
    ['Sample', `${a.sample} (${a.size} bytes)`],
    ['Inner source', (l1.inner_source_len || '?') + ' bytes'],
    ['Inner data', (l1.inner_data_len || '?') + ' bytes'],
    ['Resolver', vm.resolver ? `${vm.resolver.name} -> ${vm.resolver.decoder}(${vm.resolver.const_table}[i])` : '?'],
    ['LCG', vm.lcg && vm.lcg[0] ? `x*${vm.lcg[0].mul}+${vm.lcg[0].add} % ${vm.lcg[0].mod}` : '?'],
    ['Integrity', vm.integrity ? (vm.integrity.sha256_table ? 'SHA-256 table' : 'none') : '?'],
    ['Functions', vm.local_function_count]
  ];
  kv.innerHTML = rows.map(([k, v]) => `<div class="k">${k}</div><div class="v">${esc(String(v))}</div>`).join('');
  const cl = a.classification || {};
  const mk = (arr, css) => (arr || []).map(x => `<span class="chip ${css}">${esc(x[0])}</span>`).join('');
  pills.innerHTML = mk(cl.REAL, 'real') + mk(cl.SUSPICIOUS, 'susp') + mk(cl.DECOY, 'decoy');
}

// ---- executor ----
async function autoRun() {
  if (!state.harness) { setStage('harness', '', 'no harness (file not recognized)'); return; }
  setStage('harness', 'run', 'running via MCP...');
  const res = await window.vm.runMcp(state.harness).catch(e => ({ ok: false, error: String(e) }));
  if (res && res.ok && res.body && res.body.includes('BEGIN_UNOBF_RESULT')) {
    setStage('harness', 'done', 'ran via MCP');
    finalize(res.body);
  } else if (res && res.ok && res.body) {
    // MCP ran but the output is not our block (no Roblox client, or truncated)
    setStage('harness', '', 'MCP ran but no result block - is a Roblox client connected?');
    $('#pasteBox').value = res.body;
  } else {
    setStage('harness', '', 'MCP failed: ' + (res && res.error ? res.error : 'offline') + ' - use Executor tab');
  }
}
$('#mcpRunBtn').addEventListener('click', autoRun);
$('#copyHarnessBtn').addEventListener('click', async () => { await window.vm.copy(state.harness || ''); flash('#copyHarnessBtn', 'Copied'); });
$('#finalizeBtn').addEventListener('click', () => { const t = $('#pasteBox').value.trim(); if (t) finalize(t); else alert('Paste the result block first.'); });

async function finalize(traceText) {
  setStage('audit', 'run', 'verifying...');
  const r = await window.vm.finalize({ filePath: state.filePath, outDir: state.outDir, traceText, candidatePath: null })
    .catch(e => ({ code: -1, stderr: String(e) }));
  if (!r || r.code === -1) { setStage('audit', '', 'verify error: ' + ((r && r.stderr) || 'unknown')); return; }
  const verdict = (r.verdict || '').trim();
  const src = r.finalSource;
  if (src) {
    const ok = verdict === 'CONSISTENT';
    setStage('audit', ok ? 'done' : 'run', verdict || 'done');
    $('#verdictBox').innerHTML = `<span class="verdict ${ok ? 'ok' : 'bad'}">${verdict || 'DONE'}</span>`;
    state.finalSource = src; $('#finalLbl').textContent = 'Recovered source'; showSource($('#finalCode'), src);
  } else {
    // universal / behavior-only result
    setStage('audit', 'done', 'behavior captured');
    $('#verdictBox').innerHTML = `<span class="verdict ok">BEHAVIOR CAPTURED</span>`;
    $('#finalLbl').textContent = 'What the script actually does (universal trace)';
    showSource($('#finalCode'), r.behavior || 'No behavior recorded.');
  }
  if (r.behavior) { $('#constCode').classList.remove('empty'); $('#constCode').textContent = r.behavior; }
  pushHistory(verdict || 'BEHAVIOR');
}

// ---- final source actions ----
$('#copyBtn').addEventListener('click', async () => { await window.vm.copy(state.finalSource || $('#finalCode').textContent); flash('#copyBtn', 'Copied'); });
$('#saveBtn').addEventListener('click', async () => { const p = await window.vm.saveSource(state.finalSource || $('#finalCode').textContent); if (p) flash('#saveBtn', 'Saved'); });

function flash(sel, text) { const el = $(sel); const t = el.innerHTML; el.innerHTML = `<svg><use href="#i-shield"/></svg> ${text}`; setTimeout(() => el.innerHTML = t, 1200); }

// ---- history ----
function pushHistory(verdict) {
  state.history.unshift({ file: (state.filePath || '').split(/[\\/]/).pop(), verdict, time: new Date().toLocaleTimeString(), source: state.finalSource });
  const list = $('#histList');
  list.innerHTML = state.history.map((h, idx) =>
    `<div class="hist-item" data-i="${idx}"><span>${esc(h.file)}</span><span class="sub">${h.verdict || '-'} · ${h.time}</span></div>`).join('');
  list.querySelectorAll('.hist-item').forEach(el => el.addEventListener('click', () => {
    const h = state.history[+el.dataset.i]; if (h && h.source) { state.finalSource = h.source; showSource($('#finalCode'), h.source); $$('.nav button')[0].click(); }
  }));
}

// ---- settings ----
(async () => {
  const s = await window.vm.getSettings();
  $('#mcpUrl').value = s.mcpUrl || ''; $('#pyCmd').value = s.python || ''; $('#mcpToken').value = s.mcpToken || '';
  probeMcp();
})();
$('#saveSettings').addEventListener('click', async () => {
  await window.vm.setSettings({ mcpUrl: $('#mcpUrl').value.trim(), mcpToken: $('#mcpToken').value.trim(), python: $('#pyCmd').value.trim() });
  flash('#saveSettings', 'Saved'); probeMcp();
});
async function probeMcp() {
  const dot = $('#mcpDot'), txt = $('#mcpText');
  dot.className = 'mcp-dot off'; txt.textContent = 'MCP checking...';
  try {
    const res = await window.vm.runMcp('return "vmsmart-probe"');
    if (res && res.ok) { dot.className = 'mcp-dot on'; txt.textContent = 'MCP connected (' + (res.tool || 'exec') + ')'; }
    else { dot.className = 'mcp-dot off'; txt.textContent = 'MCP manual (' + (res && res.error ? res.error : 'offline') + ')'; }
  } catch (_) { dot.className = 'mcp-dot off'; txt.textContent = 'MCP manual mode'; }
}
