'use strict';
const { app, BrowserWindow, ipcMain, dialog, shell, clipboard } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const { spawn } = require('child_process');

// pipeline lives next to the app folder in dev, or under resources when packaged
function resolvePipeline() {
  const candidates = [
    path.join(__dirname, '..', 'pipeline'),          // dev (repo)
    path.join(process.resourcesPath || '', 'pipeline') // packaged (extraResources)
  ];
  for (const c of candidates) { try { if (fs.existsSync(path.join(c, 'deob.py'))) return c; } catch (_) {} }
  return candidates[0];
}
const PIPELINE_DIR = resolvePipeline();
const DEOB = path.join(PIPELINE_DIR, 'deob.py');
const WORK = path.join(os.tmpdir(), 'vmsmart');
fs.mkdirSync(WORK, { recursive: true });

let win;
let settings = { mcpUrl: 'http://127.0.0.1:8225/mcp', mcpToken: '', python: process.platform === 'win32' ? 'python' : 'python3' };
const SETTINGS_FILE = path.join(app.getPath('userData'), 'settings.json');
try { Object.assign(settings, JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'))); } catch (_) {}
function saveSettings() { try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2)); } catch (_) {} }

function createWindow() {
  win = new BrowserWindow({
    width: 1180, height: 780, minWidth: 900, minHeight: 620,
    backgroundColor: '#140a24', frame: true, titleBarStyle: 'hiddenInset',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

// ---- helpers ----------------------------------------------------------------
function runPython(args) {
  return new Promise((resolve) => {
    const p = spawn(settings.python, args, { cwd: WORK });
    let out = '', err = '';
    p.stdout.on('data', d => out += d);
    p.stderr.on('data', d => err += d);
    p.on('error', e => resolve({ code: -1, out, err: String(e) }));
    p.on('close', code => resolve({ code, out, err }));
  });
}

// ---- MCP (Streamable HTTP / JSON-RPC) client -------------------------------
function mcpPost(urlStr, token, sessionId, bodyObj) {
  return new Promise((resolve) => {
    let payload;
    try { payload = JSON.stringify(bodyObj); } catch (e) { return resolve({ error: String(e) }); }
    let u; try { u = new URL(urlStr); } catch (e) { return resolve({ error: 'bad url' }); }
    const lib = u.protocol === 'https:' ? require('https') : http;
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'Content-Length': Buffer.byteLength(payload)
    };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    if (sessionId) headers['Mcp-Session-Id'] = sessionId;
    const req = lib.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'POST', headers },
      res => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => {
          const sid = res.headers['mcp-session-id'] || sessionId;
          // body may be plain JSON or SSE (lines of "data: {json}")
          let obj = null;
          const trimmed = d.trim();
          if (trimmed.startsWith('{')) { try { obj = JSON.parse(trimmed); } catch (_) {} }
          if (!obj) {
            for (const line of d.split('\n')) {
              const m = line.match(/^data:\s*(.+)$/);
              if (m) { try { const o = JSON.parse(m[1]); if (o && (o.result || o.error || o.id !== undefined)) obj = o; } catch (_) {} }
            }
          }
          resolve({ status: res.statusCode, sessionId: sid, obj, raw: d });
        });
      });
    req.on('error', e => resolve({ error: String(e) }));
    req.write(payload); req.end();
  });
}

function pickExecTool(tools) {
  const score = (t) => {
    const n = (t.name || '').toLowerCase();
    let s = 0;
    if (/exec|run|dispatch/.test(n)) s += 2;
    if (/lua|luau|code|script/.test(n)) s += 2;
    if (/eval/.test(n)) s += 1;
    if (/console|log|read|get/.test(n)) s -= 3; // not the exec tool
    return s;
  };
  return tools.map(t => [score(t), t]).filter(x => x[0] >= 2).sort((a, b) => b[0] - a[0]).map(x => x[1])[0] || null;
}

function pickConsoleTool(tools) {
  const score = (t) => {
    const n = (t.name || '').toLowerCase();
    let s = 0;
    if (/console|log|output/.test(n)) s += 2;
    if (/read|get|fetch|poll|tail|dump/.test(n)) s += 1;
    if (/exec|dispatch|run/.test(n)) s -= 2;
    return s;
  };
  return tools.map(t => [score(t), t]).filter(x => x[0] >= 2).sort((a, b) => b[0] - a[0]).map(x => x[1])[0] || null;
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function fillArgs(tool, wanted) {
  // wanted: {clientId, cursor} -> map onto the tool's schema property names
  const props = (tool.inputSchema && tool.inputSchema.properties) || {};
  const keys = Object.keys(props);
  const out = {};
  const put = (cands, val) => { if (val == null) return; for (const c of cands) { const k = keys.find(x => x.toLowerCase() === c); if (k) { out[k] = val; return; } } for (const c of cands) { const k = keys.find(x => x.toLowerCase().includes(c)); if (k) { out[k] = val; return; } } };
  put(['clientid', 'client', 'target', 'targetid'], wanted.clientId);
  put(['cursor', 'after', 'since', 'from', 'offset', 'start'], wanted.cursor);
  return out;
}

function textFromResult(r) {
  let t = '';
  const add = (v) => { if (typeof v === 'string') t += (t ? '\n' : '') + v; };
  if (r) {
    if (Array.isArray(r.content)) r.content.forEach(c => add(c && c.text));
    const sc = r.structuredContent;
    if (sc) {
      if (Array.isArray(sc.lines)) sc.lines.forEach(l => add(typeof l === 'string' ? l : (l && (l.message || l.text))));
      if (Array.isArray(sc.logs)) sc.logs.forEach(l => add(typeof l === 'string' ? l : (l && (l.message || l.text))));
      add(sc.output); add(sc.console); add(sc.message);
    }
  }
  return t;
}

function execArgName(tool, lua) {
  const props = (tool.inputSchema && tool.inputSchema.properties) || {};
  const keys = Object.keys(props);
  for (const cand of ['script', 'code', 'source', 'lua', 'luau', 'text', 'command']) {
    if (keys.includes(cand)) return { [cand]: lua };
  }
  // first string property, else a generic guess
  const strKey = keys.find(k => (props[k].type || 'string') === 'string');
  return strKey ? { [strKey]: lua } : { script: lua };
}

async function mcpExecute(urlStr, token, lua) {
  // 1) initialize
  const init = await mcpPost(urlStr, token, null, {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'VmSmart', version: '1.0.0' } }
  });
  if (init.error) return { ok: false, error: init.error };
  if (init.status === 401 || init.status === 403) return { ok: false, error: 'unauthorized (check bearer token)' };
  const sid = init.sessionId;
  // 2) initialized notification
  await mcpPost(urlStr, token, sid, { jsonrpc: '2.0', method: 'notifications/initialized' });
  // 3) list tools
  const list = await mcpPost(urlStr, token, sid, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const tools = (list.obj && list.obj.result && list.obj.result.tools) || [];
  if (!tools.length) return { ok: false, error: 'no tools from MCP', tools: [] };
  const tool = pickExecTool(tools);
  if (!tool) return { ok: false, error: 'no execute tool found', tools: tools.map(t => t.name) };
  // 4) call the execute tool (async: it dispatches and returns a cursor)
  const call = await mcpPost(urlStr, token, sid, {
    jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: tool.name, arguments: execArgName(tool, lua) }
  });
  if (call.error) return { ok: false, error: call.error };
  const res = call.obj && call.obj.result;
  if (call.obj && call.obj.error) return { ok: false, error: call.obj.error.message || 'tool error' };

  let text = textFromResult(res);
  if (text.includes('BEGIN_UNOBF_RESULT')) return { ok: true, body: text, tool: tool.name, raw: res };

  // async path: read structured cursor + target, then poll a console tool
  const sc = (res && res.structuredContent) || {};
  let cursor = sc.console_cursor != null ? sc.console_cursor : (sc.cursor != null ? sc.cursor : null);
  const targets = sc.targets || sc.clients || [];
  const clientId = Array.isArray(targets) ? targets[0] : targets;
  const consoleTool = pickConsoleTool(tools);
  if (!consoleTool) return { ok: true, body: text || JSON.stringify(res), tool: tool.name, raw: res, note: 'no console tool' };

  let acc = '';
  for (let i = 0; i < 15; i++) {
    await sleep(700);
    const rc = await mcpPost(urlStr, token, sid, {
      jsonrpc: '2.0', id: 100 + i, method: 'tools/call',
      params: { name: consoleTool.name, arguments: fillArgs(consoleTool, { clientId, cursor }) }
    });
    const r2 = rc.obj && rc.obj.result;
    if (r2) {
      const chunk = textFromResult(r2);
      if (chunk) acc += (acc ? '\n' : '') + chunk;
      const s2 = r2.structuredContent;
      if (s2 && (s2.console_cursor != null || s2.cursor != null)) cursor = s2.console_cursor != null ? s2.console_cursor : s2.cursor;
    }
    if (acc.includes('END_UNOBF_RESULT')) break;
  }
  return { ok: true, body: acc || text || JSON.stringify(res), tool: tool.name + ' + ' + consoleTool.name, raw: res };
}

function parseStages(stdout) {
  const stages = { detect: null, static: null, harness: null, audit: null };
  for (const line of stdout.split('\n')) {
    if (line.includes('[1/4] DETECT')) stages.detect = line.split(':').slice(1).join(':').trim();
    if (line.includes('[2/4] STATIC')) stages.static = line.split(':').slice(1).join(':').trim();
    if (line.includes('[3/4] HARNESS')) stages.harness = line.split(':').slice(1).join(':').trim();
    if (line.includes('[4/4] AUDIT')) stages.audit = line.split('verdict=')[1] || line;
  }
  return stages;
}

// ---- IPC --------------------------------------------------------------------
ipcMain.handle('pick-file', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Lua', extensions: ['lua', 'txt'] }] });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.handle('analyze', async (_e, filePath) => {
  const outDir = path.join(WORK, 'out_' + Date.now());
  const r = await runPython([DEOB, filePath, '-o', outDir]);
  const readMaybe = (f) => { try { return fs.readFileSync(path.join(outDir, f), 'utf8'); } catch (_) { return null; } };
  const log = (() => { try { return JSON.parse(readMaybe('analysis_log.json')); } catch (_) { return null; } })();
  return {
    code: r.code, stdout: r.out, stderr: r.err, outDir,
    stages: parseStages(r.out),
    vmStructure: readMaybe('vm_structure.txt'),
    analysis: log,
    harness: readMaybe('harness.lua')
  };
});

ipcMain.handle('run-mcp', async (_e, harnessLua) => {
  return await mcpExecute(settings.mcpUrl, settings.mcpToken, harnessLua);
});

function normalizeBlock(s) {
  if (typeof s !== 'string') return '';
  // Console tools often return the block as a JSON-escaped string, so real
  // newlines arrive as literal \n. Unescape when there are no real newlines
  // inside the block but escaped ones are present.
  const hasReal = /BEGIN_UNOBF_RESULT[\s\S]*\n[\s\S]*END_UNOBF_RESULT/.test(s);
  const hasEsc = s.includes('\\n');
  if (!hasReal && hasEsc) {
    s = s.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\t/g, '\t')
         .replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return s;
}

ipcMain.handle('finalize', async (_e, { filePath, outDir, traceText, candidatePath }) => {
  if (!outDir) outDir = path.join(WORK, 'out_' + Date.now());
  try { fs.mkdirSync(outDir, { recursive: true }); } catch (_) {}
  traceText = normalizeBlock(traceText);
  const traceFile = path.join(outDir, 'result.txt');
  fs.writeFileSync(traceFile, traceText);
  const args = [DEOB, filePath, '-o', outDir, '--trace', traceFile];
  if (candidatePath) args.push('--candidate', candidatePath);
  const r = await runPython(args);
  const readMaybe = (f) => { try { return fs.readFileSync(path.join(outDir, f), 'utf8'); } catch (_) { return null; } };
  const reconstructed = readMaybe('RECONSTRUCTED.lua');
  return {
    code: r.code, stdout: r.out, stderr: r.err,
    stages: parseStages(r.out),
    behavior: readMaybe('BEHAVIOR.txt'),
    reconstructed,
    // the richest combined outputs (shown in the UI when present)
    final: readMaybe('FINAL_RECONSTRUCTION.txt'),
    logic: readMaybe('LOGIC.txt'),
    controlFlow: readMaybe('CONTROL_FLOW.txt'),
    flow: readMaybe('FLOW.txt'),
    disassembly: readMaybe('DISASSEMBLY.txt'),
    opcodeMap: readMaybe('OPCODE_MAP.txt'),
    // prefer the consolidated final report as the main "source" view
    finalSource: readMaybe('FINAL_SOURCE.lua') || readMaybe('FINAL_RECONSTRUCTION.txt') || reconstructed,
    verdict: (parseStages(r.out).audit || '').trim()
  };
});

// ONE-CLICK: the app runs everything itself - Python stages, the Lua harness
// (in the executor via MCP), then the Python reconstruction - and returns every
// report. No manual copy/paste or terminal.
ipcMain.handle('run-all', async (_e, { filePath, extraTraces }) => {
  const send = (m) => { try { win.webContents.send('run-progress', m); } catch (_) {} };
  const outDir = path.join(WORK, 'out_' + Date.now());
  const readMaybe = (f) => { try { return fs.readFileSync(path.join(outDir, f), 'utf8'); } catch (_) { return null; } };
  const collect = () => ({
    outDir,
    final: readMaybe('FINAL_RECONSTRUCTION.txt'),
    logic: readMaybe('LOGIC.txt'),
    flow: readMaybe('FLOW.txt'),
    disassembly: readMaybe('DISASSEMBLY.txt'),
    opcodeMap: readMaybe('OPCODE_MAP.txt'),
    behavior: readMaybe('BEHAVIOR.txt'),
    reconstructed: readMaybe('RECONSTRUCTED.lua'),
    finalSource: readMaybe('FINAL_SOURCE.lua') || readMaybe('RECONSTRUCTED.lua'),
    vmStructure: readMaybe('vm_structure.txt')
  });

  send('detect + static + harness');
  let r = await runPython([DEOB, filePath, '-o', outDir]);
  const harness = readMaybe('harness.lua');
  if (!harness) return { ok: false, error: 'harness not generated', stdout: r.out, stderr: r.err };

  send('running in executor (MCP)');
  const ex = await mcpExecute(settings.mcpUrl, settings.mcpToken, harness);
  if (!ex.ok) return { ok: false, error: 'executor: ' + (ex.error || 'no output'), outDir, harness };

  send('reconstructing');
  const traceFile = path.join(outDir, 'result.txt');
  fs.writeFileSync(traceFile, normalizeBlock(ex.body || ''));
  const args = [DEOB, filePath, '-o', outDir, '--trace', traceFile];
  // also merge any extra trace files the user added (e.g. full opcode_trace.txt
  // saved from the executor's workspace) so more runs stack into one report.
  for (const t of (extraTraces || [])) { if (t && fs.existsSync(t)) args.push(t); }
  r = await runPython(args);
  send('done');
  return { ok: true, code: r.code, stdout: r.out, stderr: r.err,
           stages: parseStages(r.out), verdict: (parseStages(r.out).audit || '').trim(),
           ...collect() };
});

ipcMain.handle('copy', (_e, text) => { clipboard.writeText(text || ''); return true; });
ipcMain.handle('open-path', (_e, p) => { shell.showItemInFolder(p); return true; });
ipcMain.handle('get-settings', () => settings);
ipcMain.handle('set-settings', (_e, s) => { Object.assign(settings, s); saveSettings(); return settings; });
ipcMain.handle('save-source', async (_e, text) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: 'FINAL_SOURCE.lua', filters: [{ name: 'Lua', extensions: ['lua'] }] });
  if (r.canceled) return null;
  fs.writeFileSync(r.filePath, text); return r.filePath;
});

ipcMain.handle('export-report', async (_e, { title, body, structure }) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: 'VmSmart_report.html', filters: [{ name: 'HTML', extensions: ['html'] }] });
  if (r.canceled) return null;
  const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>VmSmart report</title>
<style>body{background:#140a24;color:#ece6ff;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:32px}
h1{color:#b98bff}h2{color:#a874ff;border-bottom:1px solid #3a2a5a;padding-bottom:6px;margin-top:28px}
pre{background:#0d0718;border:1px solid #3a2a5a;border-radius:12px;padding:16px;overflow:auto;color:#cfc3ef;font:13px/1.5 Consolas,monospace}
.tag{color:#9d92c4;font-size:13px}</style></head><body>
<h1>VmSmart report</h1><div class="tag">${esc(title)} &middot; ${new Date().toLocaleString()}</div>
<h2>Recovered source / behavior</h2><pre>${esc(body)}</pre>
<h2>VM structure</h2><pre>${esc(structure)}</pre>
</body></html>`;
  fs.writeFileSync(r.filePath, html); return r.filePath;
});
