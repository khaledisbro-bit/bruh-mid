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
    if (/exec|run/.test(n)) s += 2;
    if (/lua|luau|code|script/.test(n)) s += 2;
    if (/eval/.test(n)) s += 1;
    return s;
  };
  return tools.map(t => [score(t), t]).filter(x => x[0] >= 2).sort((a, b) => b[0] - a[0]).map(x => x[1])[0] || null;
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
  // 4) call it
  const call = await mcpPost(urlStr, token, sid, {
    jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: tool.name, arguments: execArgName(tool, lua) }
  });
  if (call.error) return { ok: false, error: call.error };
  const res = call.obj && call.obj.result;
  if (call.obj && call.obj.error) return { ok: false, error: call.obj.error.message || 'tool error' };
  let text = '';
  if (res && Array.isArray(res.content)) text = res.content.map(c => c.text || '').join('\n');
  else if (typeof res === 'string') text = res;
  else text = JSON.stringify(res);
  return { ok: true, body: text, tool: tool.name };
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

ipcMain.handle('finalize', async (_e, { filePath, outDir, traceText, candidatePath }) => {
  const traceFile = path.join(outDir, 'result.txt');
  fs.writeFileSync(traceFile, traceText);
  const args = [DEOB, filePath, '-o', outDir, '--trace', traceFile];
  if (candidatePath) args.push('--candidate', candidatePath);
  const r = await runPython(args);
  const readMaybe = (f) => { try { return fs.readFileSync(path.join(outDir, f), 'utf8'); } catch (_) { return null; } };
  return {
    code: r.code, stdout: r.out, stderr: r.err,
    stages: parseStages(r.out),
    behavior: readMaybe('BEHAVIOR.txt'),
    finalSource: readMaybe('FINAL_SOURCE.lua'),
    verdict: (parseStages(r.out).audit || '').trim()
  };
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
