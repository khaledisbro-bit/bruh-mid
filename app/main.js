'use strict';
const { app, BrowserWindow, ipcMain, dialog, shell, clipboard } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const { spawn } = require('child_process');

// pipeline lives next to the app folder in the repo
const PIPELINE_DIR = path.join(__dirname, '..', 'pipeline');
const DEOB = path.join(PIPELINE_DIR, 'deob.py');
const WORK = path.join(os.tmpdir(), 'vmsmart');
fs.mkdirSync(WORK, { recursive: true });

let win;
let settings = { mcpUrl: 'http://localhost:16384', python: process.platform === 'win32' ? 'python' : 'python3' };
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
    const p = spawn(settings.python, args, { cwd: path.join(__dirname, '..') });
    let out = '', err = '';
    p.stdout.on('data', d => out += d);
    p.stderr.on('data', d => err += d);
    p.on('error', e => resolve({ code: -1, out, err: String(e) }));
    p.on('close', code => resolve({ code, out, err }));
  });
}

function postMcp(urlBase, lua) {
  // Best-effort: try a few likely execute endpoints on the local bridge.
  // Manual paste is always available as a fallback in the UI.
  const bodies = [
    { path: '/execute', payload: JSON.stringify({ script: lua }) },
    { path: '/api/execute', payload: JSON.stringify({ code: lua }) },
    { path: '/run', payload: JSON.stringify({ lua }) }
  ];
  return new Promise((resolve) => {
    let i = 0;
    const tryOne = () => {
      if (i >= bodies.length) return resolve({ ok: false, error: 'no execute endpoint responded' });
      const b = bodies[i++];
      try {
        const u = new URL(urlBase + b.path);
        const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b.payload) } },
          res => { let d = ''; res.on('data', c => d += c); res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) resolve({ ok: true, body: d });
            else tryOne();
          }); });
        req.on('error', tryOne);
        req.write(b.payload); req.end();
      } catch (_) { tryOne(); }
    };
    tryOne();
  });
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
  const res = await postMcp(settings.mcpUrl, harnessLua);
  return res;
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
