'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vm', {
  pickFile: () => ipcRenderer.invoke('pick-file'),
  analyze: (filePath) => ipcRenderer.invoke('analyze', filePath),
  runMcp: (harness) => ipcRenderer.invoke('run-mcp', harness),
  finalize: (args) => ipcRenderer.invoke('finalize', args),
  copy: (text) => ipcRenderer.invoke('copy', text),
  openPath: (p) => ipcRenderer.invoke('open-path', p),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  setSettings: (s) => ipcRenderer.invoke('set-settings', s),
  saveSource: (text) => ipcRenderer.invoke('save-source', text)
});
