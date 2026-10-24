import { contextBridge, ipcRenderer } from 'electron';

// Expose only the specific actions the UI needs; never expose ipcRenderer itself.
contextBridge.exposeInMainWorld('appPathAPI', {
  selectApk: () => ipcRenderer.invoke('apppath:select-apk'),
  analyzeSelectedApk: () => ipcRenderer.invoke('apppath:analyze-selected-apk'),
  exportReport: (report, format = 'json') => ipcRenderer.invoke('apppath:export-report', report, format),
  loadHistory: () => ipcRenderer.invoke('apppath:load-history'),
  saveHistory: (history) => ipcRenderer.invoke('apppath:save-history', history),
  getOllamaStatus: () => ipcRenderer.invoke('apppath:ollama-status'),
  remediateFinding: (request) => ipcRenderer.invoke('apppath:ollama-remediate', request),
  selectJadx: () => ipcRenderer.invoke('apppath:select-jadx'),
  decompileAndMap: (findings) => ipcRenderer.invoke('apppath:decompile-and-map', findings),
});
