'use strict';

/**
 * Electron preload script.
 *
 * Runs in an isolated context before the renderer page loads.
 * Exposes a minimal, safe bridge (window.electronAPI) to the renderer.
 *
 * The app communicates with the Python backend entirely over HTTP
 * (fetch → http://127.0.0.1:8000) so no special IPC is needed for that.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  /** Electron app version from package.json */
  getVersion:  () => ipcRenderer.invoke('app:version'),
  /** Host OS platform: 'linux' | 'darwin' | 'win32' */
  getPlatform: () => ipcRenderer.invoke('app:platform'),
});
