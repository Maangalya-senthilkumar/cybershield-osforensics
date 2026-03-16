'use strict';

/**
 * Electron main process for OSForensics.
 *
 * Responsibilities:
 *  1. Spawn the Python/FastAPI backend as a child process.
 *  2. Wait for the backend to become ready (polls /health).
 *  3. Open the BrowserWindow loading the Vite dev server (dev) or the
 *     built dist/index.html (production).
 *  4. Tear down the backend when the app quits.
 */

const { app, BrowserWindow, ipcMain, shell, dialog, session } = require('electron');
const path  = require('path');
const fs    = require('fs');
const http  = require('http');
const { spawn } = require('child_process');

// True when running via `electron .` in dev; false when running a packaged build.
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

const BACKEND_PORT = 8000;

let mainWindow    = null;
let backendProcess = null;

// ── Backend subprocess ────────────────────────────────────────────────────────

/**
 * Determine the Python command and arguments to launch the backend.
 *
 * Dev mode  : uses the project .venv created by `uv sync`.
 * Packaged  : prefers a PyInstaller single-binary at
 *             resources/backend/osforensics-server, then falls back to the
 *             system python3 with the bundled source.
 */
function getBackendCommand() {
  if (isDev) {
    const projectRoot = path.resolve(__dirname, '..', '..');
    const venvPython  = path.join(projectRoot, '.venv', 'bin', 'python');

    if (!fs.existsSync(venvPython)) {
      console.error(
        '[electron] .venv not found at', venvPython,
        '\n           Run: cd', projectRoot, '&& uv sync',
      );
    }

    return {
      cmd:  venvPython,
      args: [path.join(projectRoot, 'main.py')],
      cwd:  projectRoot,
    };
  }

  // --- packaged mode ---
  const resourcesDir = process.resourcesPath;
  const serverBin    = path.join(resourcesDir, 'backend', 'osforensics-server');

  if (fs.existsSync(serverBin)) {
    // Best case: PyInstaller single-binary bundled at build time.
    return { cmd: serverBin, args: [], cwd: resourcesDir };
  }

  // Fallback: system python3 + bundled source (requires python3 on the host).
  const backendDir = path.join(resourcesDir, 'backend');
  return {
    cmd:  'python3',
    args: [path.join(backendDir, 'main.py')],
    cwd:  backendDir,
  };
}

function startBackend() {
  const { cmd, args, cwd } = getBackendCommand();
  console.log('[electron] Spawning backend:', cmd, ...args);

  backendProcess = spawn(cmd, args, {
    cwd,
    env:   { ...process.env, PYTHONUNBUFFERED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  backendProcess.stdout.on('data', (d) => process.stdout.write(`[backend] ${d}`));
  backendProcess.stderr.on('data', (d) => process.stderr.write(`[backend] ${d}`));

  backendProcess.on('exit', (code, signal) =>
    console.log(`[backend] exited (code=${code} signal=${signal})`),
  );

  backendProcess.on('error', (err) => {
    console.error('[backend] spawn error:', err.message);
    dialog.showErrorBox(
      'Backend failed to start',
      `The Python backend could not be launched:\n\n${err.message}\n\n` +
      `• Development: ensure the .venv exists (run "uv sync" in the project root).\n` +
      `• Distribution: ensure the packaged backend binary is present in resources/.`,
    );
  });
}

/**
 * Poll GET /health until it responds or we exhaust retries.
 * Resolves (even on timeout) so the window always opens eventually.
 */
function waitForBackend(retries = 60, delayMs = 1000) {
  return new Promise((resolve) => {
    let attempts = 0;

    function try_() {
      const req = http.get(`http://127.0.0.1:${BACKEND_PORT}/health`, (res) => {
        res.resume();
        console.log('[electron] Backend ready ✓');
        resolve();
      });
      req.on('error', () => {
        if (++attempts >= retries) {
          console.warn('[electron] Backend did not respond in time – opening UI anyway');
          resolve();
        } else {
          setTimeout(try_, delayMs);
        }
      });
      req.setTimeout(delayMs, () => req.destroy());
    }

    try_();
  });
}

// ── Browser window ────────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width:     1440,
    height:    920,
    minWidth:  960,
    minHeight: 600,
    title:     'OSForensics',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
    autoHideMenuBar: true,
    show:            false,
    backgroundColor: '#0f1117', // match dark theme so there's no white flash
  });

  // In production the renderer loads from file:// and sends Origin: null.
  // The backend CORS list already includes "null", but as extra insurance we
  // also rewrite the Origin header on every request to the backend so the
  // FastAPI CORS middleware always sees a known origin.
  session.defaultSession.webRequest.onBeforeSendHeaders(
    { urls: [`http://127.0.0.1:${BACKEND_PORT}/*`] },
    (details, callback) => {
      details.requestHeaders['Origin'] = 'http://localhost:5173';
      callback({ requestHeaders: details.requestHeaders });
    },
  );

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }

  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });

  // Open external links in the OS default browser, not inside Electron.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });
}

// ── IPC handlers ──────────────────────────────────────────────────────────────

ipcMain.handle('app:version',  () => app.getVersion());
ipcMain.handle('app:platform', () => process.platform);

// ── App lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  startBackend();
  await waitForBackend();
  createWindow();

  app.on('activate', () => {
    // macOS: re-create the window when the dock icon is clicked with no windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (backendProcess && !backendProcess.killed) {
    console.log('[electron] Stopping backend…');
    backendProcess.kill('SIGTERM');
  }
});
