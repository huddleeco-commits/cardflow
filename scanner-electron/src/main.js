const { app, BrowserWindow, Tray, Menu, ipcMain, dialog, nativeImage, Notification, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile, spawn } = require('child_process');
const chokidar = require('chokidar');
const axios = require('axios');
const FormData = require('form-data');
const WebSocket = require('ws');
const Store = require('electron-store');

// Handle Squirrel events for Windows installer
if (require('electron-squirrel-startup')) {
  app.quit();
}

// Initialize persistent store
const store = new Store({
  defaults: {
    settings: {
      scanFolder: '',
      pairingMode: 'sequential',
      holoMode: false,
      brightnessBoost: 0,
      autoRotateBack: true,
      autoCrop: true,           // trim scanner bed edges
      cardWidth: 4.5,           // scan width (becomes card HEIGHT after rotation, 3.5" card + margin)
      cardHeight: 5.0,          // scan height (becomes card WIDTH after rotation, 2.5" card + margin)
      cropThreshold: 30,        // sensitivity for auto-crop trim
      removeStreaks: false,      // median filter for sensor dust streaks
      startMinimized: false,
      startWithWindows: false,
      scanMode: 'folder',       // 'direct' or 'folder'
      scannerId: null,          // Selected WIA scanner device ID
      scanDpi: 300,
      scanDuplex: true,
      viewPreference: 'grid'
    },
    credentials: null,
    authToken: null,
    slabtrackInfo: null,
    appMode: 'monitor',
    selectedCollectionId: null
  }
});

// Migrate scan dimensions — cardWidth becomes HEIGHT after rotation, needs margin beyond 3.5" card
{
  const s = store.get('settings');
  if (s.cardWidth < 4.5 || s.cardHeight < 4.0) {
    s.cardWidth = 4.5;   // perpendicular to feed → becomes card HEIGHT after rotation (3.5" card + 1" margin)
    s.cardHeight = 5.0;  // feed direction → becomes card WIDTH after rotation (2.5" card + 2.5" margin)
    store.set('settings', s);
    console.log('[migrate] Updated scan dimensions to 4.5x5.0 for feeder margin');
  }
}

// File logging for debug
const logFile = path.join(os.tmpdir(), 'slabtrack-scanner-debug.log');
function debugLog(...args) {
  const msg = `[${new Date().toISOString()}] ${args.join(' ')}\n`;
  fs.appendFileSync(logFile, msg);
  console.log(...args);
}
debugLog('=== SlabTrack Scanner starting ===');

// App state
let mainWindow = null;
let tray = null;
let watcher = null;
let ws = null;
let isScanning = false;
let authToken = store.get('authToken');
let pendingFiles = [];
let cardCounter = 0;
let stats = { scanned: 0, identified: 0, errors: 0 };
let uploadQueue = [];
let isUploading = false;
let activeUploads = 0;
const MAX_CONCURRENT_UPLOADS = 3;
let reconnectTimer = null;
let directModeEnabled = false; // True when receiving files directly from PaperStream
let directModePendingFiles = []; // Files received via command line
let scanTempDir = null; // Temp directory for direct scanner output
let isDirectScanning = false; // True when WIA scan is in progress

const sharp = require('sharp');

const API_BASE = 'https://slabtrack.io';
const WS_URL = 'wss://slabtrack.io';
const SCRIPTS_DIR = path.join(__dirname, 'scripts');

// Post-process a scanned image: orientation fix, auto-rotate back, auto-crop, streak removal
async function processScannedImage(filePath, side, settings) {
  const metadata = await sharp(filePath).metadata();
  let img = sharp(filePath);

  // 1. ADF orientation fix: fi-8170 outputs content rotated 90° CW within the frame
  //    Front: rotate -90° (CCW) to correct
  //    Back:  rotate +90° (CW) = -90° ADF fix + 180° duplex flip
  if (side === 'back' && settings.autoRotateBack) {
    img = img.rotate(90);
  } else {
    img = img.rotate(-90);
  }

  // 2. Streak line removal (median filter removes thin horizontal artifacts)
  if (settings.removeStreaks) {
    img = img.median(3);
  }

  // Write rotated image first
  const rotatedPath = filePath.replace(/\.(jpg|jpeg|bmp|png)$/i, '_rotated.jpg');
  await img.jpeg({ quality: 95 }).toFile(rotatedPath);

  // 3. Auto-crop: trim scanner bed edges using sharp's trim()
  let outputPath = rotatedPath;
  if (settings.autoCrop) {
    try {
      const cropPath = filePath.replace(/\.(jpg|jpeg|bmp|png)$/i, '_processed.jpg');
      const threshold = settings.cropThreshold || 30;
      await sharp(rotatedPath)
        .trim({ background: '#FFFFFF', threshold })
        .jpeg({ quality: 95 })
        .toFile(cropPath);
      outputPath = cropPath;
      // Clean up rotated intermediate
      try { fs.unlinkSync(rotatedPath); } catch (e) { /* ignore */ }
    } catch (err) {
      console.warn(`[processImage] Auto-crop failed for ${side}, using rotated image: ${err.message}`);
      outputPath = rotatedPath;
    }
  }

  const outMeta = await sharp(outputPath).metadata();
  console.log(`[processImage] ${side}: ${metadata.width}x${metadata.height} → ${outMeta.width}x${outMeta.height}`);

  // Clean up original if different path
  if (outputPath !== filePath && filePath !== rotatedPath) {
    try { fs.unlinkSync(filePath); } catch (e) { /* ignore */ }
  }

  return outputPath;
}

// Parse command line arguments for file paths
function getFilePathsFromArgs(args) {
  return args.filter(arg => {
    // Skip electron/app arguments
    if (arg.startsWith('-') || arg.startsWith('--')) return false;
    if (arg.includes('electron') || arg.includes('app.asar')) return false;
    // Check if it's a valid image file
    const ext = path.extname(arg).toLowerCase();
    return ['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp'].includes(ext);
  });
}

// Create main window
async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 750,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    transparent: false,
    backgroundColor: '#0a0a0f',
    icon: path.join(__dirname, '../assets/icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    show: false
  });

  const htmlPath = path.join(__dirname, 'renderer/index.html');
  mainWindow.loadFile(htmlPath);

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    const settings = store.get('settings');
    if (!settings.startMinimized) {
      mainWindow.show();
    }
    mainWindow.webContents.openDevTools({ mode: 'bottom' });
  });

  // Minimize to tray instead of closing
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      return false;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Dev shortcuts
  mainWindow.webContents.on('before-input-event', (event, input) => {
    // Ctrl+Shift+R: force reload (clear cache + reload)
    if (input.control && input.shift && input.key === 'R') {
      event.preventDefault();
      mainWindow.webContents.session.clearCache().then(() => {
        mainWindow.webContents.reloadIgnoringCache();
      });
    }
    // F5: normal reload
    if (input.key === 'F5') {
      event.preventDefault();
      mainWindow.webContents.reloadIgnoringCache();
    }
    // F12: toggle DevTools
    if (input.key === 'F12') {
      event.preventDefault();
      mainWindow.webContents.toggleDevTools();
    }
  });
}

// Create system tray
function createTray() {
  const iconPath = path.join(__dirname, '../assets/tray-icon.png');

  // Create a default icon if file doesn't exist
  let trayIcon;
  if (fs.existsSync(iconPath)) {
    trayIcon = nativeImage.createFromPath(iconPath);
  } else {
    // Create a simple colored icon
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon.isEmpty() ? createDefaultTrayIcon('gray') : trayIcon);

  updateTrayMenu();

  tray.setToolTip('SlabTrack Scanner');

  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.focus();
      } else {
        mainWindow.show();
      }
    }
  });
}

// Create a simple tray icon with color
function createDefaultTrayIcon(color) {
  const size = 16;
  const canvas = `<svg width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">
    <rect width="${size}" height="${size}" rx="3" fill="${color === 'green' ? '#00ffc8' : color === 'yellow' ? '#ffc107' : color === 'red' ? '#ff4444' : '#666'}"/>
    <text x="8" y="12" text-anchor="middle" fill="${color === 'green' || color === 'yellow' ? '#000' : '#fff'}" font-size="10" font-family="Arial" font-weight="bold">C</text>
  </svg>`;

  return nativeImage.createFromBuffer(Buffer.from(canvas));
}

// Update tray menu
function updateTrayMenu() {
  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Window',
      click: () => mainWindow && mainWindow.show()
    },
    {
      label: isScanning ? 'Stop Scanning' : 'Start Scanning',
      click: () => {
        if (isScanning) {
          stopScanning();
        } else {
          startScanning();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Restart',
      click: () => {
        app.isQuitting = true;
        app.relaunch();
        app.quit();
      }
    },
    {
      label: 'Quit',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);
}

// Update tray icon based on status
function updateTrayStatus(status) {
  if (!tray) return;

  const color = status === 'connected' ? 'green' :
                status === 'scanning' ? 'yellow' :
                status === 'error' ? 'red' : 'gray';

  tray.setImage(createDefaultTrayIcon(color));
  updateTrayMenu();
}

// Show desktop notification
function showNotification(title, body) {
  if (Notification.isSupported()) {
    new Notification({
      title,
      body,
      icon: path.join(__dirname, '../assets/icon.ico')
    }).show();
  }
}

// IPC Handlers

// Window controls
ipcMain.on('window-minimize', () => mainWindow && mainWindow.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  }
});
ipcMain.on('window-close', () => mainWindow && mainWindow.hide());

// Login
ipcMain.handle('login', async (event, email, password) => {
  debugLog('[LOGIN] Email login attempt:', email);
  try {
    const response = await axios.post(`${API_BASE}/api/auth/login`, {
      email,
      password
    });

    if (response.data.token) {
      authToken = response.data.token;
      store.set('authToken', authToken);
      store.set('credentials', { email });

      // Fetch tier + credits info via preflight
      try {
        const preflight = await axios.get(`${API_BASE}/api/desktop-scan/preflight`, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
        if (preflight.data.success) {
          const slabtrackInfo = {
            username: email,
            tier: preflight.data.tier || 'free',
            scansRemaining: preflight.data.scansRemaining,
            batchLimit: preflight.data.batchLimit
          };
          store.set('slabtrackInfo', slabtrackInfo);
        }
      } catch (e) {
        console.error('Preflight after login failed:', e.message);
      }

      // Connect WebSocket after login
      connectWebSocket();

      return { success: true, user: response.data.user, slabtrackInfo: store.get('slabtrackInfo') };
    }

    return { success: false, error: 'Invalid response from server' };
  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.error || 'Login failed. Please check your credentials.'
    };
  }
});

// SlabTrack Login (API token-based — validates via preflight endpoint)
ipcMain.handle('slabtrack-login', async (event, token) => {
  try {
    // Validate the API token by calling preflight with X-API-Token header
    const response = await axios.get(`${API_BASE}/api/desktop-scan/preflight`, {
      headers: { 'X-API-Token': token }
    });

    if (response.data.success) {
      // Token is valid — store it as the primary auth method
      authToken = token; // Use API token directly
      store.set('authToken', authToken);

      const slabtrackInfo = {
        username: response.data.tier || 'user',
        tier: response.data.tier || 'free',
        apiToken: token,
        scansRemaining: response.data.scansRemaining,
        batchLimit: response.data.batchLimit
      };
      store.set('slabtrackInfo', slabtrackInfo);

      connectWebSocket();

      return { success: true, user: { tier: response.data.tier }, slabtrackInfo };
    }

    return { success: false, error: response.data.error || 'Invalid token' };
  } catch (error) {
    console.error('SlabTrack login error:', error.response?.data || error.message);
    const errData = error.response?.data;
    if (errData?.upgradeRequired) {
      return { success: false, error: errData.error };
    }
    return {
      success: false,
      error: errData?.error || 'SlabTrack login failed. Check your API token.'
    };
  }
});

// Logout
ipcMain.handle('logout', async () => {
  authToken = null;
  store.delete('authToken');
  store.delete('credentials');
  store.delete('slabtrackInfo');
  stopScanning();
  disconnectWebSocket();
  return { success: true };
});

// Check auth status — try API token first, then Bearer JWT
ipcMain.handle('check-auth', async () => {
  if (!authToken) {
    return { authenticated: false };
  }

  const slabtrackInfo = store.get('slabtrackInfo') || null;

  try {
    // If we have an API token stored, validate via preflight
    if (slabtrackInfo?.apiToken) {
      const response = await axios.get(`${API_BASE}/api/desktop-scan/preflight`, {
        headers: { 'X-API-Token': slabtrackInfo.apiToken }
      });
      if (response.data.success) {
        connectWebSocket();
        // Update cached credits
        slabtrackInfo.tier = response.data.tier;
        slabtrackInfo.scansRemaining = response.data.scansRemaining;
        store.set('slabtrackInfo', slabtrackInfo);
        return { authenticated: true, user: { tier: response.data.tier }, slabtrackInfo };
      }
    }

    // Fallback: try Bearer JWT via /api/auth/me
    const response = await axios.get(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data.id) {
      connectWebSocket();
      return { authenticated: true, user: response.data, slabtrackInfo };
    }
  } catch (error) {
    console.error('Auth check error:', error.message);
  }

  authToken = null;
  store.delete('authToken');
  return { authenticated: false };
});

// Desktop scan preflight — check credits + tier
ipcMain.handle('desktop-scan-preflight', async () => {
  try {
    const slabtrackInfo = store.get('slabtrackInfo');
    const headers = {};
    if (slabtrackInfo?.apiToken) {
      headers['X-API-Token'] = slabtrackInfo.apiToken;
    } else if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    } else {
      return { success: false, error: 'Not authenticated' };
    }

    const response = await axios.get(`${API_BASE}/api/desktop-scan/preflight`, { headers });
    return response.data;
  } catch (error) {
    const data = error.response?.data;
    if (data?.upgradeRequired) {
      return { success: false, error: data.error, upgradeRequired: true };
    }
    return { success: false, error: data?.error || error.message };
  }
});

// Select folder
ipcMain.handle('select-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Scan Folder'
  });

  if (!result.canceled && result.filePaths.length > 0) {
    const folderPath = result.filePaths[0];
    const settings = store.get('settings');
    settings.scanFolder = folderPath;
    store.set('settings', settings);
    return { success: true, path: folderPath };
  }

  return { success: false };
});

// Get settings
ipcMain.handle('get-settings', () => {
  return store.get('settings');
});

// Save settings
ipcMain.handle('open-external', (event, url) => {
  shell.openExternal(url);
});

// App mode + collection persistence
ipcMain.handle('save-app-mode', (event, mode) => {
  store.set('appMode', mode);
  return { success: true };
});

ipcMain.handle('save-selected-collection', (event, collectionId) => {
  store.set('selectedCollectionId', collectionId);
  return { success: true };
});

ipcMain.handle('get-app-mode', () => {
  return store.get('appMode') || 'monitor';
});

ipcMain.handle('get-selected-collection', () => {
  return store.get('selectedCollectionId') || null;
});

// Fetch user's collections from SlabTrack API
ipcMain.handle('fetch-collections', async () => {
  try {
    const slabtrackInfo = store.get('slabtrackInfo');
    const headers = { 'Content-Type': 'application/json' };
    if (slabtrackInfo?.apiToken) {
      headers['X-API-Token'] = slabtrackInfo.apiToken;
    } else if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await axios.get(`${API_BASE}/api/collections`, { headers, timeout: 15000 });
    return { success: true, collections: response.data.collections || response.data || [] };
  } catch (error) {
    debugLog('[fetch-collections] ERROR:', error.message);
    return { success: false, error: error.message, collections: [] };
  }
});

// Push cards to a collection
ipcMain.handle('push-to-collection', async (event, collectionId, cardIds) => {
  try {
    const slabtrackInfo = store.get('slabtrackInfo');
    const headers = { 'Content-Type': 'application/json' };
    if (slabtrackInfo?.apiToken) {
      headers['X-API-Token'] = slabtrackInfo.apiToken;
    } else if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await axios.post(`${API_BASE}/api/collections/${collectionId}/cards`, {
      cardIds
    }, { headers, timeout: 30000 });

    return { success: true, data: response.data };
  } catch (error) {
    debugLog('[push-to-collection] ERROR:', error.message);
    return { success: false, error: error.response?.data?.error || error.message };
  }
});

ipcMain.handle('save-settings', (event, newSettings) => {
  const settings = { ...store.get('settings'), ...newSettings };
  store.set('settings', settings);

  // Handle start with Windows
  if (process.platform === 'win32') {
    app.setLoginItemSettings({
      openAtLogin: settings.startWithWindows,
      path: app.getPath('exe'),
      args: settings.startMinimized ? ['--minimized'] : []
    });
  }

  return { success: true };
});

// Start scanning
ipcMain.handle('start-scanning', () => {
  return startScanning();
});

// Stop scanning
ipcMain.handle('stop-scanning', () => {
  return stopScanning();
});

// Get stats
ipcMain.handle('get-stats', () => {
  return stats;
});

// PowerShell helpers for WIA scanner integration

function runPowerShell(scriptPath, args = []) {
  return new Promise((resolve, reject) => {
    const psArgs = ['-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...args];
    execFile('powershell.exe', psArgs, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && !stdout) {
        reject(new Error(stderr || error.message));
        return;
      }
      try {
        const result = JSON.parse(stdout.trim());
        resolve(result);
      } catch (parseError) {
        reject(new Error(`Failed to parse output: ${stdout}`));
      }
    });
  });
}

function runPowerShellStreaming(scriptPath, args = [], onLine) {
  return new Promise((resolve, reject) => {
    const psArgs = ['-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...args];
    const proc = spawn('powershell.exe', psArgs);
    let buffer = '';
    let lastError = null;

    proc.stdout.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop(); // Keep incomplete line in buffer
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const parsed = JSON.parse(trimmed);
          if (parsed.event === 'error') lastError = parsed.error;
          if (onLine) onLine(parsed);
        } catch (e) {
          // Non-JSON output, ignore
        }
      }
    });

    proc.stderr.on('data', (data) => {
      console.error('PowerShell stderr:', data.toString());
    });

    proc.on('close', (code) => {
      // Process any remaining buffer
      if (buffer.trim()) {
        try {
          const parsed = JSON.parse(buffer.trim());
          if (parsed.event === 'error') lastError = parsed.error;
          if (onLine) onLine(parsed);
        } catch (e) {}
      }
      if (code === 0 || code === null) {
        resolve();
      } else {
        reject(new Error(lastError || `PowerShell exited with code ${code}`));
      }
    });

    proc.on('error', reject);
  });
}

// Discover available scanners
ipcMain.handle('discover-scanners', async () => {
  try {
    const scriptPath = path.join(SCRIPTS_DIR, 'discover-scanners.ps1');
    const result = await runPowerShell(scriptPath);
    return result;
  } catch (error) {
    console.error('Scanner discovery error:', error);
    return { success: false, error: error.message, scanners: [], count: 0 };
  }
});

// Direct scan — uses WinRT ImageScanner API via PowerShell
// Scans cards from the ADF feeder, converts BMP to JPEG, streams progress
ipcMain.handle('scan-direct', async (event, options = {}) => {
  if (!authToken) {
    return { success: false, error: 'Not authenticated' };
  }

  if (isDirectScanning) {
    return { success: false, error: 'Scan already in progress' };
  }

  const settings = store.get('settings');
  const dpi = options.dpi || settings.scanDpi || 300;
  const duplex = options.duplex !== undefined ? options.duplex : settings.scanDuplex;
  const maxPages = options.maxPages || 0; // 0 = scan all in feeder

  // Create a unique temp dir for this scan batch
  const batchDir = path.join(scanTempDir, `batch-${Date.now()}`);
  fs.mkdirSync(batchDir, { recursive: true });

  const scriptPath = path.join(SCRIPTS_DIR, 'scan-winrt.ps1');
  const cardWidth = settings.cardWidth || 2.5;
  const cardHeight = settings.cardHeight || 3.5;
  const args = [
    '-OutputDir', batchDir,
    '-Dpi', String(dpi),
    '-MaxPages', String(maxPages),
    '-CardWidth', String(cardWidth),
    '-CardHeight', String(cardHeight)
  ];
  if (duplex) args.push('-Duplex');

  isDirectScanning = true;
  sendToRenderer('scanning-status', { scanning: true, mode: 'direct' });
  updateTrayStatus('scanning');

  let pagesScanned = 0;
  const scannedPages = []; // Collect pages during scan, process after

  try {
    await runPowerShellStreaming(scriptPath, args, (msg) => {
      switch (msg.event) {
        case 'status':
          sendToRenderer('scan-progress', { status: msg.status, message: msg.message });
          sendToRenderer('log', { type: 'info', message: msg.message });
          break;

        case 'page_scanned':
          pagesScanned++;
          scannedPages.push({ path: msg.path, side: msg.side, page: msg.page });
          sendToRenderer('scan-progress', {
            status: 'page_scanned',
            page: msg.page,
            side: msg.side,
            path: msg.path
          });
          sendToRenderer('log', { type: 'success', message: `Page ${msg.page} scanned (${msg.side})` });
          break;

        case 'scan_complete':
          sendToRenderer('scan-progress', {
            status: 'complete',
            totalPages: msg.totalPages,
            dpi: msg.dpi,
            duplex: msg.duplex
          });
          // Log DPI verification
          if (msg.requestedDpi && msg.dpi) {
            const dpiMatch = msg.requestedDpi === msg.dpi ? '✅' : '⚠️';
            sendToRenderer('log', { type: 'info', message: `${dpiMatch} DPI: requested=${msg.requestedDpi}, actual=${msg.dpi}` });
          }
          if (msg.imageWidth && msg.imageHeight) {
            sendToRenderer('log', { type: 'info', message: `Image: ${msg.imageWidth}x${msg.imageHeight}px (expected ~${msg.expectedWidth}x${msg.expectedHeight}px)` });
          }
          break;

        case 'error':
          sendToRenderer('log', { type: 'error', message: msg.error });
          break;
      }
    });

    // Post-process all scanned pages
    sendToRenderer('log', { type: 'info', message: `Processing ${scannedPages.length} scanned page(s)...` });
    for (const pg of scannedPages) {
      try {
        pg.path = await processScannedImage(pg.path, pg.side, settings);
      } catch (err) {
        sendToRenderer('log', { type: 'warning', message: `Post-processing failed for page ${pg.page}: ${err.message}` });
      }
    }

    // Pair and queue uploads
    for (const pg of scannedPages) {
      pendingFiles.push(pg.path);
      const side = pendingFiles.length % 2 === 1 ? 'front' : 'back';
      sendScannerEvent(side === 'front' ? 'scanner_front_captured' : 'scanner_back_captured', {
        filename: path.basename(pg.path)
      });
      if (pendingFiles.length >= 2) {
        const frontFile = pendingFiles.shift();
        const backFile = pendingFiles.shift();
        cardCounter++;
        queueUpload(frontFile, backFile, cardCounter);
      }
    }

    isDirectScanning = false;
    sendToRenderer('scanning-status', { scanning: false });
    updateTrayStatus(ws && ws.readyState === WebSocket.OPEN ? 'connected' : 'gray');

    // Handle any remaining unpaired file
    if (pendingFiles.length === 1) {
      sendToRenderer('log', { type: 'warning', message: 'Odd number of pages scanned — last page has no pair. Load the back side and scan again.' });
    }

    return { success: true, pagesScanned };
  } catch (error) {
    isDirectScanning = false;
    sendToRenderer('scanning-status', { scanning: false });
    updateTrayStatus(ws && ws.readyState === WebSocket.OPEN ? 'connected' : 'gray');

    // Detect multifeed/overlap errors and show helpful message
    const msg = error.message || '';
    const isMultifeed = /multifeed|overlap|double.?feed|paper.?problem/i.test(msg);
    if (isMultifeed) {
      sendToRenderer('log', { type: 'error', message: 'Multifeed detection triggered — the scanner thinks multiple pages are overlapping.' });
      sendToRenderer('log', { type: 'warning', message: 'Trading cards are thicker than paper and trigger this sensor. Open Scanner Setup to disable multifeed detection.' });
      sendToRenderer('show-multifeed-help', {});
    } else {
      sendToRenderer('log', { type: 'error', message: `Scan error: ${msg}` });
    }
    return { success: false, error: msg, isMultifeed };
  }
});

// Card operations (proxy to server API)
ipcMain.handle('fetch-cards', async (event, params = {}) => {
  try {
    const response = await axios.get(`${API_BASE}/api/cards`, {
      headers: { Authorization: `Bearer ${authToken}` },
      params
    });
    return { success: true, cards: response.data };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('fetch-card', async (event, cardId) => {
  try {
    const response = await axios.get(`${API_BASE}/api/cards/${cardId}`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    return { success: true, card: response.data };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('update-card', async (event, cardId, updates) => {
  try {
    const response = await axios.put(`${API_BASE}/api/cards/${cardId}`, updates, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    return { success: true, card: response.data };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('approve-card', async (event, { cardData, frontPath, backPath, collectionId }) => {
  try {
    // Read local image files as base64
    let frontBase64 = null;
    let backBase64 = null;
    if (frontPath && fs.existsSync(frontPath)) {
      frontBase64 = fs.readFileSync(frontPath).toString('base64');
    }
    if (backPath && fs.existsSync(backPath)) {
      backBase64 = fs.readFileSync(backPath).toString('base64');
    }

    if (!frontBase64) {
      return { success: false, error: 'Could not read front image file' };
    }

    // Determine auth header
    const slabtrackInfo = store.get('slabtrackInfo');
    const headers = { 'Content-Type': 'application/json' };
    if (slabtrackInfo?.apiToken) {
      headers['X-API-Token'] = slabtrackInfo.apiToken;
    } else {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const requestBody = {
      card: cardData,
      frontImage: frontBase64,
      backImage: backBase64
    };
    if (collectionId) requestBody.collection_id = collectionId;

    const response = await axios.post(`${API_BASE}/api/desktop-scan/approve`, requestBody, {
      headers,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 60000
    });

    return { success: true, cardId: response.data.cardId, data: response.data };
  } catch (error) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
});

ipcMain.handle('reject-card', async (event, cardId) => {
  try {
    const response = await axios.post(`${API_BASE}/api/cards/${cardId}/reject`, {}, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    return { success: true, card: response.data };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('delete-card', async (event, cardId) => {
  try {
    const response = await axios.delete(`${API_BASE}/api/cards/${cardId}`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// Bulk operations
ipcMain.handle('bulk-approve', async (event, cardIds) => {
  const results = { success: 0, failed: 0 };
  for (const cardId of cardIds) {
    try {
      await axios.post(`${API_BASE}/api/cards/${cardId}/approve`, {}, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      results.success++;
    } catch (error) {
      results.failed++;
    }
  }
  return { success: true, ...results };
});

ipcMain.handle('bulk-delete', async (event, cardIds) => {
  const results = { success: 0, failed: 0 };
  for (const cardId of cardIds) {
    try {
      await axios.delete(`${API_BASE}/api/cards/${cardId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      results.success++;
    } catch (error) {
      results.failed++;
    }
  }
  return { success: true, ...results };
});

ipcMain.handle('bulk-update', async (event, cardIds, updates) => {
  const results = { success: 0, failed: 0 };
  for (const cardId of cardIds) {
    try {
      await axios.put(`${API_BASE}/api/cards/${cardId}`, updates, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      results.success++;
    } catch (error) {
      results.failed++;
    }
  }
  return { success: true, ...results };
});

ipcMain.handle('export-cards', async (event, cardIds) => {
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Cards',
      defaultPath: `slabtrack-export-${Date.now()}.csv`,
      filters: [
        { name: 'CSV', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (result.canceled) return { success: false, canceled: true };

    // Fetch all card data
    const allCards = [];
    for (const cardId of cardIds) {
      try {
        const response = await axios.get(`${API_BASE}/api/cards/${cardId}`, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
        allCards.push(response.data);
      } catch (e) {}
    }

    // Build CSV
    const headers = ['Player', 'Year', 'Set', 'Card #', 'Parallel', 'Price', 'Status'];
    const rows = allCards.map(c => [
      c.player || c.name || '',
      c.year || '',
      c.set || c.setName || '',
      c.cardNumber || c.number || '',
      c.parallel || '',
      c.price || c.estimatedValue || '',
      c.status || ''
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

    const csv = [headers.join(','), ...rows].join('\n');
    fs.writeFileSync(result.filePath, csv, 'utf8');

    return { success: true, path: result.filePath, count: allCards.length };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('send-to-slabtrack', async (event, cardIds) => {
  try {
    const response = await axios.post(`${API_BASE}/api/cards/send-to-slabtrack`, {
      cardIds
    }, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    return { success: true, data: response.data };
  } catch (error) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
});

ipcMain.handle('swap-card-images', async (event, cardId) => {
  try {
    const response = await axios.post(`${API_BASE}/api/cards/${cardId}/swap-images`, {}, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    return { success: true, card: response.data };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// Get scanner status
ipcMain.handle('get-scanner-status', () => {
  return {
    isScanning: isDirectScanning,
    scannerId: store.get('settings').scannerId,
    scanMode: store.get('settings').scanMode
  };
});

// Open Fujitsu Software Operation Panel for scanner hardware settings
ipcMain.handle('open-scanner-settings', async () => {
  const sopPaths = [
    'C:\\Windows\\twain_32\\fjscan32\\SOP\\FjLaunch.exe',
    'C:\\Windows\\twain_32\\fjscan32\\SOP\\FtLnSOP.exe'
  ];

  for (const sopPath of sopPaths) {
    if (fs.existsSync(sopPath)) {
      try {
        execFile(sopPath, [], { detached: true, stdio: 'ignore' });
        return { success: true, path: sopPath };
      } catch (error) {
        console.error('Failed to launch SOP:', error);
      }
    }
  }

  return { success: false, error: 'Fujitsu Software Operation Panel not found. Install PaperStream IP driver.' };
});

// File watcher and scanning logic

function startScanning() {
  const settings = store.get('settings');

  if (!settings.scanFolder) {
    return { success: false, error: 'No scan folder selected' };
  }

  if (!authToken) {
    return { success: false, error: 'Not authenticated' };
  }

  if (isScanning) {
    return { success: false, error: 'Already scanning' };
  }

  try {
    // Reset state
    pendingFiles = [];
    cardCounter = 0;
    stats = { scanned: 0, identified: 0, errors: 0 };

    // Create file watcher
    watcher = chokidar.watch(settings.scanFolder, {
      ignored: /(^|[\/\\])\../, // Ignore dotfiles
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: {
        stabilityThreshold: 500,
        pollInterval: 100
      }
    });

    watcher.on('add', (filePath) => {
      handleNewFile(filePath);
    });

    watcher.on('error', (error) => {
      console.error('Watcher error:', error);
      sendToRenderer('log', { type: 'error', message: `Watcher error: ${error.message}` });
    });

    isScanning = true;
    updateTrayStatus('scanning');
    sendToRenderer('scanning-status', { scanning: true });
    sendToRenderer('log', { type: 'info', message: `Watching folder: ${settings.scanFolder}` });

    return { success: true };
  } catch (error) {
    console.error('Start scanning error:', error);
    return { success: false, error: error.message };
  }
}

function stopScanning() {
  if (watcher) {
    watcher.close();
    watcher = null;
  }

  isScanning = false;
  updateTrayStatus(ws && ws.readyState === WebSocket.OPEN ? 'connected' : 'gray');
  sendToRenderer('scanning-status', { scanning: false });
  sendToRenderer('log', { type: 'info', message: 'Scanning stopped' });

  return { success: true };
}

async function handleNewFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();

  // Only process image files
  if (!['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp'].includes(ext)) {
    return;
  }

  const settings = store.get('settings');
  const fileName = path.basename(filePath);

  sendToRenderer('log', { type: 'info', message: `New file detected: ${fileName}` });
  sendScannerEvent('scanner_file_detected', { filename: fileName });

  // Post-process the image before pairing
  try {
    filePath = await processScannedImage(filePath, 'front', settings);
  } catch (err) {
    sendToRenderer('log', { type: 'warning', message: `Post-processing failed: ${err.message}` });
  }

  if (settings.pairingMode === 'sequential') {
    // Sequential pairing: odd = front, even = back
    pendingFiles.push(filePath);

    // Notify which side was captured
    const side = pendingFiles.length % 2 === 1 ? 'front' : 'back';
    sendScannerEvent(side === 'front' ? 'scanner_front_captured' : 'scanner_back_captured', {
      filename: fileName
    });

    if (pendingFiles.length >= 2) {
      const frontFile = pendingFiles.shift();
      const backFile = pendingFiles.shift();
      cardCounter++;

      queueUpload(frontFile, backFile, cardCounter);
    }
  } else {
    // Suffix pairing: look for _front/_back or _f/_b
    const baseName = path.basename(filePath, ext);
    const dirName = path.dirname(filePath);

    if (baseName.match(/(_front|_f)$/i)) {
      // This is a front image, look for back
      const backPatterns = [
        baseName.replace(/(_front|_f)$/i, '_back') + ext,
        baseName.replace(/(_front|_f)$/i, '_b') + ext
      ];

      for (const pattern of backPatterns) {
        const backPath = path.join(dirName, pattern);
        if (fs.existsSync(backPath)) {
          cardCounter++;
          queueUpload(filePath, backPath, cardCounter);
          return;
        }
      }

      // No back found yet, store for later
      pendingFiles.push({ type: 'front', path: filePath, baseName: baseName.replace(/(_front|_f)$/i, '') });
    } else if (baseName.match(/(_back|_b)$/i)) {
      // This is a back image, look for matching front
      const baseWithoutSuffix = baseName.replace(/(_back|_b)$/i, '');
      const frontIndex = pendingFiles.findIndex(f => f.type === 'front' && f.baseName === baseWithoutSuffix);

      if (frontIndex !== -1) {
        const front = pendingFiles.splice(frontIndex, 1)[0];
        cardCounter++;
        queueUpload(front.path, filePath, cardCounter);
      } else {
        pendingFiles.push({ type: 'back', path: filePath, baseName: baseWithoutSuffix });
      }
    }
  }
}

function queueUpload(frontPath, backPath, cardNum) {
  console.log(`[queueUpload] Card #${cardNum}: front=${frontPath}, back=${backPath}`);
  uploadQueue.push({ frontPath, backPath, cardNum });

  // Add card to UI immediately with both image paths
  sendToRenderer('card-added', {
    cardNum,
    frontPath,
    backPath,
    status: 'queued'
  });

  processUploadQueue();
}

async function processUploadQueue() {
  while (uploadQueue.length > 0 && activeUploads < MAX_CONCURRENT_UPLOADS) {
    const item = uploadQueue.shift();
    activeUploads++;
    uploadCard(item).finally(() => {
      activeUploads--;
      processUploadQueue();
    });
  }

  // Update pipeline status
  sendToRenderer('pipeline-status', {
    queued: uploadQueue.length,
    uploading: activeUploads,
    scanned: stats.scanned,
    identified: stats.identified,
    errors: stats.errors
  });
}

async function uploadCard({ frontPath, backPath, cardNum }) {
  debugLog(`[uploadCard] Starting scan+upload for card #${cardNum} via SlabTrack`);
  try {
    sendToRenderer('card-status', { cardNum, status: 'uploading' });
    sendToRenderer('log', { type: 'info', message: `Scanning card #${cardNum} via SlabTrack...` });
    sendScannerEvent('scanner_uploading', { cardNum });

    // Read images as base64 for SlabTrack's desktop-scan API
    const frontBase64 = fs.readFileSync(frontPath).toString('base64');
    const backBase64 = backPath ? fs.readFileSync(backPath).toString('base64') : null;

    // Determine auth header — prefer X-API-Token (SlabTrack token), fallback to Bearer JWT
    const slabtrackInfo = store.get('slabtrackInfo');
    const headers = { 'Content-Type': 'application/json' };
    if (slabtrackInfo?.apiToken) {
      headers['X-API-Token'] = slabtrackInfo.apiToken;
    } else {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    // Always send to SlabTrack platform, include collection if selected
    const currentCollectionId = store.get('selectedCollectionId') || null;
    const requestBody = {
      frontImage: frontBase64,
      backImage: backBase64
    };
    if (currentCollectionId) {
      requestBody.collection_id = currentCollectionId;
    }

    const response = await axios.post(`${API_BASE}/api/desktop-scan/single`, requestBody, {
      headers,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 120000 // 2 min timeout for Claude Vision processing
    });

    const result = response.data;
    debugLog(`[uploadCard] Card #${cardNum} response:`, JSON.stringify(result).substring(0, 300));

    if (result.success && result.card) {
      stats.scanned++;
      stats.identified++;

      // SlabTrack returns the fully identified card immediately (no WS wait needed)
      const card = result.card;
      sendToRenderer('card-identified', {
        cardNum,
        cardId: card.id || `desktop_${cardNum}`,
        player: card.player || '',
        name: card.player || '',
        year: card.year || '',
        set: card.set_name || '',
        cardNumber: card.card_number || '',
        parallel: card.parallel || '',
        serialNumber: card.serial_number || '',
        team: card.team || '',
        sport: card.sport || '',
        condition: card.condition || '',
        subset_name: card.subset_name || '',
        numbered: card.numbered || false,
        numbered_to: card.numbered_to || '',
        confidence: card.confidence || 'high',
        isGraded: card.is_graded || false,
        gradingCompany: card.grading_company || '',
        grade: card.grade || '',
        certNumber: card.cert_number || '',
        isAutograph: card.is_autographed || false,
        ebaySearchString: card.ebay_search_string || '',
        price: card.sportscardspro_raw || '',
        pricing: {
          raw: card.sportscardspro_raw,
          psa7: card.sportscardspro_psa7,
          psa8: card.sportscardspro_psa8,
          psa9: card.sportscardspro_psa9,
          psa10: card.sportscardspro_psa10,
          bgs10: card.sportscardspro_bgs10,
          cgc10: card.sportscardspro_cgc10,
          sgc10: card.sportscardspro_sgc10
        },
        collectionAssigned: result.collectionAssigned || false,
        status: 'identified',
        thumbnail: card.front_image_url || '',
        back: card.back_image_url || ''
      });

      // Update remaining credits display
      if (result.remaining !== undefined) {
        sendToRenderer('credits-update', { remaining: result.remaining });
      }

      sendToRenderer('stats', stats);
      sendToRenderer('log', { type: 'success', message: `Card #${cardNum}: ${card.player || 'Identified'} — ${result.remaining} scans left` });
      sendScannerEvent('scanner_card_uploaded', { cardNum });
    } else {
      throw new Error(result.error || 'Scan failed');
    }
  } catch (error) {
    debugLog('[uploadCard] ERROR:', JSON.stringify(error.response?.data || error.message));
    const errMsg = error.response?.data?.error || error.message;
    stats.errors++;
    sendToRenderer('card-status', { cardNum, status: 'error', error: errMsg });
    sendToRenderer('stats', stats);
    sendToRenderer('log', { type: 'error', message: `Card #${cardNum} failed: ${errMsg}` });

    // Handle upgrade-required error
    if (error.response?.data?.upgradeRequired) {
      sendToRenderer('upgrade-required', { message: errMsg });
    }
  }
}

// WebSocket connection for real-time updates

function connectWebSocket() {
  // SlabTrack desktop scan uses HTTP API (not WebSocket) for card identification.
  // Skip WS connection entirely — just report "connected" to the UI.
  debugLog('[WS] Skipping WebSocket — desktop scan uses HTTP API');
  sendToRenderer('connection-status', { connected: true });
  sendToRenderer('log', { type: 'success', message: 'Connected to SlabTrack' });
  return;

  // --- Legacy WS code below (kept for reference, never reached) ---
  if (ws && ws.readyState === WebSocket.OPEN) {
    return;
  }

  if (!authToken) {
    return;
  }

  try {
    ws = new WebSocket(WS_URL);

    ws.on('open', () => {
      console.log('WebSocket connected, authenticating...');

      // Send scanner authentication message
      ws.send(JSON.stringify({
        type: 'scanner_auth',
        token: authToken
      }));
    });

    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());

        // Handle authentication response
        if (message.type === 'auth_success') {
          console.log('WebSocket authenticated');
          updateTrayStatus(isScanning ? 'scanning' : 'connected');
          sendToRenderer('connection-status', { connected: true });
          sendToRenderer('log', { type: 'success', message: 'Connected to SlabTrack server' });

          if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
          }
          return;
        }

        if (message.type === 'auth_error') {
          console.error('WebSocket auth error:', message.error);
          sendToRenderer('log', { type: 'error', message: 'Authentication failed' });
          ws.close();
          return;
        }

        // Handle other messages
        handleWebSocketMessage(message);
      } catch (error) {
        console.error('WebSocket message parse error:', error);
      }
    });

    ws.on('close', () => {
      console.log('WebSocket disconnected');
      updateTrayStatus('error');
      sendToRenderer('connection-status', { connected: false });
      sendToRenderer('log', { type: 'warning', message: 'Disconnected from server, reconnecting...' });

      // Auto-reconnect
      scheduleReconnect();
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      sendToRenderer('log', { type: 'error', message: `Connection error: ${error.message}` });
    });
  } catch (error) {
    console.error('WebSocket connection error:', error);
    scheduleReconnect();
  }
}

function disconnectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  if (ws) {
    ws.close();
    ws = null;
  }
}

function scheduleReconnect() {
  if (reconnectTimer) return;

  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    if (authToken) {
      connectWebSocket();
    }
  }, 3000);
}

function handleWebSocketMessage(message) {
  console.log(`[WS] Received message type: ${message.type}`, message.cardId ? `cardId=${message.cardId}` : '');
  switch (message.type) {
    case 'desktop_card_identified':
    case 'card_identified':
    case 'batch_card_identified':
      console.log(`[WS] Card identified! cardId=${message.cardId}`, JSON.stringify(message.cardData || {}).substring(0, 200));
      stats.identified++;

      // Extract card data from message — server sends snake_case field names
      const cardData = message.cardData || message;

      sendToRenderer('card-identified', {
        cardId: message.cardId,
        cardNum: message.cardNum,
        player: cardData.player || cardData.name || '',
        name: cardData.player || cardData.name || '',
        year: cardData.year || '',
        set: cardData.set_name || cardData.set || cardData.setName || '',
        cardNumber: cardData.card_number || cardData.cardNumber || '',
        parallel: cardData.parallel || '',
        serialNumber: cardData.serial_number || '',
        sport: cardData.sport || '',
        confidence: cardData.confidence || '',
        isGraded: cardData.is_graded || false,
        gradingCompany: cardData.grading_company || '',
        grade: cardData.grade || '',
        certNumber: cardData.cert_number || '',
        isAutograph: cardData.is_autograph || false,
        price: cardData.price || cardData.estimatedValue || '',
        pricing: cardData.pricing || null,
        status: 'identified',
        thumbnail: cardData.thumbnail || cardData.front || '',
        back: cardData.back || ''
      });
      sendToRenderer('stats', stats);

      // Show notification
      const cardName = player || 'Card';
      showNotification(
        `Card #${message.cardNum || message.cardId} Identified`,
        `${cardName}${year ? ' - ' + year : ''}${setName ? ' ' + setName : ''}`
      );
      break;

    case 'card_error':
    case 'batch_card_error':
    case 'identify_error':
      stats.errors++;
      sendToRenderer('card-status', {
        cardId: message.cardId,
        status: 'error',
        error: message.error
      });
      sendToRenderer('stats', stats);
      sendToRenderer('log', { type: 'error', message: `Identification failed: ${message.error}` });
      break;

    case 'ping':
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
      break;
  }
}

// Send scanner events to server (for browser clients to see)
function sendScannerEvent(eventType, data = {}) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: eventType,
      ...data
    }));
  }
}

function sendToRenderer(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

// App lifecycle

app.whenReady().then(() => {
  // Create default temp dir for scans
  scanTempDir = path.join(os.tmpdir(), 'slabtrack-scans');
  fs.mkdirSync(scanTempDir, { recursive: true });

  createWindow();
  createTray();

  // Process any files passed via command line (from PaperStream)
  processStartupArgs();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // Don't quit on macOS
  if (process.platform !== 'darwin') {
    // Keep running in tray on Windows
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  stopScanning();
  disconnectWebSocket();
});

// Handle second instance (single instance lock)
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  // Another instance exists - send our file paths to it and quit
  app.quit();
} else {
  app.on('second-instance', (event, commandLine, workingDirectory) => {
    // Another instance was launched - check for file paths
    const filePaths = getFilePathsFromArgs(commandLine);

    if (filePaths.length > 0) {
      // Process files from PaperStream
      console.log('Received files from second instance:', filePaths);
      filePaths.forEach(filePath => {
        processDirectFile(filePath);
      });
    }

    // Show window
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// Process files received directly from command line (PaperStream)
function processDirectFile(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error('File does not exist:', filePath);
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  if (!['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp'].includes(ext)) {
    console.log('Skipping non-image file:', filePath);
    return;
  }

  // Enable direct mode
  if (!directModeEnabled) {
    directModeEnabled = true;
    sendToRenderer('log', { type: 'info', message: 'Direct mode enabled - receiving files from scanner app' });
    sendToRenderer('scanning-status', { scanning: true, mode: 'direct' });
    updateTrayStatus('scanning');
  }

  const fileName = path.basename(filePath);
  sendToRenderer('log', { type: 'info', message: `Received: ${fileName}` });
  sendScannerEvent('scanner_file_detected', { filename: fileName });

  // Sequential pairing: odd = front, even = back
  directModePendingFiles.push(filePath);

  const side = directModePendingFiles.length % 2 === 1 ? 'front' : 'back';
  sendScannerEvent(side === 'front' ? 'scanner_front_captured' : 'scanner_back_captured', {
    filename: fileName
  });
  sendToRenderer('log', { type: 'info', message: `${side === 'front' ? 'Front' : 'Back'} captured: ${fileName}` });

  // When we have a pair, queue upload
  if (directModePendingFiles.length >= 2) {
    const frontFile = directModePendingFiles.shift();
    const backFile = directModePendingFiles.shift();
    cardCounter++;

    queueUpload(frontFile, backFile, cardCounter);
  }
}

// Process command line arguments on startup
function processStartupArgs() {
  const filePaths = getFilePathsFromArgs(process.argv);

  if (filePaths.length > 0) {
    console.log('Processing startup file arguments:', filePaths);

    // Wait for auth to be ready
    const checkAuth = setInterval(() => {
      if (authToken) {
        clearInterval(checkAuth);
        // Connect WebSocket first
        connectWebSocket();

        // Wait a bit for connection then process files
        setTimeout(() => {
          filePaths.forEach(filePath => {
            processDirectFile(filePath);
          });
        }, 1000);
      }
    }, 500);

    // Timeout after 10 seconds
    setTimeout(() => clearInterval(checkAuth), 10000);
  }
}
