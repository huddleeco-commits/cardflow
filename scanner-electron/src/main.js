const { app, BrowserWindow, Tray, Menu, ipcMain, dialog, nativeImage, Notification, shell } = require('electron');
const path = require('path');
const fs = require('fs');
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
      startMinimized: false,
      startWithWindows: false
    },
    credentials: null,
    authToken: null
  }
});

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
let reconnectTimer = null;
let directModeEnabled = false; // True when receiving files directly from PaperStream
let directModePendingFiles = []; // Files received via command line

const API_BASE = 'https://cardflow.be1st.io';
const WS_URL = 'wss://cardflow.be1st.io';

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
function createWindow() {
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

  mainWindow.loadFile(path.join(__dirname, 'renderer/index.html'));

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    const settings = store.get('settings');
    if (!settings.startMinimized) {
      mainWindow.show();
    }
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

  tray.setToolTip('CardFlow Scanner');

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
  try {
    const response = await axios.post(`${API_BASE}/api/auth/login`, {
      email,
      password
    });

    if (response.data.token) {
      authToken = response.data.token;
      store.set('authToken', authToken);
      store.set('credentials', { email });

      // Connect WebSocket after login
      connectWebSocket();

      return { success: true, user: response.data.user };
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

// Logout
ipcMain.handle('logout', async () => {
  authToken = null;
  store.delete('authToken');
  store.delete('credentials');
  stopScanning();
  disconnectWebSocket();
  return { success: true };
});

// Check auth status
ipcMain.handle('check-auth', async () => {
  if (!authToken) {
    return { authenticated: false };
  }

  try {
    const response = await axios.get(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data.id) {
      connectWebSocket();
      return { authenticated: true, user: response.data };
    }
  } catch (error) {
    console.error('Auth check error:', error.message);
  }

  authToken = null;
  store.delete('authToken');
  return { authenticated: false };
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

function handleNewFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();

  // Only process image files
  if (!['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp'].includes(ext)) {
    return;
  }

  const settings = store.get('settings');
  const fileName = path.basename(filePath);

  sendToRenderer('log', { type: 'info', message: `New file detected: ${fileName}` });
  sendScannerEvent('scanner_file_detected', { filename: fileName });

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
  uploadQueue.push({ frontPath, backPath, cardNum });

  // Add card to UI immediately
  sendToRenderer('card-added', {
    cardNum,
    frontPath,
    status: 'queued'
  });

  processUploadQueue();
}

async function processUploadQueue() {
  if (isUploading || uploadQueue.length === 0) {
    return;
  }

  isUploading = true;
  const { frontPath, backPath, cardNum } = uploadQueue.shift();

  try {
    sendToRenderer('card-status', { cardNum, status: 'uploading' });
    sendToRenderer('log', { type: 'info', message: `Uploading card #${cardNum}...` });
    sendScannerEvent('scanner_uploading', { cardNum });

    const settings = store.get('settings');

    // Create form data
    const form = new FormData();
    form.append('front', fs.createReadStream(frontPath));
    form.append('back', fs.createReadStream(backPath));
    form.append('batch', 'true'); // Auto-identify after upload
    form.append('holoMode', settings.holoMode.toString());
    form.append('brightnessBoost', settings.brightnessBoost.toString());
    form.append('autoRotateBack', settings.autoRotateBack.toString());

    const response = await axios.post(`${API_BASE}/api/upload-pair`, form, {
      headers: {
        ...form.getHeaders(),
        Authorization: `Bearer ${authToken}`
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    if (response.data.cardId) {
      stats.scanned++;
      sendToRenderer('card-status', {
        cardNum,
        status: 'identifying',
        cardId: response.data.cardId,
        thumbnail: response.data.front
      });
      sendToRenderer('stats', stats);
      sendToRenderer('log', { type: 'success', message: `Card #${cardNum} uploaded successfully` });
      sendScannerEvent('scanner_card_uploaded', { cardNum, cardId: response.data.cardId });
    } else {
      throw new Error(response.data.error || 'Upload failed');
    }
  } catch (error) {
    console.error('Upload error:', error);
    stats.errors++;
    sendToRenderer('card-status', { cardNum, status: 'error', error: error.message });
    sendToRenderer('stats', stats);
    sendToRenderer('log', { type: 'error', message: `Card #${cardNum} failed: ${error.message}` });
  }

  isUploading = false;
  processUploadQueue();
}

// WebSocket connection for real-time updates

function connectWebSocket() {
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
          sendToRenderer('log', { type: 'success', message: 'Connected to CardFlow server' });

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
  switch (message.type) {
    case 'card_identified':
    case 'batch_card_identified':
      stats.identified++;

      // Extract card data from message
      const cardData = message.cardData || message;
      const player = cardData.player || cardData.name || '';
      const year = cardData.year || '';
      const setName = cardData.set || cardData.setName || '';

      sendToRenderer('card-identified', {
        cardId: message.cardId,
        cardNum: message.cardNum,
        name: cardData.name || player,
        year: year,
        set: setName,
        player: player
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
