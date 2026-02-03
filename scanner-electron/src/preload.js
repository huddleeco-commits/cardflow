const { contextBridge, ipcRenderer } = require('electron');

// Expose protected APIs to renderer
contextBridge.exposeInMainWorld('api', {
  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),

  // Authentication
  login: (email, password) => ipcRenderer.invoke('login', email, password),
  logout: () => ipcRenderer.invoke('logout'),
  checkAuth: () => ipcRenderer.invoke('check-auth'),

  // Folder selection
  selectFolder: () => ipcRenderer.invoke('select-folder'),

  // Scanning
  startScanning: () => ipcRenderer.invoke('start-scanning'),
  stopScanning: () => ipcRenderer.invoke('stop-scanning'),

  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),

  // Stats
  getStats: () => ipcRenderer.invoke('get-stats'),

  // Event listeners
  onCardAdded: (callback) => {
    ipcRenderer.on('card-added', (event, data) => callback(data));
  },
  onCardStatus: (callback) => {
    ipcRenderer.on('card-status', (event, data) => callback(data));
  },
  onCardIdentified: (callback) => {
    ipcRenderer.on('card-identified', (event, data) => callback(data));
  },
  onScanningStatus: (callback) => {
    ipcRenderer.on('scanning-status', (event, data) => callback(data));
  },
  onConnectionStatus: (callback) => {
    ipcRenderer.on('connection-status', (event, data) => callback(data));
  },
  onStats: (callback) => {
    ipcRenderer.on('stats', (event, data) => callback(data));
  },
  onLog: (callback) => {
    ipcRenderer.on('log', (event, data) => callback(data));
  },

  // Remove listeners
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});
