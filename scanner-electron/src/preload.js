const { contextBridge, ipcRenderer } = require('electron');

// Expose protected APIs to renderer
contextBridge.exposeInMainWorld('api', {
  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),

  // Authentication
  login: (email, password) => ipcRenderer.invoke('login', email, password),
  slabtrackLogin: (token) => ipcRenderer.invoke('slabtrack-login', token),
  logout: () => ipcRenderer.invoke('logout'),
  checkAuth: () => ipcRenderer.invoke('check-auth'),

  // Folder selection
  selectFolder: () => ipcRenderer.invoke('select-folder'),

  // Scanning
  startScanning: () => ipcRenderer.invoke('start-scanning'),
  stopScanning: () => ipcRenderer.invoke('stop-scanning'),

  // Direct Scanner (WIA)
  discoverScanners: () => ipcRenderer.invoke('discover-scanners'),
  scanDirect: (options) => ipcRenderer.invoke('scan-direct', options),
  getScannerStatus: () => ipcRenderer.invoke('get-scanner-status'),
  openScannerSettings: () => ipcRenderer.invoke('open-scanner-settings'),

  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),

  // Stats
  getStats: () => ipcRenderer.invoke('get-stats'),

  // Card operations
  fetchCards: (params) => ipcRenderer.invoke('fetch-cards', params),
  fetchCard: (cardId) => ipcRenderer.invoke('fetch-card', cardId),
  updateCard: (cardId, updates) => ipcRenderer.invoke('update-card', cardId, updates),
  approveCard: (cardId) => ipcRenderer.invoke('approve-card', cardId),
  rejectCard: (cardId) => ipcRenderer.invoke('reject-card', cardId),
  deleteCard: (cardId) => ipcRenderer.invoke('delete-card', cardId),
  swapCardImages: (cardId) => ipcRenderer.invoke('swap-card-images', cardId),

  // Bulk operations
  bulkApprove: (cardIds) => ipcRenderer.invoke('bulk-approve', cardIds),
  bulkDelete: (cardIds) => ipcRenderer.invoke('bulk-delete', cardIds),
  bulkUpdate: (cardIds, updates) => ipcRenderer.invoke('bulk-update', cardIds, updates),
  exportCards: (cardIds) => ipcRenderer.invoke('export-cards', cardIds),
  sendToSlabTrack: (cardIds) => ipcRenderer.invoke('send-to-slabtrack', cardIds),

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
  onScanProgress: (callback) => {
    ipcRenderer.on('scan-progress', (event, data) => callback(data));
  },
  onScanComplete: (callback) => {
    ipcRenderer.on('scan-complete', (event, data) => callback(data));
  },
  onPipelineStatus: (callback) => {
    ipcRenderer.on('pipeline-status', (event, data) => callback(data));
  },
  onShowMultifeedHelp: (callback) => {
    ipcRenderer.on('show-multifeed-help', (event, data) => callback(data));
  },

  // Remove listeners
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});
