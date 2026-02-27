// SlabTrack Scanner - Renderer Process

// State
let isScanning = false;
let isConnected = false;
let cards = new Map();
let settings = {};
let slabtrackInfo = null;
let scanMode = 'direct'; // 'direct' or 'folder'
let filterStatus = 'all';
let filterSearch = '';
let selectedCards = new Set();
let scanningCardNum = null; // Track which card is currently scanning (gets pulsing border)
let expandedCardNum = null; // Track which card has the detail panel open
let dirtyCards = new Map(); // cardNum -> Set of dirty field names

// DOM Elements
const elements = {
  // Views
  loginView: document.getElementById('login-view'),
  mainView: document.getElementById('main-view'),

  // Login
  loginForm: document.getElementById('login-form'),
  emailInput: document.getElementById('email'),
  passwordInput: document.getElementById('password'),
  rememberMe: document.getElementById('remember-me'),
  loginError: document.getElementById('login-error'),
  loginBtn: document.getElementById('login-btn'),

  // SlabTrack Login
  slabtrackLoginForm: document.getElementById('slabtrack-login-form'),
  slabtrackTokenInput: document.getElementById('slabtrack-token'),
  slabtrackLoginError: document.getElementById('slabtrack-login-error'),
  slabtrackLoginBtn: document.getElementById('slabtrack-login-btn'),
  loginTabs: document.querySelectorAll('.login-tab'),

  // Tier Badge
  tierBadgeContainer: document.getElementById('tier-badge-container'),
  tierBadge: document.getElementById('tier-badge'),
  tierUsername: document.getElementById('tier-username'),

  // Window Controls
  btnMinimize: document.getElementById('btn-minimize'),
  btnMaximize: document.getElementById('btn-maximize'),
  btnClose: document.getElementById('btn-close'),

  // Main View
  connectionStatus: document.getElementById('connection-status'),
  folderPath: document.getElementById('folder-path'),
  btnBrowse: document.getElementById('btn-browse'),
  btnScan: document.getElementById('btn-scan'),

  // Scanner Mode
  modeDirectBtn: document.getElementById('mode-direct'),
  modeFolderBtn: document.getElementById('mode-folder'),
  directScannerPanel: document.getElementById('direct-scanner-panel'),
  folderWatchPanel: document.getElementById('folder-watch-panel'),
  scannerSelect: document.getElementById('scanner-select'),
  btnRefreshScanners: document.getElementById('btn-refresh-scanners'),
  btnScannerSetup: document.getElementById('btn-scanner-setup'),
  scanDpi: document.getElementById('scan-dpi'),
  scanDuplex: document.getElementById('scan-duplex'),
  multifeedHelp: document.getElementById('multifeed-help'),
  btnFixMultifeed: document.getElementById('btn-fix-multifeed'),
  btnDismissMultifeed: document.getElementById('btn-dismiss-multifeed'),
  statScanned: document.getElementById('stat-scanned'),
  statIdentified: document.getElementById('stat-identified'),
  statErrors: document.getElementById('stat-errors'),
  btnSettings: document.getElementById('btn-settings'),
  btnLogout: document.getElementById('btn-logout'),

  // Filters
  filterStatusSelect: document.getElementById('filter-status'),
  filterSearchInput: document.getElementById('filter-search'),

  // Card Detail Panel
  detailPanel: document.getElementById('card-detail-panel'),
  detailPanelTitle: document.getElementById('detail-panel-title'),
  detailFront: document.getElementById('detail-front'),
  detailBack: document.getElementById('detail-back'),
  detailSave: document.getElementById('detail-save'),
  detailApprove: document.getElementById('detail-approve'),
  detailDelete: document.getElementById('detail-delete'),
  detailClose: document.getElementById('detail-close'),

  // Card Grid
  cardGrid: document.getElementById('card-grid'),
  cardGridContainer: document.getElementById('card-grid-container'),

  // Pipeline Bar
  pipelineBar: document.getElementById('pipeline-bar'),
  pipelineScanCount: document.getElementById('pipeline-scan-count'),
  pipelineUploadCount: document.getElementById('pipeline-upload-count'),
  pipelineIdentifyCount: document.getElementById('pipeline-identify-count'),
  pipelineDoneCount: document.getElementById('pipeline-done-count'),

  // Feed
  emptyState: document.getElementById('empty-state'),
  feedCount: document.getElementById('feed-count'),

  // Bulk Toolbar
  bulkToolbar: document.getElementById('bulk-toolbar'),
  bulkCount: document.getElementById('bulk-count'),
  bulkApproveBtn: document.getElementById('bulk-approve'),
  bulkExportBtn: document.getElementById('bulk-export'),
  bulkSendSlabTrackBtn: document.getElementById('bulk-send-slabtrack'),
  bulkDeleteBtn: document.getElementById('bulk-delete'),

  // Batch Summary
  batchSummary: document.getElementById('batch-summary'),
  batchDismiss: document.getElementById('batch-dismiss'),
  batchTotal: document.getElementById('batch-total'),
  batchIdentified: document.getElementById('batch-identified'),
  batchErrors: document.getElementById('batch-errors'),
  batchApproveAll: document.getElementById('batch-approve-all'),
  batchReviewErrors: document.getElementById('batch-review-errors'),
  batchExportAll: document.getElementById('batch-export-all'),

  // Activity Log
  logContent: document.getElementById('log-content'),
  btnClearLog: document.getElementById('btn-clear-log'),

  // Settings Modal
  settingsModal: document.getElementById('settings-modal'),
  btnCloseSettings: document.getElementById('btn-close-settings'),
  btnCancelSettings: document.getElementById('btn-cancel-settings'),
  btnSaveSettings: document.getElementById('btn-save-settings'),
  settingPairingMode: document.getElementById('setting-pairing-mode'),
  settingHoloMode: document.getElementById('setting-holo-mode'),
  settingBrightness: document.getElementById('setting-brightness'),
  brightnessValue: document.getElementById('brightness-value'),
  settingAutoRotate: document.getElementById('setting-auto-rotate'),
  settingAutoCrop: document.getElementById('setting-auto-crop'),
  settingRemoveStreaks: document.getElementById('setting-remove-streaks'),
  settingCardSize: document.getElementById('setting-card-size'),
  settingCardWidth: document.getElementById('setting-card-width'),
  settingCardHeight: document.getElementById('setting-card-height'),
  customDimensions: document.getElementById('custom-dimensions'),
  settingStartMinimized: document.getElementById('setting-start-minimized'),
  settingStartWindows: document.getElementById('setting-start-windows'),

  // Sidebar presets & holo
  scanPreset: document.getElementById('scan-preset'),
  scanHoloMode: document.getElementById('scan-holo-mode')
};

// Scan Presets — bundle of settings applied at once
const SCAN_PRESETS = {
  standard: { cardWidth: 4.5, cardHeight: 5.0, holoMode: false, autoCrop: true, removeStreaks: false, scanDpi: 300 },
  holo:     { cardWidth: 4.5, cardHeight: 5.0, holoMode: true,  autoCrop: true, removeStreaks: false, scanDpi: 600 },
  thick:    { cardWidth: 5.0, cardHeight: 5.5, holoMode: false, autoCrop: true, removeStreaks: false, scanDpi: 300 },
  vintage:  { cardWidth: 4.5, cardHeight: 5.0, holoMode: false, autoCrop: true, removeStreaks: true,  scanDpi: 600 },
  raw:      { cardWidth: 5.0, cardHeight: 6.0, holoMode: false, autoCrop: false, removeStreaks: false, scanDpi: 600 },
  custom:   null  // uses current settings as-is
};

// Initialize
async function init() {
  setupEventListeners();
  setupIPCListeners();
  await checkAuth();
}

// Event Listeners
function setupEventListeners() {
  // Window controls
  elements.btnMinimize.addEventListener('click', () => window.api.minimize());
  elements.btnMaximize.addEventListener('click', () => window.api.maximize());
  elements.btnClose.addEventListener('click', () => window.api.close());

  // Login tabs
  elements.loginTabs.forEach(tab => {
    tab.addEventListener('click', () => switchLoginTab(tab.dataset.tab));
  });

  // Login forms
  elements.slabtrackLoginForm.addEventListener('submit', handleSlabTrackLogin);
  elements.loginForm.addEventListener('submit', handleLogin);

  // Scanner mode toggle
  elements.modeDirectBtn.addEventListener('click', () => switchScanMode('direct'));
  elements.modeFolderBtn.addEventListener('click', () => switchScanMode('folder'));

  // Scanner controls
  elements.btnRefreshScanners.addEventListener('click', discoverScanners);
  elements.btnScannerSetup.addEventListener('click', openScannerSettings);
  elements.btnFixMultifeed.addEventListener('click', openScannerSettings);
  elements.btnDismissMultifeed.addEventListener('click', () => {
    elements.multifeedHelp.classList.add('hidden');
  });
  elements.scanDpi.addEventListener('change', () => {
    window.api.saveSettings({ scanDpi: parseInt(elements.scanDpi.value, 10) });
  });
  elements.scanDuplex.addEventListener('change', () => {
    window.api.saveSettings({ scanDuplex: elements.scanDuplex.checked });
  });
  elements.scannerSelect.addEventListener('change', () => {
    window.api.saveSettings({ scannerId: elements.scannerSelect.value });
  });

  // Scan presets
  elements.scanPreset.addEventListener('change', handlePresetChange);

  // Holo toggle in sidebar
  elements.scanHoloMode.addEventListener('change', () => {
    const holoOn = elements.scanHoloMode.checked;
    window.api.saveSettings({ holoMode: holoOn });
    settings.holoMode = holoOn;
    // Sync preset dropdown
    if (holoOn && elements.scanPreset.value !== 'holo') {
      elements.scanPreset.value = 'holo';
      applyPreset('holo');
    } else if (!holoOn && elements.scanPreset.value === 'holo') {
      elements.scanPreset.value = 'standard';
      applyPreset('standard');
    }
  });

  // Card size dropdown in settings — show/hide custom dimensions
  if (elements.settingCardSize) {
    elements.settingCardSize.addEventListener('change', () => {
      elements.customDimensions.classList.toggle('hidden', elements.settingCardSize.value !== 'custom');
    });
  }

  // Alt folder picker for folder watch mode
  const btnBrowseAlt = document.getElementById('btn-browse-alt');
  if (btnBrowseAlt) btnBrowseAlt.addEventListener('click', handleBrowse);

  // Folder picker (for folder watch mode)
  const btnBrowse = document.getElementById('btn-browse');
  if (btnBrowse) btnBrowse.addEventListener('click', handleBrowse);

  // Scan button
  elements.btnScan.addEventListener('click', handleScanToggle);

  // Settings
  elements.btnSettings.addEventListener('click', openSettings);
  elements.btnCloseSettings.addEventListener('click', closeSettings);
  elements.btnCancelSettings.addEventListener('click', closeSettings);
  elements.btnSaveSettings.addEventListener('click', saveSettings);
  elements.settingsModal.querySelector('.modal-backdrop').addEventListener('click', closeSettings);

  // Brightness slider
  elements.settingBrightness.addEventListener('input', (e) => {
    elements.brightnessValue.textContent = e.target.value;
  });

  // Filters
  elements.filterStatusSelect.addEventListener('change', () => {
    filterStatus = elements.filterStatusSelect.value;
    applyFilters();
  });
  elements.filterSearchInput.addEventListener('input', () => {
    filterSearch = elements.filterSearchInput.value.toLowerCase();
    applyFilters();
  });

  // Bulk actions
  elements.bulkApproveBtn.addEventListener('click', handleBulkApprove);
  elements.bulkExportBtn.addEventListener('click', handleBulkExport);
  elements.bulkSendSlabTrackBtn.addEventListener('click', handleBulkSendToSlabTrack);
  elements.bulkDeleteBtn.addEventListener('click', handleBulkDelete);

  // Batch summary
  elements.batchDismiss.addEventListener('click', () => elements.batchSummary.classList.add('hidden'));
  elements.batchApproveAll.addEventListener('click', handleBatchApproveAll);
  elements.batchReviewErrors.addEventListener('click', () => {
    elements.filterStatusSelect.value = 'error';
    filterStatus = 'error';
    applyFilters();
    elements.batchSummary.classList.add('hidden');
  });
  elements.batchExportAll.addEventListener('click', handleBatchExportAll);

  // Detail panel
  wireDetailPanelEvents();

  // Keyboard shortcuts
  document.addEventListener('keydown', handleKeyboardShortcuts);

  // Logout
  elements.btnLogout.addEventListener('click', handleLogout);

  // Clear log
  elements.btnClearLog.addEventListener('click', () => {
    elements.logContent.innerHTML = '';
  });

  // Clear feed
  const btnClearFeed = document.getElementById('btn-clear-feed');
  if (btnClearFeed) btnClearFeed.addEventListener('click', () => {
    clearCards();
    addLogEntry({ type: 'info', message: 'Card feed cleared' });
  });
}

// IPC Listeners
function setupIPCListeners() {
  window.api.onCardAdded((data) => {
    addCard(data);
  });

  window.api.onCardStatus((data) => {
    updateCardStatus(data);
  });

  window.api.onCardIdentified((data) => {
    updateCardIdentified(data);
  });

  window.api.onScanningStatus((data) => {
    isScanning = data.scanning;
    updateScanButton(data.mode);
  });

  window.api.onConnectionStatus((data) => {
    isConnected = data.connected;
    updateConnectionStatus();
  });

  window.api.onStats((data) => {
    updateStats(data);
  });

  window.api.onLog((data) => {
    addLogEntry(data);
  });

  window.api.onScanProgress((data) => {
    updateScanProgress(data);
  });

  window.api.onScanComplete((data) => {
    handleScanComplete(data);
  });

  window.api.onPipelineStatus((data) => {
    updatePipelineBar(data);
  });

  window.api.onShowMultifeedHelp(() => {
    elements.multifeedHelp.classList.remove('hidden');
  });
}

// Authentication
async function checkAuth() {
  const result = await window.api.checkAuth();

  if (result.authenticated) {
    slabtrackInfo = result.slabtrackInfo || null;
    showMainView();
    updateTierBadge();
    await loadSettings();
  } else {
    showLoginView();
  }
}

async function handleLogin(e) {
  e.preventDefault();

  const email = elements.emailInput.value.trim();
  const password = elements.passwordInput.value;

  if (!email || !password) {
    showLoginError('Please enter your email and password');
    return;
  }

  elements.loginBtn.classList.add('loading');
  elements.loginError.classList.remove('show');

  try {
    const result = await window.api.login(email, password);

    if (result.success) {
      showMainView();
      await loadSettings();
    } else {
      showLoginError(result.error);
    }
  } catch (error) {
    showLoginError('An error occurred. Please try again.');
  } finally {
    elements.loginBtn.classList.remove('loading');
  }
}

async function handleLogout() {
  await window.api.logout();
  slabtrackInfo = null;
  showLoginView();
  clearCards();
  elements.logContent.innerHTML = '';
}

function showLoginError(message) {
  elements.loginError.textContent = message;
  elements.loginError.classList.add('show');
}

// Login Tab Switching
function switchLoginTab(tabName) {
  elements.loginTabs.forEach(tab => {
    tab.classList.toggle('active', tab.dataset.tab === tabName);
  });
  // Show/hide forms
  elements.slabtrackLoginForm.classList.toggle('active', tabName === 'slabtrack');
  elements.loginForm.classList.toggle('active', tabName === 'email');
}

// SlabTrack Token Login
async function handleSlabTrackLogin(e) {
  e.preventDefault();

  const token = elements.slabtrackTokenInput.value.trim();
  if (!token) {
    elements.slabtrackLoginError.textContent = 'Please enter your SlabTrack token';
    elements.slabtrackLoginError.classList.add('show');
    return;
  }

  elements.slabtrackLoginBtn.classList.add('loading');
  elements.slabtrackLoginError.classList.remove('show');

  try {
    const result = await window.api.slabtrackLogin(token);

    if (result.success) {
      slabtrackInfo = result.slabtrackInfo;
      showMainView();
      updateTierBadge();
      await loadSettings();
    } else {
      elements.slabtrackLoginError.textContent = result.error;
      elements.slabtrackLoginError.classList.add('show');
    }
  } catch (error) {
    elements.slabtrackLoginError.textContent = 'An error occurred. Please try again.';
    elements.slabtrackLoginError.classList.add('show');
  } finally {
    elements.slabtrackLoginBtn.classList.remove('loading');
  }
}

// Tier Badge
function updateTierBadge() {
  if (slabtrackInfo) {
    elements.tierBadgeContainer.classList.remove('hidden');
    const tier = (slabtrackInfo.tier || 'free').toLowerCase();
    elements.tierBadge.textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
    elements.tierBadge.className = `tier-badge tier-${tier}`;
    elements.tierUsername.textContent = slabtrackInfo.username || '';
  } else {
    elements.tierBadgeContainer.classList.add('hidden');
  }
}

function showLoginView() {
  elements.loginView.classList.remove('hidden');
  elements.mainView.classList.add('hidden');
  elements.passwordInput.value = '';
}

function showMainView() {
  elements.loginView.classList.add('hidden');
  elements.mainView.classList.remove('hidden');
}

// Scanner Mode
function switchScanMode(mode) {
  scanMode = mode;
  elements.modeDirectBtn.classList.toggle('active', mode === 'direct');
  elements.modeFolderBtn.classList.toggle('active', mode === 'folder');
  elements.directScannerPanel.classList.toggle('hidden', mode !== 'direct');
  elements.folderWatchPanel.classList.toggle('hidden', mode !== 'folder');

  // Update scan button text
  if (!isScanning) {
    elements.btnScan.querySelector('span').textContent = mode === 'direct' ? 'SCAN NOW' : 'Start Scanning';
  }

  window.api.saveSettings({ scanMode: mode });
}

// Scanner Discovery
async function discoverScanners() {
  elements.scannerSelect.innerHTML = '<option value="">Searching...</option>';
  elements.btnRefreshScanners.classList.add('spinning');

  try {
    const result = await window.api.discoverScanners();
    elements.scannerSelect.innerHTML = '';

    if (result.scanners && result.scanners.length > 0) {
      result.scanners.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.id;
        opt.textContent = `${s.name} (${s.manufacturer})`;
        elements.scannerSelect.appendChild(opt);
      });

      // Restore saved scanner selection
      if (settings.scannerId) {
        elements.scannerSelect.value = settings.scannerId;
      }

      addLogEntry({ type: 'success', message: `Found ${result.scanners.length} scanner(s)` });
    } else {
      elements.scannerSelect.innerHTML = '<option value="">No scanners found</option>';
      addLogEntry({ type: 'warning', message: 'No scanners detected. Check USB connection.' });
    }
  } catch (error) {
    elements.scannerSelect.innerHTML = '<option value="">Error detecting scanners</option>';
    addLogEntry({ type: 'error', message: `Scanner discovery failed: ${error.message}` });
  } finally {
    elements.btnRefreshScanners.classList.remove('spinning');
  }
}

// Open Fujitsu Software Operation Panel for scanner hardware settings
async function openScannerSettings() {
  addLogEntry({ type: 'info', message: 'Opening scanner hardware settings...' });
  const result = await window.api.openScannerSettings();
  if (result.success) {
    addLogEntry({ type: 'success', message: 'Scanner settings panel opened. Disable "Multifeed Detection" for card scanning.' });
  } else {
    addLogEntry({ type: 'error', message: result.error || 'Could not open scanner settings' });
  }
}

// Direct Scan — triggers WinRT scan via fi-8170 ADF
async function handleDirectScan() {
  if (isScanning) {
    addLogEntry({ type: 'warning', message: 'Scan already in progress' });
    return;
  }

  elements.btnScan.classList.add('scanning');
  elements.btnScan.querySelector('span').textContent = 'SCANNING...';

  const dpi = parseInt(elements.scanDpi.value, 10) || 300;
  const duplex = elements.scanDuplex.checked;

  try {
    const result = await window.api.scanDirect({ dpi, duplex });

    if (!result.success) {
      if (result.isMultifeed) {
        // Multifeed error already logged by main process; show help banner
        elements.multifeedHelp.classList.remove('hidden');
      } else {
        addLogEntry({ type: 'error', message: result.error });
      }
    } else {
      addLogEntry({ type: 'success', message: `Scan complete: ${result.pagesScanned} page(s)` });
    }
  } catch (error) {
    addLogEntry({ type: 'error', message: `Scan failed: ${error.message}` });
  } finally {
    elements.btnScan.classList.remove('scanning');
    elements.btnScan.querySelector('span').textContent = 'SCAN NOW';
  }
}

function updateScanProgress(data) {
  // Update UI with per-page scan progress
  if (data.status === 'scanning') {
    addLogEntry({ type: 'info', message: `Scanning page ${data.page} (${data.side})...` });
  }
}

function handleScanComplete(data) {
  addLogEntry({ type: 'success', message: `Scan complete: ${data.totalPages} pages scanned` });
  // Show batch summary after a short delay to let uploads/identifications finish
  setTimeout(() => showBatchSummary(), 2000);
}

// Pipeline Status
function updatePipelineBar(data) {
  elements.pipelineBar.classList.remove('hidden');

  elements.pipelineScanCount.textContent = data.scanned || 0;
  elements.pipelineUploadCount.textContent = (data.queued || 0) + (data.uploading || 0);
  const identifying = (data.scanned || 0) - (data.identified || 0) - (data.errors || 0);
  elements.pipelineIdentifyCount.textContent = Math.max(0, identifying);
  elements.pipelineDoneCount.textContent = data.identified || 0;

  // Highlight active stage
  document.getElementById('pipeline-uploading').classList.toggle('active', (data.uploading || 0) > 0);
  document.getElementById('pipeline-identifying').classList.toggle('active', identifying > 0);
  document.getElementById('pipeline-done').classList.toggle('active', (data.identified || 0) > 0);
}

// Folder Selection
async function handleBrowse() {
  const result = await window.api.selectFolder();

  if (result.success) {
    // Update all folder path inputs
    const folderPath = document.getElementById('folder-path');
    if (folderPath) folderPath.value = result.path;
    const folderPathAlt = document.getElementById('folder-path-alt');
    if (folderPathAlt) folderPathAlt.value = result.path;
  }
}

// Scanning
async function handleScanToggle() {
  if (scanMode === 'direct') {
    handleDirectScan();
    return;
  }

  // Folder watch mode
  if (isScanning) {
    await window.api.stopScanning();
  } else {
    const folderPath = document.getElementById('folder-path-alt');
    if (!folderPath || !folderPath.value) {
      addLogEntry({ type: 'error', message: 'Please select a scan folder first' });
      return;
    }

    const result = await window.api.startScanning();
    if (!result.success) {
      addLogEntry({ type: 'error', message: result.error });
    }
  }
}

function updateScanButton(mode) {
  if (isScanning) {
    elements.btnScan.classList.add('scanning');
    if (mode === 'direct') {
      elements.btnScan.querySelector('span').textContent = 'Direct Mode Active';
      elements.btnScan.classList.add('direct-mode');
    } else {
      elements.btnScan.querySelector('span').textContent = 'Stop Scanning';
      elements.btnScan.classList.remove('direct-mode');
    }
  } else {
    elements.btnScan.classList.remove('scanning');
    elements.btnScan.classList.remove('direct-mode');
    elements.btnScan.querySelector('span').textContent = 'Start Scanning';
  }
}

// Connection Status
function updateConnectionStatus() {
  if (isConnected) {
    elements.connectionStatus.classList.add('connected');
    elements.connectionStatus.querySelector('.status-text').textContent = 'Connected';
  } else {
    elements.connectionStatus.classList.remove('connected');
    elements.connectionStatus.querySelector('.status-text').textContent = 'Disconnected';
  }
}

// Stats
function updateStats(stats) {
  elements.statScanned.textContent = stats.scanned;
  elements.statIdentified.textContent = stats.identified;
  elements.statErrors.textContent = stats.errors;
}

// Helper: convert local file path to file:// URL for <img> src
function filePathToUrl(p) {
  if (!p) return '';
  if (p.startsWith('http')) return p;
  // Convert backslashes and prepend file:///
  return 'file:///' + p.replace(/\\/g, '/');
}

// =====================================================
// Card Feed — Scan Preview + Grid System
// =====================================================

function addCard(data) {
  cards.set(data.cardNum, {
    cardNum: data.cardNum,
    status: data.status,
    frontPath: data.frontPath,
    backPath: data.backPath
  });

  // Remove scanning state from previous card
  if (scanningCardNum !== null && scanningCardNum !== data.cardNum) {
    const prevEl = document.getElementById(`grid-${scanningCardNum}`);
    if (prevEl) {
      prevEl.classList.remove('scanning');
      const badge = prevEl.querySelector('.grid-card-scanning-badge');
      if (badge) badge.classList.add('hidden');
    }
  }

  // New card goes directly into the grid with scanning state
  scanningCardNum = data.cardNum;
  renderGridCard(data.cardNum, true); // true = scanning
  updateFeedCount();
  hideEmptyState();
}

function updateCardStatus(data) {
  const card = cards.get(data.cardNum) || findCardByCardId(data.cardId);
  if (!card) return;

  card.status = data.status;
  if (data.cardId) card.cardId = data.cardId;
  if (data.thumbnail) card.thumbnail = data.thumbnail;
  if (data.error) card.error = data.error;

  // Update grid card if it exists
  const gridEl = document.getElementById(`grid-${card.cardNum}`);
  if (gridEl) {
    updateGridCardDOM(gridEl, card);
  }

  // Update detail panel if this card is expanded
  if (expandedCardNum === card.cardNum) {
    populateDetailPanel(card);
  }
}

function updateCardIdentified(data) {
  const card = cards.get(data.cardNum) || findCardByCardId(data.cardId);
  if (!card) return;

  card.status = 'identified';
  card.name = data.name;
  card.player = data.player;
  card.year = data.year;
  card.set = data.set;
  card.cardNumber = data.cardNumber || '';
  card.parallel = data.parallel || '';
  card.serialNumber = data.serialNumber || '';
  card.sport = data.sport || '';
  card.confidence = data.confidence || '';
  card.isGraded = data.isGraded || false;
  card.gradingCompany = data.gradingCompany || '';
  card.grade = data.grade || '';
  card.certNumber = data.certNumber || '';
  card.isAutograph = data.isAutograph || false;
  card.price = data.price || '';
  card.pricing = data.pricing || null;
  if (data.thumbnail) card.thumbnail = data.thumbnail;
  if (data.back) card.back = data.back;

  // Remove scanning state when identified
  if (scanningCardNum === card.cardNum) {
    scanningCardNum = null;
  }

  // Render/update grid card
  renderGridCard(card.cardNum);

  // Update detail panel if this card is expanded
  if (expandedCardNum === card.cardNum) {
    populateDetailPanel(card);
  }
}

function findCardByCardId(cardId) {
  for (const card of cards.values()) {
    if (card.cardId === cardId) return card;
  }
  return null;
}

// =====================================================
// Card Grid
// =====================================================

function renderGridCard(cardNum, isScanning = false) {
  const card = cards.get(cardNum);
  if (!card) return;

  let el = document.getElementById(`grid-${cardNum}`);
  if (!el) {
    el = buildGridCardElement(card, isScanning);
    wireGridCardEvents(el, cardNum);
    // Prepend (newest first)
    const firstCard = elements.cardGrid.querySelector('.grid-card');
    if (firstCard) {
      elements.cardGrid.insertBefore(el, firstCard);
    } else {
      elements.cardGrid.appendChild(el);
    }
  } else {
    updateGridCardDOM(el, card);
    // Update scanning state
    if (isScanning) {
      el.classList.add('scanning');
      const badge = el.querySelector('.grid-card-scanning-badge');
      if (badge) badge.classList.remove('hidden');
    } else {
      el.classList.remove('scanning');
      const badge = el.querySelector('.grid-card-scanning-badge');
      if (badge) badge.classList.add('hidden');
    }
  }
}

function buildGridCardElement(card, isScanning = false) {
  const el = document.createElement('div');
  el.id = `grid-${card.cardNum}`;
  el.className = `grid-card`;
  if (isScanning) el.classList.add('scanning');

  const frontSrc = card.thumbnail || filePathToUrl(card.frontPath) || '';
  const player = card.player || card.name || '';
  const year = card.year || '';
  const statusClass = card.status || 'queued';
  const statusIcon = getStatusIcon(card);

  el.innerHTML = `
    <div class="grid-card-select">
      <input type="checkbox" class="grid-checkbox" data-card="${card.cardNum}">
    </div>
    <div class="grid-card-image">
      <img src="${frontSrc}" alt="" loading="lazy">
      <span class="grid-card-num-badge">#${card.cardNum}</span>
      <div class="grid-card-scanning-badge ${isScanning ? '' : 'hidden'}">SCANNING</div>
    </div>
    <div class="grid-card-info">
      <span class="grid-card-name">${escapeHtml(player) || 'Unidentified'}</span>
      <span class="grid-card-year">${escapeHtml(year)}</span>
      <span class="grid-card-status status-${statusClass}">${statusIcon}</span>
    </div>
  `;

  return el;
}

function getStatusIcon(card) {
  switch (card.status) {
    case 'queued': return '\u23F3'; // hourglass
    case 'uploading': return '\u2B06'; // up arrow
    case 'identifying': return '\uD83D\uDD0D'; // magnifying glass (🔍)
    case 'identified': return '\u2705'; // green check
    case 'approved': return '\u2714'; // check mark
    case 'error': return '\u26A0'; // warning
    default: return '\u23F3';
  }
}

function wireGridCardEvents(el, cardNum) {
  // Click on card tile → expand detail panel (but not on checkbox)
  el.addEventListener('click', (e) => {
    if (e.target.classList.contains('grid-checkbox')) return;
    expandCard(cardNum);
  });

  // Checkbox for bulk selection
  const checkbox = el.querySelector('.grid-checkbox');
  if (checkbox) {
    checkbox.addEventListener('change', (e) => {
      e.stopPropagation();
      if (checkbox.checked) {
        selectedCards.add(cardNum);
      } else {
        selectedCards.delete(cardNum);
      }
      updateBulkToolbar();
    });
  }
}

function updateGridCardDOM(el, card) {
  // Update front image
  const img = el.querySelector('.grid-card-image img');
  const frontSrc = card.thumbnail || filePathToUrl(card.frontPath) || '';
  if (img && frontSrc && img.src !== frontSrc) img.src = frontSrc;

  // Update name & year
  const nameEl = el.querySelector('.grid-card-name');
  if (nameEl) nameEl.textContent = card.player || card.name || 'Unidentified';
  const yearEl = el.querySelector('.grid-card-year');
  if (yearEl) yearEl.textContent = card.year || '';

  // Update status icon
  const statusEl = el.querySelector('.grid-card-status');
  if (statusEl) {
    statusEl.textContent = getStatusIcon(card);
    statusEl.className = `grid-card-status status-${card.status}`;
  }

  // Update scanning badge visibility
  const isScanning = scanningCardNum === card.cardNum;
  el.classList.toggle('scanning', isScanning);
  const badge = el.querySelector('.grid-card-scanning-badge');
  if (badge) badge.classList.toggle('hidden', !isScanning);

  // Update selected state
  el.classList.toggle('selected', expandedCardNum === card.cardNum);
}

async function saveDetailCard() {
  if (expandedCardNum === null) return;
  const card = cards.get(expandedCardNum);
  if (!card || !card.cardId) {
    addLogEntry({ type: 'warning', message: `Card #${expandedCardNum} has no server ID yet` });
    return;
  }

  // Collect field values and map to server's snake_case field names
  const fieldToServer = {
    player: 'player',
    year: 'year',
    cardNumber: 'card_number',
    set: 'set_name',
    parallel: 'parallel',
    serialNumber: 'serial_number',
    sport: 'sport',
    price: 'price',
    gradingCompany: 'grading_company',
    grade: 'grade'
  };
  const updates = {};
  elements.detailPanel.querySelectorAll('.detail-input').forEach(input => {
    const serverField = fieldToServer[input.dataset.field] || input.dataset.field;
    updates[serverField] = input.value;
  });

  const saveBtn = elements.detailSave;
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving...';

  try {
    const result = await window.api.updateCard(card.cardId, updates);
    if (result.success) {
      Object.assign(card, updates);
      card.name = updates.player;

      // Clear dirty state
      dirtyCards.delete(expandedCardNum);
      elements.detailPanel.querySelectorAll('.detail-input.dirty').forEach(input => {
        input.classList.remove('dirty');
      });

      // Update the grid card tile
      const el = document.getElementById(`grid-${expandedCardNum}`);
      if (el) updateGridCardDOM(el, card);

      saveBtn.textContent = 'Saved!';
      setTimeout(() => { saveBtn.textContent = 'Save'; }, 1500);
      addLogEntry({ type: 'success', message: `Card #${expandedCardNum} updated` });
    } else {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save';
      addLogEntry({ type: 'error', message: `Update failed: ${result.error}` });
    }
  } catch (error) {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
    addLogEntry({ type: 'error', message: `Save error: ${error.message}` });
  }
}

async function handleDetailApprove() {
  if (expandedCardNum === null) return;
  const card = cards.get(expandedCardNum);
  if (!card || !card.cardId) return;

  const result = await window.api.approveCard(card.cardId);
  if (result.success) {
    card.status = 'approved';
    const el = document.getElementById(`grid-${expandedCardNum}`);
    if (el) updateGridCardDOM(el, card);
    addLogEntry({ type: 'success', message: `Card #${expandedCardNum} approved` });
  }
}

async function handleDetailDelete() {
  if (expandedCardNum === null) return;
  const cardNum = expandedCardNum;
  const card = cards.get(cardNum);
  if (!card || !card.cardId) return;

  if (!confirm(`Delete card #${cardNum}? This cannot be undone.`)) return;

  const result = await window.api.deleteCard(card.cardId);
  if (result.success) {
    cards.delete(cardNum);
    dirtyCards.delete(cardNum);
    selectedCards.delete(cardNum);
    const el = document.getElementById(`grid-${cardNum}`);
    if (el) el.remove();
    closeDetailPanel();
    updateFeedCount();
    addLogEntry({ type: 'info', message: `Card #${cardNum} deleted` });
  }
}

// =====================================================
// Card Detail Panel (click-to-expand)
// =====================================================

function expandCard(cardNum) {
  const card = cards.get(cardNum);
  if (!card) return;

  // Deselect previous card
  if (expandedCardNum !== null) {
    const prevEl = document.getElementById(`grid-${expandedCardNum}`);
    if (prevEl) prevEl.classList.remove('selected');
  }

  // If clicking the same card, toggle closed
  if (expandedCardNum === cardNum) {
    closeDetailPanel();
    return;
  }

  expandedCardNum = cardNum;

  // Highlight the selected grid card
  const el = document.getElementById(`grid-${cardNum}`);
  if (el) el.classList.add('selected');

  // Populate and show detail panel
  populateDetailPanel(card);
  elements.detailPanel.classList.remove('hidden');
}

function populateDetailPanel(card) {
  elements.detailPanelTitle.textContent = `Card #${card.cardNum} — ${getStatusText(card)}`;

  // Images
  const frontSrc = card.thumbnail || filePathToUrl(card.frontPath) || '';
  const backSrc = card.back || filePathToUrl(card.backPath) || '';
  elements.detailFront.src = frontSrc;
  elements.detailBack.src = backSrc;

  // Fields — only update if not dirty
  const dirtyFields = dirtyCards.get(card.cardNum) || new Set();
  const fieldMap = {
    player: card.player || card.name || '',
    year: card.year || '',
    cardNumber: card.cardNumber || '',
    set: card.set || '',
    parallel: card.parallel || '',
    serialNumber: card.serialNumber || '',
    sport: card.sport || '',
    price: card.price || '',
    gradingCompany: card.gradingCompany || '',
    grade: card.grade || ''
  };

  elements.detailPanel.querySelectorAll('.detail-input').forEach(input => {
    const field = input.dataset.field;
    if (dirtyFields.has(field) || document.activeElement === input) return;
    input.value = fieldMap[field] || '';
    input.classList.toggle('dirty', dirtyFields.has(field));
  });

  // Confidence badge
  const confEl = document.getElementById('detail-confidence');
  if (confEl && card.confidence) {
    const confClass = card.confidence === 'high' ? 'conf-high' : card.confidence === 'medium' ? 'conf-medium' : 'conf-low';
    confEl.innerHTML = `<span class="confidence-badge ${confClass}">${card.confidence} confidence</span>`;
    if (card.isAutograph) confEl.innerHTML += ' <span class="tag-badge">Autograph</span>';
    if (card.isGraded) confEl.innerHTML += ` <span class="tag-badge">Graded</span>`;
  } else if (confEl) {
    confEl.innerHTML = '';
  }

  // Enable/disable save button
  elements.detailSave.disabled = !dirtyCards.has(card.cardNum);
}

function closeDetailPanel() {
  if (expandedCardNum !== null) {
    const prevEl = document.getElementById(`grid-${expandedCardNum}`);
    if (prevEl) prevEl.classList.remove('selected');
  }
  expandedCardNum = null;
  elements.detailPanel.classList.add('hidden');
}

function wireDetailPanelEvents() {
  // Close button
  elements.detailClose.addEventListener('click', closeDetailPanel);

  // Save button
  elements.detailSave.addEventListener('click', saveDetailCard);

  // Approve button
  elements.detailApprove.addEventListener('click', handleDetailApprove);

  // Delete button
  elements.detailDelete.addEventListener('click', handleDetailDelete);

  // Input change listeners — mark dirty
  elements.detailPanel.querySelectorAll('.detail-input').forEach(input => {
    input.addEventListener('input', () => {
      if (expandedCardNum === null) return;
      const field = input.dataset.field;
      if (!dirtyCards.has(expandedCardNum)) {
        dirtyCards.set(expandedCardNum, new Set());
      }
      dirtyCards.get(expandedCardNum).add(field);
      input.classList.add('dirty');
      elements.detailSave.disabled = false;
    });
  });
}

// =====================================================
// Status & Helpers
// =====================================================

function getStatusText(card) {
  switch (card.status) {
    case 'queued': return 'Queued';
    case 'uploading': return 'Uploading...';
    case 'identifying': return 'Identifying...';
    case 'identified': return 'Identified';
    case 'approved': return 'Approved';
    case 'error': return card.error || 'Error';
    default: return card.status;
  }
}

function clearCards() {
  cards.clear();
  dirtyCards.clear();
  selectedCards.clear();
  scanningCardNum = null;
  closeDetailPanel();
  // Remove all grid cards
  elements.cardGrid.querySelectorAll('.grid-card').forEach(el => el.remove());
  showEmptyState();
  updateFeedCount();
  updateBulkToolbar();
}

function updateFeedCount() {
  const count = cards.size;
  elements.feedCount.textContent = `${count} card${count !== 1 ? 's' : ''}`;
}

function showEmptyState() {
  elements.emptyState.classList.remove('hidden');
}

function hideEmptyState() {
  elements.emptyState.classList.add('hidden');
}

function refreshCurrentView() {
  // Re-render all grid cards
  for (const [cardNum] of cards) {
    renderGridCard(cardNum);
  }
}

// =====================================================
// Filtering
// =====================================================

function cardMatchesFilter(card) {
  if (filterStatus !== 'all' && card.status !== filterStatus) return false;
  if (filterSearch) {
    const searchable = [card.player, card.name, card.year, card.set, card.cardNumber, card.parallel]
      .filter(Boolean).join(' ').toLowerCase();
    if (!searchable.includes(filterSearch)) return false;
  }
  return true;
}

function applyFilters() {
  for (const [cardNum, card] of cards) {
    const el = document.getElementById(`grid-${cardNum}`);
    if (el) {
      el.style.display = cardMatchesFilter(card) ? '' : 'none';
    }
  }
}

// =====================================================
// Bulk Toolbar
// =====================================================

function updateBulkToolbar() {
  const count = selectedCards.size;
  if (count > 0) {
    elements.bulkToolbar.classList.remove('hidden');
    elements.bulkCount.textContent = `${count} selected`;
  } else {
    elements.bulkToolbar.classList.add('hidden');
  }
}

function getSelectedCardIds() {
  const ids = [];
  selectedCards.forEach(cardNum => {
    const card = cards.get(cardNum);
    if (card && card.cardId) ids.push(card.cardId);
  });
  return ids;
}

async function handleBulkApprove() {
  const cardIds = getSelectedCardIds();
  if (cardIds.length === 0) {
    addLogEntry({ type: 'warning', message: 'No cards with IDs selected' });
    return;
  }

  if (!confirm(`Approve ${cardIds.length} card(s)?`)) return;

  addLogEntry({ type: 'info', message: `Approving ${cardIds.length} cards...` });
  const result = await window.api.bulkApprove(cardIds);

  if (result.success) {
    // Update local state
    selectedCards.forEach(cardNum => {
      const card = cards.get(cardNum);
      if (card && card.cardId) {
        card.status = 'approved';
        const el = document.getElementById(`grid-${cardNum}`);
        if (el) updateGridCardDOM(el, card);
      }
    });
    selectedCards.clear();
    updateBulkToolbar();
    // Uncheck all checkboxes
    elements.cardGrid.querySelectorAll('.grid-checkbox:checked').forEach(cb => { cb.checked = false; });
    addLogEntry({ type: 'success', message: `Approved ${result.success} cards (${result.failed} failed)` });
  }
}

async function handleBulkDelete() {
  const cardIds = getSelectedCardIds();
  if (cardIds.length === 0) return;

  if (!confirm(`Delete ${cardIds.length} card(s)? This cannot be undone.`)) return;

  addLogEntry({ type: 'info', message: `Deleting ${cardIds.length} cards...` });
  const result = await window.api.bulkDelete(cardIds);

  if (result.success) {
    selectedCards.forEach(cardNum => {
      cards.delete(cardNum);
      dirtyCards.delete(cardNum);
      const el = document.getElementById(`grid-${cardNum}`);
      if (el) el.remove();
    });
    selectedCards.clear();
    updateFeedCount();
    updateBulkToolbar();
    addLogEntry({ type: 'success', message: `Deleted ${result.success} cards` });
  }
}

async function handleBulkExport() {
  const cardIds = getSelectedCardIds();
  if (cardIds.length === 0) return;

  addLogEntry({ type: 'info', message: `Exporting ${cardIds.length} cards...` });
  const result = await window.api.exportCards(cardIds);

  if (result.success) {
    addLogEntry({ type: 'success', message: `Exported ${result.count} cards to ${result.path}` });
  } else if (!result.canceled) {
    addLogEntry({ type: 'error', message: `Export failed: ${result.error}` });
  }
}

async function handleBulkSendToSlabTrack() {
  const cardIds = getSelectedCardIds();
  if (cardIds.length === 0) return;

  if (!confirm(`Send ${cardIds.length} card(s) to SlabTrack?`)) return;

  addLogEntry({ type: 'info', message: `Sending ${cardIds.length} cards to SlabTrack...` });
  const result = await window.api.sendToSlabTrack(cardIds);

  if (result.success) {
    addLogEntry({ type: 'success', message: `Sent ${cardIds.length} cards to SlabTrack` });
  } else {
    addLogEntry({ type: 'error', message: `Send failed: ${result.error}` });
  }
}

// =====================================================
// Batch Summary
// =====================================================

function showBatchSummary() {
  const total = cards.size;
  let identified = 0;
  let errors = 0;

  cards.forEach(card => {
    if (card.status === 'identified' || card.status === 'approved') identified++;
    if (card.status === 'error') errors++;
  });

  elements.batchTotal.textContent = total;
  elements.batchIdentified.textContent = identified;
  elements.batchErrors.textContent = errors;
  elements.batchSummary.classList.remove('hidden');
}

async function handleBatchApproveAll() {
  const cardIds = [];
  cards.forEach(card => {
    if (card.status === 'identified' && card.cardId) {
      cardIds.push(card.cardId);
    }
  });

  if (cardIds.length === 0) {
    addLogEntry({ type: 'warning', message: 'No identified cards to approve' });
    return;
  }

  if (!confirm(`Approve all ${cardIds.length} identified cards?`)) return;

  addLogEntry({ type: 'info', message: `Approving ${cardIds.length} cards...` });
  const result = await window.api.bulkApprove(cardIds);

  if (result.success) {
    cards.forEach(card => {
      if (card.status === 'identified') {
        card.status = 'approved';
        const el = document.getElementById(`grid-${card.cardNum}`);
        if (el) updateGridCardDOM(el, card);
      }
    });
    showBatchSummary(); // Refresh counts
    addLogEntry({ type: 'success', message: `Approved ${result.success} cards` });
  }
}

async function handleBatchExportAll() {
  const cardIds = [];
  cards.forEach(card => {
    if (card.cardId) cardIds.push(card.cardId);
  });

  if (cardIds.length === 0) return;

  const result = await window.api.exportCards(cardIds);
  if (result.success) {
    addLogEntry({ type: 'success', message: `Exported ${result.count} cards to ${result.path}` });
  } else if (!result.canceled) {
    addLogEntry({ type: 'error', message: `Export failed: ${result.error}` });
  }
}

// =====================================================
// Keyboard Shortcuts
// =====================================================

function handleKeyboardShortcuts(e) {
  // Don't trigger while typing in inputs
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

  // Ctrl+A: Select all
  if (e.ctrlKey && e.key === 'a') {
    e.preventDefault();
    cards.forEach((card, key) => selectedCards.add(key));
    // Check all checkboxes
    elements.cardGrid.querySelectorAll('.grid-checkbox').forEach(cb => { cb.checked = true; });
    updateBulkToolbar();
  }

  // Delete: Delete selected
  if (e.key === 'Delete' && selectedCards.size > 0) {
    e.preventDefault();
    handleBulkDelete();
  }

  // Ctrl+Enter: Approve selected
  if (e.ctrlKey && e.key === 'Enter' && selectedCards.size > 0) {
    e.preventDefault();
    handleBulkApprove();
  }

  // Escape: Close detail panel or clear selection
  if (e.key === 'Escape') {
    if (expandedCardNum !== null) {
      closeDetailPanel();
    } else {
      selectedCards.clear();
      elements.cardGrid.querySelectorAll('.grid-checkbox:checked').forEach(cb => { cb.checked = false; });
      updateBulkToolbar();
    }
  }
}

// =====================================================
// Activity Log
// =====================================================

function addLogEntry(data) {
  const entry = document.createElement('div');
  entry.className = `log-entry ${data.type}`;

  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<span class="log-time">[${time}]</span>${escapeHtml(data.message)}`;

  elements.logContent.appendChild(entry);
  elements.logContent.scrollTop = elements.logContent.scrollHeight;

  // Keep only last 100 entries
  while (elements.logContent.children.length > 100) {
    elements.logContent.removeChild(elements.logContent.firstChild);
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function escapeAttr(text) {
  if (!text) return '';
  return String(text).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// =====================================================
// Preset handling
// =====================================================

function handlePresetChange() {
  const presetName = elements.scanPreset.value;
  if (presetName === 'custom') return; // Don't change anything
  applyPreset(presetName);
}

function applyPreset(presetName) {
  const preset = SCAN_PRESETS[presetName];
  if (!preset) return;

  // Apply DPI to sidebar dropdown
  elements.scanDpi.value = preset.scanDpi;
  window.api.saveSettings({ scanDpi: preset.scanDpi });

  // Apply holo toggle
  elements.scanHoloMode.checked = preset.holoMode;

  // Save all preset values
  const presetSettings = {
    holoMode: preset.holoMode,
    autoCrop: preset.autoCrop,
    removeStreaks: preset.removeStreaks,
    cardWidth: preset.cardWidth,
    cardHeight: preset.cardHeight,
    scanDpi: preset.scanDpi
  };
  window.api.saveSettings(presetSettings);
  Object.assign(settings, presetSettings);

  addLogEntry({ type: 'info', message: `Preset applied: ${presetName}` });
}

// =====================================================
// Settings
// =====================================================

async function loadSettings() {
  settings = await window.api.getSettings();

  // Restore scan mode
  switchScanMode(settings.scanMode || 'direct');

  // Restore scanner settings
  elements.scanDpi.value = settings.scanDpi || 300;
  elements.scanDuplex.checked = settings.scanDuplex !== false;

  // Folder watch settings
  const folderPath = document.getElementById('folder-path');
  if (folderPath) folderPath.value = settings.scanFolder || '';
  const folderPathAlt = document.getElementById('folder-path-alt');
  if (folderPathAlt) folderPathAlt.value = settings.scanFolder || '';

  elements.settingPairingMode.value = settings.pairingMode || 'sequential';
  elements.settingHoloMode.checked = settings.holoMode || false;
  elements.settingBrightness.value = settings.brightnessBoost || 0;
  elements.brightnessValue.textContent = settings.brightnessBoost || 0;
  elements.settingAutoRotate.checked = settings.autoRotateBack !== false;
  elements.settingAutoCrop.checked = settings.autoCrop !== false;
  elements.settingRemoveStreaks.checked = settings.removeStreaks || false;

  // Card dimensions
  const w = settings.cardWidth || 2.5;
  const h = settings.cardHeight || 3.5;
  const sizeKey = `${w}x${h}`;
  const sizeOption = Array.from(elements.settingCardSize.options).find(o => o.value === sizeKey);
  if (sizeOption) {
    elements.settingCardSize.value = sizeKey;
    elements.customDimensions.classList.add('hidden');
  } else {
    elements.settingCardSize.value = 'custom';
    elements.customDimensions.classList.remove('hidden');
  }
  elements.settingCardWidth.value = w;
  elements.settingCardHeight.value = h;

  elements.settingStartMinimized.checked = settings.startMinimized || false;
  elements.settingStartWindows.checked = settings.startWithWindows || false;

  // Sidebar holo toggle
  elements.scanHoloMode.checked = settings.holoMode || false;

  // Auto-discover scanners
  discoverScanners();
}

function openSettings() {
  loadSettings();
  elements.settingsModal.classList.remove('hidden');
}

function closeSettings() {
  elements.settingsModal.classList.add('hidden');
}

async function saveSettings() {
  // Parse card dimensions from dropdown or custom inputs
  let cardWidth, cardHeight;
  if (elements.settingCardSize.value === 'custom') {
    cardWidth = parseFloat(elements.settingCardWidth.value) || 2.5;
    cardHeight = parseFloat(elements.settingCardHeight.value) || 3.5;
  } else {
    const [w, h] = elements.settingCardSize.value.split('x').map(Number);
    cardWidth = w;
    cardHeight = h;
  }

  const newSettings = {
    pairingMode: elements.settingPairingMode.value,
    holoMode: elements.settingHoloMode.checked,
    brightnessBoost: parseInt(elements.settingBrightness.value, 10),
    autoRotateBack: elements.settingAutoRotate.checked,
    autoCrop: elements.settingAutoCrop.checked,
    removeStreaks: elements.settingRemoveStreaks.checked,
    cardWidth,
    cardHeight,
    startMinimized: elements.settingStartMinimized.checked,
    startWithWindows: elements.settingStartWindows.checked
  };

  await window.api.saveSettings(newSettings);
  settings = { ...settings, ...newSettings };

  // Sync sidebar holo toggle
  elements.scanHoloMode.checked = newSettings.holoMode;

  closeSettings();
  addLogEntry({ type: 'success', message: 'Settings saved' });
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
