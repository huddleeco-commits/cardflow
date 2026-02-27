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
let currentView = 'grid'; // 'grid' or 'list'
let lastCardAddedTime = 0; // For staggered entrance animation
let cardStaggerIndex = 0; // Counter for stagger delay
let listDirtyCards = new Map(); // cardNum -> Set of dirty field names (list view)
let appMode = 'standalone'; // 'monitor' or 'standalone'
let collections = [];
let selectedCollectionId = null;

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

  // Card List View
  cardListContainer: document.getElementById('card-list-container'),
  cardList: document.getElementById('card-list'),

  // View Toggle
  viewGridBtn: document.getElementById('view-grid-btn'),
  viewListBtn: document.getElementById('view-list-btn'),

  // View Collection
  btnViewCollection: document.getElementById('btn-view-collection'),

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
  scanHoloMode: document.getElementById('scan-holo-mode'),

  // App Mode
  modeMonitorBtn: document.getElementById('mode-monitor'),
  modeStandaloneBtn: document.getElementById('mode-standalone'),

  // Collection
  collectionSelect: document.getElementById('collection-select'),
  collectionHint: document.getElementById('collection-hint'),
  collectionSection: document.getElementById('collection-section'),
  detailPushCollection: document.getElementById('detail-push-collection'),
  bulkPushCollection: document.getElementById('bulk-push-collection')
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

  // App mode toggle
  elements.modeMonitorBtn.addEventListener('click', () => switchAppMode('monitor'));
  elements.modeStandaloneBtn.addEventListener('click', () => switchAppMode('standalone'));

  // Collection select
  elements.collectionSelect.addEventListener('change', () => {
    selectedCollectionId = elements.collectionSelect.value || null;
    window.api.saveSelectedCollection(selectedCollectionId);
  });

  // Push to Collection buttons
  if (elements.detailPushCollection) {
    elements.detailPushCollection.addEventListener('click', handleDetailPushToCollection);
  }
  if (elements.bulkPushCollection) {
    elements.bulkPushCollection.addEventListener('click', handleBulkPushToCollection);
  }

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

  // View toggle
  elements.viewGridBtn.addEventListener('click', () => switchView('grid'));
  elements.viewListBtn.addEventListener('click', () => switchView('list'));

  // View Collection
  if (elements.btnViewCollection) {
    elements.btnViewCollection.addEventListener('click', () => {
      window.api.openExternal('https://slabtrack.io/collection');
    });
  }

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

  // Desktop scan credits
  window.api.onCreditsUpdate((data) => {
    updateCreditsDisplay(data.remaining);
  });

  window.api.onUpgradeRequired((data) => {
    const scanBtn = document.getElementById('btn-scan');
    if (scanBtn) scanBtn.disabled = true;
    addLogEntry({ type: 'error', message: data.message || 'Upgrade required for desktop scanning' });
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
  // Fetch scan credits on login
  fetchScanCredits();
  // Load collections and restore app mode
  loadCollections();
  restoreAppMode();
}

async function restoreAppMode() {
  try {
    const savedMode = await window.api.getAppMode();
    const savedCollection = await window.api.getSelectedCollection();
    if (savedMode) switchAppMode(savedMode);
    if (savedCollection) {
      selectedCollectionId = savedCollection;
      // Dropdown will be populated after loadCollections resolves
      setTimeout(() => {
        if (elements.collectionSelect) {
          elements.collectionSelect.value = savedCollection;
        }
      }, 500);
    }
  } catch (err) {
    console.error('Failed to restore app mode:', err);
  }
}

// Desktop scan credits display
async function fetchScanCredits() {
  try {
    const result = await window.api.desktopScanPreflight();
    if (result.success) {
      updateCreditsDisplay(result.scansRemaining, result.monthlyLimit, result.tier);
    } else if (result.upgradeRequired) {
      updateCreditsDisplay(0, 0, 'free');
      addLogEntry({ type: 'warning', message: result.error });
    }
  } catch (err) {
    console.error('Preflight error:', err);
  }
}

function updateCreditsDisplay(remaining, limit, tier) {
  // Update or create credits element in the sidebar stats area
  let creditsEl = document.getElementById('scan-credits-display');
  if (!creditsEl) {
    creditsEl = document.createElement('div');
    creditsEl.id = 'scan-credits-display';
    creditsEl.className = 'scan-credits';
    // Insert after tier badge
    const tierContainer = elements.tierBadgeContainer;
    if (tierContainer && tierContainer.parentNode) {
      tierContainer.parentNode.insertBefore(creditsEl, tierContainer.nextSibling);
    }
  }
  const limitText = limit === 'unlimited' ? 'Unlimited' : (limit || '?');
  creditsEl.innerHTML = `<span class="credits-label">Scans:</span> <span class="credits-value">${remaining ?? '?'}</span>${limit ? ` / ${limitText}` : ''}`;
  creditsEl.style.cssText = 'padding: 4px 12px; font-size: 11px; color: #94a3b8; text-align: center;';
  if (remaining !== undefined && remaining <= 5) {
    creditsEl.querySelector('.credits-value').style.color = '#f87171';
  }
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

// App Mode (Monitor vs Standalone)
function switchAppMode(mode) {
  appMode = mode;
  elements.modeMonitorBtn.classList.toggle('active', mode === 'monitor');
  elements.modeStandaloneBtn.classList.toggle('active', mode === 'standalone');
  window.api.saveAppMode(mode);

  if (mode === 'monitor') {
    document.body.classList.add('monitor-mode');
    // Hide detail panel, force grid view
    if (elements.detailPanel) elements.detailPanel.classList.add('hidden');
    expandedCardNum = null;
    switchView('grid');
    // Update hint
    if (elements.collectionHint) {
      elements.collectionHint.textContent = 'Scanned cards auto-assign to this collection';
    }
  } else {
    document.body.classList.remove('monitor-mode');
    // Restore hint
    if (elements.collectionHint) {
      elements.collectionHint.textContent = 'Review cards first, then push to collection';
    }
  }
}

// Collections
async function loadCollections() {
  try {
    const result = await window.api.fetchCollections();
    if (result.success && result.collections) {
      collections = result.collections;
      populateCollectionDropdown();
    }
  } catch (err) {
    console.error('Failed to load collections:', err);
  }
}

function populateCollectionDropdown() {
  const select = elements.collectionSelect;
  if (!select) return;

  // Preserve current value
  const currentVal = selectedCollectionId || '';
  select.innerHTML = '<option value="">No collection (cards only)</option>';

  collections.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.id;
    opt.textContent = c.name || `Collection #${c.id}`;
    select.appendChild(opt);
  });

  // Restore selection
  if (currentVal) {
    select.value = currentVal;
  }
}

async function handleDetailPushToCollection() {
  if (expandedCardNum === null) return;
  const card = cards.get(expandedCardNum);
  if (!card || !card.cardId) {
    addLogEntry({ type: 'warning', message: 'Card has no server ID yet' });
    return;
  }
  if (!selectedCollectionId) {
    addLogEntry({ type: 'warning', message: 'Select a collection first' });
    return;
  }

  try {
    const result = await window.api.pushToCollection(selectedCollectionId, [card.cardId]);
    if (result.success) {
      card.collectionAssigned = true;
      if (card.status === 'review') card.status = 'identified';
      renderGridCard(card.cardNum);
      // Refresh detail panel to reflect new status
      if (expandedCardNum === card.cardNum) populateDetailPanel(card);
      addLogEntry({ type: 'success', message: `Card #${card.cardNum} added to collection` });
    } else {
      addLogEntry({ type: 'error', message: `Failed: ${result.error}` });
    }
  } catch (err) {
    addLogEntry({ type: 'error', message: `Push failed: ${err.message}` });
  }
}

async function handleBulkPushToCollection() {
  if (selectedCards.size === 0) return;
  if (!selectedCollectionId) {
    addLogEntry({ type: 'warning', message: 'Select a collection first' });
    return;
  }

  const cardIds = [];
  for (const cardNum of selectedCards) {
    const card = cards.get(cardNum);
    if (card && card.cardId) cardIds.push(card.cardId);
  }

  if (cardIds.length === 0) {
    addLogEntry({ type: 'warning', message: 'No cards with server IDs to push' });
    return;
  }

  try {
    const result = await window.api.pushToCollection(selectedCollectionId, cardIds);
    if (result.success) {
      for (const cardNum of selectedCards) {
        const card = cards.get(cardNum);
        if (card) {
          card.collectionAssigned = true;
          if (card.status === 'review') card.status = 'identified';
          renderGridCard(cardNum);
        }
      }
      addLogEntry({ type: 'success', message: `${cardIds.length} card(s) added to collection` });
    } else {
      addLogEntry({ type: 'error', message: `Failed: ${result.error}` });
    }
  } catch (err) {
    addLogEntry({ type: 'error', message: `Bulk push failed: ${err.message}` });
  }
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

  // Stagger entrance animation — reset counter if >5s gap
  const now = Date.now();
  if (now - lastCardAddedTime > 5000) cardStaggerIndex = 0;
  lastCardAddedTime = now;
  const staggerDelay = cardStaggerIndex * 150;
  cardStaggerIndex++;

  // New card goes directly into the grid with scanning state
  scanningCardNum = data.cardNum;
  renderGridCard(data.cardNum, true, staggerDelay);
  if (currentView === 'list') renderListCard(data.cardNum, staggerDelay);
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

  // Update list row if list view exists
  updateListRow(card.cardNum);

  // Update detail panel if this card is expanded
  if (expandedCardNum === card.cardNum) {
    populateDetailPanel(card);
  }
}

function updateCardIdentified(data) {
  const card = cards.get(data.cardNum) || findCardByCardId(data.cardId);
  if (!card) return;

  card.status = (data.appMode === 'monitor') ? 'identified' : 'review';
  card.name = data.name;
  card.player = data.player;
  card.year = data.year;
  card.set = data.set;
  card.cardNumber = data.cardNumber || '';
  card.parallel = data.parallel || '';
  card.serialNumber = data.serialNumber || '';
  card.numbered = data.numbered || false;
  card.numberedTo = data.numbered_to || data.numberedTo || '';
  card.sport = data.sport || '';
  card.confidence = data.confidence || '';
  card.isGraded = data.isGraded || false;
  card.gradingCompany = data.gradingCompany || '';
  card.grade = data.grade || '';
  card.certNumber = data.certNumber || '';
  card.isAutograph = data.isAutograph || false;
  card.price = data.price || '';
  card.pricing = data.pricing || null;
  card.team = data.team || '';
  card.condition = data.condition || '';
  card.subsetName = data.subset_name || data.subsetName || '';
  card.ebaySearchString = data.ebay_search_string || data.ebaySearchString || '';
  card.syncedToSlabTrack = true; // Cards are auto-saved via API with entry_method='desktop_scan'
  card.collectionAssigned = data.collectionAssigned || false;
  if (data.cardId) card.cardId = data.cardId;
  if (data.thumbnail) card.thumbnail = data.thumbnail;
  if (data.back) card.back = data.back;

  // Remove scanning state when identified
  if (scanningCardNum === card.cardNum) {
    scanningCardNum = null;
  }

  // Render/update grid card
  renderGridCard(card.cardNum);

  // Update list view
  renderListCard(card.cardNum);

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

function renderGridCard(cardNum, isScanning = false, staggerDelay = 0) {
  const card = cards.get(cardNum);
  if (!card) return;

  let el = document.getElementById(`grid-${cardNum}`);
  if (!el) {
    el = buildGridCardElement(card, isScanning);
    wireGridCardEvents(el, cardNum);

    // Add entrance animation with stagger
    if (staggerDelay > 0) {
      el.style.animationDelay = `${staggerDelay}ms`;
    }
    el.classList.add('card-entrance');

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
  const serialBadge = card.numbered && card.serialNumber ? `<span class="grid-card-serial">${escapeHtml(formatSerialNumber(card))}</span>` : '';
  const syncedIcon = card.syncedToSlabTrack ? '<span class="grid-card-synced" title="Synced to SlabTrack">&#9729;</span>' : '';
  const collectionBadge = card.collectionAssigned ? '<span class="grid-card-collection-badge" title="In collection">&#128194;</span>' : '';
  const reviewBadge = card.status === 'review' ? '<span class="grid-card-review-badge">Review</span>' : '';
  const overlayHtml = getStatusOverlay(card.status);

  el.innerHTML = `
    <div class="grid-card-select">
      <input type="checkbox" class="grid-checkbox" data-card="${card.cardNum}">
    </div>
    <div class="grid-card-image">
      <img src="${frontSrc}" alt="" loading="lazy">
      ${serialBadge}
      ${syncedIcon}
      ${collectionBadge}
      ${reviewBadge}
      <span class="grid-card-num-badge">#${card.cardNum}</span>
      <div class="grid-card-scanning-badge ${isScanning ? '' : 'hidden'}">SCANNING</div>
      ${overlayHtml}
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
    case 'review': return '\uD83D\uDD0E'; // magnifying glass tilted right (🔎) — needs review
    case 'approved': return '\u2714'; // check mark
    case 'error': return '\u26A0'; // warning
    default: return '\u23F3';
  }
}

function wireGridCardEvents(el, cardNum) {
  // Click on card tile → expand detail panel (but not on checkbox)
  el.addEventListener('click', (e) => {
    if (e.target.classList.contains('grid-checkbox')) return;
    // Monitor mode: open card on SlabTrack in browser instead of detail panel
    if (appMode === 'monitor') {
      const card = cards.get(cardNum);
      if (card && card.cardId && !String(card.cardId).startsWith('desktop_')) {
        window.api.openExternal(`https://slabtrack.io/cards/${card.cardId}`);
      }
      return;
    }
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
  const isCardScanning = scanningCardNum === card.cardNum;
  el.classList.toggle('scanning', isCardScanning);
  const badge = el.querySelector('.grid-card-scanning-badge');
  if (badge) badge.classList.toggle('hidden', !isCardScanning);

  // Update selected state
  el.classList.toggle('selected', expandedCardNum === card.cardNum);

  // Update status overlay
  const imageDiv = el.querySelector('.grid-card-image');
  let overlay = el.querySelector('.grid-card-overlay');
  const overlayHtml = getStatusOverlay(card.status);
  if (overlayHtml) {
    if (!overlay) {
      imageDiv.insertAdjacentHTML('beforeend', overlayHtml);
    } else {
      overlay.outerHTML = overlayHtml;
    }
  } else if (overlay) {
    overlay.remove();
  }

  // Update serial badge
  let serialEl = el.querySelector('.grid-card-serial');
  if (card.numbered && card.serialNumber) {
    if (!serialEl) {
      imageDiv.insertAdjacentHTML('afterbegin', `<span class="grid-card-serial">${escapeHtml(formatSerialNumber(card))}</span>`);
    } else {
      serialEl.textContent = formatSerialNumber(card);
    }
  } else if (serialEl) {
    serialEl.remove();
  }

  // Update synced icon
  let syncedEl = el.querySelector('.grid-card-synced');
  if (card.syncedToSlabTrack) {
    if (!syncedEl) {
      imageDiv.insertAdjacentHTML('beforeend', '<span class="grid-card-synced" title="Synced to SlabTrack">&#9729;</span>');
    }
  } else if (syncedEl) {
    syncedEl.remove();
  }

  // Update collection badge
  let collBadge = el.querySelector('.grid-card-collection-badge');
  if (card.collectionAssigned) {
    if (!collBadge) {
      imageDiv.insertAdjacentHTML('beforeend', '<span class="grid-card-collection-badge" title="In collection">&#128194;</span>');
    }
  } else if (collBadge) {
    collBadge.remove();
  }

  // Update review badge
  let reviewBadge = el.querySelector('.grid-card-review-badge');
  if (card.status === 'review') {
    if (!reviewBadge) {
      imageDiv.insertAdjacentHTML('beforeend', '<span class="grid-card-review-badge">Review</span>');
    }
  } else if (reviewBadge) {
    reviewBadge.remove();
  }
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
    grade: 'grade',
    team: 'team',
    condition: 'condition',
    subsetName: 'subset_name',
    numberedTo: 'numbered_to',
    ebaySearchString: 'ebay_search_string'
  };
  const updates = {};
  elements.detailPanel.querySelectorAll('.detail-input').forEach(input => {
    const field = input.dataset.field;
    const serverField = fieldToServer[field] || field;

    // Parse combined serial "24/49" back to separate fields
    if (field === 'serialNumber') {
      const val = input.value.trim();
      if (val.includes('/')) {
        const [serial, numTo] = val.split('/');
        updates['serial_number'] = serial.trim();
        updates['numbered_to'] = numTo.trim();
        updates['numbered'] = true;
      } else {
        updates['serial_number'] = val;
      }
    } else {
      updates[serverField] = input.value;
    }
  });

  const saveBtn = elements.detailSave;
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving...';

  try {
    const result = await window.api.updateCard(card.cardId, updates);
    if (result.success) {
      Object.assign(card, updates);
      if (updates.player) card.name = updates.player;
      // Sync snake_case server fields back to camelCase card state
      if (updates.serial_number) card.serialNumber = updates.serial_number;
      if (updates.numbered_to) card.numberedTo = updates.numbered_to;
      if (updates.set_name) card.set = updates.set_name;
      if (updates.card_number) card.cardNumber = updates.card_number;
      if (updates.grading_company) card.gradingCompany = updates.grading_company;
      if (updates.subset_name) card.subsetName = updates.subset_name;
      if (updates.ebay_search_string) card.ebaySearchString = updates.ebay_search_string;

      // Clear dirty state
      dirtyCards.delete(expandedCardNum);
      elements.detailPanel.querySelectorAll('.detail-input.dirty').forEach(input => {
        input.classList.remove('dirty');
      });

      // Update the grid card tile
      const el = document.getElementById(`grid-${expandedCardNum}`);
      if (el) updateGridCardDOM(el, card);

      // Update the list row
      updateListRow(expandedCardNum);

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
    serialNumber: formatSerialNumber(card),
    sport: card.sport || '',
    price: card.price || '',
    gradingCompany: card.gradingCompany || '',
    grade: card.grade || '',
    team: card.team || '',
    condition: card.condition || '',
    subsetName: card.subsetName || '',
    numberedTo: card.numberedTo || '',
    ebaySearchString: card.ebaySearchString || ''
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
  listDirtyCards.clear();
  selectedCards.clear();
  scanningCardNum = null;
  closeDetailPanel();
  // Remove all grid cards
  elements.cardGrid.querySelectorAll('.grid-card').forEach(el => el.remove());
  // Remove all list rows
  if (elements.cardList) elements.cardList.innerHTML = '';
  showEmptyState();
  updateFeedCount();
  updateBulkToolbar();
}

function updateFeedCount() {
  const count = cards.size;
  let syncedCount = 0;
  cards.forEach(c => { if (c.syncedToSlabTrack) syncedCount++; });

  let html = `${count} card${count !== 1 ? 's' : ''}`;
  if (syncedCount > 0) {
    html += ` <span class="feed-synced"><span class="synced-dot"></span>${syncedCount} synced</span>`;
  }
  elements.feedCount.innerHTML = html;
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
  // Also rebuild list view if active
  if (currentView === 'list') {
    rebuildListView();
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
    const matches = cardMatchesFilter(card);
    // Grid view
    const gridEl = document.getElementById(`grid-${cardNum}`);
    if (gridEl) gridEl.style.display = matches ? '' : 'none';
    // List view
    const listEl = document.getElementById(`list-${cardNum}`);
    if (listEl) listEl.style.display = matches ? '' : 'none';
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

  // Restore view preference
  if (settings.viewPreference && settings.viewPreference !== currentView) {
    switchView(settings.viewPreference);
  }

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

// =====================================================
// Serial Number Helper
// =====================================================

function formatSerialNumber(card) {
  if (!card) return '';
  const serial = card.serialNumber || '';
  const numTo = card.numberedTo || '';
  if (serial && numTo) return `${serial}/${numTo}`;
  return serial;
}

// =====================================================
// Status Overlay Helper (streaming feel)
// =====================================================

function getStatusOverlay(status) {
  if (status === 'queued') {
    return `<div class="grid-card-overlay"><div class="overlay-spinner"></div><span class="overlay-text">Queued</span></div>`;
  }
  if (status === 'uploading') {
    return `<div class="grid-card-overlay"><div class="overlay-spinner uploading"></div><span class="overlay-text uploading">Uploading</span></div>`;
  }
  if (status === 'identifying') {
    return `<div class="grid-card-overlay"><div class="overlay-spinner"></div><span class="overlay-text">Identifying</span></div>`;
  }
  return ''; // No overlay for identified/approved/error
}

// =====================================================
// View Toggle (Grid vs List)
// =====================================================

function switchView(view) {
  currentView = view;
  elements.viewGridBtn.classList.toggle('active', view === 'grid');
  elements.viewListBtn.classList.toggle('active', view === 'list');
  elements.cardGridContainer.classList.toggle('hidden', view !== 'grid');
  elements.cardListContainer.classList.toggle('hidden', view !== 'list');

  if (view === 'list') {
    rebuildListView();
  }

  // Persist preference
  window.api.saveSettings({ viewPreference: view });
}

// =====================================================
// List View
// =====================================================

function rebuildListView() {
  if (!elements.cardList) return;
  elements.cardList.innerHTML = '';

  // Sort cards descending by cardNum
  const sorted = [...cards.entries()].sort((a, b) => b[0] - a[0]);
  for (const [cardNum, card] of sorted) {
    if (!cardMatchesFilter(card)) continue;
    const row = buildListRow(card);
    elements.cardList.appendChild(row);
  }
}

function buildListRow(card) {
  const row = document.createElement('div');
  row.id = `list-${card.cardNum}`;
  row.className = 'list-row';
  if (card.status === 'identified' || card.status === 'approved') {
    row.classList.add('list-row-ready');
  }

  const frontSrc = card.thumbnail || filePathToUrl(card.frontPath) || '';
  const overlayHtml = getStatusOverlay(card.status);
  const statusClass = card.status || 'queued';
  const serialVal = formatSerialNumber(card);
  const syncedBadge = card.syncedToSlabTrack ? '<span class="list-synced-badge">Synced</span>' : '';

  row.innerHTML = `
    <div class="list-row-thumb">
      <img src="${frontSrc}" alt="" loading="lazy">
      ${overlayHtml}
    </div>
    <div class="list-row-fields">
      <div class="list-fields-row">
        <div class="list-field">
          <label>Player</label>
          <input class="list-input" data-field="player" value="${escapeAttr(card.player || card.name || '')}">
        </div>
        <div class="list-field-sm">
          <label>Year</label>
          <input class="list-input" data-field="year" value="${escapeAttr(card.year || '')}">
        </div>
        <div class="list-field-sm">
          <label>Card #</label>
          <input class="list-input" data-field="cardNumber" value="${escapeAttr(card.cardNumber || '')}">
        </div>
      </div>
      <div class="list-fields-row">
        <div class="list-field">
          <label>Set</label>
          <input class="list-input" data-field="set" value="${escapeAttr(card.set || '')}">
        </div>
        <div class="list-field-sm">
          <label>Parallel</label>
          <input class="list-input" data-field="parallel" value="${escapeAttr(card.parallel || '')}">
        </div>
        <div class="list-field-sm">
          <label>Serial</label>
          <input class="list-input" data-field="serialNumber" value="${escapeAttr(serialVal)}">
        </div>
      </div>
      <div class="list-fields-row">
        <div class="list-field-sm">
          <label>Team</label>
          <input class="list-input" data-field="team" value="${escapeAttr(card.team || '')}">
        </div>
        <div class="list-field-sm">
          <label>Sport</label>
          <input class="list-input" data-field="sport" value="${escapeAttr(card.sport || '')}">
        </div>
        <div class="list-field-sm">
          <label>Subset</label>
          <input class="list-input" data-field="subsetName" value="${escapeAttr(card.subsetName || '')}">
        </div>
        <div class="list-field-sm">
          <label>Condition</label>
          <input class="list-input" data-field="condition" value="${escapeAttr(card.condition || '')}">
        </div>
      </div>
      <div class="list-fields-row">
        <div class="list-field-sm">
          <label>Grading</label>
          <input class="list-input" data-field="gradingCompany" value="${escapeAttr(card.gradingCompany || '')}">
        </div>
        <div class="list-field-sm">
          <label>Grade</label>
          <input class="list-input" data-field="grade" value="${escapeAttr(card.grade || '')}">
        </div>
        <div class="list-field-sm">
          <label>Price</label>
          <input class="list-input" data-field="price" value="${escapeAttr(card.price || '')}">
        </div>
      </div>
    </div>
    <div class="list-row-actions">
      <span class="list-card-num">#${card.cardNum}</span>
      <span class="status-pill status-${statusClass}">${getStatusText(card)}</span>
      ${syncedBadge}
      <div class="list-row-btns">
        <button class="btn btn-primary btn-small list-save-btn" disabled>Save</button>
        <button class="btn btn-secondary btn-small list-approve-btn" ${card.status !== 'identified' ? 'disabled' : ''}>OK</button>
      </div>
    </div>
  `;

  wireListRowEvents(row, card.cardNum);
  return row;
}

function wireListRowEvents(row, cardNum) {
  // Dirty tracking on inputs
  row.querySelectorAll('.list-input').forEach(input => {
    input.addEventListener('input', () => {
      if (!listDirtyCards.has(cardNum)) {
        listDirtyCards.set(cardNum, new Set());
      }
      listDirtyCards.get(cardNum).add(input.dataset.field);
      input.classList.add('dirty');
      const saveBtn = row.querySelector('.list-save-btn');
      if (saveBtn) saveBtn.disabled = false;
    });
  });

  // Save button
  const saveBtn = row.querySelector('.list-save-btn');
  if (saveBtn) {
    saveBtn.addEventListener('click', () => saveListRow(cardNum));
  }

  // Approve button
  const approveBtn = row.querySelector('.list-approve-btn');
  if (approveBtn) {
    approveBtn.addEventListener('click', () => approveListRow(cardNum));
  }

  // Click thumbnail to expand detail panel
  const thumb = row.querySelector('.list-row-thumb');
  if (thumb) {
    thumb.addEventListener('click', () => expandCard(cardNum));
    thumb.style.cursor = 'pointer';
  }
}

async function saveListRow(cardNum) {
  const card = cards.get(cardNum);
  if (!card || !card.cardId) {
    addLogEntry({ type: 'warning', message: `Card #${cardNum} has no server ID yet` });
    return;
  }

  const row = document.getElementById(`list-${cardNum}`);
  if (!row) return;

  const fieldToServer = {
    player: 'player', year: 'year', cardNumber: 'card_number',
    set: 'set_name', parallel: 'parallel', serialNumber: 'serial_number',
    sport: 'sport', price: 'price', gradingCompany: 'grading_company',
    grade: 'grade', team: 'team', condition: 'condition',
    subsetName: 'subset_name'
  };

  const updates = {};
  row.querySelectorAll('.list-input').forEach(input => {
    const field = input.dataset.field;
    const serverField = fieldToServer[field] || field;

    if (field === 'serialNumber') {
      const val = input.value.trim();
      if (val.includes('/')) {
        const [serial, numTo] = val.split('/');
        updates['serial_number'] = serial.trim();
        updates['numbered_to'] = numTo.trim();
        updates['numbered'] = true;
      } else {
        updates['serial_number'] = val;
      }
    } else {
      updates[serverField] = input.value;
    }
  });

  const saveBtn = row.querySelector('.list-save-btn');
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = '...';
  }

  try {
    const result = await window.api.updateCard(card.cardId, updates);
    if (result.success) {
      // Update local card state
      Object.assign(card, updates);
      card.name = updates.player || card.name;
      if (updates.serial_number) card.serialNumber = updates.serial_number;
      if (updates.numbered_to) card.numberedTo = updates.numbered_to;
      if (updates.set_name) card.set = updates.set_name;
      if (updates.card_number) card.cardNumber = updates.card_number;
      if (updates.grading_company) card.gradingCompany = updates.grading_company;
      if (updates.subset_name) card.subsetName = updates.subset_name;

      // Clear dirty
      listDirtyCards.delete(cardNum);
      row.querySelectorAll('.list-input.dirty').forEach(i => i.classList.remove('dirty'));

      // Update grid card too
      const gridEl = document.getElementById(`grid-${cardNum}`);
      if (gridEl) updateGridCardDOM(gridEl, card);

      if (saveBtn) {
        saveBtn.textContent = 'Done';
        setTimeout(() => { saveBtn.textContent = 'Save'; }, 1200);
      }
      addLogEntry({ type: 'success', message: `Card #${cardNum} updated` });
    } else {
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save'; }
      addLogEntry({ type: 'error', message: `Update failed: ${result.error}` });
    }
  } catch (err) {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save'; }
    addLogEntry({ type: 'error', message: `Save error: ${err.message}` });
  }
}

async function approveListRow(cardNum) {
  const card = cards.get(cardNum);
  if (!card || !card.cardId) return;

  const result = await window.api.approveCard(card.cardId);
  if (result.success) {
    card.status = 'approved';
    updateListRow(cardNum);
    const gridEl = document.getElementById(`grid-${cardNum}`);
    if (gridEl) updateGridCardDOM(gridEl, card);
    addLogEntry({ type: 'success', message: `Card #${cardNum} approved` });
  }
}

function updateListRow(cardNum) {
  const row = document.getElementById(`list-${cardNum}`);
  if (!row) return;
  const card = cards.get(cardNum);
  if (!card) return;

  // Update thumbnail
  const img = row.querySelector('.list-row-thumb img');
  const frontSrc = card.thumbnail || filePathToUrl(card.frontPath) || '';
  if (img && frontSrc && img.src !== frontSrc) img.src = frontSrc;

  // Update status pill
  const pill = row.querySelector('.status-pill');
  if (pill) {
    pill.className = `status-pill status-${card.status}`;
    pill.textContent = getStatusText(card);
  }

  // Update ready border
  row.classList.toggle('list-row-ready', card.status === 'identified' || card.status === 'approved');

  // Update overlay
  const thumbDiv = row.querySelector('.list-row-thumb');
  let overlay = row.querySelector('.grid-card-overlay');
  const overlayHtml = getStatusOverlay(card.status);
  if (overlayHtml) {
    if (!overlay) {
      thumbDiv.insertAdjacentHTML('beforeend', overlayHtml);
    } else {
      overlay.outerHTML = overlayHtml;
    }
  } else if (overlay) {
    overlay.remove();
  }

  // Update synced badge
  const actionsDiv = row.querySelector('.list-row-actions');
  let syncedBadge = row.querySelector('.list-synced-badge');
  if (card.syncedToSlabTrack && !syncedBadge) {
    const btnsDiv = row.querySelector('.list-row-btns');
    if (btnsDiv) btnsDiv.insertAdjacentHTML('beforebegin', '<span class="list-synced-badge">Synced</span>');
  }

  // Update approve button state
  const approveBtn = row.querySelector('.list-approve-btn');
  if (approveBtn) approveBtn.disabled = card.status !== 'identified';

  // Update non-dirty inputs
  const dirtyFields = listDirtyCards.get(cardNum) || new Set();
  const fieldMap = {
    player: card.player || card.name || '', year: card.year || '',
    cardNumber: card.cardNumber || '', set: card.set || '',
    parallel: card.parallel || '', serialNumber: formatSerialNumber(card),
    sport: card.sport || '', price: card.price || '',
    gradingCompany: card.gradingCompany || '', grade: card.grade || '',
    team: card.team || '', condition: card.condition || '',
    subsetName: card.subsetName || ''
  };

  row.querySelectorAll('.list-input').forEach(input => {
    const field = input.dataset.field;
    if (dirtyFields.has(field) || document.activeElement === input) return;
    if (fieldMap[field] !== undefined) input.value = fieldMap[field];
  });
}

function renderListCard(cardNum, staggerDelay = 0) {
  if (!elements.cardList) return;
  const card = cards.get(cardNum);
  if (!card) return;

  const existing = document.getElementById(`list-${cardNum}`);
  if (existing) {
    updateListRow(cardNum);
    return;
  }

  // Only add if currently in list view or creating for first time
  const row = buildListRow(card);
  if (staggerDelay > 0) {
    row.style.animationDelay = `${staggerDelay}ms`;
  }

  // Prepend (newest first)
  if (elements.cardList.firstChild) {
    elements.cardList.insertBefore(row, elements.cardList.firstChild);
  } else {
    elements.cardList.appendChild(row);
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
