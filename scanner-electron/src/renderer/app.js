// SlabTrack Scanner - Renderer Process

// State
let isScanning = false;
let isConnected = false;
let cards = new Map();
let settings = {};
let slabtrackInfo = null;
let scanMode = 'direct'; // 'direct' or 'folder'
let viewMode = 'grid'; // 'grid' or 'table'
let filterStatus = 'all';
let filterSearch = '';
let selectedCards = new Set();
let detailCardNum = null;

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
  scanDpi: document.getElementById('scan-dpi'),
  scanDuplex: document.getElementById('scan-duplex'),
  statScanned: document.getElementById('stat-scanned'),
  statIdentified: document.getElementById('stat-identified'),
  statErrors: document.getElementById('stat-errors'),
  btnSettings: document.getElementById('btn-settings'),
  btnLogout: document.getElementById('btn-logout'),

  // View Toggle & Filters
  viewTableBtn: document.getElementById('view-table'),
  viewGridBtn: document.getElementById('view-grid'),
  filterStatusSelect: document.getElementById('filter-status'),
  filterSearchInput: document.getElementById('filter-search'),
  cardTableContainer: document.getElementById('card-table-container'),
  cardTableBody: document.getElementById('card-table-body'),
  selectAll: document.getElementById('select-all'),

  // Card Detail Modal
  cardDetailModal: document.getElementById('card-detail-modal'),
  detailTitle: document.getElementById('detail-title'),
  detailPrev: document.getElementById('detail-prev'),
  detailNext: document.getElementById('detail-next'),
  btnCloseDetail: document.getElementById('btn-close-detail'),
  detailFrontImg: document.getElementById('detail-front-img'),
  detailBackImg: document.getElementById('detail-back-img'),
  detailPlayer: document.getElementById('detail-player'),
  detailYear: document.getElementById('detail-year'),
  detailSet: document.getElementById('detail-set'),
  detailCardNumber: document.getElementById('detail-card-number'),
  detailParallel: document.getElementById('detail-parallel'),
  detailPrice: document.getElementById('detail-price'),
  detailStatus: document.getElementById('detail-status'),
  detailApprove: document.getElementById('detail-approve'),
  detailReject: document.getElementById('detail-reject'),
  detailDelete: document.getElementById('detail-delete'),
  detailSave: document.getElementById('detail-save'),

  // Pipeline Bar
  pipelineBar: document.getElementById('pipeline-bar'),
  pipelineScanCount: document.getElementById('pipeline-scan-count'),
  pipelineUploadCount: document.getElementById('pipeline-upload-count'),
  pipelineIdentifyCount: document.getElementById('pipeline-identify-count'),
  pipelineDoneCount: document.getElementById('pipeline-done-count'),

  // Card Feed
  cardFeed: document.getElementById('card-feed'),
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
  settingStartMinimized: document.getElementById('setting-start-minimized'),
  settingStartWindows: document.getElementById('setting-start-windows')
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
  elements.scannerSelect.addEventListener('change', (e) => {
    window.api.saveSettings({ scannerId: e.target.value });
  });
  elements.scanDpi.addEventListener('change', (e) => {
    window.api.saveSettings({ scanDpi: parseInt(e.target.value, 10) });
  });
  elements.scanDuplex.addEventListener('change', (e) => {
    window.api.saveSettings({ scanDuplex: e.target.checked });
  });

  // Folder picker
  elements.btnBrowse.addEventListener('click', handleBrowse);

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

  // View toggle
  elements.viewTableBtn.addEventListener('click', () => toggleView('table'));
  elements.viewGridBtn.addEventListener('click', () => toggleView('grid'));

  // Filters
  elements.filterStatusSelect.addEventListener('change', () => {
    filterStatus = elements.filterStatusSelect.value;
    applyFilters();
  });
  elements.filterSearchInput.addEventListener('input', () => {
    filterSearch = elements.filterSearchInput.value.toLowerCase();
    applyFilters();
  });

  // Select all checkbox
  elements.selectAll.addEventListener('change', (e) => {
    if (e.target.checked) {
      cards.forEach((card, key) => selectedCards.add(key));
    } else {
      selectedCards.clear();
    }
    refreshCurrentView();
    updateBulkToolbar();
  });

  // Card detail modal
  elements.btnCloseDetail.addEventListener('click', closeCardDetail);
  elements.cardDetailModal.querySelector('.modal-backdrop').addEventListener('click', closeCardDetail);
  elements.detailPrev.addEventListener('click', () => navigateDetail(-1));
  elements.detailNext.addEventListener('click', () => navigateDetail(1));
  elements.detailApprove.addEventListener('click', handleDetailApprove);
  elements.detailReject.addEventListener('click', handleDetailReject);
  elements.detailDelete.addEventListener('click', handleDetailDelete);
  elements.detailSave.addEventListener('click', handleDetailSave);

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
    toggleView('table');
    applyFilters();
    elements.batchSummary.classList.add('hidden');
  });
  elements.batchExportAll.addEventListener('click', handleBatchExportAll);

  // Keyboard shortcuts
  document.addEventListener('keydown', handleKeyboardShortcuts);

  // Logout
  elements.btnLogout.addEventListener('click', handleLogout);

  // Clear log
  elements.btnClearLog.addEventListener('click', () => {
    elements.logContent.innerHTML = '';
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
  elements.btnRefreshScanners.classList.add('loading');
  addLogEntry({ type: 'info', message: 'Searching for scanners...' });

  try {
    const result = await window.api.discoverScanners();

    elements.scannerSelect.innerHTML = '<option value="">Select scanner...</option>';

    if (result.success && result.scanners.length > 0) {
      result.scanners.forEach(scanner => {
        const option = document.createElement('option');
        option.value = scanner.id;
        option.textContent = `${scanner.name} (${scanner.manufacturer})`;
        elements.scannerSelect.appendChild(option);
      });

      // Auto-select saved scanner or first one
      const savedId = settings.scannerId;
      if (savedId && result.scanners.some(s => s.id === savedId)) {
        elements.scannerSelect.value = savedId;
      } else if (result.scanners.length === 1) {
        elements.scannerSelect.value = result.scanners[0].id;
        window.api.saveSettings({ scannerId: result.scanners[0].id });
      }

      addLogEntry({ type: 'success', message: `Found ${result.count} scanner(s)` });
    } else {
      addLogEntry({ type: 'warning', message: result.error || 'No scanners found' });
    }
  } catch (error) {
    addLogEntry({ type: 'error', message: `Scanner discovery failed: ${error.message}` });
  } finally {
    elements.btnRefreshScanners.classList.remove('loading');
  }
}

// Direct Scan
async function handleDirectScan() {
  const scannerId = elements.scannerSelect.value;
  if (!scannerId) {
    addLogEntry({ type: 'error', message: 'Please select a scanner first' });
    return;
  }

  elements.btnScan.classList.add('scanning');
  elements.btnScan.querySelector('span').textContent = 'Scanning...';
  elements.btnScan.disabled = true;

  try {
    const result = await window.api.scanDirect({
      scannerId,
      dpi: parseInt(elements.scanDpi.value, 10),
      duplex: elements.scanDuplex.checked
    });

    if (!result.success) {
      addLogEntry({ type: 'error', message: result.error });
    }
  } catch (error) {
    addLogEntry({ type: 'error', message: `Scan failed: ${error.message}` });
  } finally {
    elements.btnScan.classList.remove('scanning');
    elements.btnScan.querySelector('span').textContent = 'SCAN NOW';
    elements.btnScan.disabled = false;
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
    elements.folderPath.value = result.path;
  }
}

// Scanning
async function handleScanToggle() {
  if (scanMode === 'direct') {
    // Direct scanner mode
    handleDirectScan();
    return;
  }

  // Folder watch mode
  if (isScanning) {
    await window.api.stopScanning();
  } else {
    if (!elements.folderPath.value) {
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

// Card Feed
function addCard(data) {
  cards.set(data.cardNum, {
    cardNum: data.cardNum,
    status: data.status,
    frontPath: data.frontPath
  });

  renderCard(data.cardNum);
  if (viewMode === 'table') renderTableRow(data.cardNum);
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

  renderCard(card.cardNum);
  if (viewMode === 'table') renderTableRow(card.cardNum);
}

function updateCardIdentified(data) {
  const card = cards.get(data.cardNum) || findCardByCardId(data.cardId);
  if (!card) return;

  card.status = 'identified';
  card.name = data.name;
  card.player = data.player;
  card.year = data.year;
  card.set = data.set;
  if (data.cardNumber) card.cardNumber = data.cardNumber;
  if (data.parallel) card.parallel = data.parallel;
  if (data.price) card.price = data.price;
  if (data.thumbnail) card.thumbnail = data.thumbnail;
  if (data.back) card.back = data.back;

  renderCard(card.cardNum);
  if (viewMode === 'table') renderTableRow(card.cardNum);
}

function findCardByCardId(cardId) {
  for (const card of cards.values()) {
    if (card.cardId === cardId) return card;
  }
  return null;
}

function renderCard(cardNum) {
  const card = cards.get(cardNum);
  if (!card) return;

  let cardEl = document.getElementById(`card-${cardNum}`);

  if (!cardEl) {
    cardEl = document.createElement('div');
    cardEl.id = `card-${cardNum}`;
    cardEl.className = 'card-item';
    elements.cardFeed.insertBefore(cardEl, elements.cardFeed.firstChild);
  }

  const statusClass = card.status;
  const statusText = getStatusText(card);
  const displayName = card.player || card.name || '';
  const details = card.year && card.set ? `${card.year} ${card.set}` : '';

  cardEl.innerHTML = `
    <div class="card-thumbnail">
      ${card.thumbnail
        ? `<img src="${card.thumbnail}" alt="Card ${cardNum}">`
        : `<span class="placeholder">#${cardNum}</span>`
      }
    </div>
    <div class="card-info">
      <div class="card-number">Card #${cardNum}</div>
      ${card.status === 'identified'
        ? `<div class="card-name">${displayName}</div>
           <div class="card-details">${details}</div>`
        : `<div class="card-status ${statusClass}">
             <span class="status-indicator"></span>
             ${statusText}
           </div>`
      }
    </div>
  `;
}

function getStatusText(card) {
  switch (card.status) {
    case 'queued': return 'Queued...';
    case 'uploading': return 'Uploading...';
    case 'identifying': return 'Identifying...';
    case 'identified': return card.name || 'Identified';
    case 'error': return card.error || 'Error';
    default: return card.status;
  }
}

function clearCards() {
  cards.clear();
  elements.cardFeed.innerHTML = '';
  showEmptyState();
  updateFeedCount();
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

// View Toggle
function toggleView(mode) {
  viewMode = mode;
  elements.viewTableBtn.classList.toggle('active', mode === 'table');
  elements.viewGridBtn.classList.toggle('active', mode === 'grid');
  elements.cardTableContainer.classList.toggle('hidden', mode !== 'table');
  elements.cardFeed.classList.toggle('hidden', mode !== 'grid');

  if (mode === 'table') {
    renderTableView();
  }
}

function refreshCurrentView() {
  if (viewMode === 'table') {
    renderTableView();
  }
}

// Table View
function renderTableView() {
  elements.cardTableBody.innerHTML = '';
  const filtered = getFilteredCards();

  filtered.forEach(([cardNum]) => {
    renderTableRow(cardNum);
  });
}

function renderTableRow(cardNum) {
  const card = cards.get(cardNum);
  if (!card) return;

  // Check filter
  if (!cardMatchesFilter(card)) {
    const existing = document.getElementById(`row-${cardNum}`);
    if (existing) existing.remove();
    return;
  }

  let row = document.getElementById(`row-${cardNum}`);
  const isNew = !row;

  if (isNew) {
    row = document.createElement('tr');
    row.id = `row-${cardNum}`;
    row.className = 'card-row';
  }

  const isSelected = selectedCards.has(cardNum);
  row.classList.toggle('selected', isSelected);

  const statusClass = card.status || 'queued';
  const displayName = card.player || card.name || '';

  row.innerHTML = `
    <td class="td-checkbox"><input type="checkbox" class="row-select" data-card="${cardNum}" ${isSelected ? 'checked' : ''}></td>
    <td class="td-thumb">
      ${card.thumbnail
        ? `<img src="${card.thumbnail}" class="table-thumb" alt="">`
        : `<span class="table-thumb-placeholder">#${cardNum}</span>`
      }
    </td>
    <td class="td-num">${cardNum}</td>
    <td class="td-player editable" data-field="player" data-card="${cardNum}">${escapeHtml(displayName)}</td>
    <td class="td-year editable" data-field="year" data-card="${cardNum}">${escapeHtml(card.year || '')}</td>
    <td class="td-set editable" data-field="set" data-card="${cardNum}">${escapeHtml(card.set || '')}</td>
    <td class="td-cardnum editable" data-field="cardNumber" data-card="${cardNum}">${escapeHtml(card.cardNumber || '')}</td>
    <td class="td-parallel editable" data-field="parallel" data-card="${cardNum}">${escapeHtml(card.parallel || '')}</td>
    <td class="td-price editable" data-field="price" data-card="${cardNum}">${card.price ? '$' + card.price : ''}</td>
    <td class="td-status"><span class="status-pill status-${statusClass}">${statusClass}</span></td>
    <td class="td-actions">
      <button class="btn btn-ghost btn-small action-view" data-card="${cardNum}" title="View">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg>
      </button>
      ${card.status === 'identified' ? `<button class="btn btn-ghost btn-small action-approve" data-card="${cardNum}" title="Approve">&#10003;</button>` : ''}
    </td>
  `;

  // Attach event listeners
  const selectBox = row.querySelector('.row-select');
  selectBox.addEventListener('change', (e) => {
    if (e.target.checked) {
      selectedCards.add(cardNum);
    } else {
      selectedCards.delete(cardNum);
    }
    row.classList.toggle('selected', e.target.checked);
    updateBulkToolbar();
  });

  const viewBtn = row.querySelector('.action-view');
  if (viewBtn) viewBtn.addEventListener('click', () => openCardDetail(cardNum));

  const approveBtn = row.querySelector('.action-approve');
  if (approveBtn) approveBtn.addEventListener('click', async () => {
    if (card.cardId) {
      const result = await window.api.approveCard(card.cardId);
      if (result.success) {
        card.status = 'approved';
        renderTableRow(cardNum);
        renderCard(cardNum);
      }
    }
  });

  // Double-click to edit
  row.querySelectorAll('.editable').forEach(cell => {
    cell.addEventListener('dblclick', () => startInlineEdit(cell));
  });

  // Click row to select
  row.addEventListener('click', (e) => {
    if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'BUTTON' && !e.target.closest('button')) {
      openCardDetail(cardNum);
    }
  });

  if (isNew) {
    // Insert at top or at appropriate position
    if (elements.cardTableBody.firstChild) {
      elements.cardTableBody.insertBefore(row, elements.cardTableBody.firstChild);
    } else {
      elements.cardTableBody.appendChild(row);
    }
  }
}

// Inline Editing
function startInlineEdit(cell) {
  if (cell.querySelector('input')) return; // Already editing

  const field = cell.dataset.field;
  const cardNum = parseInt(cell.dataset.card, 10);
  const card = cards.get(cardNum);
  if (!card) return;

  const currentValue = card[field] || '';
  const originalText = cell.textContent;

  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'inline-edit-input';
  input.value = currentValue;

  cell.textContent = '';
  cell.appendChild(input);
  input.focus();
  input.select();

  const finishEdit = async () => {
    const newValue = input.value.trim();
    cell.textContent = newValue || originalText;

    if (newValue !== currentValue) {
      card[field] = newValue;
      // Save to server if card has an ID
      if (card.cardId) {
        const result = await window.api.updateCard(card.cardId, { [field]: newValue });
        if (!result.success) {
          addLogEntry({ type: 'error', message: `Failed to update card: ${result.error}` });
          card[field] = currentValue;
          cell.textContent = originalText;
        }
      }
    }
  };

  input.addEventListener('blur', finishEdit);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { input.blur(); }
    if (e.key === 'Escape') {
      input.value = currentValue;
      input.blur();
    }
  });
}

// Filtering
function getFilteredCards() {
  const entries = Array.from(cards.entries());
  return entries.filter(([, card]) => cardMatchesFilter(card)).reverse();
}

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
  if (viewMode === 'table') {
    renderTableView();
  }
  // For grid view, we could also filter but keeping it simple — grid shows all
}

// Card Detail Modal
function openCardDetail(cardNum) {
  const card = cards.get(cardNum);
  if (!card) return;

  detailCardNum = cardNum;
  elements.detailTitle.textContent = `Card #${cardNum}`;

  // Images
  elements.detailFrontImg.src = card.thumbnail || '';
  elements.detailFrontImg.style.display = card.thumbnail ? 'block' : 'none';
  elements.detailBackImg.src = card.back || '';
  elements.detailBackImg.style.display = card.back ? 'block' : 'none';

  // Fields
  elements.detailPlayer.value = card.player || card.name || '';
  elements.detailYear.value = card.year || '';
  elements.detailSet.value = card.set || '';
  elements.detailCardNumber.value = card.cardNumber || '';
  elements.detailParallel.value = card.parallel || '';
  elements.detailPrice.value = card.price || '';

  // Status
  const status = card.status || 'queued';
  elements.detailStatus.textContent = status;
  elements.detailStatus.className = `status-pill status-${status}`;

  // Show/hide action buttons based on status
  elements.detailApprove.style.display = ['identified', 'error'].includes(status) ? '' : 'none';
  elements.detailReject.style.display = ['identified', 'approved'].includes(status) ? '' : 'none';

  elements.cardDetailModal.classList.remove('hidden');
}

function closeCardDetail() {
  elements.cardDetailModal.classList.add('hidden');
  detailCardNum = null;
}

function navigateDetail(direction) {
  if (detailCardNum === null) return;

  const cardNums = Array.from(cards.keys()).sort((a, b) => a - b);
  const idx = cardNums.indexOf(detailCardNum);
  const newIdx = idx + direction;

  if (newIdx >= 0 && newIdx < cardNums.length) {
    openCardDetail(cardNums[newIdx]);
  }
}

async function handleDetailApprove() {
  const card = cards.get(detailCardNum);
  if (!card || !card.cardId) return;

  const result = await window.api.approveCard(card.cardId);
  if (result.success) {
    card.status = 'approved';
    openCardDetail(detailCardNum); // Refresh
    renderCard(detailCardNum);
    if (viewMode === 'table') renderTableRow(detailCardNum);
    addLogEntry({ type: 'success', message: `Card #${detailCardNum} approved` });
  }
}

async function handleDetailReject() {
  const card = cards.get(detailCardNum);
  if (!card || !card.cardId) return;

  const result = await window.api.rejectCard(card.cardId);
  if (result.success) {
    card.status = 'rejected';
    openCardDetail(detailCardNum);
    renderCard(detailCardNum);
    if (viewMode === 'table') renderTableRow(detailCardNum);
    addLogEntry({ type: 'info', message: `Card #${detailCardNum} rejected` });
  }
}

async function handleDetailDelete() {
  const card = cards.get(detailCardNum);
  if (!card || !card.cardId) return;

  if (!confirm(`Delete card #${detailCardNum}? This cannot be undone.`)) return;

  const result = await window.api.deleteCard(card.cardId);
  if (result.success) {
    cards.delete(detailCardNum);
    const cardEl = document.getElementById(`card-${detailCardNum}`);
    if (cardEl) cardEl.remove();
    const rowEl = document.getElementById(`row-${detailCardNum}`);
    if (rowEl) rowEl.remove();
    closeCardDetail();
    updateFeedCount();
    addLogEntry({ type: 'info', message: `Card #${detailCardNum} deleted` });
  }
}

async function handleDetailSave() {
  const card = cards.get(detailCardNum);
  if (!card || !card.cardId) return;

  const updates = {
    player: elements.detailPlayer.value,
    year: elements.detailYear.value,
    set: elements.detailSet.value,
    cardNumber: elements.detailCardNumber.value,
    parallel: elements.detailParallel.value,
    price: elements.detailPrice.value
  };

  const result = await window.api.updateCard(card.cardId, updates);
  if (result.success) {
    Object.assign(card, updates);
    card.name = updates.player;
    renderCard(detailCardNum);
    if (viewMode === 'table') renderTableRow(detailCardNum);
    addLogEntry({ type: 'success', message: `Card #${detailCardNum} updated` });
  } else {
    addLogEntry({ type: 'error', message: `Update failed: ${result.error}` });
  }
}

// Bulk Toolbar
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
      if (card && card.cardId) card.status = 'approved';
    });
    selectedCards.clear();
    refreshCurrentView();
    updateBulkToolbar();
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
      const el = document.getElementById(`card-${cardNum}`);
      if (el) el.remove();
      const row = document.getElementById(`row-${cardNum}`);
      if (row) row.remove();
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

// Batch Summary
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
      if (card.status === 'identified') card.status = 'approved';
    });
    refreshCurrentView();
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

// Keyboard Shortcuts
function handleKeyboardShortcuts(e) {
  // Don't trigger while typing in inputs
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

  // Ctrl+A: Select all
  if (e.ctrlKey && e.key === 'a') {
    e.preventDefault();
    cards.forEach((card, key) => selectedCards.add(key));
    refreshCurrentView();
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

  // Arrow keys for detail navigation
  if (detailCardNum !== null) {
    if (e.key === 'ArrowLeft') { e.preventDefault(); navigateDetail(-1); }
    if (e.key === 'ArrowRight') { e.preventDefault(); navigateDetail(1); }
    if (e.key === 'Escape') { e.preventDefault(); closeCardDetail(); }
  } else if (e.key === 'Escape') {
    // Clear selection
    selectedCards.clear();
    refreshCurrentView();
    updateBulkToolbar();
  }
}

// Activity Log
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

// Settings
async function loadSettings() {
  settings = await window.api.getSettings();

  // Restore scan mode
  switchScanMode(settings.scanMode || 'direct');

  // Restore scanner settings
  if (settings.scanDpi) elements.scanDpi.value = settings.scanDpi;
  if (settings.scanDuplex !== undefined) elements.scanDuplex.checked = settings.scanDuplex;

  // Auto-discover scanners on load
  if (settings.scanMode !== 'folder') {
    discoverScanners();
  }

  elements.folderPath.value = settings.scanFolder || '';
  elements.settingPairingMode.value = settings.pairingMode || 'sequential';
  elements.settingHoloMode.checked = settings.holoMode || false;
  elements.settingBrightness.value = settings.brightnessBoost || 0;
  elements.brightnessValue.textContent = settings.brightnessBoost || 0;
  elements.settingAutoRotate.checked = settings.autoRotateBack !== false;
  elements.settingStartMinimized.checked = settings.startMinimized || false;
  elements.settingStartWindows.checked = settings.startWithWindows || false;
}

function openSettings() {
  loadSettings();
  elements.settingsModal.classList.remove('hidden');
}

function closeSettings() {
  elements.settingsModal.classList.add('hidden');
}

async function saveSettings() {
  const newSettings = {
    pairingMode: elements.settingPairingMode.value,
    holoMode: elements.settingHoloMode.checked,
    brightnessBoost: parseInt(elements.settingBrightness.value, 10),
    autoRotateBack: elements.settingAutoRotate.checked,
    startMinimized: elements.settingStartMinimized.checked,
    startWithWindows: elements.settingStartWindows.checked
  };

  await window.api.saveSettings(newSettings);
  settings = { ...settings, ...newSettings };
  closeSettings();
  addLogEntry({ type: 'success', message: 'Settings saved' });
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
