// CardFlow Scanner - Renderer Process

// State
let isScanning = false;
let isConnected = false;
let cards = new Map();
let settings = {};

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

  // Window Controls
  btnMinimize: document.getElementById('btn-minimize'),
  btnMaximize: document.getElementById('btn-maximize'),
  btnClose: document.getElementById('btn-close'),

  // Main View
  connectionStatus: document.getElementById('connection-status'),
  folderPath: document.getElementById('folder-path'),
  btnBrowse: document.getElementById('btn-browse'),
  btnScan: document.getElementById('btn-scan'),
  statScanned: document.getElementById('stat-scanned'),
  statIdentified: document.getElementById('stat-identified'),
  statErrors: document.getElementById('stat-errors'),
  btnSettings: document.getElementById('btn-settings'),
  btnLogout: document.getElementById('btn-logout'),

  // Card Feed
  cardFeed: document.getElementById('card-feed'),
  emptyState: document.getElementById('empty-state'),
  feedCount: document.getElementById('feed-count'),

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

  // Login form
  elements.loginForm.addEventListener('submit', handleLogin);

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
}

// Authentication
async function checkAuth() {
  const result = await window.api.checkAuth();

  if (result.authenticated) {
    showMainView();
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
  showLoginView();
  clearCards();
  elements.logContent.innerHTML = '';
}

function showLoginError(message) {
  elements.loginError.textContent = message;
  elements.loginError.classList.add('show');
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

// Folder Selection
async function handleBrowse() {
  const result = await window.api.selectFolder();

  if (result.success) {
    elements.folderPath.value = result.path;
  }
}

// Scanning
async function handleScanToggle() {
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
}

function updateCardIdentified(data) {
  const card = cards.get(data.cardNum) || findCardByCardId(data.cardId);
  if (!card) return;

  card.status = 'identified';
  card.name = data.name;
  card.player = data.player;
  card.year = data.year;
  card.set = data.set;

  renderCard(card.cardNum);
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
