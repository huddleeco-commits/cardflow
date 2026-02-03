#!/usr/bin/env node
/**
 * CardFlow Scanner Agent
 *
 * Watches a folder for scanned images, pairs front/back,
 * and uploads to CardFlow in real-time.
 *
 * Usage:
 *   node agent.js --folder "C:\Scans" --server "http://localhost:3000"
 *
 * Or configure via config.json
 */

const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const FormData = require('form-data');
const axios = require('axios');
const chokidar = require('chokidar');

// Parse command line args or use config
const args = process.argv.slice(2);
let config = {
  watchFolder: '',
  serverUrl: 'http://localhost:3000',
  token: '',
  // Image processing
  holoMode: false,
  brightnessBoost: 0,
  autoRotateBack: true,
  // Pairing
  pairingMode: 'sequential', // 'sequential' (odd=front, even=back) or 'suffix' (_a/_b)
};

// Load config file if exists
const configPath = path.join(__dirname, 'config.json');
if (fs.existsSync(configPath)) {
  const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  config = { ...config, ...fileConfig };
}

// Parse command line overrides
for (let i = 0; i < args.length; i += 2) {
  const key = args[i]?.replace('--', '');
  const value = args[i + 1];
  if (key === 'folder') config.watchFolder = value;
  if (key === 'server') config.serverUrl = value;
  if (key === 'token') config.token = value;
}

// Validate config
if (!config.watchFolder) {
  console.error('Error: No watch folder specified.');
  console.error('Usage: node agent.js --folder "C:\\Scans" --server "http://localhost:3000" --token "your-jwt-token"');
  console.error('Or create config.json with { "watchFolder": "...", "serverUrl": "...", "token": "..." }');
  process.exit(1);
}

if (!config.token) {
  console.error('Error: No auth token specified. Get your token from CardFlow settings.');
  process.exit(1);
}

// Console styling
const log = {
  info: (msg) => console.log(`\x1b[36m[Scanner]\x1b[0m ${msg}`),
  success: (msg) => console.log(`\x1b[32m[Scanner]\x1b[0m ${msg}`),
  warn: (msg) => console.log(`\x1b[33m[Scanner]\x1b[0m ${msg}`),
  error: (msg) => console.log(`\x1b[31m[Scanner]\x1b[0m ${msg}`),
};

// State
let ws = null;
let isConnected = false;
let pendingFront = null; // Holds front image waiting for back
let cardCounter = 0;
let processedFiles = new Set(); // Track processed files to avoid duplicates

// Connect to CardFlow WebSocket
function connectWebSocket() {
  const wsUrl = config.serverUrl.replace('http', 'ws');
  log.info(`Connecting to ${wsUrl}...`);

  ws = new WebSocket(wsUrl);

  ws.on('open', () => {
    isConnected = true;
    log.success('Connected to CardFlow');

    // Authenticate
    ws.send(JSON.stringify({
      type: 'scanner_auth',
      token: config.token
    }));
  });

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.type === 'auth_success') {
        log.success('Authenticated successfully');
      } else if (msg.type === 'card_identified') {
        log.success(`Card ${msg.cardId} identified: ${msg.player || 'Unknown'}`);
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    isConnected = false;
    log.warn('Disconnected from CardFlow. Reconnecting in 3s...');
    setTimeout(connectWebSocket, 3000);
  });

  ws.on('error', (err) => {
    log.error(`WebSocket error: ${err.message}`);
  });
}

// Send status update via WebSocket
function sendStatus(type, data) {
  if (ws && isConnected) {
    ws.send(JSON.stringify({ type, ...data }));
  }
}

// Upload card pair to CardFlow
async function uploadCardPair(frontPath, backPath) {
  cardCounter++;
  const cardNum = cardCounter;

  log.info(`Uploading card #${cardNum}...`);
  sendStatus('scanner_uploading', { cardNum });

  try {
    const formData = new FormData();
    formData.append('front', fs.createReadStream(frontPath));
    if (backPath && fs.existsSync(backPath)) {
      formData.append('back', fs.createReadStream(backPath));
    }
    formData.append('batch', 'true');
    formData.append('source', 'scanner');

    const response = await axios.post(`${config.serverUrl}/api/upload-pair`, formData, {
      headers: {
        ...formData.getHeaders(),
        'Authorization': `Bearer ${config.token}`
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    if (response.data?.cardId) {
      log.success(`Card #${cardNum} uploaded (ID: ${response.data.cardId})`);
      sendStatus('scanner_card_uploaded', {
        cardNum,
        cardId: response.data.cardId,
        frontPath: path.basename(frontPath),
        backPath: backPath ? path.basename(backPath) : null
      });
      return response.data.cardId;
    }
  } catch (err) {
    log.error(`Upload failed for card #${cardNum}: ${err.message}`);
    sendStatus('scanner_upload_error', { cardNum, error: err.message });
    return null;
  }
}

// Process a new image file
async function processNewFile(filePath) {
  // Skip if already processed
  if (processedFiles.has(filePath)) return;

  // Skip non-image files
  const ext = path.extname(filePath).toLowerCase();
  if (!['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp'].includes(ext)) {
    return;
  }

  // Wait a moment for file to finish writing
  await new Promise(r => setTimeout(r, 500));

  // Check file is readable
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
  } catch {
    log.warn(`File not ready: ${filePath}, will retry...`);
    setTimeout(() => processNewFile(filePath), 1000);
    return;
  }

  processedFiles.add(filePath);
  const fileName = path.basename(filePath);

  log.info(`New scan detected: ${fileName}`);
  sendStatus('scanner_file_detected', { fileName });

  if (config.pairingMode === 'sequential') {
    // Sequential pairing: odd files are fronts, even files are backs
    if (pendingFront === null) {
      // This is a front
      pendingFront = filePath;
      log.info(`Front captured, waiting for back...`);
      sendStatus('scanner_front_captured', { fileName });
    } else {
      // This is a back - pair with pending front
      const frontPath = pendingFront;
      const backPath = filePath;
      pendingFront = null;

      log.info(`Back captured, uploading pair...`);
      sendStatus('scanner_back_captured', { fileName });

      await uploadCardPair(frontPath, backPath);
    }
  } else if (config.pairingMode === 'suffix') {
    // Suffix pairing: look for _a/_b or _front/_back patterns
    const baseName = fileName.replace(/(_a|_b|_front|_back|_1|_2)\.[^.]+$/i, '');
    const isFront = /_a\.|_front\.|_1\./i.test(fileName);
    const isBack = /_b\.|_back\.|_2\./i.test(fileName);

    if (isFront) {
      // Store and wait for back
      pendingFront = filePath;
      pendingFrontBase = baseName;
    } else if (isBack && pendingFront && pendingFrontBase === baseName) {
      // Found matching back
      await uploadCardPair(pendingFront, filePath);
      pendingFront = null;
    }
  }
}

// Start watching folder
function startWatching() {
  log.info(`Watching folder: ${config.watchFolder}`);
  log.info(`Pairing mode: ${config.pairingMode}`);
  log.info('Ready! Start scanning cards...');
  log.info('');

  // Use chokidar for reliable file watching
  const watcher = chokidar.watch(config.watchFolder, {
    ignored: /(^|[\/\\])\../, // Ignore dotfiles
    persistent: true,
    ignoreInitial: true, // Don't process existing files
    awaitWriteFinish: {
      stabilityThreshold: 1000,
      pollInterval: 100
    }
  });

  watcher.on('add', (filePath) => {
    processNewFile(filePath);
  });

  watcher.on('error', (err) => {
    log.error(`Watcher error: ${err.message}`);
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    log.info('Shutting down...');
    watcher.close();
    if (ws) ws.close();
    process.exit(0);
  });
}

// Main
console.log('');
console.log('\x1b[36m╔════════════════════════════════════╗\x1b[0m');
console.log('\x1b[36m║    CardFlow Scanner Agent v1.0     ║\x1b[0m');
console.log('\x1b[36m╚════════════════════════════════════╝\x1b[0m');
console.log('');

connectWebSocket();
startWatching();
