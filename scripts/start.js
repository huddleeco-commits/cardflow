#!/usr/bin/env node
/**
 * CardFlow - Production Start Script
 * Runs migrations then starts the server
 */

const { spawn } = require('child_process');
const path = require('path');

console.log('[start] Starting CardFlow...');

// Run migration first
const migrate = spawn('node', [path.join(__dirname, 'railway-migrate.js')], {
  stdio: 'inherit',
  env: process.env
});

migrate.on('close', (code) => {
  if (code !== 0) {
    console.error(`[start] Migration failed with code ${code}`);
    process.exit(code);
  }

  console.log('[start] Migration complete, starting server...');

  // Start server
  const server = spawn('node', [path.join(__dirname, '..', 'web', 'server.js')], {
    stdio: 'inherit',
    env: process.env
  });

  server.on('error', (err) => {
    console.error('[start] Server error:', err);
    process.exit(1);
  });

  server.on('close', (code) => {
    console.log(`[start] Server exited with code ${code}`);
    process.exit(code);
  });
});

migrate.on('error', (err) => {
  console.error('[start] Migration error:', err);
  process.exit(1);
});
