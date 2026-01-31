#!/usr/bin/env node
/**
 * CardFlow - Export Script
 *
 * Exports cards to various destinations:
 * - SlabTrack (API + Cloudinary images)
 * - CSV file
 * - Excel file
 * - JSON file
 *
 * Usage:
 *   node scripts/export.js --target slabtrack
 *   node scripts/export.js --target csv
 *   node scripts/export.js --target excel
 *   node scripts/export.js --target json
 */

const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');

// Configuration
const CONFIG = {
  pricedFolder: path.join(__dirname, '..', '3-priced'),
  exportedFolder: path.join(__dirname, '..', '4-exported'),
  reportsFolder: path.join(__dirname, '..'),
  dbPath: path.join(__dirname, '..', 'cards.json'),

  // SlabTrack config
  slabtrack: {
    url: process.env.SLABTRACK_URL || 'https://slabtrack-production.up.railway.app',
    username: process.env.SLABTRACK_USERNAME || 'huddleeco@gmail.com',
    password: process.env.SLABTRACK_PASSWORD || 'test1pswd'
  },

  // Cloudinary config
  cloudinary: {
    cloudName: process.env.CLOUDINARY_CLOUD_NAME || 'dj1feypnp',
    apiKey: process.env.CLOUDINARY_API_KEY || '311447296432398',
    apiSecret: process.env.CLOUDINARY_API_SECRET || '372uPfS1GPy0VSgu0qHE7u0pTP4'
  },

  email: {
    enabled: !!process.env.SMTP_USER,
    recipient: process.env.EMAIL_TO || 'huddleeco@gmail.com'
  }
};

// Database
let cardsDb = [];

function loadDb() {
  try {
    if (fs.existsSync(CONFIG.dbPath)) {
      cardsDb = JSON.parse(fs.readFileSync(CONFIG.dbPath, 'utf8'));
    }
  } catch (e) {
    cardsDb = [];
  }
}

function saveDb() {
  fs.writeFileSync(CONFIG.dbPath, JSON.stringify(cardsDb, null, 2));
}

// Logging
function log(message, type = 'info') {
  const icons = { info: '\u2139\uFE0F', success: '\u2705', error: '\u274C', warn: '\u26A0\uFE0F', export: '\uD83D\uDCE4' };
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[${timestamp}] ${icons[type] || ''} ${message}`);
}

// Get cards ready for export
function getExportableCards() {
  return cardsDb.filter(c => c.status === 'priced' || c.status === 'approved');
}

// Convert image to base64
function imageToBase64(imagePath) {
  try {
    if (!fs.existsSync(imagePath)) return null;
    const buffer = fs.readFileSync(imagePath);
    const ext = path.extname(imagePath).toLowerCase().replace('.', '');
    const mimeType = ext === 'jpg' ? 'jpeg' : ext;
    return `data:image/${mimeType};base64,${buffer.toString('base64')}`;
  } catch (e) {
    return null;
  }
}

// Login to SlabTrack
async function slabtrackLogin() {
  log('Logging into SlabTrack...', 'info');

  const response = await fetch(`${CONFIG.slabtrack.url}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: CONFIG.slabtrack.username,
      password: CONFIG.slabtrack.password
    })
  });

  if (!response.ok) {
    throw new Error(`Login failed: ${response.status}`);
  }

  const data = await response.json();
  log('Logged in successfully', 'success');
  return data.token;
}

// Export to SlabTrack
async function exportToSlabTrack(cards) {
  log(`Exporting ${cards.length} cards to SlabTrack...`, 'export');

  const token = await slabtrackLogin();

  // Prepare cards for API
  const apiCards = cards.map(card => {
    // Get image paths
    const frontPath = card.front ? path.join(CONFIG.pricedFolder, card.front) : null;
    const backPath = card.back ? path.join(CONFIG.pricedFolder, card.back) : null;

    return {
      player: card.player,
      year: card.year ? String(card.year) : null,
      set_name: card.set_name,
      card_number: card.card_number,
      parallel: card.parallel,
      team: card.team,
      sport: card.sport || 'Football',
      numbered: !!card.numbered,
      serial_number: card.numbered,
      is_graded: card.is_graded || false,
      grading_company: card.grading_company,
      grade: card.grade ? String(card.grade) : null,
      cert_number: card.cert_number,
      condition: card.condition || 'near_mint',
      ebay_low: card.ebay_low,
      ebay_avg: card.ebay_avg,
      ebay_high: card.ebay_high,
      ebay_sample_size: card.sample_size,
      ebay_search_string: card.search_string,
      front_image_base64: frontPath ? imageToBase64(frontPath) : null,
      back_image_base64: backPath ? imageToBase64(backPath) : null,
      raw_title: `${card.year || ''} ${card.set_name || ''} ${card.player || ''} ${card.parallel || ''}`.trim()
    };
  });

  // Call bulk import API
  const response = await fetch(`${CONFIG.slabtrack.url}/api/atlas/bulk-import`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ cards: apiCards })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Import failed: ${response.status} - ${errorText}`);
  }

  const result = await response.json();
  return result;
}

// Export to CSV
function exportToCsv(cards) {
  log(`Exporting ${cards.length} cards to CSV...`, 'export');

  const headers = [
    'Player', 'Year', 'Set', 'Card Number', 'Parallel', 'Numbered',
    'Team', 'Sport', 'Graded', 'Company', 'Grade', 'Cert Number',
    'Condition', 'eBay Low', 'eBay Avg', 'eBay High', 'Sample Size'
  ];

  const rows = cards.map(card => [
    card.player || '',
    card.year || '',
    card.set_name || '',
    card.card_number || '',
    card.parallel || 'Base',
    card.numbered || '',
    card.team || '',
    card.sport || '',
    card.is_graded ? 'Yes' : 'No',
    card.grading_company || '',
    card.grade || '',
    card.cert_number || '',
    card.condition || '',
    card.ebay_low || '',
    card.ebay_avg || '',
    card.ebay_high || '',
    card.sample_size || 0
  ]);

  const csv = [headers, ...rows].map(row =>
    row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
  ).join('\n');

  const exportPath = path.join(CONFIG.reportsFolder, 'cardflow-export.csv');
  fs.writeFileSync(exportPath, csv);

  log(`Exported to: ${exportPath}`, 'success');
  return exportPath;
}

// Export to Excel
function exportToExcel(cards) {
  log(`Exporting ${cards.length} cards to Excel...`, 'export');

  const wb = XLSX.utils.book_new();

  const rows = [
    ['Player', 'Year', 'Set', 'Card #', 'Parallel', 'Numbered', 'Team', 'Sport',
     'Graded', 'Company', 'Grade', 'Cert #', 'Condition',
     'eBay Low', 'eBay Avg', 'eBay High', 'Sample Size', 'Notes']
  ];

  let totalValue = 0;
  cards.forEach(card => {
    totalValue += card.ebay_avg || 0;
    rows.push([
      card.player || '',
      card.year || '',
      card.set_name || '',
      card.card_number || '',
      card.parallel || 'Base',
      card.numbered || '',
      card.team || '',
      card.sport || '',
      card.is_graded ? 'Yes' : 'No',
      card.grading_company || '',
      card.grade || '',
      card.cert_number || '',
      card.condition || '',
      card.ebay_low || '',
      card.ebay_avg || '',
      card.ebay_high || '',
      card.sample_size || 0,
      card.notes || ''
    ]);
  });

  rows.push([]);
  rows.push(['', '', '', '', '', '', '', 'TOTAL:', '', '', '', '', '', '', totalValue, '', '', '']);

  const ws = XLSX.utils.aoa_to_sheet(rows);
  XLSX.utils.book_append_sheet(wb, ws, 'Cards');

  const exportPath = path.join(CONFIG.reportsFolder, 'cardflow-export.xlsx');
  XLSX.writeFile(wb, exportPath);

  log(`Exported to: ${exportPath}`, 'success');
  return exportPath;
}

// Export to JSON
function exportToJson(cards) {
  log(`Exporting ${cards.length} cards to JSON...`, 'export');

  const exportData = {
    exported_at: new Date().toISOString(),
    total_cards: cards.length,
    total_value: cards.reduce((sum, c) => sum + (c.ebay_avg || 0), 0),
    cards: cards.map(card => ({
      player: card.player,
      year: card.year,
      set_name: card.set_name,
      card_number: card.card_number,
      parallel: card.parallel,
      numbered: card.numbered,
      team: card.team,
      sport: card.sport,
      is_graded: card.is_graded,
      grading_company: card.grading_company,
      grade: card.grade,
      cert_number: card.cert_number,
      condition: card.condition,
      ebay_low: card.ebay_low,
      ebay_avg: card.ebay_avg,
      ebay_high: card.ebay_high,
      sample_size: card.sample_size
    }))
  };

  const exportPath = path.join(CONFIG.reportsFolder, 'cardflow-export.json');
  fs.writeFileSync(exportPath, JSON.stringify(exportData, null, 2));

  log(`Exported to: ${exportPath}`, 'success');
  return exportPath;
}

// Move files to exported folder
function moveToExported(cards) {
  if (!fs.existsSync(CONFIG.exportedFolder)) {
    fs.mkdirSync(CONFIG.exportedFolder, { recursive: true });
  }

  for (const card of cards) {
    try {
      if (card.front) {
        const src = path.join(CONFIG.pricedFolder, card.front);
        const dst = path.join(CONFIG.exportedFolder, card.front);
        if (fs.existsSync(src)) fs.renameSync(src, dst);
      }
      if (card.back) {
        const src = path.join(CONFIG.pricedFolder, card.back);
        const dst = path.join(CONFIG.exportedFolder, card.back);
        if (fs.existsSync(src)) fs.renameSync(src, dst);
      }
    } catch (e) {
      log(`Failed to move ${card.front}: ${e.message}`, 'warn');
    }
  }
}

// Send email notification
async function sendNotification(cards, target, result) {
  if (!CONFIG.email.enabled) return;

  try {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const totalValue = cards.reduce((sum, c) => sum + (c.ebay_avg || 0), 0);

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: CONFIG.email.recipient,
      subject: `\uD83D\uDCE4 CardFlow: ${cards.length} cards exported to ${target}`,
      html: `
        <h2>Export Complete</h2>
        <p><strong>${cards.length}</strong> cards exported to <strong>${target}</strong>.</p>
        <p>Total Value: <strong>$${totalValue.toFixed(2)}</strong></p>
        ${target === 'slabtrack' ? '<p><a href="https://slabtrack.io/collection">View in SlabTrack</a></p>' : ''}
        <hr>
        <p style="color: #888; font-size: 12px;">CardFlow - Bulk Card Processing</p>
      `
    });

    log('Email notification sent', 'success');
  } catch (e) {
    log(`Email failed: ${e.message}`, 'warn');
  }
}

// Main function
async function main() {
  console.log('\n\u2550'.repeat(50));
  console.log('  CARDFLOW - EXPORT');
  console.log('\u2550'.repeat(50) + '\n');

  // Parse arguments
  const args = process.argv.slice(2);
  const targetIdx = args.indexOf('--target');
  const target = targetIdx !== -1 ? args[targetIdx + 1] : 'slabtrack';

  const validTargets = ['slabtrack', 'csv', 'excel', 'json'];
  if (!validTargets.includes(target)) {
    log(`Invalid target: ${target}. Use: ${validTargets.join(', ')}`, 'error');
    process.exit(1);
  }

  loadDb();

  const cards = getExportableCards();
  if (cards.length === 0) {
    log('No cards ready for export.', 'warn');
    log('Run identify and price first.', 'info');
    return;
  }

  log(`Found ${cards.length} cards to export`, 'info');
  log(`Target: ${target}`, 'info');

  let result;
  try {
    switch (target) {
      case 'slabtrack':
        result = await exportToSlabTrack(cards);
        log(`Imported: ${result.imported} cards`, 'success');
        if (result.failed > 0) {
          log(`Failed: ${result.failed} cards`, 'warn');
        }
        break;

      case 'csv':
        result = exportToCsv(cards);
        break;

      case 'excel':
        result = exportToExcel(cards);
        break;

      case 'json':
        result = exportToJson(cards);
        break;
    }

    // Update card status in database
    cards.forEach(card => {
      const idx = cardsDb.findIndex(c => c.id === card.id);
      if (idx !== -1) {
        cardsDb[idx].status = 'exported';
        cardsDb[idx].exported_at = new Date().toISOString();
        cardsDb[idx].exported_to = target;
      }
    });
    saveDb();

    // Move files
    if (target === 'slabtrack') {
      moveToExported(cards);
    }

    // Send notification
    await sendNotification(cards, target, result);

  } catch (e) {
    log(`Export failed: ${e.message}`, 'error');
    process.exit(1);
  }

  // Summary
  const totalValue = cards.reduce((sum, c) => sum + (c.ebay_avg || 0), 0);
  console.log('\n' + '\u2550'.repeat(50));
  log(`EXPORT COMPLETE`, 'success');
  log(`Cards: ${cards.length}`, 'info');
  log(`Total Value: $${totalValue.toFixed(2)}`, 'info');
  log(`Target: ${target}`, 'info');
  console.log('\u2550'.repeat(50) + '\n');
}

main().catch(e => {
  log(`Fatal error: ${e.message}`, 'error');
  process.exit(1);
});
