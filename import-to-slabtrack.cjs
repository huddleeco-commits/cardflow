#!/usr/bin/env node
/**
 * Import Cards to SlabTrack
 *
 * Usage: node import-to-slabtrack.js
 *
 * Reads identification-report.xlsx and pricing-report.xlsx from current folder,
 * combines the data, uploads images to Cloudinary, and imports to SlabTrack.
 */

const XLSX = require('xlsx');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  slabtrackUrl: 'https://slabtrack-production.up.railway.app',
  username: 'huddleeco@gmail.com',
  password: 'test1pswd',
  watchFolder: process.cwd()
};

// ==================== HELPERS ====================
function log(message, type = 'info') {
  const icons = { info: 'ℹ️', success: '✅', error: '❌', warn: '⚠️' };
  console.log(`${icons[type] || ''} ${message}`);
}

function findExcelFile(pattern) {
  // Check main folder first
  const files = fs.readdirSync(CONFIG.watchFolder);
  let found = files.find(f => f.toLowerCase().includes(pattern) && f.endsWith('.xlsx'));
  if (found) return found;

  // Check processed folder (supplier-worker may have archived it)
  const processedFolder = path.join(CONFIG.watchFolder, 'processed');
  if (fs.existsSync(processedFolder)) {
    const processedFiles = fs.readdirSync(processedFolder);
    found = processedFiles.find(f => f.toLowerCase().includes(pattern) && f.endsWith('.xlsx'));
    if (found) return path.join('processed', found);
  }

  return null;
}

// ==================== EXCEL PARSING ====================
function parseIdentificationReport(filePath) {
  log(`Parsing identification report: ${filePath}`);
  const workbook = XLSX.readFile(filePath);
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

  // Find header row (skip title row)
  let headerRowIndex = 0;
  for (let i = 0; i < Math.min(5, data.length); i++) {
    if (data[i] && data[i].some(cell => cell && cell.toString().toLowerCase().includes('player'))) {
      headerRowIndex = i;
      break;
    }
  }

  const headers = data[headerRowIndex].map(h => h ? h.toString().toLowerCase().trim() : '');
  const cards = [];

  for (let i = headerRowIndex + 1; i < data.length; i++) {
    const row = data[i];
    if (!row || row.length === 0) continue;

    const card = {};
    headers.forEach((header, idx) => {
      if (header && row[idx] !== undefined && row[idx] !== null && row[idx] !== '') {
        card[header] = row[idx];
      }
    });

    // Only add if has player name
    if (card.player || card['player/card']) {
      cards.push(card);
    }
  }

  log(`Found ${cards.length} cards in identification report`, 'success');
  return cards;
}

function parsePricingReport(filePath) {
  log(`Parsing pricing report: ${filePath}`);
  const workbook = XLSX.readFile(filePath);
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

  // Find header row
  let headerRowIndex = 0;
  for (let i = 0; i < Math.min(5, data.length); i++) {
    if (data[i] && data[i].some(cell => cell && cell.toString().toLowerCase().includes('ebay'))) {
      headerRowIndex = i;
      break;
    }
  }

  const headers = data[headerRowIndex].map(h => h ? h.toString().toLowerCase().trim().replace(/\s+/g, '_') : '');
  const pricing = [];

  for (let i = headerRowIndex + 1; i < data.length; i++) {
    const row = data[i];
    if (!row || row.length === 0) continue;

    const price = {};
    headers.forEach((header, idx) => {
      if (header && row[idx] !== undefined && row[idx] !== null && row[idx] !== '') {
        price[header] = row[idx];
      }
    });

    if (Object.keys(price).length > 0) {
      pricing.push(price);
    }
  }

  log(`Found ${pricing.length} pricing entries`, 'success');
  return pricing;
}

// ==================== DATA COMBINATION ====================
function combineData(identifications, pricing) {
  return identifications.map((card, idx) => {
    const priceData = pricing[idx] || {};

    // Map to SlabTrack API format
    return {
      player: card.player || card['player/card'] || 'Unknown',
      year: card.year ? String(card.year) : null,
      set_name: card.set || card.set_name || null,
      card_number: card['card_#'] || card.card_number || card['card #'] || null,
      parallel: card.parallel || card['parallel/variant'] || null,
      team: card.team || null,
      sport: mapSport(card.sport),
      numbered: card.numbered && card.numbered !== 'N/A' && card.numbered !== 'No',
      serial_number: extractSerial(card.numbered),
      is_graded: card.graded === 'Yes' || card.graded === true,
      grading_company: card['grading_company'] || card.grading_company || null,
      grade: card.grade && card.grade !== 'N/A' ? String(card.grade) : null,
      condition: mapCondition(card.condition),
      ebay_low: parsePrice(priceData.ebay_low),
      ebay_avg: parsePrice(priceData.ebay_avg),
      ebay_high: parsePrice(priceData.ebay_high),
      ebay_sample_size: priceData.sample_size ? parseInt(priceData.sample_size) : null,
      raw_title: `${card.year || ''} ${card.set || ''} ${card.player || ''} ${card.parallel || ''}`.trim()
    };
  });
}

function mapSport(sport) {
  if (!sport) return 'Football';
  const s = sport.toLowerCase();
  if (s.includes('baseball')) return 'Baseball';
  if (s.includes('basketball')) return 'Basketball';
  if (s.includes('football')) return 'Football';
  if (s.includes('hockey')) return 'Hockey';
  if (s.includes('soccer')) return 'Soccer';
  if (s.includes('pokemon') || s.includes('tcg')) return 'Pokemon';
  return 'Football';
}

function mapCondition(condition) {
  if (!condition) return 'near_mint';
  const c = condition.toLowerCase();
  if (c.includes('mint') && !c.includes('near')) return 'mint';
  if (c.includes('near') || c.includes('nm')) return 'near_mint';
  if (c.includes('excellent') || c.includes('ex')) return 'excellent';
  if (c.includes('good')) return 'good';
  if (c.includes('fair')) return 'fair';
  if (c.includes('poor')) return 'poor';
  return 'near_mint';
}

function extractSerial(numbered) {
  if (!numbered || numbered === 'N/A' || numbered === 'No') return null;
  const match = String(numbered).match(/\/(\d+)/);
  return match ? match[0] : null;
}

function parsePrice(value) {
  if (value === null || value === undefined || value === 'N/A') return null;
  const num = parseFloat(String(value).replace(/[$,]/g, ''));
  return isNaN(num) ? null : num;
}

// ==================== SLABTRACK API ====================
async function loginToSlabTrack() {
  log('Logging into SlabTrack...');

  const response = await fetch(`${CONFIG.slabtrackUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: CONFIG.username,
      password: CONFIG.password
    })
  });

  if (!response.ok) {
    throw new Error(`Login failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  log('Logged in successfully', 'success');
  return data.token;
}

async function importCards(token, cards) {
  log(`Importing ${cards.length} cards to SlabTrack...`);

  const response = await fetch(`${CONFIG.slabtrackUrl}/api/atlas/bulk-import`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ cards })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Import failed: ${response.status} - ${errorText}`);
  }

  return await response.json();
}

// ==================== MAIN ====================
async function main() {
  console.log('\n╔════════════════════════════════════════════════╗');
  console.log('║     IMPORT CARDS TO SLABTRACK                  ║');
  console.log('╚════════════════════════════════════════════════╝\n');

  try {
    // Find Excel files
    const idReport = findExcelFile('identification') || findExcelFile('id-report');
    const priceReport = findExcelFile('pricing');

    if (!idReport) {
      log('No identification-report.xlsx found in current folder', 'error');
      log('Please create identification report first.', 'warn');
      process.exit(1);
    }

    // Parse identification report
    const identifications = parseIdentificationReport(path.join(CONFIG.watchFolder, idReport));

    // Parse pricing report if exists
    let pricing = [];
    if (priceReport) {
      pricing = parsePricingReport(path.join(CONFIG.watchFolder, priceReport));
    } else {
      log('No pricing report found, importing without pricing data', 'warn');
    }

    // Combine data
    const cards = combineData(identifications, pricing);

    if (cards.length === 0) {
      log('No cards to import', 'error');
      process.exit(1);
    }

    // Show preview
    console.log('\n📋 Cards to import:');
    console.log('─'.repeat(60));
    cards.forEach((card, i) => {
      const price = card.ebay_avg ? `$${card.ebay_avg.toFixed(2)}` : 'No pricing';
      const grade = card.is_graded ? `${card.grading_company} ${card.grade}` : 'Raw';
      console.log(`${i + 1}. ${card.player} - ${card.year || ''} ${card.set_name || ''} [${grade}] ${price}`);
    });
    console.log('─'.repeat(60));

    // Login and import
    const token = await loginToSlabTrack();
    const result = await importCards(token, cards);

    // Report results
    console.log('\n' + '═'.repeat(60));
    log(`IMPORT COMPLETE!`, 'success');
    console.log('═'.repeat(60));
    console.log(`  ✅ Imported: ${result.imported} cards`);
    console.log(`  ❌ Failed: ${result.failed || 0} cards`);
    console.log(`  📸 Images uploaded: ${result.imagesUploaded || 0}`);
    console.log(`  ⏱️  Duration: ${result.duration}`);
    console.log(`  💰 Scan credits used: ${result.scanCreditsUsed} (FREE!)`);

    if (result.errors && result.errors.length > 0) {
      console.log('\n⚠️  Errors:');
      result.errors.forEach(err => {
        console.log(`   - Card ${err.index}: ${err.error}`);
      });
    }

    console.log('\n🎉 Cards are now in your SlabTrack collection!');
    console.log(`   View at: https://slabtrack.io/collection\n`);

  } catch (error) {
    log(`Import failed: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
  }
}

main();
