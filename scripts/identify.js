#!/usr/bin/env node
/**
 * CardFlow - Identify Script
 *
 * Scans images in 1-new/, identifies cards using Claude Vision API,
 * creates Excel report with thumbnails, moves to 2-identified/
 *
 * Usage: node scripts/identify.js
 *
 * Required: ANTHROPIC_API_KEY environment variable
 */

const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');

// Load config and costs
const configPath = path.join(__dirname, '..', 'config.json');
const costsPath = path.join(__dirname, '..', 'costs.json');

function loadConfig() {
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
  } catch (e) {}
  return {
    models: {
      sonnet4: { id: 'claude-sonnet-4-20250514', name: 'Sonnet 4' }
    },
    defaults: { identify_model: 'sonnet4' }
  };
}

function loadCosts() {
  try {
    if (fs.existsSync(costsPath)) {
      return JSON.parse(fs.readFileSync(costsPath, 'utf8'));
    }
  } catch (e) {}
  return { total: { input_tokens: 0, output_tokens: 0, estimated_cost: 0, cards_processed: 0 }, by_model: {}, by_date: {} };
}

function saveCosts(costs) {
  fs.writeFileSync(costsPath, JSON.stringify(costs, null, 2));
}

function trackUsage(modelKey, inputTokens, outputTokens, taskType = 'identify') {
  const costs = loadCosts();
  const config = loadConfig();
  const model = config.models[modelKey] || {};

  const inputCost = (inputTokens / 1000000) * (model.input_cost_per_1m || 3);
  const outputCost = (outputTokens / 1000000) * (model.output_cost_per_1m || 15);
  const totalCost = inputCost + outputCost;

  // Update totals
  costs.total.input_tokens += inputTokens;
  costs.total.output_tokens += outputTokens;
  costs.total.estimated_cost += totalCost;
  costs.total.cards_processed += 1;

  // Update by model
  if (!costs.by_model[modelKey]) {
    costs.by_model[modelKey] = { input_tokens: 0, output_tokens: 0, estimated_cost: 0, cards_processed: 0, identify_count: 0, price_count: 0 };
  }
  costs.by_model[modelKey].input_tokens += inputTokens;
  costs.by_model[modelKey].output_tokens += outputTokens;
  costs.by_model[modelKey].estimated_cost += totalCost;
  costs.by_model[modelKey].cards_processed += 1;
  costs.by_model[modelKey][`${taskType}_count`] += 1;

  // Update by date
  const today = new Date().toISOString().split('T')[0];
  if (!costs.by_date[today]) {
    costs.by_date[today] = { input_tokens: 0, output_tokens: 0, estimated_cost: 0, cards_processed: 0 };
  }
  costs.by_date[today].input_tokens += inputTokens;
  costs.by_date[today].output_tokens += outputTokens;
  costs.by_date[today].estimated_cost += totalCost;
  costs.by_date[today].cards_processed += 1;

  saveCosts(costs);
  return totalCost;
}

// Parse CLI arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const result = { model: null };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--model' && args[i + 1]) {
      result.model = args[i + 1];
      i++;
    }
  }
  return result;
}

const cliArgs = parseArgs();
const appConfig = loadConfig();

// Get model to use (CLI > config default)
function getModelConfig() {
  const modelKey = cliArgs.model || appConfig.defaults?.identify_model || 'sonnet4';
  const model = appConfig.models?.[modelKey];

  if (!model) {
    console.error(`Unknown model: ${modelKey}`);
    console.error('Available models:', Object.keys(appConfig.models || {}).join(', '));
    process.exit(1);
  }

  return { key: modelKey, ...model };
}

// Configuration
const CONFIG = {
  newFolder: path.join(__dirname, '..', '1-new'),
  identifiedFolder: path.join(__dirname, '..', '2-identified'),
  reportsFolder: path.join(__dirname, '..'),
  imageExtensions: ['.jpg', '.jpeg', '.png', '.webp'],
  apiTimeout: 30000, // 30 second timeout
  pairPatterns: [
    { front: /(.+)-front\./i, back: /(.+)-back\./i },
    { front: /(.+)_front\./i, back: /(.+)_back\./i },
    { front: /(.+)-1\./i, back: /(.+)-2\./i },
    { front: /(.+)_1\./i, back: /(.+)_2\./i },
    { front: /(.+)_a\./i, back: /(.+)_b\./i },
    { front: /(.+)\(1\)\./i, back: /(.+)\(2\)\./i },
    { front: /(.+)\./i, back: /(.+)b\./i }
  ],
  email: {
    enabled: !!process.env.SMTP_USER,
    recipient: process.env.EMAIL_TO || 'huddleeco@gmail.com'
  }
};

// Get API key from config or environment
function getApiKey() {
  const config = loadConfig();

  // Priority: 1. Config file, 2. Environment variable
  if (config.api_key) {
    return { key: config.api_key, source: 'config.json' };
  }

  if (process.env.ANTHROPIC_API_KEY) {
    return { key: process.env.ANTHROPIC_API_KEY, source: 'environment variable' };
  }

  return null;
}

// Check for API key
function checkApiKey() {
  const keyInfo = getApiKey();

  if (!keyInfo) {
    console.error('\n' + '='.repeat(60));
    console.error('  ERROR: No API key configured');
    console.error('='.repeat(60));
    console.error('\nTo fix this, either:\n');
    console.error('  1. Add your API key in the dashboard Settings -> API Key tab');
    console.error('     (This saves it to config.json)\n');
    console.error('  2. Or set an environment variable:\n');
    console.error('     Windows (PowerShell):');
    console.error('       $env:ANTHROPIC_API_KEY = "your-api-key-here"');
    console.error('\n     Windows (Command Prompt):');
    console.error('       set ANTHROPIC_API_KEY=your-api-key-here');
    console.error('\n     Linux/Mac:');
    console.error('       export ANTHROPIC_API_KEY=your-api-key-here');
    console.error('\nGet your API key at: https://console.anthropic.com/\n');
    process.exit(1);
  }

  log(`Using API key from ${keyInfo.source}`, 'success');
  return new Anthropic({ apiKey: keyInfo.key });
}

// Initialize Anthropic client
let anthropic = null;

// Database for cards
let cardsDb = [];
const dbPath = path.join(__dirname, '..', 'cards.json');

// Load existing database
function loadDb() {
  try {
    if (fs.existsSync(dbPath)) {
      cardsDb = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    }
  } catch (e) {
    cardsDb = [];
  }
}

// Save database
function saveDb() {
  fs.writeFileSync(dbPath, JSON.stringify(cardsDb, null, 2));
}

// Logging
function log(message, type = 'info') {
  const icons = { info: '\u2139\uFE0F', success: '\u2705', error: '\u274C', warn: '\u26A0\uFE0F', card: '\uD83C\uDCCF' };
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[${timestamp}] ${icons[type] || ''} ${message}`);
}

// Find image files
function findImages() {
  if (!fs.existsSync(CONFIG.newFolder)) {
    fs.mkdirSync(CONFIG.newFolder, { recursive: true });
    return [];
  }

  const files = fs.readdirSync(CONFIG.newFolder);
  return files.filter(f => {
    const ext = path.extname(f).toLowerCase();
    return CONFIG.imageExtensions.includes(ext);
  });
}

// Pair front/back images
function pairImages(files) {
  const pairs = [];
  const used = new Set();

  for (const file of files) {
    if (used.has(file)) continue;

    const baseName = path.basename(file);
    let paired = false;

    // Try each pairing pattern
    for (const pattern of CONFIG.pairPatterns) {
      const frontMatch = baseName.match(pattern.front);
      if (frontMatch) {
        const baseId = frontMatch[1];

        // Look for matching back
        for (const otherFile of files) {
          if (used.has(otherFile) || otherFile === file) continue;

          const otherBase = path.basename(otherFile);
          const backMatch = otherBase.match(pattern.back);

          if (backMatch && backMatch[1].toLowerCase() === baseId.toLowerCase()) {
            pairs.push({
              id: `card_${Date.now()}_${pairs.length}`,
              front: file,
              back: otherFile,
              baseName: baseId,
              status: 'pending'
            });
            used.add(file);
            used.add(otherFile);
            paired = true;
            break;
          }
        }
        if (paired) break;
      }
    }

    // Single image (no pair found) - likely a graded card slab photo
    if (!used.has(file)) {
      const nameWithoutExt = path.basename(file, path.extname(file));
      pairs.push({
        id: `card_${Date.now()}_${pairs.length}`,
        front: file,
        back: null,
        baseName: nameWithoutExt,
        status: 'pending'
      });
      used.add(file);
    }
  }

  return pairs;
}

// Convert image to base64 with media type
function imageToBase64(imagePath) {
  const buffer = fs.readFileSync(imagePath);
  const ext = path.extname(imagePath).toLowerCase();
  const mediaTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.gif': 'image/gif'
  };
  return {
    type: 'base64',
    media_type: mediaTypes[ext] || 'image/jpeg',
    data: buffer.toString('base64')
  };
}

// Identify a single card using Claude Vision API
async function identifyCard(pair, modelOverride = null) {
  const frontPath = path.join(CONFIG.newFolder, pair.front);
  const backPath = pair.back ? path.join(CONFIG.newFolder, pair.back) : null;

  // Get model configuration
  const modelConfig = modelOverride || getModelConfig();
  log(`Identifying: ${pair.baseName} (using ${modelConfig.name})`, 'card');

  // Build content array with images
  const content = [];

  // Add front image
  try {
    const frontSize = fs.statSync(frontPath).size;
    log(`  Loading front image: ${pair.front} (${(frontSize / 1024).toFixed(1)} KB)`, 'info');
    content.push({
      type: 'image',
      source: imageToBase64(frontPath)
    });
  } catch (e) {
    log(`  Failed to load front image: ${e.message}`, 'error');
    throw new Error(`Cannot load front image: ${e.message}`);
  }

  // Add back image if exists
  if (backPath && fs.existsSync(backPath)) {
    try {
      const backSize = fs.statSync(backPath).size;
      log(`  Loading back image: ${pair.back} (${(backSize / 1024).toFixed(1)} KB)`, 'info');
      content.push({
        type: 'image',
        source: imageToBase64(backPath)
      });
    } catch (e) {
      log(`  Warning: Failed to load back image: ${e.message}`, 'warn');
    }
  }

  // Add prompt — matches SlabTrack scanner prompt for consistency
  content.push({
    type: 'text',
    text: `Extract card data from ALL images provided.

${backPath ? 'Front and back images provided.' : 'Front image only.'}

SPORT DETECTION (CHECK FIRST):
Look at the TEAM NAME to determine sport:
- BASEBALL (MLB): Dodgers, Yankees, Cubs, Mets, Cardinals, Red Sox, Giants, Braves, Astros, Phillies, Padres, Mariners, Rangers, Orioles, Twins, Guardians, Royals, Tigers
- BASKETBALL (NBA): Lakers, Celtics, Heat, Warriors, Bulls, Nets, Knicks, Suns, Bucks, 76ers, Mavericks, Grizzlies, Pelicans, Clippers, Kings, Hawks, Cavaliers, Raptors, Thunder
- FOOTBALL (NFL): Chiefs, Cowboys, Eagles, 49ers, Bills, Dolphins, Patriots, Packers, Ravens, Bengals, Browns, Steelers, Titans, Colts, Jaguars, Texans, Broncos, Raiders, Chargers
- HOCKEY (NHL): Bruins, Rangers, Maple Leafs, Canadiens, Penguins, Blackhawks, Red Wings, Flyers, Capitals, Lightning, Panthers, Hurricanes, Devils, Islanders

COLOR (check card BORDER edge, ignore holographic reflections):
Green=grass/emerald, Red=fire truck, Pink=light red/magenta, Orange=pumpkin, Blue=sky/navy
Aqua=teal/blue-green (NOT green), Purple=violet/deep purple
WARNING: Aqua/teal is NOT Green — if the border is blue-green/teal, the parallel is "Aqua" not "Green".

PARALLEL NAMING (use SportsCardsPro format):
- Use color only, NOT "Color Prizm" or "Color Refractor": Orange, Green, Red, Blue, Pink, Silver, Gold, Aqua, Purple, Teal
- Exception: "Refractor" for base chrome refractor cards
- For Mosaic: use "Mosaic" not "Mosaic Prizm"
- Inserts are NOT parallels: Game Ticket, Fireworks, Kaboom, Downtown = set parallel to "Base"

YEAR DETECTION (CRITICAL):
- For GRADED cards: the slab label shows the year — read it, most reliable source
- For RAW cards: check the BACK of the card, bottom fine print, for copyright year (e.g., "© 2024 Panini" or "© 2026 Topps")
- The copyright year on the back IS the card year — USE IT
- Do NOT use years from the set name on the front (e.g., "2025 All Topps Team" is a SET NAME, not the card year)
- Do NOT guess the year from the player's rookie year or jersey number

SET NAME vs MANUFACTURER (CRITICAL):
- set_name must be the PRODUCT name, NOT the manufacturer/brand
- Manufacturers: Topps, Panini, Upper Deck, Leaf, Bowman (parent brand)
- Products: Mosaic, Prizm, Select, Optic, Donruss, Chrome, Heritage, Series 1, Series 2, Bowman Chrome, Finest, Stadium Club, Allen & Ginter, Absolute, Contenders, Hoops, Court Kings, National Treasures, Spectra, Revolution, Score, Prestige, Phoenix
- "Topps" alone is WRONG — look for the actual product (Chrome, Heritage, Series 1, etc.)
- "Panini" alone is WRONG — look for the actual product (Mosaic, Prizm, Select, etc.)
- If you see "Panini Mosaic" the set_name is "Mosaic" (drop the manufacturer)
- If you see "Topps Chrome" the set_name is "Topps Chrome" (Topps Chrome IS the product name)

CRITICAL:
- Graded? Extract company/grade/cert from slab label
- Auto? Set is_autographed=true
- Serial (15/99)? Extract both numbers
- Check BACK image for serial numbers, parallel text, copyright year, and set name

JSON only:
{
  "player": "Full player name",
  "year": 2024,
  "set_name": "Product name (no year, no manufacturer)",
  "card_number": "Card number",
  "parallel": "Base or color variant",
  "numbered": "/99 or null",
  "team": "Team name",
  "sport": "Baseball/Basketball/Football/Hockey/Pokemon",
  "is_graded": true,
  "grading_company": "PSA/BGS/SGC/CGC or null",
  "grade": "10 or null",
  "cert_number": "12345678 or null",
  "is_autographed": false,
  "condition": "mint, near_mint, excellent, good, fair, poor",
  "confidence": "high, medium, or low",
  "notes": "Any special observations"
}`
  });

  // Make API call with timeout
  log(`  Calling Claude API (${modelConfig.id}, timeout: ${CONFIG.apiTimeout / 1000}s)...`, 'info');
  const startTime = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.apiTimeout);

    const response = await anthropic.messages.create({
      model: modelConfig.id,
      max_tokens: 1024,
      messages: [{ role: 'user', content }]
    }, {
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    // Track usage and cost
    const inputTokens = response.usage?.input_tokens || 0;
    const outputTokens = response.usage?.output_tokens || 0;
    const cost = trackUsage(modelConfig.key, inputTokens, outputTokens, 'identify');

    log(`  API response received (${elapsed}s, ${inputTokens}+${outputTokens} tokens, $${cost.toFixed(4)})`, 'success');

    // Extract text response
    const textContent = response.content.find(c => c.type === 'text');
    if (!textContent) {
      throw new Error('No text in API response');
    }

    const output = textContent.text;

    // Debug: show raw response if no JSON found
    const jsonMatch = output.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      log(`  Raw response: ${output.substring(0, 200)}...`, 'warn');
      throw new Error('No JSON in response');
    }

    const data = JSON.parse(jsonMatch[0]);
    return {
      ...pair,
      ...data,
      identified_at: new Date().toISOString(),
      model_used: modelConfig.key,
      model_name: modelConfig.name,
      api_cost: cost,
      tokens: { input: inputTokens, output: outputTokens }
    };

  } catch (e) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    if (e.name === 'AbortError' || e.message?.includes('abort')) {
      log(`  API timeout after ${elapsed}s`, 'error');
      throw new Error(`API timeout after ${CONFIG.apiTimeout / 1000}s`);
    }

    if (e.status === 401) {
      log(`  API authentication failed - check your ANTHROPIC_API_KEY`, 'error');
      throw new Error('Invalid API key');
    }

    if (e.status === 429) {
      log(`  Rate limited - too many requests`, 'error');
      throw new Error('Rate limited');
    }

    log(`  API error (${elapsed}s): ${e.message}`, 'error');

    // Return partial result for parse errors
    if (e.message?.includes('JSON')) {
      return {
        ...pair,
        player: 'Unknown',
        year: null,
        set_name: null,
        card_number: null,
        parallel: null,
        numbered: null,
        team: null,
        sport: 'Unknown',
        is_graded: false,
        grading_company: null,
        grade: null,
        cert_number: null,
        condition: 'unknown',
        confidence: 'low',
        notes: 'Identification failed - manual review needed',
        identified_at: new Date().toISOString()
      };
    }

    throw e;
  }
}

// Create thumbnail
async function createThumbnail(imagePath, size = 100) {
  try {
    const sharp = require('sharp');
    const buffer = await sharp(imagePath)
      .resize(size, size, { fit: 'inside' })
      .jpeg({ quality: 80 })
      .toBuffer();
    return buffer;
  } catch (e) {
    // Return null if sharp fails (will skip thumbnail)
    return null;
  }
}

// Generate Excel report
async function generateReport(cards) {
  const wb = XLSX.utils.book_new();

  // Prepare data rows
  const rows = [
    ['#', 'ID', 'Player', 'Year', 'Set', 'Card #', 'Parallel', 'Numbered',
     'Team', 'Sport', 'Graded', 'Company', 'Grade', 'Cert #',
     'Condition', 'Confidence', 'Notes', 'Front Image', 'Back Image', 'Status']
  ];

  cards.forEach((card, idx) => {
    rows.push([
      idx + 1,
      card.id,
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
      card.confidence || '',
      card.notes || '',
      card.front || '',
      card.back || '',
      card.status || 'pending'
    ]);
  });

  const ws = XLSX.utils.aoa_to_sheet(rows);

  // Set column widths
  ws['!cols'] = [
    { wch: 4 }, { wch: 20 }, { wch: 20 }, { wch: 6 }, { wch: 25 },
    { wch: 10 }, { wch: 20 }, { wch: 10 }, { wch: 20 }, { wch: 12 },
    { wch: 8 }, { wch: 10 }, { wch: 8 }, { wch: 12 },
    { wch: 12 }, { wch: 12 }, { wch: 40 }, { wch: 30 }, { wch: 30 }, { wch: 10 }
  ];

  XLSX.utils.book_append_sheet(wb, ws, 'Identification Report');

  const reportPath = path.join(CONFIG.reportsFolder, 'identification-report.xlsx');
  XLSX.writeFile(wb, reportPath);

  log(`Report saved: ${reportPath}`, 'success');
  return reportPath;
}

// Move files to identified folder
function moveToIdentified(cards) {
  if (!fs.existsSync(CONFIG.identifiedFolder)) {
    fs.mkdirSync(CONFIG.identifiedFolder, { recursive: true });
  }

  for (const card of cards) {
    try {
      // Move front image
      const frontSrc = path.join(CONFIG.newFolder, card.front);
      const frontDst = path.join(CONFIG.identifiedFolder, card.front);
      if (fs.existsSync(frontSrc)) {
        fs.renameSync(frontSrc, frontDst);
      }

      // Move back image if exists
      if (card.back) {
        const backSrc = path.join(CONFIG.newFolder, card.back);
        const backDst = path.join(CONFIG.identifiedFolder, card.back);
        if (fs.existsSync(backSrc)) {
          fs.renameSync(backSrc, backDst);
        }
      }
    } catch (e) {
      log(`Failed to move ${card.front}: ${e.message}`, 'warn');
    }
  }
}

// Send email notification
async function sendNotification(cards) {
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

    const highConfidence = cards.filter(c => c.confidence === 'high').length;
    const needsReview = cards.filter(c => c.confidence !== 'high').length;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: CONFIG.email.recipient,
      subject: `\uD83C\uDCCF CardFlow: ${cards.length} cards identified`,
      html: `
        <h2>Card Identification Complete</h2>
        <p><strong>${cards.length}</strong> cards have been identified.</p>
        <ul>
          <li>\u2705 High confidence: ${highConfidence}</li>
          <li>\u26A0\uFE0F Needs review: ${needsReview}</li>
        </ul>
        <p><a href="http://localhost:3005">Open Dashboard to Review</a></p>
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
  console.log('\n' + '='.repeat(50));
  console.log('  CARDFLOW - IDENTIFY');
  console.log('='.repeat(50) + '\n');

  // Check if in FREE mode
  if (appConfig.mode === 'free') {
    console.log('');
    log('FREE MODE ACTIVE - $0 cost using Claude Pro', 'success');
    console.log('');
    console.log('  For FREE mode, use these commands instead:');
    console.log('    npm run free generate    Generate prompt for Claude.ai');
    console.log('    npm run free:watch       Watch for results');
    console.log('');
    console.log('  Or switch to API mode in Settings to use this command.');
    console.log('');
    console.log('  Running anyway with API (will cost money)...');
    console.log('');
  }

  // Check API key and initialize client
  anthropic = checkApiKey();
  log('API key found, client initialized', 'success');

  // Show model info
  const modelConfig = getModelConfig();
  log(`Model: ${modelConfig.name} (${modelConfig.id})`, 'info');
  log(`Estimated cost: ~$${modelConfig.estimated_cost_per_card || 0.01}/card`, 'info');
  console.log('');

  loadDb();

  // Find images
  const images = findImages();
  if (images.length === 0) {
    log('No images found in 1-new/ folder', 'warn');
    log('Drop card images there and run again.', 'info');
    return;
  }

  log(`Found ${images.length} images`, 'info');

  // Pair images
  const pairs = pairImages(images);
  log(`Detected ${pairs.length} cards (${pairs.filter(p => p.back).length} with front/back pairs)`, 'info');

  // Identify each card
  const identifiedCards = [];
  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i];
    log(`[${i + 1}/${pairs.length}] Processing ${pair.baseName}...`, 'info');

    try {
      const card = await identifyCard(pair);
      card.status = 'identified';
      identifiedCards.push(card);
      log(`  \u2192 ${card.player || 'Unknown'} - ${card.year || '?'} ${card.set_name || ''}`, 'success');
    } catch (e) {
      log(`  \u2192 Failed: ${e.message}`, 'error');
      pair.status = 'error';
      pair.notes = e.message;
      identifiedCards.push(pair);
    }
  }

  // Save to database
  cardsDb = [...cardsDb, ...identifiedCards];
  saveDb();

  // Generate report
  await generateReport(identifiedCards);

  // Move files
  moveToIdentified(identifiedCards);

  // Send notification
  await sendNotification(identifiedCards);

  // Calculate total cost
  const totalCost = identifiedCards.reduce((sum, c) => sum + (c.api_cost || 0), 0);
  const costs = loadCosts();

  // Summary
  console.log('\n' + '\u2550'.repeat(50));
  log(`COMPLETE: ${identifiedCards.length} cards identified`, 'success');
  log(`Model: ${modelConfig.name}`, 'info');
  log(`Session cost: $${totalCost.toFixed(4)}`, 'info');
  log(`Total cost (all time): $${costs.total.estimated_cost.toFixed(4)}`, 'info');
  console.log('\u2550'.repeat(50));
  console.log(`
  Next steps:
  1. Open dashboard: npm run dashboard
  2. Review and edit cards at http://localhost:3005
  3. Run pricing: npm run price

  Model options:
  --model sonnet4   Best accuracy (default, recommended)
  --model haiku35   Fast and accurate ($0.004/card)
  --model sonnet3   Legacy option
  `);
}

main().catch(e => {
  log(`Fatal error: ${e.message}`, 'error');
  process.exit(1);
});
