#!/usr/bin/env node
/**
 * CardFlow - FREE Mode Helper
 *
 * Generates prompts for Claude Pro web interface and imports results.
 * $0 cost using your existing Claude Pro subscription!
 *
 * Usage:
 *   node scripts/free-mode.js generate    Generate identify prompt
 *   node scripts/free-mode.js price       Generate pricing prompt
 *   node scripts/free-mode.js import      Import results from JSON file
 *   node scripts/free-mode.js watch       Watch for results files
 *
 * Workflow:
 *   1. Run: npm run free generate
 *   2. Copy prompt to Claude.ai
 *   3. Upload images from 1-new/
 *   4. Copy Claude's response
 *   5. Save as identification-results.json (auto-detected)
 */

const fs = require('fs');
const path = require('path');
const chokidar = require('chokidar');

// Paths
const BASE_DIR = path.join(__dirname, '..');
const NEW_FOLDER = path.join(BASE_DIR, '1-new');
const IDENTIFIED_FOLDER = path.join(BASE_DIR, '2-identified');
const DB_PATH = path.join(BASE_DIR, 'cards.json');
const PROMPTS_FOLDER = path.join(BASE_DIR, 'prompts');

// Ensure folders exist
[NEW_FOLDER, IDENTIFIED_FOLDER, PROMPTS_FOLDER].forEach(f => {
  if (!fs.existsSync(f)) fs.mkdirSync(f, { recursive: true });
});

function log(msg, type = 'info') {
  const icons = { info: 'i', success: '+', error: 'x', warn: '!', free: '$' };
  console.log(`[${icons[type]}] ${msg}`);
}

function loadDb() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {}
  return [];
}

function saveDb(cards) {
  fs.writeFileSync(DB_PATH, JSON.stringify(cards, null, 2));
}

// Find images in 1-new folder
function findNewImages() {
  const imageExts = ['.jpg', '.jpeg', '.png', '.webp'];
  if (!fs.existsSync(NEW_FOLDER)) return [];

  return fs.readdirSync(NEW_FOLDER).filter(f =>
    imageExts.includes(path.extname(f).toLowerCase())
  );
}

// Generate identification prompt for Claude.ai
function generateIdentifyPrompt() {
  const images = findNewImages();

  if (images.length === 0) {
    log('No images found in 1-new/ folder', 'error');
    return null;
  }

  log(`Found ${images.length} images to identify`, 'info');

  const prompt = `I have ${images.length} sports card images to identify. Please analyze each one and return a JSON array with the identification data.

For each card, identify:
- Player name
- Year
- Set name (e.g., Topps Chrome, Panini Prizm)
- Card number
- Parallel type (Base, Refractor, Silver, Gold, etc.)
- Serial numbering if visible (/99, /25, etc.)
- Team
- Sport (Baseball, Basketball, Football, Hockey, Soccer, Pokemon)
- Whether it's graded (in a slab)
- If graded: company (PSA, BGS, SGC, CGC), grade, cert number
- Condition estimate if raw
- Confidence level (high, medium, low)

IMPORTANT: Return ONLY a valid JSON array, no other text. Format:

[
  {
    "filename": "image1.jpg",
    "player": "Patrick Mahomes",
    "year": 2017,
    "set_name": "Panini Prizm",
    "card_number": "269",
    "parallel": "Silver",
    "numbered": null,
    "team": "Kansas City Chiefs",
    "sport": "Football",
    "is_graded": true,
    "grading_company": "PSA",
    "grade": "10",
    "cert_number": "12345678",
    "condition": "gem_mint",
    "confidence": "high",
    "notes": "Rookie card"
  },
  {
    "filename": "image2.jpg",
    "player": "...",
    ...
  }
]

The images are named: ${images.join(', ')}

Now I'll upload the ${images.length} images. Please identify each one.`;

  // Save prompt to file
  const promptPath = path.join(PROMPTS_FOLDER, 'identify-prompt.txt');
  fs.writeFileSync(promptPath, prompt);

  log(`Prompt saved to: ${promptPath}`, 'success');

  return { prompt, images, promptPath };
}

// Generate pricing prompt for identified cards
function generatePricePrompt() {
  const cards = loadDb().filter(c => c.status === 'identified' || c.status === 'approved');

  if (cards.length === 0) {
    log('No cards ready for pricing. Run identification first.', 'error');
    return null;
  }

  log(`Found ${cards.length} cards to price`, 'info');

  const cardList = cards.map((c, i) => {
    const grade = c.is_graded ? `${c.grading_company} ${c.grade}` : 'Raw';
    return `${i + 1}. ${c.player} - ${c.year} ${c.set_name} ${c.parallel || 'Base'} ${c.numbered || ''} - ${grade}`;
  }).join('\n');

  const prompt = `I need pricing research for ${cards.length} sports cards. For each card, provide:
- Estimated value based on recent eBay sold listings
- Price range (low, average, high)
- Sample size (how many recent sales)
- For RAW cards: also include PSA 9 and PSA 10 comparable values

Return ONLY a valid JSON array with this format:

[
  {
    "card_index": 1,
    "player": "Patrick Mahomes",
    "recommended_price": 450.00,
    "sources": {
      "ebay": {
        "low": 380.00,
        "avg": 450.00,
        "high": 520.00,
        "sample_size": 15
      }
    },
    "grading_potential": {
      "raw_value": 150.00,
      "psa9_avg": 350.00,
      "psa10_avg": 800.00,
      "worth_grading": true
    },
    "confidence": "high",
    "market_notes": "Strong demand, prices stable"
  }
]

Cards to price:
${cardList}

Please research current market values for each card.`;

  const promptPath = path.join(PROMPTS_FOLDER, 'price-prompt.txt');
  fs.writeFileSync(promptPath, prompt);

  log(`Prompt saved to: ${promptPath}`, 'success');

  return { prompt, cards, promptPath };
}

// Import identification results from JSON
function importIdentifyResults(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');

    // Try to extract JSON from the content (in case there's extra text)
    let jsonMatch = content.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      // Try parsing the whole thing
      jsonMatch = [content];
    }

    const results = JSON.parse(jsonMatch[0]);

    if (!Array.isArray(results)) {
      throw new Error('Results must be a JSON array');
    }

    log(`Importing ${results.length} identification results`, 'info');

    const cards = loadDb();
    const newCards = [];
    const images = findNewImages();

    results.forEach((result, index) => {
      // Match to image file
      let filename = result.filename;
      if (!filename && images[index]) {
        filename = images[index];
      }

      const card = {
        id: `card_${Date.now()}_${index}`,
        front: filename,
        back: null,
        player: result.player || 'Unknown',
        year: result.year,
        set_name: result.set_name,
        card_number: result.card_number,
        parallel: result.parallel || 'Base',
        numbered: result.numbered,
        team: result.team,
        sport: result.sport,
        is_graded: result.is_graded || false,
        grading_company: result.grading_company,
        grade: result.grade,
        cert_number: result.cert_number,
        condition: result.condition,
        confidence: result.confidence || 'medium',
        notes: result.notes,
        status: 'identified',
        identified_at: new Date().toISOString(),
        identification_source: 'free_mode'
      };

      newCards.push(card);

      // Move image to identified folder
      if (filename) {
        const srcPath = path.join(NEW_FOLDER, filename);
        const dstPath = path.join(IDENTIFIED_FOLDER, filename);
        if (fs.existsSync(srcPath)) {
          try {
            fs.renameSync(srcPath, dstPath);
          } catch (e) {
            log(`Failed to move ${filename}: ${e.message}`, 'warn');
          }
        }
      }
    });

    // Save to database
    const updatedCards = [...cards, ...newCards];
    saveDb(updatedCards);

    log(`Successfully imported ${newCards.length} cards!`, 'success');
    log(`Cards are now visible in the dashboard`, 'info');

    // Rename the results file so it's not re-imported
    const processedPath = filePath.replace('.json', `-imported-${Date.now()}.json`);
    fs.renameSync(filePath, processedPath);

    return newCards;

  } catch (e) {
    log(`Failed to import results: ${e.message}`, 'error');
    return null;
  }
}

// Import pricing results from JSON
function importPriceResults(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');

    let jsonMatch = content.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      jsonMatch = [content];
    }

    const results = JSON.parse(jsonMatch[0]);
    const cards = loadDb();

    // Match results to cards
    const identifiedCards = cards.filter(c => c.status === 'identified' || c.status === 'approved');

    results.forEach(result => {
      const index = (result.card_index || 1) - 1;
      const card = identifiedCards[index];

      if (card) {
        const dbIndex = cards.findIndex(c => c.id === card.id);
        if (dbIndex !== -1) {
          cards[dbIndex] = {
            ...cards[dbIndex],
            recommended_price: result.recommended_price,
            sources: result.sources,
            grading_potential: result.grading_potential,
            market_notes: result.market_notes,
            pricing_confidence: result.confidence,
            status: 'priced',
            priced_at: new Date().toISOString(),
            pricing_source: 'free_mode'
          };
        }
      }
    });

    saveDb(cards);

    log(`Successfully imported pricing for ${results.length} cards!`, 'success');

    const processedPath = filePath.replace('.json', `-imported-${Date.now()}.json`);
    fs.renameSync(filePath, processedPath);

    return results;

  } catch (e) {
    log(`Failed to import pricing: ${e.message}`, 'error');
    return null;
  }
}

// Watch for results files
function watchForResults() {
  log('Watching for results files...', 'info');
  log(`Drop files in: ${BASE_DIR}`, 'info');
  log('Expected files:', 'info');
  log('  - identification-results.json', 'info');
  log('  - pricing-results.json', 'info');
  console.log('');

  const watcher = chokidar.watch(BASE_DIR, {
    ignored: /(^|[\/\\])\..|(node_modules|2-identified|3-priced|4-exported)/,
    persistent: true,
    depth: 0,
    awaitWriteFinish: { stabilityThreshold: 1000 }
  });

  watcher.on('add', (filePath) => {
    const filename = path.basename(filePath).toLowerCase();

    if (filename === 'identification-results.json' || filename.includes('identify') && filename.endsWith('.json')) {
      log(`Detected identification results: ${filePath}`, 'success');
      importIdentifyResults(filePath);
    }

    if (filename === 'pricing-results.json' || filename.includes('price') && filename.endsWith('.json')) {
      log(`Detected pricing results: ${filePath}`, 'success');
      importPriceResults(filePath);
    }
  });

  log('Press Ctrl+C to stop watching', 'info');
}

// Print help and instructions
function showHelp() {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║              CARDFLOW - FREE MODE                            ║
║              $0 Cost Using Claude Pro                        ║
╚══════════════════════════════════════════════════════════════╝

COMMANDS:
  npm run free generate     Generate identification prompt
  npm run free price        Generate pricing prompt
  npm run free import       Import results file
  npm run free watch        Watch for results files (auto-import)

WORKFLOW:

1. IDENTIFY CARDS:
   a) Run: npm run free generate
   b) Open Claude.ai (https://claude.ai)
   c) Copy the prompt from prompts/identify-prompt.txt
   d) Upload images from 1-new/ folder
   e) Paste prompt and send
   f) Copy Claude's JSON response
   g) Save as: identification-results.json in the project folder
   h) CardFlow auto-imports it!

2. PRICE CARDS:
   a) Run: npm run free price
   b) Copy prompt to Claude.ai
   c) Get pricing data
   d) Save as: pricing-results.json
   e) Auto-imported!

3. VIEW RESULTS:
   npm run dashboard
   Open http://localhost:3005

TIPS:
- Claude Pro allows image uploads
- You can upload up to 20 images at once
- For more cards, do multiple batches
- Results auto-import when you save the JSON file

`);
}

// Main
const command = process.argv[2];

switch (command) {
  case 'generate':
  case 'identify':
    console.log('\n' + '='.repeat(60));
    console.log('  FREE MODE - GENERATE IDENTIFY PROMPT');
    console.log('='.repeat(60) + '\n');

    const identifyData = generateIdentifyPrompt();
    if (identifyData) {
      console.log('\n' + '-'.repeat(60));
      console.log('NEXT STEPS:');
      console.log('-'.repeat(60));
      console.log('1. Open Claude.ai: https://claude.ai');
      console.log(`2. Open prompt file: ${identifyData.promptPath}`);
      console.log('3. Copy the prompt');
      console.log(`4. Upload ${identifyData.images.length} images from: ${NEW_FOLDER}`);
      console.log('5. Paste prompt and send');
      console.log('6. Copy Claude\'s JSON response');
      console.log('7. Save as: identification-results.json');
      console.log('8. Run: npm run free watch  (to auto-import)');
      console.log('-'.repeat(60) + '\n');
    }
    break;

  case 'price':
  case 'pricing':
    console.log('\n' + '='.repeat(60));
    console.log('  FREE MODE - GENERATE PRICING PROMPT');
    console.log('='.repeat(60) + '\n');

    const priceData = generatePricePrompt();
    if (priceData) {
      console.log('\n' + '-'.repeat(60));
      console.log('NEXT STEPS:');
      console.log('-'.repeat(60));
      console.log('1. Open Claude.ai: https://claude.ai');
      console.log(`2. Open prompt file: ${priceData.promptPath}`);
      console.log('3. Copy the prompt and paste in Claude');
      console.log('4. Copy Claude\'s JSON response');
      console.log('5. Save as: pricing-results.json');
      console.log('6. Run: npm run free watch  (to auto-import)');
      console.log('-'.repeat(60) + '\n');
    }
    break;

  case 'import':
    const importFile = process.argv[3];
    if (!importFile) {
      log('Please specify a file to import', 'error');
      log('Usage: npm run free import results.json', 'info');
      process.exit(1);
    }

    const fullPath = path.isAbsolute(importFile) ? importFile : path.join(process.cwd(), importFile);

    if (importFile.toLowerCase().includes('price')) {
      importPriceResults(fullPath);
    } else {
      importIdentifyResults(fullPath);
    }
    break;

  case 'watch':
    console.log('\n' + '='.repeat(60));
    console.log('  FREE MODE - WATCHING FOR RESULTS');
    console.log('='.repeat(60) + '\n');
    watchForResults();
    break;

  default:
    showHelp();
}
