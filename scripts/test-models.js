#!/usr/bin/env node
/**
 * CardFlow - Batch Model Testing
 *
 * Run batch tests to evaluate model performance across multiple cards.
 * Useful for determining optimal model for your card types.
 *
 * Usage:
 *   node scripts/test-models.js --batch 10
 *   node scripts/test-models.js --batch 5 --model haiku3
 *   npm run test-models -- --batch 10
 *
 * Required: ANTHROPIC_API_KEY environment variable
 */

const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');

// Paths
const configPath = path.join(__dirname, '..', 'config.json');
const costsPath = path.join(__dirname, '..', 'costs.json');
const newFolder = path.join(__dirname, '..', '1-new');

function loadConfig() {
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
  } catch (e) {}
  return { models: {} };
}

function loadCosts() {
  try {
    if (fs.existsSync(costsPath)) {
      return JSON.parse(fs.readFileSync(costsPath, 'utf8'));
    }
  } catch (e) {}
  return { total: {}, by_model: {}, by_date: {} };
}

function saveCosts(costs) {
  fs.writeFileSync(costsPath, JSON.stringify(costs, null, 2));
}

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

function checkApiKey() {
  const keyInfo = getApiKey();

  if (!keyInfo) {
    console.error('ERROR: No API key configured');
    console.error('Add your API key in the dashboard Settings -> API Key tab');
    console.error('Or set: $env:ANTHROPIC_API_KEY = "your-key"');
    process.exit(1);
  }

  console.log(`Using API key from ${keyInfo.source}`);
  return new Anthropic({ apiKey: keyInfo.key });
}

function parseArgs() {
  const args = process.argv.slice(2);
  const result = {
    batch: 5,
    model: null,
    allModels: false
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--batch' && args[i + 1]) {
      result.batch = parseInt(args[i + 1]) || 5;
      i++;
    }
    if (args[i] === '--model' && args[i + 1]) {
      result.model = args[i + 1];
      i++;
    }
    if (args[i] === '--all') {
      result.allModels = true;
    }
  }
  return result;
}

function log(msg, type = 'info') {
  const icons = { info: 'i', success: '+', error: 'x', warn: '!', test: 'T' };
  const ts = new Date().toLocaleTimeString();
  console.log(`[${ts}] [${icons[type] || ' '}] ${msg}`);
}

function imageToBase64(imagePath) {
  const buffer = fs.readFileSync(imagePath);
  const ext = path.extname(imagePath).toLowerCase();
  const mediaTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp'
  };
  return {
    type: 'base64',
    media_type: mediaTypes[ext] || 'image/jpeg',
    data: buffer.toString('base64')
  };
}

function findImages(limit) {
  const imageExts = ['.jpg', '.jpeg', '.png', '.webp'];

  if (!fs.existsSync(newFolder)) {
    return [];
  }

  let files = fs.readdirSync(newFolder).filter(f =>
    imageExts.includes(path.extname(f).toLowerCase())
  );

  // Randomize for better sampling
  files = files.sort(() => Math.random() - 0.5);

  if (limit > 0) {
    files = files.slice(0, limit);
  }

  return files.map(f => ({
    filename: f,
    path: path.join(newFolder, f)
  }));
}

async function testModel(anthropic, images, modelConfig) {
  const results = {
    model: modelConfig.key,
    modelName: modelConfig.name,
    total: 0,
    success: 0,
    failed: 0,
    parseErrors: 0,
    totalTime: 0,
    totalTokens: 0,
    totalCost: 0,
    cards: []
  };

  for (let i = 0; i < images.length; i++) {
    const image = images[i];
    log(`  [${i + 1}/${images.length}] ${image.filename}`, 'test');

    const content = [
      { type: 'image', source: imageToBase64(image.path) },
      {
        type: 'text',
        text: `Identify this sports card. Return ONLY JSON:
{
  "player": "name",
  "year": 2024,
  "set_name": "set",
  "card_number": "number",
  "parallel": "type or null",
  "is_graded": true,
  "grade": "number or null",
  "confidence": "high/medium/low"
}`
      }
    ];

    const startTime = Date.now();
    results.total++;

    try {
      const response = await anthropic.messages.create({
        model: modelConfig.id,
        max_tokens: 1024,
        messages: [{ role: 'user', content }]
      });

      const elapsed = Date.now() - startTime;
      const inputTokens = response.usage?.input_tokens || 0;
      const outputTokens = response.usage?.output_tokens || 0;

      const inputCost = (inputTokens / 1000000) * (modelConfig.input_cost_per_1m || 3);
      const outputCost = (outputTokens / 1000000) * (modelConfig.output_cost_per_1m || 15);
      const cost = inputCost + outputCost;

      results.totalTime += elapsed;
      results.totalTokens += inputTokens + outputTokens;
      results.totalCost += cost;

      const textContent = response.content.find(c => c.type === 'text');
      const jsonMatch = textContent?.text.match(/\{[\s\S]*\}/);

      if (jsonMatch) {
        try {
          const parsed = JSON.parse(jsonMatch[0]);
          results.success++;
          results.cards.push({
            filename: image.filename,
            success: true,
            player: parsed.player,
            year: parsed.year,
            confidence: parsed.confidence,
            elapsed,
            cost
          });
          log(`    -> ${parsed.player || 'Unknown'} (${elapsed}ms)`, 'success');
        } catch (e) {
          results.parseErrors++;
          results.failed++;
          results.cards.push({ filename: image.filename, success: false, error: 'JSON parse error', elapsed, cost });
          log(`    -> Parse error (${elapsed}ms)`, 'error');
        }
      } else {
        results.parseErrors++;
        results.failed++;
        results.cards.push({ filename: image.filename, success: false, error: 'No JSON in response', elapsed, cost });
        log(`    -> No JSON (${elapsed}ms)`, 'error');
      }

    } catch (e) {
      const elapsed = Date.now() - startTime;
      results.failed++;
      results.cards.push({ filename: image.filename, success: false, error: e.message, elapsed, cost: 0 });
      log(`    -> API error: ${e.message}`, 'error');
    }
  }

  return results;
}

function generateReport(allResults) {
  const wb = XLSX.utils.book_new();

  // Summary
  const summaryRows = [
    ['Batch Model Test Results'],
    ['Generated:', new Date().toISOString()],
    [],
    ['Model', 'Success Rate', 'Avg Time (ms)', 'Avg Cost/Card', 'Total Cost', 'Parse Errors']
  ];

  for (const result of allResults) {
    const successRate = result.total > 0 ? ((result.success / result.total) * 100).toFixed(1) : 0;
    const avgTime = result.total > 0 ? Math.round(result.totalTime / result.total) : 0;
    const avgCost = result.total > 0 ? (result.totalCost / result.total).toFixed(4) : 0;

    summaryRows.push([
      result.modelName,
      `${successRate}%`,
      avgTime,
      `$${avgCost}`,
      `$${result.totalCost.toFixed(4)}`,
      result.parseErrors
    ]);
  }

  const summaryWs = XLSX.utils.aoa_to_sheet(summaryRows);
  XLSX.utils.book_append_sheet(wb, summaryWs, 'Summary');

  // Details for each model
  for (const result of allResults) {
    const rows = [['Filename', 'Success', 'Player', 'Year', 'Confidence', 'Time (ms)', 'Cost']];
    for (const card of result.cards) {
      rows.push([
        card.filename,
        card.success ? 'Yes' : 'No',
        card.player || card.error || '-',
        card.year || '-',
        card.confidence || '-',
        card.elapsed,
        `$${card.cost.toFixed(4)}`
      ]);
    }
    const ws = XLSX.utils.aoa_to_sheet(rows);
    XLSX.utils.book_append_sheet(wb, ws, result.model.substring(0, 31));
  }

  const reportPath = path.join(__dirname, '..', 'test-results.xlsx');
  XLSX.writeFile(wb, reportPath);
  return reportPath;
}

async function main() {
  console.log('\n' + '='.repeat(60));
  console.log('  CARDFLOW - BATCH MODEL TESTING');
  console.log('='.repeat(60) + '\n');

  const anthropic = checkApiKey();
  const args = parseArgs();
  const config = loadConfig();

  // Determine which models to test
  let modelsToTest = [];

  if (args.allModels) {
    modelsToTest = Object.entries(config.models).map(([key, model]) => ({ key, ...model }));
  } else if (args.model) {
    if (config.models[args.model]) {
      modelsToTest = [{ key: args.model, ...config.models[args.model] }];
    } else {
      log(`Unknown model: ${args.model}`, 'error');
      log('Available: ' + Object.keys(config.models).join(', '), 'info');
      process.exit(1);
    }
  } else {
    // Default to comparing main models
    const defaultModels = ['sonnet4', 'haiku35'];
    modelsToTest = defaultModels
      .filter(m => config.models[m])
      .map(m => ({ key: m, ...config.models[m] }));
  }

  if (modelsToTest.length === 0) {
    log('No models to test', 'error');
    process.exit(1);
  }

  // Find images
  const images = findImages(args.batch);
  if (images.length === 0) {
    log('No images found in 1-new/ folder', 'error');
    return;
  }

  log(`Testing ${modelsToTest.length} model(s) on ${images.length} images`, 'info');
  log(`Models: ${modelsToTest.map(m => m.name).join(', ')}`, 'info');
  console.log('');

  // Run tests
  const allResults = [];

  for (const model of modelsToTest) {
    console.log('-'.repeat(50));
    log(`Testing: ${model.name} (${model.id})`, 'test');
    console.log('');

    const results = await testModel(anthropic, images, model);
    allResults.push(results);

    const successRate = results.total > 0 ? ((results.success / results.total) * 100).toFixed(0) : 0;
    const avgTime = results.total > 0 ? Math.round(results.totalTime / results.total) : 0;

    console.log('');
    log(`${model.name}: ${successRate}% success, ${avgTime}ms avg, $${results.totalCost.toFixed(4)} total`, 'info');
    console.log('');
  }

  // Generate report
  const reportPath = generateReport(allResults);

  // Summary
  console.log('='.repeat(60));
  log('BATCH TEST COMPLETE', 'success');
  console.log('');

  // Rank models
  const ranked = [...allResults].sort((a, b) => {
    // Primary: success rate, Secondary: cost efficiency
    const aRate = a.total > 0 ? a.success / a.total : 0;
    const bRate = b.total > 0 ? b.success / b.total : 0;
    if (Math.abs(aRate - bRate) > 0.1) return bRate - aRate;
    const aCost = a.total > 0 ? a.totalCost / a.total : 0;
    const bCost = b.total > 0 ? b.totalCost / b.total : 0;
    return aCost - bCost;
  });

  log('Ranking (by success rate, then cost):', 'info');
  ranked.forEach((r, i) => {
    const rate = r.total > 0 ? ((r.success / r.total) * 100).toFixed(0) : 0;
    const avgCost = r.total > 0 ? (r.totalCost / r.total).toFixed(4) : 0;
    log(`  ${i + 1}. ${r.modelName}: ${rate}% success, $${avgCost}/card`, 'info');
  });

  console.log('');
  log(`Report saved: ${reportPath}`, 'success');

  // Recommendation
  const best = ranked[0];
  const cheapest = [...allResults].sort((a, b) => {
    const aCost = a.total > 0 ? a.totalCost / a.total : 999;
    const bCost = b.total > 0 ? b.totalCost / b.total : 999;
    return aCost - bCost;
  })[0];

  console.log('');
  if (best.model === cheapest.model) {
    log(`Recommendation: Use ${best.modelName} - best accuracy AND cheapest!`, 'success');
  } else {
    const bestRate = best.total > 0 ? ((best.success / best.total) * 100).toFixed(0) : 0;
    const cheapRate = cheapest.total > 0 ? ((cheapest.success / cheapest.total) * 100).toFixed(0) : 0;
    log(`Best accuracy: ${best.modelName} (${bestRate}%)`, 'info');
    log(`Most economical: ${cheapest.modelName} (${cheapRate}%, cheaper)`, 'info');
  }

  console.log('='.repeat(60));
}

main().catch(e => {
  log(`Fatal error: ${e.message}`, 'error');
  process.exit(1);
});
