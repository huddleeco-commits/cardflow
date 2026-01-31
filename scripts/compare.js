#!/usr/bin/env node
/**
 * CardFlow - Model Comparison / A/B Testing
 *
 * Compare multiple Claude models on the same cards to evaluate:
 * - Accuracy differences
 * - Speed differences
 * - Cost differences
 *
 * Usage:
 *   node scripts/compare.js --models sonnet4,haiku35,haiku3
 *   node scripts/compare.js --models sonnet4,haiku35 --limit 5
 *   npm run compare -- --models sonnet4,haiku35
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
const dbPath = path.join(__dirname, '..', 'cards.json');
const comparisonsPath = path.join(__dirname, '..', 'comparisons.json');
const newFolder = path.join(__dirname, '..', '1-new');

// Load config
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
  return { total: {}, by_model: {}, comparisons: [] };
}

function saveCosts(costs) {
  fs.writeFileSync(costsPath, JSON.stringify(costs, null, 2));
}

function loadComparisons() {
  try {
    if (fs.existsSync(comparisonsPath)) {
      return JSON.parse(fs.readFileSync(comparisonsPath, 'utf8'));
    }
  } catch (e) {}
  return { sessions: [], results: [] };
}

function saveComparisons(data) {
  fs.writeFileSync(comparisonsPath, JSON.stringify(data, null, 2));
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

// Check API key
function checkApiKey() {
  const keyInfo = getApiKey();

  if (!keyInfo) {
    console.error('\nERROR: No API key configured');
    console.error('Add your API key in the dashboard Settings -> API Key tab');
    console.error('Or set: $env:ANTHROPIC_API_KEY = "your-key"');
    process.exit(1);
  }

  console.log(`Using API key from ${keyInfo.source}`);
  return new Anthropic({ apiKey: keyInfo.key });
}

// Parse CLI arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const result = {
    models: ['sonnet4', 'haiku35'],
    limit: 0,
    task: 'identify'
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--models' && args[i + 1]) {
      result.models = args[i + 1].split(',').map(m => m.trim());
      i++;
    }
    if (args[i] === '--limit' && args[i + 1]) {
      result.limit = parseInt(args[i + 1]) || 0;
      i++;
    }
    if (args[i] === '--task' && args[i + 1]) {
      result.task = args[i + 1];
      i++;
    }
  }
  return result;
}

function log(msg, type = 'info') {
  const icons = { info: 'i', success: '+', error: 'x', warn: '!', compare: '~' };
  const ts = new Date().toLocaleTimeString();
  console.log(`[${ts}] [${icons[type] || ' '}] ${msg}`);
}

// Convert image to base64
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

// Find images to compare
function findImages(limit) {
  const imageExts = ['.jpg', '.jpeg', '.png', '.webp'];

  if (!fs.existsSync(newFolder)) {
    return [];
  }

  let files = fs.readdirSync(newFolder).filter(f =>
    imageExts.includes(path.extname(f).toLowerCase())
  );

  if (limit > 0) {
    files = files.slice(0, limit);
  }

  return files.map(f => ({
    filename: f,
    path: path.join(newFolder, f)
  }));
}

// Identify card with a specific model
async function identifyWithModel(anthropic, image, modelConfig) {
  const content = [
    {
      type: 'image',
      source: imageToBase64(image.path)
    },
    {
      type: 'text',
      text: `Analyze this sports card image and identify it.

Return ONLY a JSON object with these fields (no other text):
{
  "player": "Full player name",
  "year": 2024,
  "set_name": "Full set name",
  "card_number": "Card number",
  "parallel": "Parallel type if any",
  "numbered": "Serial numbering if any or null",
  "team": "Team name",
  "sport": "Sport",
  "is_graded": true,
  "grading_company": "PSA, BGS, SGC, CGC, or null",
  "grade": "Grade number or null",
  "confidence": "high, medium, or low"
}`
    }
  ];

  const startTime = Date.now();

  try {
    const response = await anthropic.messages.create({
      model: modelConfig.id,
      max_tokens: 1024,
      messages: [{ role: 'user', content }]
    });

    const elapsed = Date.now() - startTime;
    const inputTokens = response.usage?.input_tokens || 0;
    const outputTokens = response.usage?.output_tokens || 0;

    // Calculate cost
    const inputCost = (inputTokens / 1000000) * (modelConfig.input_cost_per_1m || 3);
    const outputCost = (outputTokens / 1000000) * (modelConfig.output_cost_per_1m || 15);
    const totalCost = inputCost + outputCost;

    const textContent = response.content.find(c => c.type === 'text');
    const jsonMatch = textContent?.text.match(/\{[\s\S]*\}/);

    let result = null;
    let parseError = null;

    if (jsonMatch) {
      try {
        result = JSON.parse(jsonMatch[0]);
      } catch (e) {
        parseError = e.message;
      }
    }

    return {
      success: !!result,
      result,
      parseError,
      elapsed,
      inputTokens,
      outputTokens,
      cost: totalCost,
      rawResponse: textContent?.text?.substring(0, 500)
    };

  } catch (e) {
    return {
      success: false,
      error: e.message,
      elapsed: Date.now() - startTime,
      inputTokens: 0,
      outputTokens: 0,
      cost: 0
    };
  }
}

// Compare results between models
function compareResults(results) {
  const modelKeys = Object.keys(results);
  if (modelKeys.length < 2) return { match: true };

  const comparison = {
    match: true,
    differences: []
  };

  const baseResult = results[modelKeys[0]]?.result;
  if (!baseResult) return comparison;

  const fieldsToCompare = ['player', 'year', 'set_name', 'card_number', 'parallel', 'is_graded', 'grade', 'confidence'];

  for (let i = 1; i < modelKeys.length; i++) {
    const otherResult = results[modelKeys[i]]?.result;
    if (!otherResult) continue;

    for (const field of fieldsToCompare) {
      const val1 = baseResult[field];
      const val2 = otherResult[field];

      if (String(val1).toLowerCase() !== String(val2).toLowerCase()) {
        comparison.match = false;
        comparison.differences.push({
          field,
          [modelKeys[0]]: val1,
          [modelKeys[i]]: val2
        });
      }
    }
  }

  return comparison;
}

// Generate comparison report
function generateReport(sessionData) {
  const wb = XLSX.utils.book_new();

  // Summary sheet
  const summaryRows = [
    ['Model Comparison Report'],
    ['Generated:', new Date().toISOString()],
    ['Images tested:', sessionData.images.length],
    ['Models compared:', sessionData.models.join(', ')],
    [],
    ['Model', 'Success Rate', 'Avg Time (ms)', 'Avg Tokens', 'Total Cost', 'Avg Cost/Card']
  ];

  for (const [modelKey, stats] of Object.entries(sessionData.modelStats)) {
    const successRate = stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(1) : 0;
    const avgTime = stats.total > 0 ? Math.round(stats.totalTime / stats.total) : 0;
    const avgTokens = stats.total > 0 ? Math.round(stats.totalTokens / stats.total) : 0;
    const avgCost = stats.total > 0 ? (stats.totalCost / stats.total).toFixed(4) : 0;

    summaryRows.push([
      modelKey,
      `${successRate}%`,
      avgTime,
      avgTokens,
      `$${stats.totalCost.toFixed(4)}`,
      `$${avgCost}`
    ]);
  }

  summaryRows.push([]);
  summaryRows.push(['Agreement Rate:', `${sessionData.agreementRate.toFixed(1)}%`]);
  summaryRows.push(['Total Differences:', sessionData.totalDifferences]);

  const summaryWs = XLSX.utils.aoa_to_sheet(summaryRows);
  XLSX.utils.book_append_sheet(wb, summaryWs, 'Summary');

  // Detailed results sheet
  const detailRows = [['Image', 'Model', 'Success', 'Player', 'Year', 'Set', 'Confidence', 'Time (ms)', 'Cost']];

  for (const result of sessionData.results) {
    for (const [modelKey, modelResult] of Object.entries(result.byModel)) {
      detailRows.push([
        result.filename,
        modelKey,
        modelResult.success ? 'Yes' : 'No',
        modelResult.result?.player || '-',
        modelResult.result?.year || '-',
        modelResult.result?.set_name || '-',
        modelResult.result?.confidence || '-',
        modelResult.elapsed,
        `$${modelResult.cost.toFixed(4)}`
      ]);
    }
    detailRows.push([]); // Blank row between images
  }

  const detailWs = XLSX.utils.aoa_to_sheet(detailRows);
  XLSX.utils.book_append_sheet(wb, detailWs, 'Details');

  // Differences sheet
  const diffRows = [['Image', 'Field', ...sessionData.models]];

  for (const result of sessionData.results) {
    if (!result.comparison.match && result.comparison.differences) {
      for (const diff of result.comparison.differences) {
        const row = [result.filename, diff.field];
        for (const model of sessionData.models) {
          row.push(diff[model] || '-');
        }
        diffRows.push(row);
      }
    }
  }

  const diffWs = XLSX.utils.aoa_to_sheet(diffRows);
  XLSX.utils.book_append_sheet(wb, diffWs, 'Differences');

  const reportPath = path.join(__dirname, '..', 'comparison-report.xlsx');
  XLSX.writeFile(wb, reportPath);

  return reportPath;
}

// Main
async function main() {
  console.log('\n' + '='.repeat(60));
  console.log('  CARDFLOW - MODEL A/B COMPARISON');
  console.log('='.repeat(60) + '\n');

  const anthropic = checkApiKey();
  const args = parseArgs();
  const config = loadConfig();

  // Validate models
  const validModels = [];
  for (const modelKey of args.models) {
    if (config.models[modelKey]) {
      validModels.push({ key: modelKey, ...config.models[modelKey] });
    } else {
      log(`Unknown model: ${modelKey}`, 'warn');
    }
  }

  if (validModels.length < 2) {
    log('Need at least 2 valid models to compare', 'error');
    log('Available models: ' + Object.keys(config.models).join(', '), 'info');
    process.exit(1);
  }

  log(`Comparing models: ${validModels.map(m => m.name).join(' vs ')}`, 'compare');

  // Find images
  const images = findImages(args.limit);
  if (images.length === 0) {
    log('No images found in 1-new/ folder', 'error');
    return;
  }

  log(`Found ${images.length} images to test`, 'info');
  console.log('');

  // Initialize session data
  const sessionData = {
    id: `compare_${Date.now()}`,
    startTime: new Date().toISOString(),
    models: validModels.map(m => m.key),
    images: images.map(i => i.filename),
    results: [],
    modelStats: {},
    agreementRate: 0,
    totalDifferences: 0
  };

  // Initialize stats for each model
  for (const model of validModels) {
    sessionData.modelStats[model.key] = {
      total: 0,
      success: 0,
      totalTime: 0,
      totalTokens: 0,
      totalCost: 0
    };
  }

  // Process each image with each model
  let matches = 0;

  for (let i = 0; i < images.length; i++) {
    const image = images[i];
    console.log('-'.repeat(50));
    log(`[${i + 1}/${images.length}] ${image.filename}`, 'info');

    const imageResult = {
      filename: image.filename,
      byModel: {},
      comparison: {}
    };

    // Run each model
    for (const model of validModels) {
      log(`  Testing ${model.name}...`, 'compare');

      const result = await identifyWithModel(anthropic, image, model);
      imageResult.byModel[model.key] = result;

      // Update stats
      sessionData.modelStats[model.key].total++;
      if (result.success) sessionData.modelStats[model.key].success++;
      sessionData.modelStats[model.key].totalTime += result.elapsed;
      sessionData.modelStats[model.key].totalTokens += result.inputTokens + result.outputTokens;
      sessionData.modelStats[model.key].totalCost += result.cost;

      if (result.success) {
        log(`    -> ${result.result.player || 'Unknown'} (${result.elapsed}ms, $${result.cost.toFixed(4)})`, 'success');
      } else {
        log(`    -> Failed: ${result.error || result.parseError}`, 'error');
      }
    }

    // Compare results between models
    imageResult.comparison = compareResults(imageResult.byModel);

    if (imageResult.comparison.match) {
      matches++;
      log(`  All models agree`, 'success');
    } else {
      log(`  DIFFERENCES FOUND:`, 'warn');
      for (const diff of imageResult.comparison.differences || []) {
        const vals = validModels.map(m => `${m.key}=${diff[m.key]}`).join(', ');
        log(`    ${diff.field}: ${vals}`, 'warn');
      }
      sessionData.totalDifferences += imageResult.comparison.differences?.length || 0;
    }

    sessionData.results.push(imageResult);
    console.log('');
  }

  // Calculate agreement rate
  sessionData.agreementRate = images.length > 0 ? (matches / images.length) * 100 : 0;
  sessionData.endTime = new Date().toISOString();

  // Save comparison data
  const comparisons = loadComparisons();
  comparisons.sessions.push(sessionData);
  saveComparisons(comparisons);

  // Update costs
  const costs = loadCosts();
  if (!costs.comparisons) costs.comparisons = [];
  costs.comparisons.push({
    id: sessionData.id,
    models: sessionData.models,
    images: images.length,
    totalCost: Object.values(sessionData.modelStats).reduce((sum, s) => sum + s.totalCost, 0)
  });
  saveCosts(costs);

  // Generate report
  const reportPath = generateReport(sessionData);

  // Summary
  console.log('='.repeat(60));
  log('COMPARISON COMPLETE', 'success');
  console.log('');

  for (const [modelKey, stats] of Object.entries(sessionData.modelStats)) {
    const model = validModels.find(m => m.key === modelKey);
    const successRate = stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(0) : 0;
    const avgTime = stats.total > 0 ? Math.round(stats.totalTime / stats.total) : 0;
    log(`${model.name}: ${successRate}% success, ${avgTime}ms avg, $${stats.totalCost.toFixed(4)} total`, 'info');
  }

  console.log('');
  log(`Agreement rate: ${sessionData.agreementRate.toFixed(1)}%`, sessionData.agreementRate >= 90 ? 'success' : 'warn');
  log(`Total differences: ${sessionData.totalDifferences}`, 'info');
  log(`Report saved: ${reportPath}`, 'success');

  console.log('='.repeat(60));
  console.log(`
  View detailed comparison in: comparison-report.xlsx

  Tips:
  - High agreement = cheaper model may work for your cards
  - Check 'Differences' tab to see where models disagree
  - Consider using faster model for bulk, better model for valuable cards
  `);
}

main().catch(e => {
  log(`Fatal error: ${e.message}`, 'error');
  process.exit(1);
});
