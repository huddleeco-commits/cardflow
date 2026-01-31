#!/usr/bin/env node
/**
 * CardFlow - REAL Pricing with Web Scraping
 *
 * Uses SlabTrack's proven patterns for eBay scraping.
 *
 * Features:
 * - Cascading search queries (specific → broad)
 * - Realistic browser headers
 * - COMC with proper headers
 * - Claude estimation fallback
 * - Always provides clickable URLs
 *
 * Usage: node scripts/price.js
 */

const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');

// Configuration
const CONFIG = {
  identifiedFolder: path.join(__dirname, '..', '2-identified'),
  pricedFolder: path.join(__dirname, '..', '3-priced'),
  reportsFolder: path.join(__dirname, '..'),
  dbPath: path.join(__dirname, '..', 'cards.json'),
  configPath: path.join(__dirname, '..', 'config.json'),
  dashboardPort: 3005,
  requestDelay: 1000, // 1 second between requests
  timeout: 15000
};

// SlabTrack-style browser headers (proven to work)
const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate, br',
  'DNT': '1',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1'
};

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

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG.configPath)) {
      return JSON.parse(fs.readFileSync(CONFIG.configPath, 'utf8'));
    }
  } catch (e) {}
  return { models: {} };
}

function log(message, type = 'info') {
  const icons = { info: 'i', success: '+', error: 'x', warn: '!', money: '$', search: '?' };
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[${timestamp}] [${icons[type] || ' '}] ${message}`);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================
// QUERY BUILDING (SlabTrack Pattern)
// ============================================

/**
 * Build cascading search queries from specific to broad
 * Based on SlabTrack's proven approach
 */
function buildSearchQueries(card) {
  const queries = [];

  const player = card.player || '';
  const year = card.year || '';
  const setName = card.set_name || '';
  const cardNum = card.card_number || '';
  const parallel = card.parallel && card.parallel !== 'Base' ? card.parallel : '';
  const gradeStr = card.is_graded ? `${card.grading_company} ${card.grade}` : '';

  // Check if year is already in set name
  const hasYearInSet = setName.match(/^\d{4}\s+/) || (year && setName.includes(year.toString()));

  // Query 1: Full query with grade (most specific)
  if (gradeStr) {
    const parts = hasYearInSet
      ? [setName, player, cardNum, parallel, gradeStr]
      : [year, setName, player, cardNum, parallel, gradeStr];
    queries.push(parts.filter(Boolean).join(' ').trim());
  }

  // Query 2: Full query without grade
  {
    const parts = hasYearInSet
      ? [setName, player, cardNum, parallel]
      : [year, setName, player, cardNum, parallel];
    queries.push(parts.filter(Boolean).join(' ').trim());
  }

  // Query 3: Without card number
  {
    const parts = hasYearInSet
      ? [setName, player, parallel, gradeStr]
      : [year, setName, player, parallel, gradeStr];
    queries.push(parts.filter(Boolean).join(' ').trim());
  }

  // Query 4: Without parallel
  {
    const parts = hasYearInSet
      ? [setName, player, gradeStr]
      : [year, setName, player, gradeStr];
    queries.push(parts.filter(Boolean).join(' ').trim());
  }

  // Query 5: Broad - just year, set, player
  {
    const parts = hasYearInSet
      ? [setName, player]
      : [year, setName, player];
    queries.push(parts.filter(Boolean).join(' ').trim());
  }

  // Query 6: Broadest - just player + year
  if (year && player) {
    queries.push(`${year} ${player}`.trim());
  }

  // Remove duplicates while preserving order
  return [...new Set(queries)].filter(q => q.length > 0);
}

// Parse price string to number
function parsePrice(priceStr) {
  if (!priceStr) return null;
  const cleaned = priceStr.replace(/[^0-9.]/g, '');
  const price = parseFloat(cleaned);
  return isNaN(price) ? null : price;
}

// Build eBay sold listings URL (SlabTrack format)
function buildEbayUrl(query) {
  const encoded = encodeURIComponent(query);
  // SlabTrack URL pattern: LH_Complete=1&LH_Sold=1&_sop=13 (sort by recent)
  return `https://www.ebay.com/sch/i.html?_nkw=${encoded}&LH_Complete=1&LH_Sold=1&_sop=13`;
}

// Build COMC URL (SlabTrack format)
function buildComcUrl(query) {
  const encoded = encodeURIComponent(query);
  // SlabTrack COMC URL pattern: sr,= for search, sdi,0 for depth, so,dp,-dp for sort
  return `https://www.comc.com/Cards,sr,=${encoded},sdi,0,so,dp,-dp`;
}

// Build SportsCardsPro URL
function buildScpUrl(query) {
  const encoded = encodeURIComponent(query);
  return `https://www.sportscardspro.com/search?q=${encoded}`;
}

// ============================================
// EBAY SCRAPING
// ============================================

async function scrapeEbay(queries) {
  // Try queries from most specific to broadest
  for (let i = 0; i < queries.length; i++) {
    const query = queries[i];
    const url = buildEbayUrl(query);

    log(`  [${i + 1}/${queries.length}] eBay: "${query}"`, 'search');

    try {
      const response = await axios.get(url, {
        headers: {
          ...BROWSER_HEADERS,
          'Referer': 'https://www.ebay.com/'
        },
        timeout: CONFIG.timeout
      });

      const $ = cheerio.load(response.data);
      const prices = [];
      const listings = [];

      // Parse sold listings (SlabTrack selector pattern)
      $('.s-item').each((idx, el) => {
        if (idx === 0) return; // Skip header

        const title = $(el).find('.s-item__title').text().trim();

        // Get price - try multiple selectors
        const priceEl = $(el).find('.s-item__price');
        const priceText = priceEl.text().trim();

        // Skip price ranges
        if (!priceText || priceText.includes(' to ')) return;

        const link = $(el).find('.s-item__link').attr('href');
        const price = parsePrice(priceText);

        // Sanity check prices
        if (price && price > 0.5 && price < 50000) {
          prices.push(price);
          listings.push({
            title: title.substring(0, 100),
            price,
            url: link ? link.split('?')[0] : null
          });
        }
      });

      // If we found results, return them
      if (prices.length >= 3) {
        prices.sort((a, b) => a - b);
        const low = prices[0];
        const high = prices[prices.length - 1];
        const avg = prices.reduce((a, b) => a + b, 0) / prices.length;
        const median = prices[Math.floor(prices.length / 2)];

        log(`    Found ${prices.length} sales: $${low.toFixed(2)} - $${avg.toFixed(2)} - $${high.toFixed(2)}`, 'success');

        return {
          source: 'ebay',
          source_name: 'eBay Sold',
          url,
          search_query: query,
          success: true,
          low: Math.round(low * 100) / 100,
          avg: Math.round(avg * 100) / 100,
          high: Math.round(high * 100) / 100,
          median: Math.round(median * 100) / 100,
          sample_size: prices.length,
          individual_sales: prices.slice(0, 10).map(p => Math.round(p * 100) / 100),
          recent_listings: listings.slice(0, 5),
          query_used: query,
          query_index: i + 1
        };
      }

      log(`    Only ${prices.length} results, trying broader search...`, 'warn');

      // Small delay before next attempt
      if (i < queries.length - 1) {
        await sleep(500);
      }

    } catch (e) {
      log(`    Error: ${e.message}`, 'error');

      // If it's a rate limit or server error, don't try more queries
      if (e.response?.status === 429 || e.response?.status === 503) {
        log(`    Rate limited, stopping eBay search`, 'warn');
        break;
      }
    }
  }

  // No results found with any query - return URL for manual check
  const firstQuery = queries[0] || '';
  return {
    source: 'ebay',
    source_name: 'eBay Sold',
    url: buildEbayUrl(firstQuery),
    search_query: firstQuery,
    success: false,
    error: 'No sold listings found with any query',
    sample_size: 0,
    queries_tried: queries.length
  };
}

// ============================================
// COMC SCRAPING
// ============================================

async function scrapeCOMC(card) {
  // Build a simpler query for COMC (they have good search)
  const parts = [card.player, card.year, card.set_name, card.card_number].filter(Boolean);
  const query = parts.join(' ');
  const url = buildComcUrl(query);

  log(`  COMC: "${query}"`, 'search');

  try {
    const response = await axios.get(url, {
      headers: {
        ...BROWSER_HEADERS,
        'Referer': 'https://www.comc.com/'
      },
      timeout: 8000 // SlabTrack uses 8s for COMC
    });

    // SlabTrack pattern: extract prices with regex from page
    const priceMatches = response.data.match(/\$(\d+\.?\d*)/g) || [];
    const prices = priceMatches
      .slice(0, 20) // First 20 prices
      .map(p => parseFloat(p.replace('$', '')))
      .filter(p => p > 0.5 && p < 10000);

    if (prices.length >= 2) {
      prices.sort((a, b) => a - b);
      const low = prices[0];
      const high = prices[prices.length - 1];
      const avg = prices.reduce((a, b) => a + b, 0) / prices.length;

      log(`    Found ${prices.length} listings: $${low.toFixed(2)} - $${avg.toFixed(2)} - $${high.toFixed(2)}`, 'success');

      return {
        source: 'comc',
        source_name: 'COMC',
        url,
        search_query: query,
        success: true,
        low: Math.round(low * 100) / 100,
        avg: Math.round(avg * 100) / 100,
        high: Math.round(high * 100) / 100,
        sample_size: prices.length,
        individual_sales: prices.slice(0, 10).map(p => Math.round(p * 100) / 100)
      };
    }

    log(`    No COMC listings found`, 'warn');
    return {
      source: 'comc',
      source_name: 'COMC',
      url,
      search_query: query,
      success: false,
      error: 'No listings found',
      sample_size: 0
    };

  } catch (e) {
    const status = e.response?.status;
    log(`    COMC error: ${status || e.message}`, 'error');

    return {
      source: 'comc',
      source_name: 'COMC',
      url,
      search_query: query,
      success: false,
      error: status === 403 ? 'Access blocked (403)' : e.message,
      sample_size: 0
    };
  }
}

// ============================================
// SPORTSCARDSPRO (URL Only)
// ============================================

function getSportsCardsProUrl(card) {
  const parts = [card.player, card.year, card.set_name].filter(Boolean);
  const query = parts.join(' ');

  return {
    source: 'sportscardspro',
    source_name: 'SportsCardsPro',
    url: buildScpUrl(query),
    search_query: query,
    success: true,
    note: 'Manual check required - click link',
    sample_size: 0
  };
}

// ============================================
// CLAUDE ESTIMATION FALLBACK
// ============================================

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

async function getClaudeEstimate(card) {
  // Check if we should use Claude fallback
  const config = loadConfig();

  // Only use if API mode and we have an API key
  const keyInfo = getApiKey();
  if (config.mode === 'free' || !keyInfo) {
    return null;
  }

  log(`  Using Claude for price estimation...`, 'search');

  try {
    const Anthropic = require('@anthropic-ai/sdk');
    const anthropic = new Anthropic({ apiKey: keyInfo.key });

    const gradeStr = card.is_graded ? `${card.grading_company} ${card.grade}` : 'Raw/Ungraded';

    const prompt = `Based on your knowledge of sports card values, estimate the market value for this card:

Player: ${card.player}
Year: ${card.year}
Set: ${card.set_name}
Card Number: ${card.card_number || 'N/A'}
Parallel: ${card.parallel || 'Base'}
Numbered: ${card.numbered || 'No'}
Condition: ${gradeStr}
Sport: ${card.sport}

Provide a realistic price estimate based on:
- Recent market trends for this player
- Set popularity and rarity
- Condition premium

Return ONLY a JSON object:
{
  "estimated_low": 10.00,
  "estimated_avg": 25.00,
  "estimated_high": 40.00,
  "confidence": "medium",
  "reasoning": "Brief explanation"
}`;

    const response = await anthropic.messages.create({
      model: config.models?.haiku35?.id || 'claude-3-5-haiku-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: prompt }]
    });

    const text = response.content[0]?.text || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);

    if (jsonMatch) {
      const data = JSON.parse(jsonMatch[0]);

      log(`    Estimated: $${data.estimated_low} - $${data.estimated_avg} - $${data.estimated_high} (${data.confidence})`, 'success');

      return {
        source: 'claude_estimate',
        source_name: 'AI Estimate',
        success: true,
        low: data.estimated_low,
        avg: data.estimated_avg,
        high: data.estimated_high,
        confidence: data.confidence,
        reasoning: data.reasoning,
        note: 'ESTIMATED - Not from actual sales data',
        sample_size: 0
      };
    }
  } catch (e) {
    log(`    Claude estimation failed: ${e.message}`, 'error');
  }

  return null;
}

// ============================================
// MAIN PRICING FUNCTION
// ============================================

async function researchPricing(card) {
  const queries = buildSearchQueries(card);

  log(`Pricing: ${card.player} - ${card.year} ${card.set_name}`, 'money');
  log(`  Built ${queries.length} search queries`, 'info');

  const results = {
    search_queries: queries,
    sources: {},
    source_urls: {},
    priced_at: new Date().toISOString()
  };

  // 1. eBay Sold Listings (primary source)
  const ebayResult = await scrapeEbay(queries);
  results.sources.ebay = ebayResult;
  results.source_urls.ebay = {
    name: 'eBay Sold',
    url: ebayResult.url,
    search_term: ebayResult.search_query
  };

  await sleep(CONFIG.requestDelay);

  // 2. COMC
  const comcResult = await scrapeCOMC(card);
  results.sources.comc = comcResult;
  results.source_urls.comc = {
    name: 'COMC',
    url: comcResult.url,
    search_term: comcResult.search_query
  };

  // 3. SportsCardsPro (URL only)
  const scpResult = getSportsCardsProUrl(card);
  results.sources.sportscardspro = scpResult;
  results.source_urls.sportscardspro = {
    name: 'SportsCardsPro',
    url: scpResult.url,
    search_term: scpResult.search_query
  };

  // 4. PSA 9/10 comps for raw cards
  if (!card.is_graded) {
    await sleep(CONFIG.requestDelay);

    // PSA 9 search
    const psa9Queries = queries.slice(0, 3).map(q => `${q} PSA 9`);
    const psa9Result = await scrapeEbay(psa9Queries);

    await sleep(CONFIG.requestDelay);

    // PSA 10 search
    const psa10Queries = queries.slice(0, 3).map(q => `${q} PSA 10`);
    const psa10Result = await scrapeEbay(psa10Queries);

    results.grading_potential = {
      psa9: psa9Result.success ? {
        low: psa9Result.low,
        avg: psa9Result.avg,
        high: psa9Result.high,
        sample_size: psa9Result.sample_size,
        url: psa9Result.url
      } : null,
      psa10: psa10Result.success ? {
        low: psa10Result.low,
        avg: psa10Result.avg,
        high: psa10Result.high,
        sample_size: psa10Result.sample_size,
        url: psa10Result.url
      } : null
    };

    // Calculate if worth grading
    const rawAvg = ebayResult.success ? ebayResult.avg : 0;
    const psa10Avg = psa10Result.success ? psa10Result.avg : 0;
    const gradingCost = 25;

    if (rawAvg > 0 && psa10Avg > 0) {
      const profit = psa10Avg - rawAvg - gradingCost;
      results.grading_potential.worth_grading = profit > 20;
      results.grading_potential.potential_profit = Math.round(profit);
      results.grading_potential.recommendation = profit > 50
        ? 'Highly recommended - significant upside'
        : profit > 20
          ? 'Worth considering if card is mint'
          : 'Not recommended at current prices';
    }

    results.source_urls.ebay_psa9 = {
      name: 'eBay PSA 9 Comps',
      url: psa9Result.url,
      search_term: psa9Result.search_query
    };
    results.source_urls.ebay_psa10 = {
      name: 'eBay PSA 10 Comps',
      url: psa10Result.url,
      search_term: psa10Result.search_query
    };
  }

  // Calculate recommended price from valid sources
  const validSources = [ebayResult, comcResult].filter(s => s.success && s.avg > 0);

  if (validSources.length > 0) {
    const avgOfAvgs = validSources.reduce((sum, s) => sum + s.avg, 0) / validSources.length;
    results.recommended_price = Math.round(avgOfAvgs * 100) / 100;
    results.confidence = validSources.length >= 2 ? 'high' : 'medium';
    results.pricing_method = 'scraped';
    results.combined = {
      avg_of_averages: results.recommended_price,
      total_sample_size: validSources.reduce((sum, s) => sum + s.sample_size, 0),
      source_count: validSources.length
    };
  } else {
    // Try Claude estimation as fallback
    const estimate = await getClaudeEstimate(card);

    if (estimate) {
      results.sources.claude_estimate = estimate;
      results.recommended_price = estimate.avg;
      results.confidence = estimate.confidence || 'low';
      results.pricing_method = 'estimated';
      results.market_notes = `AI ESTIMATED: ${estimate.reasoning || 'Based on market knowledge'}`;
      results.combined = {
        avg_of_averages: estimate.avg,
        total_sample_size: 0,
        source_count: 0
      };
    } else {
      results.recommended_price = null;
      results.confidence = 'none';
      results.pricing_method = 'manual';
      results.market_notes = 'No data found. Check source URLs manually.';
    }
  }

  return results;
}

// Generate report
function generateReport(cards) {
  const wb = XLSX.utils.book_new();

  // Summary sheet
  const summaryRows = [
    ['#', 'Player', 'Year', 'Set', 'Grade', 'Price', 'Method', 'eBay', 'COMC', 'Samples', 'Confidence']
  ];

  let totalValue = 0;
  cards.forEach((card, idx) => {
    const rec = card.recommended_price || 0;
    totalValue += rec;

    const sources = card.sources || {};
    summaryRows.push([
      idx + 1,
      card.player || '',
      card.year || '',
      card.set_name || '',
      card.is_graded ? `${card.grading_company} ${card.grade}` : 'Raw',
      rec ? `$${rec.toFixed(2)}` : 'N/A',
      card.pricing_method || '-',
      sources.ebay?.avg ? `$${sources.ebay.avg.toFixed(2)}` : '-',
      sources.comc?.avg ? `$${sources.comc.avg.toFixed(2)}` : '-',
      card.combined?.total_sample_size || 0,
      card.confidence || 'N/A'
    ]);
  });

  summaryRows.push([]);
  summaryRows.push(['', '', '', '', 'TOTAL:', `$${totalValue.toFixed(2)}`]);

  const summaryWs = XLSX.utils.aoa_to_sheet(summaryRows);
  summaryWs['!cols'] = [
    { wch: 4 }, { wch: 22 }, { wch: 6 }, { wch: 25 }, { wch: 12 },
    { wch: 10 }, { wch: 10 }, { wch: 10 }, { wch: 10 }, { wch: 8 }, { wch: 10 }
  ];
  XLSX.utils.book_append_sheet(wb, summaryWs, 'Summary');

  // Source URLs sheet (always include for manual verification)
  const urlRows = [['Player', 'Source', 'URL', 'Query', 'Status', 'Price Range', 'Samples']];

  cards.forEach(card => {
    const sourceUrls = card.source_urls || {};
    const sources = card.sources || {};

    Object.entries(sourceUrls).forEach(([key, urlInfo]) => {
      const sourceData = sources[key] || {};

      urlRows.push([
        card.player || '',
        urlInfo.name,
        urlInfo.url,
        urlInfo.search_term,
        sourceData.success ? 'OK' : sourceData.error || 'No data',
        sourceData.avg ? `$${sourceData.low}-${sourceData.avg}-${sourceData.high}` : '-',
        sourceData.sample_size || 0
      ]);
    });
    urlRows.push([]);
  });

  const urlWs = XLSX.utils.aoa_to_sheet(urlRows);
  urlWs['!cols'] = [
    { wch: 20 }, { wch: 15 }, { wch: 80 }, { wch: 40 }, { wch: 20 }, { wch: 20 }, { wch: 8 }
  ];
  XLSX.utils.book_append_sheet(wb, urlWs, 'Source URLs');

  // Grading potential sheet
  const rawCards = cards.filter(c => !c.is_graded && c.grading_potential);
  if (rawCards.length > 0) {
    const gradingRows = [
      ['Player', 'Year', 'Set', 'Raw', 'PSA 9', 'PSA 10', 'Worth It?', 'Profit', 'Recommendation']
    ];

    rawCards.forEach(card => {
      const gp = card.grading_potential;
      const sources = card.sources || {};
      gradingRows.push([
        card.player || '',
        card.year || '',
        card.set_name || '',
        sources.ebay?.avg ? `$${sources.ebay.avg.toFixed(2)}` : '-',
        gp.psa9?.avg ? `$${gp.psa9.avg.toFixed(2)}` : '-',
        gp.psa10?.avg ? `$${gp.psa10.avg.toFixed(2)}` : '-',
        gp.worth_grading ? 'YES' : 'NO',
        gp.potential_profit ? `$${gp.potential_profit}` : '-',
        gp.recommendation || ''
      ]);
    });

    const gradingWs = XLSX.utils.aoa_to_sheet(gradingRows);
    XLSX.utils.book_append_sheet(wb, gradingWs, 'Grading Potential');
  }

  const reportPath = path.join(CONFIG.reportsFolder, 'pricing-report.xlsx');
  XLSX.writeFile(wb, reportPath);

  log(`Report saved: ${reportPath}`, 'success');
  return { path: reportPath, totalValue };
}

// Move files to priced folder
function moveToPriced(cards) {
  if (!fs.existsSync(CONFIG.pricedFolder)) {
    fs.mkdirSync(CONFIG.pricedFolder, { recursive: true });
  }

  for (const card of cards) {
    try {
      if (card.front) {
        const frontSrc = path.join(CONFIG.identifiedFolder, card.front);
        const frontDst = path.join(CONFIG.pricedFolder, card.front);
        if (fs.existsSync(frontSrc)) fs.renameSync(frontSrc, frontDst);
      }
      if (card.back) {
        const backSrc = path.join(CONFIG.identifiedFolder, card.back);
        const backDst = path.join(CONFIG.pricedFolder, card.back);
        if (fs.existsSync(backSrc)) fs.renameSync(backSrc, backDst);
      }
    } catch (e) {
      log(`Failed to move ${card.front}: ${e.message}`, 'warn');
    }
  }
}

// Notify dashboard
function notifyDashboard(cards, totalValue) {
  return new Promise((resolve) => {
    try {
      const WebSocket = require('ws');
      const ws = new WebSocket(`ws://localhost:${CONFIG.dashboardPort}`);

      ws.on('open', () => {
        ws.send(JSON.stringify({
          type: 'cards_priced',
          count: cards.length,
          totalValue,
          cards: cards.map(c => ({
            id: c.id,
            player: c.player,
            recommended_price: c.recommended_price,
            source_count: c.combined?.source_count || 0
          }))
        }));
        log('Dashboard notified', 'success');
        ws.close();
        resolve(true);
      });

      ws.on('error', () => resolve(false));
      setTimeout(() => { ws.close(); resolve(false); }, 2000);
    } catch (e) {
      resolve(false);
    }
  });
}

// Main function
async function main() {
  console.log('\n' + '='.repeat(60));
  console.log('  CARDFLOW - REAL PRICING (SlabTrack Patterns)');
  console.log('='.repeat(60) + '\n');

  log('Using cascading search strategy (specific → broad)', 'info');
  log('Sources: eBay Sold, COMC, SportsCardsPro', 'info');
  log('Fallback: Claude AI estimation', 'info');
  console.log('');

  loadDb();

  const cardsToPriceFromDb = cardsDb.filter(c =>
    c.status === 'identified' || c.status === 'approved'
  );

  if (cardsToPriceFromDb.length === 0) {
    log('No cards ready for pricing.', 'warn');
    log('Run identify first, then approve cards in the dashboard.', 'info');
    return;
  }

  log(`Found ${cardsToPriceFromDb.length} cards to price`, 'info');
  console.log('');

  const pricedCards = [];
  for (let i = 0; i < cardsToPriceFromDb.length; i++) {
    const card = cardsToPriceFromDb[i];
    console.log('-'.repeat(50));
    log(`[${i + 1}/${cardsToPriceFromDb.length}] ${card.player}`, 'info');

    try {
      const pricing = await researchPricing(card);

      const pricedCard = {
        ...card,
        ...pricing,
        status: 'priced',
        priced_at: new Date().toISOString()
      };

      // Backward compatibility
      if (pricing.sources?.ebay?.success) {
        pricedCard.ebay_low = pricing.sources.ebay.low;
        pricedCard.ebay_avg = pricing.sources.ebay.avg;
        pricedCard.ebay_high = pricing.sources.ebay.high;
        pricedCard.sample_size = pricing.sources.ebay.sample_size;
      }

      pricedCards.push(pricedCard);

      const idx = cardsDb.findIndex(c => c.id === card.id);
      if (idx !== -1) cardsDb[idx] = pricedCard;

      // Log result
      if (pricing.recommended_price) {
        const method = pricing.pricing_method === 'estimated' ? ' (ESTIMATED)' : '';
        log(`  PRICE: $${pricing.recommended_price.toFixed(2)}${method} (${pricing.confidence})`, 'success');
      } else {
        log(`  No price found - check URLs manually`, 'warn');
      }

    } catch (e) {
      log(`  Error: ${e.message}`, 'error');
    }

    console.log('');

    if (i < cardsToPriceFromDb.length - 1) {
      await sleep(CONFIG.requestDelay);
    }
  }

  saveDb();

  const { totalValue } = generateReport(pricedCards);

  moveToPriced(pricedCards);

  await notifyDashboard(pricedCards, totalValue);

  // Summary
  const scraped = pricedCards.filter(c => c.pricing_method === 'scraped').length;
  const estimated = pricedCards.filter(c => c.pricing_method === 'estimated').length;
  const manual = pricedCards.filter(c => c.pricing_method === 'manual').length;

  console.log('='.repeat(60));
  log(`COMPLETE: ${pricedCards.length} cards priced`, 'success');
  log(`TOTAL VALUE: $${totalValue.toFixed(2)}`, 'money');
  console.log('');
  log(`Scraped (verified): ${scraped}`, scraped > 0 ? 'success' : 'info');
  log(`AI Estimated: ${estimated}`, estimated > 0 ? 'warn' : 'info');
  log(`Manual check needed: ${manual}`, manual > 0 ? 'warn' : 'info');
  console.log('='.repeat(60));
  console.log(`
  Dashboard: http://localhost:3005
  Report: pricing-report.xlsx

  All source URLs are clickable for verification!
  `);
}

main().catch(e => {
  log(`Fatal error: ${e.message}`, 'error');
  console.error(e);
  process.exit(1);
});
