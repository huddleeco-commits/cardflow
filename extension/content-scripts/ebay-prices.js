/**
 * CardFlow Extension - eBay Price Detection Content Script
 * Scrapes sold prices from eBay search results and sends them to CardFlow
 */

(function() {
  'use strict';

  const CARDFLOW_ORIGIN = 'https://cardflow.be1st.io';

  // Check if this is a sold listings search
  function isSoldListingsPage() {
    return window.location.href.includes('LH_Sold=1') ||
           window.location.href.includes('LH_Complete=1');
  }

  // Extract prices from eBay sold listings
  function extractSoldPrices() {
    const prices = [];

    // eBay sold listings have items in various containers depending on view
    const selectors = [
      '.s-item', // Standard search results
      '.srp-results .s-item__wrapper', // Alternative structure
      '[data-gr4="true"]' // Grid view
    ];

    let items = [];
    for (const selector of selectors) {
      const found = document.querySelectorAll(selector);
      if (found.length > 0) {
        items = found;
        break;
      }
    }

    items.forEach((item, index) => {
      // Skip "Shop on eBay" promotional items
      if (item.classList.contains('s-item__pl-on-bottom')) return;
      if (item.querySelector('.s-item__title--tag')?.textContent?.includes('Shop on eBay')) return;

      // Get price - try multiple selectors
      const priceEl = item.querySelector('.s-item__price') ||
                      item.querySelector('[class*="price"]') ||
                      item.querySelector('.prc');

      if (!priceEl) return;

      let priceText = priceEl.textContent.trim();

      // Handle price ranges (take the lower price for conservative estimate)
      if (priceText.includes(' to ')) {
        priceText = priceText.split(' to ')[0];
      }

      // Extract numeric value
      const priceMatch = priceText.match(/[\d,]+\.?\d*/);
      if (!priceMatch) return;

      const price = parseFloat(priceMatch[0].replace(/,/g, ''));
      if (isNaN(price) || price <= 0) return;

      // Get title for reference
      const titleEl = item.querySelector('.s-item__title') ||
                      item.querySelector('[class*="title"]');
      const title = titleEl ? titleEl.textContent.trim() : '';

      // Get sold date if available
      const soldEl = item.querySelector('.s-item__title--tagblock .POSITIVE') ||
                     item.querySelector('.s-item__detail--sold') ||
                     item.querySelector('[class*="sold"]');
      const soldDate = soldEl ? soldEl.textContent.trim() : '';

      // Get image for visual reference
      const imgEl = item.querySelector('img');
      const image = imgEl ? imgEl.src : '';

      // Get link
      const linkEl = item.querySelector('a.s-item__link') || item.querySelector('a');
      const link = linkEl ? linkEl.href : '';

      prices.push({
        price,
        title: title.replace(/New Listing|Sponsored|SPONSORED/gi, '').trim(),
        soldDate,
        image,
        link,
        index
      });
    });

    return prices;
  }

  // Calculate statistics from prices
  function calculateStats(prices) {
    if (!prices || prices.length === 0) return null;

    const values = prices.map(p => p.price).sort((a, b) => a - b);
    const sum = values.reduce((a, b) => a + b, 0);

    return {
      low: values[0],
      high: values[values.length - 1],
      avg: sum / values.length,
      median: values.length % 2 === 0
        ? (values[values.length/2 - 1] + values[values.length/2]) / 2
        : values[Math.floor(values.length/2)],
      count: values.length
    };
  }

  // Send price data to CardFlow
  function sendPriceData(prices, stats) {
    // Try to find the opener window (CardFlow)
    if (window.opener) {
      try {
        window.opener.postMessage({
          type: 'CARDFLOW_PRICE_DATA',
          source: 'ebay-sold',
          prices: prices.slice(0, 20), // Send first 20 results
          stats,
          url: window.location.href
        }, CARDFLOW_ORIGIN);
        console.log('[CardFlow] Sent price data to opener:', stats);
      } catch (e) {
        console.warn('[CardFlow] Could not send to opener:', e);
      }
    }

    // Also store in chrome.storage for popup access
    if (chrome?.storage?.local) {
      chrome.storage.local.set({
        lastEbayPrices: {
          prices: prices.slice(0, 20),
          stats,
          url: window.location.href,
          timestamp: Date.now()
        }
      });
    }
  }

  // Create floating price summary UI
  function createPriceSummaryUI(stats, prices) {
    // Remove existing UI
    const existing = document.getElementById('cardflow-price-summary');
    if (existing) existing.remove();

    const container = document.createElement('div');
    container.id = 'cardflow-price-summary';
    container.innerHTML = `
      <style>
        #cardflow-price-summary {
          position: fixed;
          top: 80px;
          right: 20px;
          width: 280px;
          background: linear-gradient(145deg, #1a1a24, #12121a);
          border: 1px solid rgba(0, 246, 255, 0.3);
          border-radius: 12px;
          padding: 16px;
          z-index: 99999;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
          color: #fff;
        }
        #cardflow-price-summary .cf-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        #cardflow-price-summary .cf-title {
          font-size: 14px;
          font-weight: 600;
          color: #00f6ff;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        #cardflow-price-summary .cf-close {
          background: none;
          border: none;
          color: #666;
          cursor: pointer;
          font-size: 18px;
          padding: 4px;
        }
        #cardflow-price-summary .cf-close:hover {
          color: #fff;
        }
        #cardflow-price-summary .cf-stats {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
          margin-bottom: 12px;
        }
        #cardflow-price-summary .cf-stat {
          background: rgba(0, 0, 0, 0.3);
          padding: 10px;
          border-radius: 8px;
          text-align: center;
        }
        #cardflow-price-summary .cf-stat-value {
          font-size: 16px;
          font-weight: 700;
          color: #10b981;
        }
        #cardflow-price-summary .cf-stat-label {
          font-size: 10px;
          color: #9ca3af;
          text-transform: uppercase;
          margin-top: 2px;
        }
        #cardflow-price-summary .cf-count {
          text-align: center;
          font-size: 11px;
          color: #9ca3af;
          margin-bottom: 12px;
        }
        #cardflow-price-summary .cf-actions {
          display: flex;
          gap: 8px;
        }
        #cardflow-price-summary .cf-btn {
          flex: 1;
          padding: 8px 12px;
          border: none;
          border-radius: 6px;
          font-size: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        #cardflow-price-summary .cf-btn-primary {
          background: linear-gradient(135deg, #00f6ff, #a855f7);
          color: #000;
        }
        #cardflow-price-summary .cf-btn-primary:hover {
          opacity: 0.9;
        }
        #cardflow-price-summary .cf-btn-secondary {
          background: rgba(255,255,255,0.1);
          color: #fff;
          border: 1px solid rgba(255,255,255,0.2);
        }
        #cardflow-price-summary .cf-btn-secondary:hover {
          background: rgba(255,255,255,0.15);
        }
      </style>
      <div class="cf-header">
        <span class="cf-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
          </svg>
          CardFlow Prices
        </span>
        <button class="cf-close" onclick="this.closest('#cardflow-price-summary').remove()">&times;</button>
      </div>
      <div class="cf-stats">
        <div class="cf-stat">
          <div class="cf-stat-value">$${stats.low.toFixed(2)}</div>
          <div class="cf-stat-label">Low</div>
        </div>
        <div class="cf-stat">
          <div class="cf-stat-value">$${stats.high.toFixed(2)}</div>
          <div class="cf-stat-label">High</div>
        </div>
        <div class="cf-stat">
          <div class="cf-stat-value">$${stats.avg.toFixed(2)}</div>
          <div class="cf-stat-label">Average</div>
        </div>
        <div class="cf-stat">
          <div class="cf-stat-value">$${stats.median.toFixed(2)}</div>
          <div class="cf-stat-label">Median</div>
        </div>
      </div>
      <div class="cf-count">Based on ${stats.count} sold listings</div>
      <div class="cf-actions">
        <button class="cf-btn cf-btn-primary" id="cf-use-median">Use $${stats.median.toFixed(2)}</button>
        <button class="cf-btn cf-btn-secondary" id="cf-copy-prices">Copy All</button>
      </div>
    `;

    document.body.appendChild(container);

    // Add event listeners
    document.getElementById('cf-use-median').addEventListener('click', () => {
      sendSelectedPrice(stats.median);
    });

    document.getElementById('cf-copy-prices').addEventListener('click', () => {
      const text = prices.map(p => `$${p.price.toFixed(2)} - ${p.title}`).join('\n');
      navigator.clipboard.writeText(text);
      showToast('Prices copied to clipboard!');
    });
  }

  // Send selected price to CardFlow
  function sendSelectedPrice(price) {
    if (window.opener) {
      try {
        window.opener.postMessage({
          type: 'CARDFLOW_SELECTED_PRICE',
          price,
          source: 'ebay-sold'
        }, CARDFLOW_ORIGIN);
        showToast(`Price $${price.toFixed(2)} sent to CardFlow!`);
      } catch (e) {
        console.warn('[CardFlow] Could not send price to opener:', e);
        showToast('Copy the price and paste in CardFlow');
      }
    } else {
      // Copy to clipboard if no opener
      navigator.clipboard.writeText(price.toFixed(2));
      showToast(`$${price.toFixed(2)} copied to clipboard!`);
    }
  }

  // Simple toast notification
  function showToast(message) {
    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: #10b981;
      color: #fff;
      padding: 12px 24px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      z-index: 999999;
      animation: fadeIn 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  // Main execution
  function init() {
    if (!isSoldListingsPage()) {
      console.log('[CardFlow] Not a sold listings page, skipping price detection');
      return;
    }

    // Wait for search results to load
    const waitForResults = setInterval(() => {
      const results = document.querySelectorAll('.s-item, .srp-results .s-item__wrapper');
      if (results.length > 2) { // More than just the promo items
        clearInterval(waitForResults);

        const prices = extractSoldPrices();
        if (prices.length > 0) {
          const stats = calculateStats(prices);
          console.log('[CardFlow] Extracted prices:', { prices, stats });

          sendPriceData(prices, stats);
          createPriceSummaryUI(stats, prices);
        }
      }
    }, 500);

    // Timeout after 10 seconds
    setTimeout(() => clearInterval(waitForResults), 10000);
  }

  // Run when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Also handle dynamic page navigation (eBay uses SPA-like navigation)
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(init, 1000);
    }
  }).observe(document, { subtree: true, childList: true });

})();
