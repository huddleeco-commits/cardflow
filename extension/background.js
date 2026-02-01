/**
 * CardFlow Quick Search - Background Service Worker
 *
 * Provides right-click context menu for:
 * - Searching selected text across multiple pricing sources
 * - Scanning images to identify cards
 */

// CardFlow API URL (change for production)
const CARDFLOW_API = 'https://cardflow.be1st.io/api';

// Create context menus on extension install
chrome.runtime.onInstalled.addListener(() => {
  console.log('[CardFlow] Creating context menus...');

  // Parent menu for text selection
  chrome.contextMenus.create({
    id: 'cardflow-search',
    title: 'CardFlow: Search "%s"',
    contexts: ['selection']
  });

  // Submenu - eBay Sold
  chrome.contextMenus.create({
    id: 'search-ebay-sold',
    parentId: 'cardflow-search',
    title: 'eBay Sold Listings',
    contexts: ['selection']
  });

  // Submenu - eBay Buy It Now
  chrome.contextMenus.create({
    id: 'search-ebay-bin',
    parentId: 'cardflow-search',
    title: 'eBay Buy It Now',
    contexts: ['selection']
  });

  // Submenu - COMC
  chrome.contextMenus.create({
    id: 'search-comc',
    parentId: 'cardflow-search',
    title: 'COMC Marketplace',
    contexts: ['selection']
  });

  // Submenu - SportsCardsPro
  chrome.contextMenus.create({
    id: 'search-scp',
    parentId: 'cardflow-search',
    title: 'SportsCardsPro',
    contexts: ['selection']
  });

  // Submenu - PriceCharting (Pokemon/TCG)
  chrome.contextMenus.create({
    id: 'search-pricecharting',
    parentId: 'cardflow-search',
    title: 'PriceCharting (Pokemon)',
    contexts: ['selection']
  });

  // Separator
  chrome.contextMenus.create({
    id: 'separator-1',
    parentId: 'cardflow-search',
    type: 'separator',
    contexts: ['selection']
  });

  // Search ALL at once
  chrome.contextMenus.create({
    id: 'search-all',
    parentId: 'cardflow-search',
    title: 'Search ALL Sources',
    contexts: ['selection']
  });

  // Scan image context menu
  chrome.contextMenus.create({
    id: 'cardflow-scan-image',
    title: 'CardFlow: Identify This Card',
    contexts: ['image']
  });

  console.log('[CardFlow] Context menus created');
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  console.log('[CardFlow] Context menu clicked:', info.menuItemId);

  // Handle text selection searches
  if (info.menuItemId.startsWith('search-')) {
    const query = info.selectionText?.trim();
    if (!query) return;

    const q = encodeURIComponent(query);
    const qPlus = query.replace(/\s+/g, '+');

    // URL templates for each source
    const urls = {
      'search-ebay-sold': `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_Complete=1&LH_Sold=1&_sop=13`,
      'search-ebay-bin': `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_BIN=1&_sop=15`,
      'search-comc': `https://www.comc.com/Cards,sr,=${qPlus},fb,i100`,
      'search-scp': `https://www.sportscardspro.com/search?q=${q}`,
      'search-pricecharting': `https://www.pricecharting.com/search-products?q=${q}&type=prices`
    };

    if (info.menuItemId === 'search-all') {
      // Open all sources in new tabs
      const allUrls = [
        urls['search-ebay-sold'],
        urls['search-ebay-bin'],
        urls['search-comc'],
        urls['search-scp']
      ];

      allUrls.forEach((url, i) => {
        setTimeout(() => {
          chrome.tabs.create({ url, active: i === 0 });
        }, i * 150); // Stagger tab opening
      });

      console.log('[CardFlow] Opened all search sources for:', query);
    } else if (urls[info.menuItemId]) {
      chrome.tabs.create({ url: urls[info.menuItemId] });
      console.log('[CardFlow] Opened', info.menuItemId, 'for:', query);
    }
  }

  // Handle image scan
  if (info.menuItemId === 'cardflow-scan-image') {
    const imageUrl = info.srcUrl;
    if (!imageUrl) return;

    console.log('[CardFlow] Scanning image:', imageUrl);

    // Store the image URL and open popup
    await chrome.storage.local.set({ pendingImageScan: imageUrl });

    // Open the popup (or create a new tab with scan UI)
    try {
      await chrome.action.openPopup();
    } catch (e) {
      // If popup can't open, open in new tab
      chrome.tabs.create({
        url: chrome.runtime.getURL('popup/popup.html?scan=' + encodeURIComponent(imageUrl))
      });
    }
  }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'searchCard') {
    const { query } = request;
    const q = encodeURIComponent(query);

    // Open eBay sold search
    chrome.tabs.create({
      url: `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_Complete=1&LH_Sold=1&_sop=13`
    });

    sendResponse({ success: true });
  }

  if (request.action === 'searchAll') {
    const { query } = request;
    const q = encodeURIComponent(query);
    const qPlus = query.replace(/\s+/g, '+');

    const urls = [
      `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_Complete=1&LH_Sold=1&_sop=13`,
      `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_BIN=1&_sop=15`,
      `https://www.comc.com/Cards,sr,=${qPlus},fb,i100`,
      `https://www.sportscardspro.com/search?q=${q}`
    ];

    urls.forEach((url, i) => {
      setTimeout(() => {
        chrome.tabs.create({ url, active: i === 0 });
      }, i * 150);
    });

    sendResponse({ success: true });
  }

  return true; // Keep message channel open for async
});

console.log('[CardFlow] Background service worker loaded');
