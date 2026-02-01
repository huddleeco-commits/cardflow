/**
 * CardFlow Quick Search - Popup Script
 */

// Get the search input value
function getQuery() {
  return document.getElementById('search-input').value.trim();
}

// Search eBay sold listings
function searchEbay() {
  const query = getQuery();
  if (!query) {
    document.getElementById('search-input').focus();
    return;
  }

  const q = encodeURIComponent(query);
  chrome.tabs.create({
    url: `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_Complete=1&LH_Sold=1&_sop=13`
  });
}

// Search all sources at once
function searchAll() {
  const query = getQuery();
  if (!query) {
    document.getElementById('search-input').focus();
    return;
  }

  chrome.runtime.sendMessage({ action: 'searchAll', query });
}

// Open a specific source
function openSource(source) {
  const query = getQuery();
  if (!query) {
    // If no query, just open the site homepage
    const homepages = {
      'ebay-sold': 'https://www.ebay.com/sch/Sports-Trading-Cards/212/i.html',
      'ebay-bin': 'https://www.ebay.com/sch/Sports-Trading-Cards/212/i.html',
      'comc': 'https://www.comc.com/',
      'scp': 'https://www.sportscardspro.com/',
      'pricecharting': 'https://www.pricecharting.com/'
    };
    chrome.tabs.create({ url: homepages[source] || 'https://www.ebay.com' });
    return;
  }

  const q = encodeURIComponent(query);
  const qPlus = query.replace(/\s+/g, '+');

  const urls = {
    'ebay-sold': `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_Complete=1&LH_Sold=1&_sop=13`,
    'ebay-bin': `https://www.ebay.com/sch/i.html?_nkw=${q}&LH_BIN=1&_sop=15`,
    'comc': `https://www.comc.com/Cards,sr,=${qPlus},fb,i100`,
    'scp': `https://www.sportscardspro.com/search?q=${q}`,
    'pricecharting': `https://www.pricecharting.com/search-products?q=${q}&type=prices`
  };

  if (urls[source]) {
    chrome.tabs.create({ url: urls[source] });
  }
}

// Open CardFlow dashboard
function openCardFlow() {
  chrome.tabs.create({ url: 'https://cardflow.be1st.io' });
}

// Handle Enter key in search input
document.getElementById('search-input').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    searchEbay();
  }
});

// Check for pending image scan
chrome.storage.local.get(['pendingImageScan'], (result) => {
  if (result.pendingImageScan) {
    // Clear it
    chrome.storage.local.remove('pendingImageScan');

    // Show scan UI (for now, just notify)
    const input = document.getElementById('search-input');
    input.placeholder = 'Image scan: Open CardFlow to identify...';

    // Could redirect to CardFlow with the image URL
    // For now, open CardFlow
    setTimeout(() => {
      chrome.tabs.create({
        url: 'https://cardflow.be1st.io?scan=' + encodeURIComponent(result.pendingImageScan)
      });
    }, 500);
  }
});

// Focus search input on load
document.getElementById('search-input').focus();
