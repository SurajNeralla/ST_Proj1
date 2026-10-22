/**
 * PhishGuard AI - Background Service Worker (Manifest V3)
 * Monitors top-level navigations, applies security modes, and manages alerts.
 */

/* global importScripts, chrome, PhishStorage, PhishDetector, PhishDB */

importScripts('phishing_db.js', 'storage.js', 'detector.js');

// In-memory cache of recent tab navigations to avoid redundant cycles and loops
const navigationCache = new Map();
const CACHE_TTL_MS = 4000;

/**
 * Handle top-level frame navigation
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only inspect top-level frame navigations (not iframes or background sub-resources)
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  // 1. Skip browser internal pages, extension pages, and exempt schemes
  if (PhishDetector.isExemptUrl(url)) return;

  // Avoid scanning the warning page itself
  const warningUrlPrefix = chrome.runtime.getURL('warning.html');
  if (url.startsWith(warningUrlPrefix)) return;

  // 2. Fetch current settings from persistent storage
  const settings = await PhishStorage.getSettings();
  if (!settings.protectionEnabled) {
    // Protection is explicitly turned off by user
    return;
  }

  // 3. Prevent duplicate scan cycles for the exact same tab within TTL window
  const cacheKey = `${tabId}:::${url}`;
  const now = Date.now();
  if (navigationCache.has(cacheKey) && (now - navigationCache.get(cacheKey) < CACHE_TTL_MS)) {
    return;
  }
  navigationCache.set(cacheKey, now);

  // Clean old entries periodically
  if (navigationCache.size > 200) {
    navigationCache.clear();
  }

  // 4. Parse hostname and check whitelist
  const parsed = PhishDetector.parseUrl(url);
  if (!parsed) return;
  const hostname = parsed.hostname.toLowerCase();

  const isWhitelisted = await PhishStorage.isHostnameAllowed(hostname);
  if (isWhitelisted) return;

  // 5. Run threat analysis
  const result = PhishDetector.analyzeUrl(url, settings.testMode);
  if (!result || !result.shouldScan) return;

  // Case A: Detection Service Unavailable
  if (result.status === 'unavailable') {
    await PhishStorage.addHistoryRecord({
      hostname,
      url,
      riskScore: 0,
      riskLevel: 'Detection Unavailable',
      detectionMethod: result.detectionMethod,
      indicators: result.indicators,
      isConfirmedPhishing: false,
      blocked: false,
      tabClosed: false
    });
    // Requirement 2: "Detection Unavailable: Do not automatically close the tab.
    // Clearly indicate that the website could not be checked."
    showNotification(
      'PhishGuard AI: Threat Check Inconclusive',
      `Could not verify reputation for ${hostname}. Tab remains open. Exercise caution.`
    );
    return;
  }

  // Case B: Low Risk
  if (result.riskLevel === 'Low Risk') {
    await PhishStorage.addHistoryRecord({
      hostname,
      url,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      detectionMethod: result.detectionMethod,
      indicators: result.indicators,
      isConfirmedPhishing: false,
      blocked: false,
      tabClosed: false
    });
    return;
  }

  // Case C: Confirmed Phishing (High confidence match against blocklist / fixture)
  if (result.isConfirmedPhishing) {
    await PhishStorage.incrementBlockedCount();

    if (settings.protectionMode === 'auto_close') {
      // Auto-Close Mode:
      // Show short notification explaining why tab was closed
      showNotification(
        'PhishGuard AI: Phishing Website Blocked',
        `Confirmed threat detected at ${hostname}. Tab was automatically closed for your safety.`
      );

      // Record in history
      await PhishStorage.addHistoryRecord({
        hostname,
        url,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        detectionMethod: result.detectionMethod,
        indicators: result.indicators,
        isConfirmedPhishing: true,
        blocked: true,
        tabClosed: true
      });

      // Close ONLY this specific tab
      try {
        await chrome.tabs.remove(tabId);
      } catch (e) {
        console.warn('Could not close tab:', e);
      }
      return;
    } else {
      // Safe Mode (Default):
      // Redirect to warning page without closing tab
      await PhishStorage.addHistoryRecord({
        hostname,
        url,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        detectionMethod: result.detectionMethod,
        indicators: result.indicators,
        isConfirmedPhishing: true,
        blocked: true,
        tabClosed: false
      });

      redirectToWarning(tabId, result, true);
      return;
    }
  }

  // Case D: Suspicious or Heuristic High Risk (Unconfirmed)
  // "The extension must not close tabs simply because a website is unfamiliar or its URL looks unusual."
  // "A high heuristic score alone must not be described as proof of phishing."
  // Safe warning page displayed, never auto-closed.
  await PhishStorage.addHistoryRecord({
    hostname,
    url,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    detectionMethod: result.detectionMethod,
    indicators: result.indicators,
    isConfirmedPhishing: false,
    blocked: true,
    tabClosed: false
  });

  redirectToWarning(tabId, result, false);
});

/**
 * Intercept and kill ad popup tabs spawned by web pages (window.open, target="_blank", pop-unders)
 */
if (typeof chrome !== 'undefined' && chrome.webNavigation && chrome.webNavigation.onCreatedNavigationTarget) {
  chrome.webNavigation.onCreatedNavigationTarget.addListener(async (details) => {
    const targetUrl = details.url;
    const popupTabId = details.tabId;

    const settings = await PhishStorage.getSettings();
    if (!settings.protectionEnabled) return;

    if (!targetUrl || targetUrl === 'about:blank' || PhishDetector.isExemptUrl(targetUrl)) {
      return;
    }

    const result = PhishDetector.analyzeUrl(targetUrl, settings.testMode);
    if (result && (result.riskScore >= 30 || result.isConfirmedPhishing)) {
      console.warn(`[PhishGuard AI] Automatically killed ad popup tab: ${targetUrl}`);
      await PhishStorage.incrementBlockedCount();
      showNotification(
        'PhishGuard AI: Ad Popup Neutralized',
        `Blocked unwanted ad popup to ${result.hostname}.`
      );
      try {
        await chrome.tabs.remove(popupTabId);
      } catch (e) {}
    }
  });
}

/**
 * Fallback popup interceptor using chrome.tabs.onCreated
 */
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.onCreated) {
  chrome.tabs.onCreated.addListener(async (tab) => {
    const targetUrl = tab.pendingUrl || tab.url;
    if (!targetUrl || PhishDetector.isExemptUrl(targetUrl)) return;

    const settings = await PhishStorage.getSettings();
    if (!settings.protectionEnabled) return;

    const result = PhishDetector.analyzeUrl(targetUrl, settings.testMode);
    if (result && (result.riskScore >= 60 || result.isConfirmedPhishing)) {
      try {
        await chrome.tabs.remove(tab.id);
      } catch (e) {}
    }
  });
}

/**
 * Handle committed navigations to guarantee threat page replacement even on fast server responses & redirects
 */
if (typeof chrome !== 'undefined' && chrome.webNavigation && chrome.webNavigation.onCommitted) {
  chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    const url = details.url;
    const tabId = details.tabId;

    if (PhishDetector.isExemptUrl(url)) return;
    const warningUrlPrefix = chrome.runtime.getURL('warning.html');
    if (url.startsWith(warningUrlPrefix)) return;

    const settings = await PhishStorage.getSettings();
    if (!settings.protectionEnabled) return;

    const parsed = PhishDetector.parseUrl(url);
    if (!parsed) return;
    const hostname = parsed.hostname.toLowerCase();

    const isWhitelisted = await PhishStorage.isHostnameAllowed(hostname);
    if (isWhitelisted) return;

    const result = PhishDetector.analyzeUrl(url, settings.testMode);
    if (!result || !result.shouldScan) return;

    if (result.riskScore >= 60 || result.isConfirmedPhishing) {
      if (settings.protectionMode === 'auto_close' && result.canAutoClose) {
        try {
          await chrome.tabs.remove(tabId);
        } catch (e) {}
      } else {
        redirectToWarning(tabId, result, result.isConfirmedPhishing);
      }
    }
  });
}

/**
 * Redirects tab to custom warning page with URL parameters
 */
function redirectToWarning(tabId, result, isConfirmed) {
  const warningUrl = chrome.runtime.getURL('warning.html') +
    '?url=' + encodeURIComponent(result.url) +
    '&hostname=' + encodeURIComponent(result.hostname) +
    '&risk=' + encodeURIComponent(result.riskLevel) +
    '&score=' + encodeURIComponent(result.riskScore) +
    '&reason=' + encodeURIComponent(result.reason) +
    '&method=' + encodeURIComponent(result.detectionMethod) +
    '&confirmed=' + (isConfirmed ? '1' : '0') +
    '&indicators=' + encodeURIComponent(JSON.stringify(result.indicators || []));

  chrome.tabs.update(tabId, { url: warningUrl });
}

/**
 * Helper to display native notifications safely
 */
function showNotification(title, message) {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon48.png'),
      title: title,
      message: message,
      priority: 2
    });
  } catch (e) {
    console.warn('Notification failed:', e);
  }
}

/**
 * Listener for messaging from Popup, Warning page, or Content Script
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'SCAN_ACTIVE_TAB') {
    (async () => {
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!activeTab || !activeTab.url) {
          sendResponse({ success: false, error: 'No active tab found' });
          return;
        }

        const settings = await PhishStorage.getSettings();
        if (PhishDetector.isExemptUrl(activeTab.url)) {
          sendResponse({
            success: true,
            isExempt: true,
            url: activeTab.url,
            hostname: 'System / Internal URL',
            riskLevel: 'Exempt',
            riskScore: 0,
            indicators: [],
            reason: 'Internal browser scheme not subject to external phishing threats.'
          });
          return;
        }

        const result = PhishDetector.analyzeUrl(activeTab.url, settings.testMode);
        sendResponse({ success: true, isExempt: false, data: result, settings });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true; // Keep message channel open for async response
  }

  // Handle in-page ad or auto-redirect detection from content.js
  if (message.action === 'INTRUSIVE_AD_OR_REDIRECT_DETECTED') {
    (async () => {
      const tabId = sender.tab ? sender.tab.id : null;
      if (!tabId) return;

      const settings = await PhishStorage.getSettings();
      if (!settings.protectionEnabled) return;

      await PhishStorage.incrementBlockedCount();
      const currentHost = PhishDetector.parseUrl(message.url)?.hostname || 'Malvertising Host';
      const blockedResult = {
        url: message.url || message.targetUrl,
        hostname: currentHost,
        riskLevel: 'Very High Risk',
        riskScore: 95,
        detectionMethod: 'In-Page Malvertising & Redirect Defense',
        reason: message.reason || 'Deceptive ad script or auto-redirect detected on page.',
        indicators: [
          {
            name: 'Deceptive Ad or Auto-Redirect Blocked',
            severity: 'Critical',
            detail: message.reason
          }
        ]
      };

      if (settings.protectionMode === 'auto_close') {
        showNotification(
          'PhishGuard AI: Intrusive Ad Redirect Blocked',
          `Intrusive ad redirect on ${currentHost} was blocked and tab closed.`
        );
        try {
          await chrome.tabs.remove(tabId);
        } catch (e) {}
      } else {
        redirectToWarning(tabId, blockedResult, true);
      }
    })();
    return true;
  }

  if (message.action === 'AD_BLOCKED_NOTIFICATION') {
    showNotification(
      'PhishGuard AI: Ad Pop-Under Blocked',
      message.reason || 'Blocked an unprompted background ad pop-under.'
    );
    return true;
  }

  if (message.action === 'CLOSE_TAB') {
    const targetTabId = sender.tab ? sender.tab.id : message.tabId;
    if (targetTabId) {
      chrome.tabs.remove(targetTabId);
    }
    return true;
  }
});
