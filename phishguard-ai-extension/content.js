/**
 * PhishGuard AI - Comprehensive Content Security Script
 * Runs at document_start to block malicious pages, intrusive popups,
 * client-side auto-redirects, clickjacking overlays, and malvertising networks.
 */

/* global chrome, PhishDetector, PhishStorage, PhishDB */

(function () {
  'use strict';

  const currentUrl = window.location.href;

  // Skip browser internal pages and extension pages
  if (!currentUrl || typeof PhishDetector === 'undefined' || PhishDetector.isExemptUrl(currentUrl)) {
    return;
  }

  const warningUrlPrefix = chrome.runtime.getURL('warning.html');
  if (currentUrl.startsWith(warningUrlPrefix)) {
    return;
  }

  // 1. FAST AT-DOCUMENT-START THREAT INTERCEPTION
  // If the destination is a confirmed threat or high-risk site (e.g. 5movierulz.recipes),
  // immediately STOP document parsing and execution before any ad popups or redirects fire!
  try {
    const analysis = PhishDetector.analyzeUrl(currentUrl, true);
    if (analysis && (analysis.riskScore >= 60 || analysis.isConfirmedPhishing)) {
      // Check if user previously clicked "Proceed Anyway" for this host
      chrome.storage.local.get(['phishguard_settings', 'phishguard_whitelist'], (res) => {
        const settings = res.phishguard_settings || {};
        if (settings.protectionEnabled === false) return;

        const whitelist = res.phishguard_whitelist || [];
        const hostname = analysis.hostname;
        if (whitelist.includes(hostname)) return;

        // CRITICAL ACTION: Freeze page execution immediately
        window.stop();
        if (document.documentElement) {
          document.documentElement.innerHTML = '<head><title>PhishGuard AI — Intercepting Threat</title></head><body style="background:#070d1a;color:#f8fafc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;"><div style="text-align:center;"><h2>PhishGuard AI Intercepted Threat</h2><p>Redirecting to safety warning...</p></div></body>';
        }

        // Redirect to local warning page
        const warningUrl = chrome.runtime.getURL('warning.html') +
          '?url=' + encodeURIComponent(analysis.url) +
          '&hostname=' + encodeURIComponent(analysis.hostname) +
          '&risk=' + encodeURIComponent(analysis.riskLevel) +
          '&score=' + encodeURIComponent(analysis.riskScore) +
          '&reason=' + encodeURIComponent(analysis.reason) +
          '&method=' + encodeURIComponent(analysis.detectionMethod) +
          '&confirmed=' + (analysis.isConfirmedPhishing ? '1' : '0') +
          '&indicators=' + encodeURIComponent(JSON.stringify(analysis.indicators || []));

        // If in auto_close mode and confirmed threat, notify background to close tab
        if (settings.protectionMode === 'auto_close' && analysis.canAutoClose) {
          chrome.runtime.sendMessage({
            action: 'INTRUSIVE_AD_OR_REDIRECT_DETECTED',
            url: currentUrl,
            reason: analysis.reason
          });
        } else {
          window.location.replace(warningUrl);
        }
      });
      return;
    }
  } catch (err) {
    console.warn('[PhishGuard AI] Fast threat check error:', err);
  }

  // 2. INJECT MAIN-WORLD SCRIPT TO INTERCEPT WINDOW.OPEN & JAVASCRIPT REDIRECTS
  // In Chrome MV3, content scripts run in an isolated world. Injecting an inline
  // script into documentElement ensures we intercept the page's actual window.open!
  function injectMainWorldShield() {
    try {
      const script = document.createElement('script');
      script.textContent = `
        (function() {
          const originalOpen = window.open;
          const blockedKeywords = [
            'adsterra', 'propeller', 'popcash', 'popads', 'monetag', 'clickadu',
            'exoclick', 'adcash', 'bet365', '1xbet', 'redirect', 'click', 'affiliate',
            'jump', 'track', 'trafficjunky', 'juicyads', 'yllix', 'richpush'
          ];

          window.open = function(url, target, features) {
            const urlStr = (url || '').toString().toLowerCase();
            const isAd = blockedKeywords.some(kw => urlStr.includes(kw));

            // If an unprompted popup or ad network is targeted, block it
            if (isAd || !urlStr || urlStr === 'about:blank') {
              console.warn('[PhishGuard AI] Neutralized ad popup window.open:', url);
              window.dispatchEvent(new CustomEvent('PHISHGUARD_POPUP_BLOCKED', { detail: { url: urlStr } }));
              return null;
            }

            return originalOpen.apply(this, arguments);
          };

          // Neutralize location.replace if pointing to known ad networks
          const originalReplace = window.location.replace;
          window.location.replace = function(dest) {
            const destStr = (dest || '').toString().toLowerCase();
            if (blockedKeywords.some(kw => destStr.includes(kw))) {
              console.warn('[PhishGuard AI] Blocked malicious location.replace to:', dest);
              window.dispatchEvent(new CustomEvent('PHISHGUARD_POPUP_BLOCKED', { detail: { url: destStr } }));
              return;
            }
            return originalReplace.apply(window.location, arguments);
          };
        })();
      `;
      (document.head || document.documentElement).appendChild(script);
      script.remove();
    } catch (e) {
      console.warn('[PhishGuard AI] Could not inject main world shield:', e);
    }
  }

  injectMainWorldShield();

  // Listen for popup blocks from the main world
  window.addEventListener('PHISHGUARD_POPUP_BLOCKED', (e) => {
    try {
      chrome.runtime.sendMessage({
        action: 'AD_BLOCKED_NOTIFICATION',
        reason: `Blocked deceptive ad popup to ${e.detail?.url || 'unverified ad network'}`
      });
    } catch (err) {}
  });

  // 3. NEUTRALIZE TRANSPARENT CLICKJACKING OVERLAYS & META REFRESH
  function neutralizeClickjackingOverlays() {
    const elements = document.querySelectorAll('div, a, iframe');
    elements.forEach(el => {
      try {
        const style = window.getComputedStyle(el);
        const isFullScreen = (
          (el.offsetWidth >= window.innerWidth * 0.90 && el.offsetHeight >= window.innerHeight * 0.90) ||
          (style.position === 'fixed' && (style.width === '100%' || style.width === '100vw'))
        );
        const isTransparent = parseFloat(style.opacity) < 0.1 || style.backgroundColor === 'transparent';
        const hasHighZIndex = parseInt(style.zIndex, 10) > 100;

        if (isFullScreen && isTransparent && hasHighZIndex) {
          console.warn('[PhishGuard AI] Removed full-screen transparent clickjacking trap overlay');
          el.remove();
        }
      } catch (e) {}
    });
  }

  function checkMetaRefresh() {
    const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
    metaTags.forEach(meta => {
      const content = meta.getAttribute('content') || '';
      if (/url=/i.test(content)) {
        console.warn('[PhishGuard AI] Removed deceptive meta-refresh auto-redirect');
        meta.remove();
      }
    });
  }

  // Observe and sanitize DOM as it renders
  document.addEventListener('DOMContentLoaded', () => {
    neutralizeClickjackingOverlays();
    checkMetaRefresh();

    const observer = new MutationObserver(() => {
      neutralizeClickjackingOverlays();
      checkMetaRefresh();
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  });

})();
