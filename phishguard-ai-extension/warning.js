/**
 * PhishGuard AI - Warning Page Script
 * Reads URL query parameters and handles user response safely.
 */

/* global chrome, PhishStorage */

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);

  const targetUrl = params.get('url') || 'Unknown URL';
  const hostname = params.get('hostname') || 'Unknown Host';
  const riskLevel = params.get('risk') || 'High Risk';
  const score = params.get('score') || '90';
  const reason = params.get('reason') || 'High-confidence indicators detected.';
  const method = params.get('method') || 'PhishGuard AI Engine';
  const isConfirmed = params.get('confirmed') === '1';

  let indicators = [];
  try {
    const rawIndicators = params.get('indicators');
    if (rawIndicators) {
      indicators = JSON.parse(rawIndicators);
    }
  } catch (e) {
    indicators = [];
  }

  // Populate DOM elements
  const elHostname = document.getElementById('displayHostname');
  const elScore = document.getElementById('displayScore');
  const elUrl = document.getElementById('displayUrl');
  const elReason = document.getElementById('displayReason');
  const elRiskBadge = document.getElementById('badgeRiskLevel');
  const elMethodBadge = document.getElementById('badgeDetectionMethod');
  const elHeader = document.getElementById('titleHeader');
  const elIndicatorsList = document.getElementById('indicatorsList');
  const advancedSection = document.getElementById('advancedSection');
  const advancedPanel = document.getElementById('advancedPanel');

  if (elHostname) elHostname.textContent = hostname;
  if (elScore) elScore.textContent = `${score} / 100`;
  if (elUrl) elUrl.textContent = targetUrl;
  if (elReason) elReason.textContent = reason;
  if (elMethodBadge) elMethodBadge.textContent = method;

  if (elRiskBadge) {
    elRiskBadge.textContent = riskLevel;
    if (riskLevel === 'Suspicious') {
      elRiskBadge.className = 'risk-badge risk-suspicious';
    } else {
      elRiskBadge.className = 'risk-badge risk-high';
    }
  }

  if (isConfirmed) {
    if (elHeader) elHeader.textContent = 'Confirmed Phishing Website Blocked';
    // Strict Requirement: Do NOT include continue button for confirmed malicious URLs
    if (advancedSection) advancedSection.classList.add('hidden');
  } else {
    if (elHeader) elHeader.textContent = 'Potential Phishing Threat Blocked';
    // For unconfirmed / suspicious websites, show advanced option
    if (advancedSection) advancedSection.classList.remove('hidden');
  }

  // Render indicators
  if (elIndicatorsList) {
    elIndicatorsList.innerHTML = '';
    if (indicators && indicators.length > 0) {
      indicators.forEach(ind => {
        const li = document.createElement('li');
        const severityClass = (ind.severity || 'high').toLowerCase();
        li.className = `indicator-item ${severityClass}`;

        const content = document.createElement('div');
        content.className = 'indicator-content';

        const title = document.createElement('strong');
        title.textContent = ind.name || 'Threat Flag';

        const detail = document.createElement('span');
        detail.textContent = ind.detail || '';

        content.appendChild(title);
        content.appendChild(detail);
        li.appendChild(content);
        elIndicatorsList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.className = 'indicator-item medium';
      li.innerHTML = '<div class="indicator-content"><strong>Heuristic Evaluation</strong><span>Elevated anomaly score triggered by domain syntax patterns.</span></div>';
      elIndicatorsList.appendChild(li);
    }
  }

  // Action: Close Tab
  const btnClose = document.getElementById('btnCloseTab');
  if (btnClose) {
    btnClose.addEventListener('click', () => {
      // Send message to background to safely remove current tab
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'CLOSE_TAB' });
      }
      window.close();
    });
  }

  // Action: Return to Safety
  const btnSafety = document.getElementById('btnReturnSafety');
  if (btnSafety) {
    btnSafety.addEventListener('click', () => {
      window.location.href = 'https://www.google.com';
    });
  }

  // Toggle Advanced Panel
  const btnToggleAdv = document.getElementById('btnToggleAdvanced');
  if (btnToggleAdv && advancedPanel) {
    btnToggleAdv.addEventListener('click', () => {
      advancedPanel.classList.toggle('hidden');
    });
  }

  // Action: Proceed Anyway (Only accessible for unconfirmed suspicious cases)
  const btnProceed = document.getElementById('btnProceedAnyway');
  if (btnProceed) {
    btnProceed.addEventListener('click', async () => {
      if (typeof PhishStorage !== 'undefined') {
        await PhishStorage.allowHostname(hostname);
      }
      // Redirect to original URL
      window.location.href = targetUrl;
    });
  }
});
