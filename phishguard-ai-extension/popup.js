/**
 * PhishGuard AI - Popup Script
 * Manages user interface, settings toggles, live active tab inspection, and history.
 */

/* global chrome, PhishStorage, PhishDetector */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  const toggleMaster = document.getElementById('toggleMasterProtection');
  const statusBanner = document.getElementById('statusBanner');
  const statusText = document.getElementById('statusText');

  const radioSafe = document.getElementById('radioSafeMode');
  const radioAuto = document.getElementById('radioAutoClose');
  const pillSafe = document.getElementById('labelSafeMode');
  const pillAuto = document.getElementById('labelAutoClose');

  const activeHostname = document.getElementById('activeHostname');
  const activeRiskBadge = document.getElementById('activeRiskBadge');
  const activeScoreDisplay = document.getElementById('activeScoreDisplay');
  const scoreBarFill = document.getElementById('scoreBarFill');
  const activeIndicatorsContainer = document.getElementById('activeIndicatorsContainer');
  const btnRescan = document.getElementById('btnRescan');

  const statBlocked = document.getElementById('statBlocked');
  const statScanned = document.getElementById('statScanned');

  const btnToggleDemo = document.getElementById('btnToggleDemo');
  const demoPanel = document.getElementById('demoPanel');
  const demoChevron = document.getElementById('demoChevron');

  const btnToggleHistory = document.getElementById('btnToggleHistory');
  const historyPanel = document.getElementById('historyPanel');
  const historyList = document.getElementById('historyList');
  const btnClearHistory = document.getElementById('btnClearHistory');

  // 1. Load initial settings
  const settings = await PhishStorage.getSettings();
  const history = await PhishStorage.getHistory();

  // Set Master Toggle state
  toggleMaster.checked = !!settings.protectionEnabled;
  updateStatusBanner(settings.protectionEnabled);

  // Set Protection Mode state
  if (settings.protectionMode === 'auto_close') {
    radioAuto.checked = true;
    pillAuto.classList.add('active');
    pillSafe.classList.remove('active');
  } else {
    radioSafe.checked = true;
    pillSafe.classList.add('active');
    pillAuto.classList.remove('active');
  }

  // Update Stats Counters
  updateStatsDisplay(settings.blockedCount || 0, history.length);

  // 2. Scan and display active tab
  await scanActiveTab(settings.testMode);

  // 3. Event Listeners

  // Master Toggle Change
  toggleMaster.addEventListener('change', async () => {
    const isEnabled = toggleMaster.checked;
    await PhishStorage.updateSettings({ protectionEnabled: isEnabled });
    updateStatusBanner(isEnabled);
    // Refresh active tab inspection
    await scanActiveTab(settings.testMode);
  });

  // Protection Mode Change
  function updateModeSelection(mode) {
    if (mode === 'auto_close') {
      pillAuto.classList.add('active');
      pillSafe.classList.remove('active');
    } else {
      pillSafe.classList.add('active');
      pillAuto.classList.remove('active');
    }
    PhishStorage.updateSettings({ protectionMode: mode });
  }

  radioSafe.addEventListener('change', () => updateModeSelection('safe'));
  radioAuto.addEventListener('change', () => updateModeSelection('auto_close'));

  // Rescan Active Tab Button
  btnRescan.addEventListener('click', async () => {
    btnRescan.style.transform = 'rotate(180deg)';
    setTimeout(() => { btnRescan.style.transform = 'none'; }, 300);
    const curSettings = await PhishStorage.getSettings();
    await scanActiveTab(curSettings.testMode);
  });

  // Toggle Demo Panel
  btnToggleDemo.addEventListener('click', () => {
    demoPanel.classList.toggle('hidden');
    demoChevron.classList.toggle('open');
  });

  // Demo URL Buttons: Opens target in Chrome tab to trigger demonstration
  document.querySelectorAll('.btn-demo').forEach(btn => {
    btn.addEventListener('click', () => {
      const demoUrl = btn.getAttribute('data-url');
      if (demoUrl && typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.create({ url: demoUrl });
      }
    });
  });

  // Toggle History Drawer
  btnToggleHistory.addEventListener('click', async () => {
    const isHidden = historyPanel.classList.contains('hidden');
    if (isHidden) {
      await renderHistoryList();
      historyPanel.classList.remove('hidden');
    } else {
      historyPanel.classList.add('hidden');
    }
  });

  // Clear History Button
  btnClearHistory.addEventListener('click', async () => {
    if (confirm('Clear all scan history? This action cannot be undone.')) {
      await PhishStorage.clearHistory();
      await renderHistoryList();
      const curSettings = await PhishStorage.getSettings();
      updateStatsDisplay(curSettings.blockedCount || 0, 0);
    }
  });

  // --- Helper Functions ---

  function updateStatusBanner(isActive) {
    if (isActive) {
      statusBanner.className = 'status-banner status-active';
      statusText.textContent = 'Protection Active';
    } else {
      statusBanner.className = 'status-banner status-disabled';
      statusText.textContent = 'Protection Disabled';
    }
  }

  function updateStatsDisplay(blocked, scanned) {
    if (statBlocked) statBlocked.textContent = blocked;
    if (statScanned) statScanned.textContent = scanned;
  }

  async function scanActiveTab(testMode) {
    if (typeof chrome === 'undefined' || !chrome.tabs) {
      activeHostname.textContent = 'Non-Extension Context';
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) {
        activeHostname.textContent = 'No Active Tab';
        return;
      }

      const url = tab.url;

      // Check for internal browser URLs
      if (PhishDetector.isExemptUrl(url)) {
        activeHostname.textContent = 'Browser System / Internal Page';
        activeRiskBadge.className = 'badge badge-exempt';
        activeRiskBadge.textContent = 'Exempt';
        activeScoreDisplay.textContent = 'Score: 0';
        scoreBarFill.style.width = '0%';
        scoreBarFill.style.background = '#64748b';
        activeIndicatorsContainer.innerHTML = '<span class="indicator-pill low">Internal system scheme (safe from phishing)</span>';
        return;
      }

      const parsed = PhishDetector.parseUrl(url);
      activeHostname.textContent = parsed ? parsed.hostname : url;

      // Check if protection is enabled
      const isEnabled = toggleMaster.checked;
      if (!isEnabled) {
        activeRiskBadge.className = 'badge badge-exempt';
        activeRiskBadge.textContent = 'Paused';
        activeScoreDisplay.textContent = 'Off';
        scoreBarFill.style.width = '0%';
        activeIndicatorsContainer.innerHTML = '<span class="indicator-pill medium">Protection currently disabled by user.</span>';
        return;
      }

      // Analyze active URL
      const result = PhishDetector.analyzeUrl(url, testMode);

      if (result.status === 'unavailable') {
        activeRiskBadge.className = 'badge badge-suspicious';
        activeRiskBadge.textContent = 'Unavailable';
        activeScoreDisplay.textContent = 'Score: --';
        scoreBarFill.style.width = '20%';
        scoreBarFill.style.background = '#f59e0b';
        activeIndicatorsContainer.innerHTML = '<span class="indicator-pill medium">Detection intelligence unavailable. Tab allowed to remain open.</span>';
        return;
      }

      // Risk level badge & score fill
      const score = result.riskScore || 0;
      activeScoreDisplay.textContent = `Score: ${score}/100`;
      scoreBarFill.style.width = `${Math.min(100, Math.max(4, score))}%`;

      if (score >= 80 || result.riskLevel === 'Very High Risk') {
        activeRiskBadge.className = 'badge badge-high';
        activeRiskBadge.textContent = 'Very High Risk';
        scoreBarFill.style.background = '#ef4444';
      } else if (score >= 60 || result.riskLevel === 'High Risk') {
        activeRiskBadge.className = 'badge badge-high';
        activeRiskBadge.textContent = 'High Risk';
        scoreBarFill.style.background = '#f87171';
      } else if (score >= 30 || result.riskLevel === 'Suspicious') {
        activeRiskBadge.className = 'badge badge-suspicious';
        activeRiskBadge.textContent = 'Suspicious';
        scoreBarFill.style.background = '#f59e0b';
      } else {
        activeRiskBadge.className = 'badge badge-low';
        activeRiskBadge.textContent = 'Low Risk';
        scoreBarFill.style.background = '#10b981';
      }

      // Render indicators
      activeIndicatorsContainer.innerHTML = '';
      if (result.indicators && result.indicators.length > 0) {
        result.indicators.slice(0, 3).forEach(ind => {
          const pill = document.createElement('div');
          const severityClass = (ind.severity || 'high').toLowerCase();
          pill.className = `indicator-pill ${severityClass}`;
          pill.textContent = `${ind.name}: ${ind.detail}`;
          activeIndicatorsContainer.appendChild(pill);
        });
      } else {
        const pill = document.createElement('div');
        pill.className = 'indicator-pill low';
        pill.textContent = 'No suspicious domain patterns or anomalies detected.';
        activeIndicatorsContainer.appendChild(pill);
      }
    } catch (err) {
      console.warn('Error evaluating active tab:', err);
      activeHostname.textContent = 'Inspection Error';
    }
  }

  async function renderHistoryList() {
    const list = await PhishStorage.getHistory();
    historyList.innerHTML = '';

    if (!list || list.length === 0) {
      historyList.innerHTML = '<p class="empty-text">No scans recorded yet.</p>';
      return;
    }

    list.slice(0, 20).forEach(item => {
      const div = document.createElement('div');
      div.className = 'history-item';

      const hostSpan = document.createElement('span');
      hostSpan.className = 'history-host';
      hostSpan.textContent = item.hostname;
      hostSpan.title = item.url || item.hostname;

      const metaSpan = document.createElement('div');
      metaSpan.className = 'history-meta';

      const badge = document.createElement('span');
      if (item.riskLevel.includes('High')) {
        badge.className = 'tag tag-red';
      } else if (item.riskLevel.includes('Suspicious') || item.riskLevel.includes('Unavailable')) {
        badge.className = 'tag tag-yellow';
      } else {
        badge.className = 'tag tag-green';
      }
      badge.textContent = item.riskLevel;

      const scoreSpan = document.createElement('span');
      scoreSpan.style.color = '#94a3b8';
      scoreSpan.textContent = `${item.riskScore}`;

      metaSpan.appendChild(scoreSpan);
      metaSpan.appendChild(badge);

      div.appendChild(hostSpan);
      div.appendChild(metaSpan);
      historyList.appendChild(div);
    });
  }
});
