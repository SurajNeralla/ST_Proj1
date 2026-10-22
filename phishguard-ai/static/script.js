/**
 * PhishGuard AI - Web Application Frontend Controller
 * Handles analysis requests, presets, metric updates, and SQLite history table.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const messageInput = document.getElementById('messageInput');
  const charCount = document.getElementById('charCount');
  const btnAnalyze = document.getElementById('btnAnalyze');
  const btnClearInput = document.getElementById('btnClearInput');

  const resultsPlaceholder = document.getElementById('resultsPlaceholder');
  const resultsContent = document.getElementById('resultsContent');
  const assessmentBanner = document.getElementById('assessmentBanner');
  const classificationTitle = document.getElementById('classificationTitle');
  const scoreNum = document.getElementById('scoreNum');
  const gaugeFill = document.getElementById('gaugeFill');
  const explanationText = document.getElementById('explanationText');
  const warningList = document.getElementById('warningList');
  const warningCount = document.getElementById('warningCount');
  const mitigationsList = document.getElementById('mitigationsList');
  const resultTimestamp = document.getElementById('resultTimestamp');

  const metricTotal = document.getElementById('metricTotal');
  const metricPhishing = document.getElementById('metricPhishing');
  const metricSuspicious = document.getElementById('metricSuspicious');
  const metricLow = document.getElementById('metricLow');
  const metricAvgScore = document.getElementById('metricAvgScore');

  const historyTableBody = document.getElementById('historyTableBody');
  const btnClearHistory = document.getElementById('btnClearHistory');

  // Preset Messages for 1-Click Evaluation Testing
  const PRESETS = {
    otp: "URGENT NOTICE: Your bank account will be suspended within 24 hours due to suspicious activity. Please confirm your identity immediately by replying with your One-Time Password (OTP) verification code.",
    suspension: "SECURITY ALERT: Unauthorized sign-in attempt detected from an unrecognized device. Your account has been temporarily locked. Verify your credentials now at http://paypal-security-update.xyz to prevent permanent deactivation.",
    lottery: "CONGRATULATIONS! You have been selected as the grand winner of the 2026 International Cash Lottery Prize of $1,000,000! Claim your reward immediately by paying the $150 processing fee via wire transfer.",
    link: "ACTION REQUIRED: Unpaid invoice #83921 is past due. Settle payment immediately to avoid legal action. Access your secure payment portal here: http://192.168.1.105/billing/pay-now",
    normal: "Hi Suraj, hope you're having a productive week. Please review the updated design slides for tomorrow's project meeting when you get a chance. Let's sync up after lunch."
  };

  // 1. Initial Load: Fetch metrics & history from SQLite
  fetchStats();
  fetchHistory();

  // 2. Character Counter
  messageInput.addEventListener('input', () => {
    charCount.textContent = messageInput.value.length;
  });

  // 3. Preset Buttons
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const presetKey = chip.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        messageInput.value = PRESETS[presetKey];
        charCount.textContent = messageInput.value.length;
        messageInput.focus();
      }
    });
  });

  // 4. Clear Input
  btnClearInput.addEventListener('click', () => {
    messageInput.value = '';
    charCount.textContent = '0';
    messageInput.focus();
  });

  // 5. Analyze Message Submission
  btnAnalyze.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    if (!text) {
      alert('Please enter or paste a message to analyze.');
      messageInput.focus();
      return;
    }

    // Set loading state
    btnAnalyze.disabled = true;
    btnAnalyze.innerHTML = '<span class="status-indicator"></span> Analyzing...';

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text })
      });

      const data = await response.json();

      if (!data.success) {
        alert(data.error || 'Failed to analyze message.');
        return;
      }

      // Display results
      renderResults(data.data);

      // Refresh metrics and history from SQLite
      fetchStats();
      fetchHistory();

    } catch (err) {
      console.error('Analysis error:', err);
      alert('A network error occurred while communicating with the analysis engine.');
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span>Analyze Message</span>
      `;
    }
  });

  // 6. Clear History Button
  btnClearHistory.addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear all analysis history records from the database?')) {
      try {
        const response = await fetch('/api/history/clear', { method: 'POST' });
        const data = await response.json();
        if (data.success) {
          fetchStats();
          fetchHistory();
        } else {
          alert('Could not clear history: ' + data.error);
        }
      } catch (e) {
        alert('Network error while clearing history.');
      }
    }
  });

  // --- Helper Functions ---

  function renderResults(res) {
    resultsPlaceholder.classList.add('hidden');
    resultsContent.classList.remove('hidden');

    resultTimestamp.textContent = `Analyzed on ${res.timestamp || new Date().toLocaleTimeString()}`;
    classificationTitle.textContent = res.classification;
    scoreNum.textContent = res.risk_score;

    // Update gauge fill width and colors
    gaugeFill.style.width = `${Math.min(100, Math.max(5, res.risk_score))}%`;

    assessmentBanner.className = 'assessment-banner';
    if (res.classification === 'Likely Phishing') {
      assessmentBanner.classList.add('phish');
      gaugeFill.style.background = '#ef4444';
    } else if (res.classification === 'Suspicious') {
      assessmentBanner.classList.add('suspicious');
      gaugeFill.style.background = '#f59e0b';
    } else {
      assessmentBanner.classList.add('safe');
      gaugeFill.style.background = '#10b981';
    }

    explanationText.textContent = res.explanation;

    // Warning Signs
    warningCount.textContent = res.warnings.length;
    warningList.innerHTML = '';
    if (res.warnings.length === 0) {
      warningList.innerHTML = `
        <div class="warning-item low">
          <strong>No Explicit Warning Signs Matched</strong>
          <span>Message did not trigger common keyword, urgency, or deceptive link heuristics.</span>
        </div>
      `;
    } else {
      res.warnings.forEach(w => {
        const div = document.createElement('div');
        const sevClass = (w.severity || 'high').toLowerCase();
        div.className = `warning-item ${sevClass}`;
        div.innerHTML = `
          <strong>${escapeHtml(w.title)} <small style="color:#94a3b8">(${escapeHtml(w.category)})</small></strong>
          <span>${escapeHtml(w.explanation)}</span>
        `;
        warningList.appendChild(div);
      });
    }

    // Recommended Actions
    mitigationsList.innerHTML = '';
    if (res.mitigations && res.mitigations.length > 0) {
      res.mitigations.forEach(m => {
        const li = document.createElement('li');
        li.textContent = m;
        mitigationsList.appendChild(li);
      });
    }
  }

  async function fetchStats() {
    try {
      const response = await fetch('/api/stats');
      const data = await response.json();
      if (data.success && data.stats) {
        metricTotal.textContent = data.stats.total;
        metricPhishing.textContent = data.stats.likely_phishing;
        metricSuspicious.textContent = data.stats.suspicious;
        metricLow.textContent = data.stats.low_indicators;
        metricAvgScore.textContent = data.stats.avg_risk_score;
      }
    } catch (e) {
      console.warn('Could not fetch stats:', e);
    }
  }

  async function fetchHistory() {
    try {
      const response = await fetch('/api/history');
      const data = await response.json();
      if (!data.success || !data.history || data.history.length === 0) {
        historyTableBody.innerHTML = `
          <tr>
            <td colspan="6" class="text-center empty-history">No message analyses recorded yet. Paste a message above to run a scan.</td>
          </tr>
        `;
        return;
      }

      historyTableBody.innerHTML = '';
      data.history.forEach(item => {
        const tr = document.createElement('tr');

        let badgeClass = 'badge-low';
        if (item.classification === 'Likely Phishing') badgeClass = 'badge-critical';
        else if (item.classification === 'Suspicious') badgeClass = 'badge-medium';

        const indicatorCount = item.indicators ? item.indicators.length : 0;
        const indicatorsSummary = item.indicators && item.indicators.length > 0
          ? item.indicators.slice(0, 2).join(', ') + (item.indicators.length > 2 ? ` (+${item.indicators.length - 2} more)` : '')
          : 'None';

        tr.innerHTML = `
          <td>#${item.id}</td>
          <td style="white-space:nowrap; font-size:0.8rem; color:#94a3b8;">${escapeHtml(item.timestamp)}</td>
          <td class="history-code" title="${escapeHtml(item.message_preview)}">${escapeHtml(item.message_preview)}</td>
          <td><strong>${item.risk_score}</strong>/100</td>
          <td><span class="badge ${badgeClass}">${escapeHtml(item.classification)}</span></td>
          <td style="font-size:0.82rem;">${escapeHtml(indicatorsSummary)}</td>
        `;
        historyTableBody.appendChild(tr);
      });
    } catch (e) {
      console.warn('Could not fetch history:', e);
      historyTableBody.innerHTML = `
        <tr><td colspan="6" class="text-center empty-history">Could not load history.</td></tr>
      `;
    }
  }

  function escapeHtml(text) {
    if (!text) return '';
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }
});
