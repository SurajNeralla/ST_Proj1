/**
 * PhishGuard AI - Storage Manager
 * Encapsulates chrome.storage.local operations with fallback support.
 */

(function (global) {
  'use strict';

  // Default configuration
  const DEFAULT_SETTINGS = {
    protectionEnabled: true,
    protectionMode: 'safe', // 'safe' (warning page) or 'auto_close' (closes tab on confirmed phishing)
    testMode: true,         // Allows demonstration of phishing-test.example, etc.
    blockedCount: 0
  };

  const STORAGE_KEYS = {
    SETTINGS: 'phishguard_settings',
    HISTORY: 'phishguard_history',
    WHITELIST: 'phishguard_whitelist'
  };

  // Check if chrome.storage.local is available
  const hasChromeStorage = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;

  // In-memory fallback (for unit tests / node environment)
  const memoryStore = {};

  const PhishStorage = {
    /**
     * Retrieve application settings
     */
    async getSettings() {
      if (hasChromeStorage) {
        return new Promise((resolve) => {
          chrome.storage.local.get([STORAGE_KEYS.SETTINGS], (result) => {
            const settings = Object.assign({}, DEFAULT_SETTINGS, result[STORAGE_KEYS.SETTINGS] || {});
            resolve(settings);
          });
        });
      }
      return Object.assign({}, DEFAULT_SETTINGS, memoryStore[STORAGE_KEYS.SETTINGS] || {});
    },

    /**
     * Update application settings
     */
    async updateSettings(partialSettings) {
      const current = await this.getSettings();
      const updated = Object.assign({}, current, partialSettings);
      if (hasChromeStorage) {
        return new Promise((resolve) => {
          chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: updated }, () => {
            resolve(updated);
          });
        });
      }
      memoryStore[STORAGE_KEYS.SETTINGS] = updated;
      return updated;
    },

    /**
     * Increment blocked website counter
     */
    async incrementBlockedCount() {
      const settings = await this.getSettings();
      const newCount = (settings.blockedCount || 0) + 1;
      await this.updateSettings({ blockedCount: newCount });
      return newCount;
    },

    /**
     * Add a record to scan history
     */
    async addHistoryRecord(record) {
      const history = await this.getHistory();
      const newRecord = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        hostname: record.hostname || 'Unknown',
        url: record.url || '',
        timestamp: new Date().toLocaleString(),
        riskScore: record.riskScore || 0,
        riskLevel: record.riskLevel || 'Low Risk',
        detectionMethod: record.detectionMethod || 'Rule-Based Engine',
        indicators: record.indicators || [],
        isConfirmedPhishing: !!record.isConfirmedPhishing,
        blocked: !!record.blocked,
        tabClosed: !!record.tabClosed
      };

      // Keep most recent 50 scans
      const updatedHistory = [newRecord, ...history.slice(0, 49)];

      if (hasChromeStorage) {
        return new Promise((resolve) => {
          chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: updatedHistory }, () => {
            resolve(newRecord);
          });
        });
      }
      memoryStore[STORAGE_KEYS.HISTORY] = updatedHistory;
      return newRecord;
    },

    /**
     * Get scan history list
     */
    async getHistory() {
      if (hasChromeStorage) {
        return new Promise((resolve) => {
          chrome.storage.local.get([STORAGE_KEYS.HISTORY], (result) => {
            resolve(result[STORAGE_KEYS.HISTORY] || []);
          });
        });
      }
      return memoryStore[STORAGE_KEYS.HISTORY] || [];
    },

    /**
     * Clear all scan history
     */
    async clearHistory() {
      if (hasChromeStorage) {
        return new Promise((resolve) => {
          chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: [] }, () => {
            resolve(true);
          });
        });
      }
      memoryStore[STORAGE_KEYS.HISTORY] = [];
      return true;
    },

    /**
     * Temporarily whitelist a hostname (user chose to proceed anyway on suspicious warning)
     */
    async allowHostname(hostname) {
      if (!hostname) return;
      const whitelist = await this.getWhitelist();
      if (!whitelist.includes(hostname)) {
        whitelist.push(hostname);
        if (hasChromeStorage) {
          return new Promise((resolve) => {
            chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist }, () => resolve());
          });
        }
        memoryStore[STORAGE_KEYS.WHITELIST] = whitelist;
      }
    },

    /**
     * Check if hostname is whitelisted
     */
    async isHostnameAllowed(hostname) {
      const whitelist = await this.getWhitelist();
      return whitelist.includes(hostname);
    },

    /**
     * Get whitelist
     */
    async getWhitelist() {
      if (hasChromeStorage) {
        return new Promise((resolve) => {
          chrome.storage.local.get([STORAGE_KEYS.WHITELIST], (result) => {
            resolve(result[STORAGE_KEYS.WHITELIST] || []);
          });
        });
      }
      return memoryStore[STORAGE_KEYS.WHITELIST] || [];
    }
  };

  // Export to global scope and CommonJS (for Node test suite)
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishStorage;
  }
  global.PhishStorage = PhishStorage;

})(typeof self !== 'undefined' ? self : this);
