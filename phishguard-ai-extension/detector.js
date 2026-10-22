/**
 * PhishGuard AI - Phishing Detection Engine (Rule-Based & Threat Intelligence)
 * Evaluates URLs for phishing indicators, deceptive patterns, malvertising mirrors, and test fixtures.
 */

(function (global) {
  'use strict';

  // Suspicious Top-Level Domains frequently leveraged in bulk phishing, scam mirrors & malvertising
  const SUSPICIOUS_TLDS = new Set([
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov',
    '.country', '.click', '.work', '.rest', '.buzz', '.surf', '.icu',
    '.cam', '.fit', '.cfd', '.sbs', '.quest', '.recipes', '.download',
    '.stream', '.live', '.link', '.monster', '.gdn', '.vip', '.pro',
    '.online', '.site', '.space', '.website', '.fun', '.uno', '.bid',
    '.loan', '.date', '.win', '.racing', '.party', '.trade', '.faith',
    '.cricket', '.accountant', '.webcam'
  ]);

  // Frequently targeted consumer & enterprise brands
  const TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'netflix', 'amazon',
    'chase', 'wellsfargo', 'bankofamerica', 'facebook', 'instagram',
    'binance', 'coinbase', 'steam', 'whatsapp', 'telegram'
  ];

  // High-risk security and credential keywords
  const SENSITIVE_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'security', 'account',
    'banking', 'update', 'wallet', 'confirm', 'support', 'auth',
    'passcode', 'credential', 'recovery'
  ];

  // Known high-risk rogue piracy, malvertising clone, and scam streaming signatures
  // These sites are notorious for drive-by malware downloads, fake security popups, and survey phishing
  const MALICIOUS_CLONE_SIGNATURES = [
    {
      regex: /movierulz/i,
      name: 'MovieRulz Piracy & Malvertising Mirror',
      severity: 'Critical',
      score: 55,
      detail: 'Matches known MovieRulz rogue clone network. These sites routinely distribute malvertising, drive-by downloads, fake virus alerts, and credential-harvesting survey scams.'
    },
    {
      regex: /tamilrockers/i,
      name: 'TamilRockers Clone Network',
      severity: 'Critical',
      score: 55,
      detail: 'Known rogue mirror network distributing aggressive popup redirects and fraudulent phishing traps.'
    },
    {
      regex: /123movies/i,
      name: '123Movies Clone Mirror',
      severity: 'High',
      score: 50,
      detail: 'Deceptive streaming clone that lures users into malicious browser extension installs and phishing subscription scams.'
    },
    {
      regex: /fmovies/i,
      name: 'FMovies Rogue Mirror',
      severity: 'High',
      score: 50,
      detail: 'Rogue streaming portal known for aggressive ad injection and fake system warning scams.'
    },
    {
      regex: /putlocker/i,
      name: 'Putlocker Scam Clone',
      severity: 'High',
      score: 50,
      detail: 'Impersonates defunct streaming brand to distribute malware and credential-capture pages.'
    },
    {
      regex: /filmywap|bolly4u|djmaza/i,
      name: 'Unregulated Piracy Distribution Host',
      severity: 'High',
      score: 45,
      detail: 'Illicit media distribution clone known for malicious pop-under networks and notification hijackers.'
    }
  ];

  // Tech support and fake alert scam patterns
  const FAKE_SECURITY_SCAM_PATTERNS = [
    {
      regex: /(windows-defender|microsoft-security|apple-support|device-infected|virus-alert|trojan-found)/i,
      name: 'Fake Tech Support / Scareware Pattern',
      severity: 'Critical',
      score: 50,
      detail: 'Domain matches signature of scareware portals that simulate fake system infection warnings to extort money or credentials.'
    },
    {
      regex: /(airdrop-claim|crypto-doubler|free-bitcoin|free-ethereum|trustwallet-verify|metamask-sync)/i,
      name: 'Cryptocurrency Wallet Drainer / Scam',
      severity: 'Critical',
      score: 50,
      detail: 'Matches patterns used by cryptocurrency drainers and fraudulent giveaway scams.'
    }
  ];

  // Known URL shorteners
  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    't.co', 'cutt.ly', 'rb.gy', 'shorturl.at'
  ]);

  // Local Demonstration Fixtures (Safe for classroom/college evaluation)
  const DEMO_FIXTURES = {
    // 1. Confirmed Phishing Simulations
    'phishing-test.example': {
      riskScore: 100,
      riskLevel: 'Very High Risk',
      isConfirmedPhishing: true,
      detectionMethod: 'Demonstration Phishing Blocklist',
      indicators: [
        {
          name: 'Confirmed Phishing Simulation Target',
          severity: 'Critical',
          detail: 'Matched exact entry in local high-confidence phishing test fixture.'
        },
        {
          name: 'Deceptive Credential Form Simulation',
          severity: 'High',
          detail: 'Known to simulate credential harvesting behaviors for security evaluation.'
        }
      ],
      reason: 'This domain is a confirmed phishing simulation fixture used for demonstration.'
    },
    'bank-verify-security.test': {
      riskScore: 95,
      riskLevel: 'Very High Risk',
      isConfirmedPhishing: true,
      detectionMethod: 'Demonstration Phishing Blocklist',
      indicators: [
        {
          name: 'Simulated Banking Impersonation',
          severity: 'Critical',
          detail: 'Matches test fixture simulating deceptive financial portal.'
        }
      ],
      reason: 'Target is verified in test database as a high-confidence credential harvesting simulation.'
    },
    'account-update-urgent.example': {
      riskScore: 92,
      riskLevel: 'Very High Risk',
      isConfirmedPhishing: true,
      detectionMethod: 'Demonstration Phishing Blocklist',
      indicators: [
        {
          name: 'Simulated Urgent Account Lockout Lure',
          severity: 'High',
          detail: 'Simulates account suspension social engineering tactic.'
        }
      ],
      reason: 'High-confidence demonstration target simulating emergency re-verification scam.'
    },

    // 2. Suspicious Website Simulation (Requires user decision, does NOT auto-close)
    'suspicious-deals.xyz': {
      riskScore: 55,
      riskLevel: 'Suspicious',
      isConfirmedPhishing: false,
      detectionMethod: 'Heuristic Pattern Match',
      indicators: [
        {
          name: 'Abused Top-Level Domain (.xyz)',
          severity: 'Medium',
          detail: 'Uses disposable top-level domain frequently encountered in unsolicited promotions.'
        },
        {
          name: 'Unverified Commercial Host',
          severity: 'Low',
          detail: 'Domain lacks recognized corporate registry or historical trust signals.'
        }
      ],
      reason: 'Heuristics triggered cautionary indicators. Proceed with vigilance.'
    },

    // 3. Low Risk Normal Website Simulation
    'safe-demo.example': {
      riskScore: 5,
      riskLevel: 'Low Risk',
      isConfirmedPhishing: false,
      detectionMethod: 'Reputation Verification',
      indicators: [],
      reason: 'Domain adheres to standard safe naming conventions with no detected threats.'
    },

    // 4. Simulated Unavailable Service (Tests graceful handling of detection outages)
    'unavailable-service.example': {
      status: 'unavailable',
      riskScore: 0,
      riskLevel: 'Detection Unavailable',
      isConfirmedPhishing: false,
      detectionMethod: 'System Status',
      indicators: [
        {
          name: 'Threat Intelligence Unreachable',
          severity: 'Warning',
          detail: 'Detection service was unable to evaluate this domain due to simulated network timeout.'
        }
      ],
      reason: 'Could not complete threat assessment. Do not treat as safe, but tab will not be closed.'
    }
  };

  const PhishDetector = {
    /**
     * Check if a URL should be excluded from analysis (internal / system pages)
     */
    isExemptUrl(rawUrl) {
      if (!rawUrl || typeof rawUrl !== 'string') return true;
      const lower = rawUrl.toLowerCase().trim();
      return (
        lower.startsWith('chrome://') ||
        lower.startsWith('chrome-extension://') ||
        lower.startsWith('edge://') ||
        lower.startsWith('about:') ||
        lower.startsWith('file://') ||
        lower.startsWith('devtools://') ||
        lower.startsWith('view-source:')
      );
    },

    /**
     * Parse and normalize URL safely
     */
    parseUrl(rawUrl) {
      try {
        let input = rawUrl.trim();
        if (!input.includes('://')) {
          input = 'http://' + input;
        }
        return new URL(input);
      } catch (e) {
        return null;
      }
    },

    /**
     * Primary URL analysis function
     * @param {string} rawUrl - The URL to inspect
     * @param {boolean} testMode - Whether test mode fixtures are active
     * @returns {object} Analysis result
     */
    analyzeUrl(rawUrl, testMode = true) {
      if (!rawUrl || typeof rawUrl !== 'string') {
        return {
          shouldScan: false,
          error: 'Empty or invalid URL provided'
        };
      }

      // 1. Check for browser system / internal schemes
      if (this.isExemptUrl(rawUrl)) {
        return {
          shouldScan: false,
          reason: 'Internal browser scheme / system page exempted from scanning',
          url: rawUrl
        };
      }

      const parsed = this.parseUrl(rawUrl);
      if (!parsed) {
        return {
          shouldScan: false,
          error: 'Malformed URL structure',
          url: rawUrl
        };
      }

      const hostname = parsed.hostname.toLowerCase();
      const pathname = parsed.pathname.toLowerCase();
      const fullUrl = parsed.href;

      // 2. Check Test Mode Fixtures (Safe Demonstration Targets)
      if (testMode && DEMO_FIXTURES[hostname]) {
        const fixture = DEMO_FIXTURES[hostname];
        if (fixture.status === 'unavailable') {
          return {
            shouldScan: true,
            status: 'unavailable',
            url: fullUrl,
            hostname,
            riskScore: 0,
            riskLevel: 'Detection Unavailable',
            isConfirmedPhishing: false,
            indicators: fixture.indicators,
            detectionMethod: fixture.detectionMethod,
            reason: fixture.reason,
            canAutoClose: false
          };
        }

        return {
          shouldScan: true,
          status: 'success',
          url: fullUrl,
          hostname,
          riskScore: fixture.riskScore,
          riskLevel: fixture.riskLevel,
          isConfirmedPhishing: fixture.isConfirmedPhishing,
          indicators: fixture.indicators,
          detectionMethod: fixture.detectionMethod,
          reason: fixture.reason,
          canAutoClose: fixture.isConfirmedPhishing
        };
      }

      // 2b. Check Phishing.Database Active Threat Intelligence Feed
      let isThreatFeedMatch = false;
      try {
        const db = typeof PhishDB !== 'undefined' ? PhishDB : (typeof require !== 'undefined' ? require('./phishing_db.js') : null);
        if (db && db.isListed && db.isListed(hostname)) {
          isThreatFeedMatch = true;
        }
      } catch (e) {
        // Fallback gracefully if database not loaded
      }

      if (isThreatFeedMatch) {
        return {
          shouldScan: true,
          status: 'success',
          url: fullUrl,
          hostname,
          riskScore: 100,
          riskLevel: 'Very High Risk',
          isConfirmedPhishing: true,
          indicators: [
            {
              name: 'Phishing.Database Active Threat Feed Match',
              severity: 'Critical',
              detail: `Domain matches an active verified phishing record in the global Phishing.Database threat intelligence feed.`
            }
          ],
          detectionMethod: 'Phishing.Database Threat Feed',
          reason: 'This domain is a confirmed active phishing destination tracked in the global Phishing.Database repository.',
          canAutoClose: true
        };
      }

      // 3. Rule-Based Heuristic & Threat Intelligence Evaluation
      const indicators = [];
      let score = 0;
      let hasConfirmedThreatSignature = false;

      // Rule 1: IP-Address-based Hostname
      const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      const isIpHost = ipv4Pattern.test(hostname) || (hostname.startsWith('[') && hostname.endsWith(']'));
      if (isIpHost) {
        indicators.push({
          name: 'IP Address Hostname',
          severity: 'High',
          detail: `Destination relies on direct numeric IP (${hostname}) instead of a registered domain, evading reputation lists.`
        });
        score += 45;
      }

      // Rule 2: Deceptive '@' Symbol in URL Authority
      if (rawUrl.includes('@') && !rawUrl.includes('mailto:')) {
        indicators.push({
          name: 'Deceptive "@" Authority Symbol',
          severity: 'High',
          detail: 'Uses HTTP authentication syntax to deceive users into misidentifying the true target server.'
        });
        score += 35;
      }

      // Rule 3: Known Malicious Clone / Rogue Streaming / Malvertising Signatures
      for (const sig of MALICIOUS_CLONE_SIGNATURES) {
        if (sig.regex.test(hostname) || sig.regex.test(pathname)) {
          indicators.push({
            name: sig.name,
            severity: sig.severity,
            detail: sig.detail
          });
          score += sig.score;
          hasConfirmedThreatSignature = true;
          break;
        }
      }

      // Rule 4: Fake Security Alert / Scareware & Wallet Drainer Signatures
      for (const scam of FAKE_SECURITY_SCAM_PATTERNS) {
        if (scam.regex.test(hostname) || scam.regex.test(pathname)) {
          indicators.push({
            name: scam.name,
            severity: scam.severity,
            detail: scam.detail
          });
          score += scam.score;
          hasConfirmedThreatSignature = true;
          break;
        }
      }

      // Rule 5: Rotating Numbered Mirror Evasion Pattern (e.g., 5movierulz, 123movies, 7stream)
      const domainLabels = hostname.split('.');
      const mainLabel = domainLabels.length >= 2 ? domainLabels[domainLabels.length - 2] : hostname;
      const numericEvasionPattern = /^\d+[a-z]{3,}/i;
      if (numericEvasionPattern.test(mainLabel)) {
        indicators.push({
          name: 'Rotating Numbered Mirror Evasion Pattern',
          severity: 'High',
          detail: `Domain main label "${mainLabel}" uses a numeric prefix evasion pattern commonly employed by rogue clone networks to bypass DNS and ISP blockades.`
        });
        score += 25;
      }

        // Rule 6: Abused / Risky Top-Level Domain (TLD)
      for (const tld of SUSPICIOUS_TLDS) {
        if (hostname.endsWith(tld)) {
          indicators.push({
            name: `High-Risk / Abused TLD (${tld})`,
            severity: 'Medium',
            detail: `Domain uses top-level extension "${tld}" with statistically high frequency in malicious campaigns, scam mirrors, and disposable hosts.`
          });
          score += 25;
          break;
        }
      }

      // Rule 6b: Deceptive Auto-Redirect / Open Redirect Gateway
      const hasRedirectParam = /[?&](redirect|redirect_to|url|link|target|destination|dest|jump|out|goto|click_url|r)=https?%3A/i.test(fullUrl) ||
                               /[?&](redirect|redirect_to|url|link|target|destination|dest|jump|out|goto|click_url|r)=https?:\/\//i.test(fullUrl) ||
                               /\/(redirect|out|goto|jump|click|track|affiliate|bouncer)\.(php|html|cgi|asp)/i.test(pathname);
      if (hasRedirectParam) {
        indicators.push({
          name: 'Deceptive Auto-Redirect / Open Redirect Gateway',
          severity: 'Critical',
          detail: 'URL contains redirect parameters or tracking hops used by phishing and malvertising networks to bounce users to fraudulent landing pages.'
        });
        score += 45;
        hasConfirmedThreatSignature = true;
      }

      // Rule 6c: Recognized Malvertising & Ad Injection Networks
      const AD_NETWORKS = [
        { regex: /adsterra/i, name: 'Adsterra Malvertising Network' },
        { regex: /propellerads/i, name: 'PropellerAds Pop-Under Network' },
        { regex: /popcash/i, name: 'PopCash Aggressive Ad Network' },
        { regex: /popads/i, name: 'PopAds Pop-Under Exchange' },
        { regex: /monetag/i, name: 'Monetag Malvertising Network' },
        { regex: /clickadu/i, name: 'Clickadu Push/Ad Network' },
        { regex: /exoclick/i, name: 'ExoClick Ad Network' },
        { regex: /adcash/i, name: 'Adcash Ad Network' },
        { regex: /hilltopads/i, name: 'HilltopAds Ad Injection Network' },
        { regex: /richpush/i, name: 'RichPush Notification Spam Network' },
        { regex: /juicyads/i, name: 'JuicyAds Network' },
        { regex: /trafficjunky/i, name: 'TrafficJunky Ad Network' },
        { regex: /zeroredirect/i, name: 'ZeroRedirect Traffic Hijacker' },
        { regex: /bet365|1xbet|parimatch|mostbet|melbet|stake/i, name: 'Predatory Gambling / Betting Ad Lure' }
      ];
      for (const adNet of AD_NETWORKS) {
        if (adNet.regex.test(hostname)) {
          indicators.push({
            name: `${adNet.name} Blocked`,
            severity: 'Critical',
            detail: `Domain belongs to recognized malvertising, pop-under, or deceptive ad injection network: ${adNet.name}.`
          });
          score += 70;
          hasConfirmedThreatSignature = true;
          break;
        }
      }

      // Rule 7: Misleading Brand Impersonation in Domain or Subdomain
      for (const brand of TARGET_BRANDS) {
        if (hostname.includes(brand)) {
          // Verify if it is genuine official domain
          const legitimateSuffixes = [
            `${brand}.com`, `${brand}.org`, `${brand}.net`, `${brand}.co.uk`, `${brand}.in`, `${brand}.gov`
          ];
          const isOfficial = legitimateSuffixes.some(s => hostname === s || hostname.endsWith('.' + s));
          if (!isOfficial) {
            indicators.push({
              name: `Potential Brand Impersonation (${brand.toUpperCase()})`,
              severity: 'High',
              detail: `Domain references trusted brand "${brand}", but does not resolve to an authentic ${brand} domain.`
            });
            score += 35;
            break;
          }
        }
      }

      // Rule 8: Excessive Subdomain Stacking (Depth >= 4)
      if (domainLabels.length >= 5 && !isIpHost) {
        indicators.push({
          name: 'Excessive Subdomain Depth',
          severity: 'Medium',
          detail: `Host contains ${domainLabels.length} nested subdomain levels, a technique used to obscure the true domain.`
        });
        score += 20;
      }

      // Rule 9: Hyphen-Overloaded Hostname (>= 3 hyphens)
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount >= 3) {
        indicators.push({
          name: 'Multiple Hyphen Separators',
          severity: 'Low',
          detail: 'Contains multiple hyphens in the domain, typical of synthetically generated spoofing domains.'
        });
        score += 15;
      }

      // Rule 10: Sensitive Credential Keywords in URL Path/Subdomain
      const matchedKeywords = SENSITIVE_KEYWORDS.filter(kw => fullUrl.toLowerCase().includes(kw));
      if (matchedKeywords.length >= 2) {
        indicators.push({
          name: 'Sensitive Credential & Security Keywords',
          severity: 'Medium',
          detail: `URL contains multiple authentication-oriented terms: [${matchedKeywords.slice(0, 3).join(', ')}].`
        });
        score += 20;
      }

      // Rule 11: Insecure HTTP Protocol on Authentication Pages
      if (parsed.protocol === 'http:' && matchedKeywords.length >= 1) {
        indicators.push({
          name: 'Unencrypted HTTP on Authentication Target',
          severity: 'Medium',
          detail: 'Transmits credentials or sensitive actions over unencrypted HTTP protocol.'
        });
        score += 20;
      }

      // Rule 12: URL Shortener Obfuscation
      if (URL_SHORTENERS.has(hostname)) {
        indicators.push({
          name: 'URL Shortener Concealment',
          severity: 'Low',
          detail: 'Uses a redirection shortener service to conceal the destination URL.'
        });
        score += 15;
      }

      // Cap score between 0 and 100
      const finalScore = Math.min(100, Math.max(0, score));

      // Determine Risk Level according to the transparent bands
      let riskLevel;
      if (finalScore >= 80) {
        riskLevel = 'Very High Risk';
      } else if (finalScore >= 60) {
        riskLevel = 'High Risk';
      } else if (finalScore >= 30) {
        riskLevel = 'Suspicious';
      } else {
        riskLevel = 'Low Risk';
      }

      // Confirmed Phishing / Confirmed Malicious Threat:
      // True when matching a verified threat signature (e.g. MovieRulz clone, wallet drainer)
      // OR when multiple critical risk indicators combine to score >= 85
      const isConfirmedPhishing = hasConfirmedThreatSignature || finalScore >= 85;

      let reason;
      if (riskLevel === 'Low Risk') {
        reason = 'Standard domain structure and reputation markers. No anomalous phishing indicators were detected.';
      } else if (riskLevel === 'Suspicious') {
        reason = `Heuristic engine flagged ${indicators.length} warning sign(s). While not verified phishing, caution is strongly advised.`;
      } else {
        reason = `High-confidence threat score (${finalScore}/100) based on ${indicators.length} structural indicators and risk signatures. Immediate blocking recommended.`;
      }

      return {
        shouldScan: true,
        status: 'success',
        url: fullUrl,
        hostname,
        riskScore: finalScore,
        riskLevel,
        isConfirmedPhishing,
        indicators,
        detectionMethod: hasConfirmedThreatSignature ? 'Threat Signature & Heuristic Engine' : 'Heuristic Rule-Based Engine',
        reason,
        canAutoClose: isConfirmedPhishing
      };
    }
  };

  // Export for browser extension scripts and Node.js test environment
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishDetector;
  }
  global.PhishDetector = PhishDetector;

})(typeof self !== 'undefined' ? self : this);
