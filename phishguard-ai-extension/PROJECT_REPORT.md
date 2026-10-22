# Project Report: PhishGuard AI
## AI-Assisted Cybersecurity Threat Model & Real-Time Phishing Protection Chrome Extension

---

**Project Title:** PhishGuard AI  
**Course / Track:** College Mini Project — Cybersecurity & Web Technologies  
**Target Architecture:** Google Chrome Extension Manifest V3  
**Authors:** Student Project Team  
**Evaluation Date:** October 2026  

---

## 1. Executive Summary

Phishing attacks remain the leading attack vector for initial compromise, credential theft, and unauthorized access across modern computing environments. Attackers continuously engineer deceptive domain names, abuse typosquatting, deploy raw IP hosts, and leverage social engineering lures to trick end users into disclosing passwords, One-Time Passwords (OTPs), and banking credentials.

**PhishGuard AI** was designed and implemented as an educational, lightweight, and fully functional Google Chrome extension that provides real-time client-side protection against phishing websites. Operating under Chrome Extension Manifest V3, the tool performs transparent, deterministic heuristic analysis of visited URLs, classifies threats into transparent risk bands, logs scan history locally, and offers two distinct user-configurable enforcement modes: **Safe Mode** (educational intercept with warning page) and **Auto-Close Mode** (automated tab termination for confirmed malicious destinations).

The entire system operates 100% offline without requiring paid cloud API keys or external telemetry servers, ensuring user privacy and rapid zero-latency analysis.

---

## 2. Problem Statement & Objectives

### 2.1 Problem Statement
Mainstream browser protection solutions often rely on delayed cloud-lookup blocklists that may take hours or days to register newly minted zero-day phishing domains. Furthermore, users often lack visibility into *why* a particular website was flagged, resulting in warning fatigue. Traditional security education also lacks interactive feedback during the user's active browsing workflow.

### 2.2 Project Objectives
1. **Real-Time Client-Side Inspection:** Intercept web navigation events before malicious page contents or scripts are rendered.
2. **Deterministic Heuristic Detection:** Analyze syntactic and semantic anomalies in URLs (IP hostnames, brand impersonation, excessive subdomains, risky TLDs, deceptive `@` characters).
3. **Dual Enforcement Strategies:**
   - *Safe Mode:* Present an informative warning page explaining detected anomalies.
   - *Auto-Close Mode:* Immediately terminate confirmed malicious tabs to prevent user error.
4. **Strict Isolation & False-Positive Mitigation:** Guarantee that internal browser pages (`chrome://`, `about:`) and unconfirmed suspicious sites are never closed automatically.
5. **Demonstrable & Reproducible:** Provide controlled demonstration fixtures allowing college project evaluators to safely test the complete workflow offline.

---

## 3. Phishing Threat Model

As part of the project's cybersecurity foundation, a structured phishing threat model was developed covering five primary threat scenarios:

| # | Threat Scenario | Attack Description | Threat Likelihood | Threat Impact | Recommended Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **T1** | **Fake Login & Credential Harvesting** | Attackers host lookalike login portals imitating popular platforms (Google, PayPal, Chase) to steal user credentials. | **High** | **Critical** | Multi-Factor Authentication (FIDO2/WebAuthn), domain spoofing heuristic detection, and password manager autofill constraints. |
| **T2** | **Deceptive URL & Drive-By Redirection** | Attackers employ URL shorteners, raw IP addresses, and `@` authority symbols to obscure true malicious destinations. | **High** | **High** | In-browser URL normalization, shortener expansion, and real-time destination reputation checks. |
| **T3** | **Fake Payment & Invoice Fraud** | Phishing messages direct victims to unencrypted or spoofed payment gateways demanding urgent fund transfers. | **Medium** | **Critical** | Strict HTTPS enforcement on transactional hosts, out-of-band verification of billing requests. |
| **T4** | **Brand Impersonation & Typosquatting** | Attackers register domains containing recognized trademarks in subdomains or with deceptive hyphens (e.g. `paypal-security.xyz`). | **High** | **High** | Trademark token matching, Levenshtein distance brand analysis, and high-abuse TLD flagging. |
| **T5** | **Weak Authentication Exploitation** | Attackers bypass weak, single-factor SMS OTP authentication via real-time reverse proxy phishing (e.g., Modlishka, Evilginx). | **Medium** | **High** | Phishing-resistant hardware security keys (FIDO2) and blocking unauthorized intermediate proxy domains. |

*Note: The scenarios above represent educational threat models and design baselines for defensive browser engineering.*

---

## 4. System Architecture & Components

PhishGuard AI conforms strictly to **Google Chrome Extension Manifest V3**, adhering to modern security standards including service-worker execution and non-persistent event-driven lifecycles.

```
+-------------------------------------------------------------------------+
|                              USER BROWSER                               |
|                                                                         |
|   +-------------------+                     +-----------------------+   |
|   |   Extension UI    |                     |  Web Navigation Event |   |
|   |  - popup.html     |                     | (User opens website)  |   |
|   |  - popup.js       |                     +-----------+-----------+   |
|   |  - popup.css      |                                 |               |
|   +---------+---------+                                 v               |
|             |                       +---------------------------------+ |
|             +---------------------->|   Background Service Worker     | |
|                                     |        (background.js)          | |
|                                     +---------------+-----------------+ |
|                                                     |                   |
|                       +-----------------------------+                   |
|                       v                                                 |
|        +------------------------------+                                 |
|        | Phishing Detection Engine    |                                 |
|        |       (detector.js)          |                                 |
|        | - Rule Heuristics (0-100)    |                                 |
|        | - Test Mode Fixtures         |                                 |
|        | - Scheme Exemption Validator |                                 |
|        +--------------+---------------+                                 |
|                       |                                                 |
|         +-------------+-------------+                                   |
|         |                           |                                   |
|         v                           v                                   |
|   [Low Risk]               [Threat Detected]                            |
|  - Allow page              - Add to History (storage.js)                |
|  - Log history             - Check Mode:                                |
|                               * Safe Mode -> Redirect to warning.html   |
|                               * Auto-Close -> Notify & Close Tab        |
+-------------------------------------------------------------------------+
```

### Component Breakdown:
1. **`manifest.json` (V3):** Declares permissions (`storage`, `tabs`, `webNavigation`, `notifications`), specifies `background.js` service worker, popup action, and web-accessible resources.
2. **`background.js`:** Listens for `chrome.webNavigation.onBeforeNavigate` events on top-level frames (`frameId === 0`). Manages caching to prevent recursive evaluation loops.
3. **`detector.js`:** Pure, modular JavaScript engine implementing URL parsing, heuristic scoring, and test fixtures. Reusable across browser service workers, popup scripts, and Node.js test runners.
4. **`storage.js`:** Promise-based wrapper around `chrome.storage.local` ensuring persistent state across browser restarts without external databases.
5. **`popup.html / css / js`:** Cybersecurity dashboard featuring dark navy visuals, live tab inspection, master toggle, protection mode switch, metric counters, and collapsible test fixtures.
6. **`warning.html / css / js`:** High-visibility intercept screen displaying threat details, score meters, indicator rationale, and safe exit actions.

---

## 5. Detection Engine & Scoring Methodology

The heuristic detection engine calculates a cumulative risk score bounded between **0 and 100** based on verifiable syntactic indicators:

### 5.1 Heuristic Feature Matrix

| Feature / Rule | Condition | Score Weight | Severity |
| :--- | :--- | :---: | :---: |
| **IP-Based Hostname** | Hostname is an IPv4 or IPv6 address (e.g. `192.168.1.1`) | +45 | High |
| **Deceptive `@` Authority** | URL contains `@` symbol before path (HTTP basic auth deception) | +35 | High |
| **Brand Impersonation** | Target brand (`paypal`, `chase`, `google`) in host, but not official domain | +35 | High |
| **High-Abuse TLD** | Domain ends in heavily abused TLD (`.xyz`, `.top`, `.tk`, `.zip`, `.mov`, etc.) | +25 | Medium |
| **Excessive Subdomain Stacking** | Host contains 5 or more label segments (`a.b.c.d.domain.com`) | +20 | Medium |
| **Sensitive Credential Keywords** | URL contains 2+ security terms (`login`, `verify`, `banking`, `auth`) | +20 | Medium |
| **Insecure HTTP Authentication** | Unencrypted `http://` protocol combined with login/account keywords | +20 | Medium |
| **URL Shortener Concealment** | Domain belongs to recognized shortening service (`bit.ly`, `tinyurl`) | +15 | Low |
| **Hyphen-Overloaded Host** | Hostname contains 3 or more hyphens | +15 | Low |

### 5.2 Classification Bands

```
Score:  0 ----------- 29 ------------- 59 ------------- 79 ----------- 100
Band:   |   Low Risk   |   Suspicious   |   High Risk   | Very High Risk |
Action: Allow freely   Warning (Choice) Warning (Choice) Confirmed Phishing
                                                         (Auto-Close if set)
```

### 5.3 Critical Tab-Closing Principle
A foundational tenet of the PhishGuard AI architecture is that **a high heuristic score alone does not justify automatic tab termination**. Heuristics assess probability, not certainty. Therefore:
- Heuristic matches classify websites as *Suspicious* or *High Risk*, triggering the informational `warning.html` page where the user maintains ultimate autonomy.
- **Auto-Close Mode** activates *strictly* when a destination matches a confirmed threat entry (such as the verified demonstration fixtures or a high-confidence threat blocklist).

---

## 6. Demonstration & Test Fixtures Framework

To ensure that evaluators can verify all facets of PhishGuard AI without navigating to live, hazardous malware servers, the extension incorporates standardized `.example` and `.test` test fixtures (reserved by IANA RFC 2606 for documentation and testing):

1. **`http://phishing-test.example`**:
   - *Status:* Confirmed Phishing Simulation Target.
   - *Score:* 100/100 (Very High Risk).
   - *Demonstration:* Tests Safe Mode redirection and Auto-Close Mode tab termination.
2. **`http://bank-verify-security.test`**:
   - *Status:* Confirmed Banking Credential Harvesting Simulation.
   - *Score:* 95/100 (Very High Risk).
   - *Demonstration:* Tests financial brand spoofing detection.
3. **`http://suspicious-deals.xyz`**:
   - *Status:* Suspicious Domain Simulation.
   - *Score:* 55/100 (Suspicious).
   - *Demonstration:* Verifies that suspicious sites do NOT auto-close and offer an "Advanced Proceed" option.
4. **`http://safe-demo.example`**:
   - *Status:* Benign Baseline Simulation.
   - *Score:* 5/100 (Low Risk).
   - *Demonstration:* Demonstrates unhindered navigation for normal websites.
5. **`http://unavailable-service.example`**:
   - *Status:* Simulated Reputation Service Outage.
   - *Score:* 0 (Detection Unavailable).
   - *Demonstration:* Verifies that threat intelligence timeouts do not crash the browser or close tabs.

---

## 7. Verification & Experimental Test Results

An automated Node.js unit test runner (`tests/test_detector.js`) was developed to validate the detection engine. All 12 test specifications were executed and verified:

```
====================================================
 PhishGuard AI - Running Automated Test Suite
====================================================

[PASS] Exemption of chrome:// internal scheme
[PASS] Exemption of about:blank scheme
[PASS] Normal website classified as Low Risk
[PASS] Demonstration target (phishing-test.example) confirmed as Phishing
[PASS] Demonstration target (bank-verify-security.test) confirmed as Threat
[PASS] Suspicious website requires user choice and must NOT auto-close
[PASS] Detection Unavailable handled gracefully without closing tab
[PASS] Heuristic: Raw IP address flagged with high severity
[PASS] Heuristic: Deceptive "@" character flagged
[PASS] Heuristic: Brand impersonation in risky TLD flagged
[PASS] Empty URL handled safely without throwing exceptions
[PASS] Null URL handled safely without crashing

====================================================
 Summary: 12 Passed, 0 Failed (100% Success Rate)
====================================================
```

### Manual Chrome Verification Checklist:
- [x] Extension loads cleanly via `chrome://extensions` with zero manifest errors.
- [x] Master protection toggle instantly pauses and resumes background interception.
- [x] Switching between Safe Mode and Auto-Close Mode persists across browser restarts.
- [x] Visiting `phishing-test.example` in Safe Mode loads `warning.html` with functional "Close Tab" button.
- [x] Visiting `phishing-test.example` in Auto-Close Mode triggers desktop notification and closes only the test tab.
- [x] Unrelated browser tabs, developer tools, and internal settings remain open and unaffected.
- [x] Scan history correctly logs timestamps, scores, and hostnames with working purge confirmation.

---

## 8. Limitations & Boundary Analysis

1. **Client-Side Lexical Scope:** The current implementation analyzes URL structure and domain naming conventions. It does not inspect dynamically rendered DOM elements, page source code, or form fields before navigation completes.
2. **Obfuscated / Shortened URLs:** While the presence of URL shorteners is flagged as an indicator, determining the final destination of multi-hop redirects requires asynchronous HTTP HEAD requests which may introduce network latency.
3. **Zero-Day Clean Domains:** Legitimate compromised domains (e.g., hacked legitimate WordPress sites hosting phishing kits) will not exhibit lexical domain anomalies and rely on reputation feeds or DOM content classifiers.

---

## 9. Future Scope & Enhancements

1. **Google Safe Browsing v4 API Integration:** Adding an optional backend proxy to query Google Safe Browsing / VirusTotal APIs without exposing private developer keys.
2. **Lightweight On-Device Machine Learning:** Incorporating a TensorFlow.js or ONNX-runtime classifier trained on lexical URL datasets (e.g. PhishTank, OpenPhish) to predict novel phishing patterns with non-linear feature combinations.
3. **Visual Similarity & Favicon Hashing:** Comparing destination page favicons and title tags against legitimate corporate signatures to catch credential harvest kits.

---

## 10. Conclusion

**PhishGuard AI** successfully demonstrates the design, engineering, and evaluation of an AI-assisted cybersecurity threat model embedded within a Google Chrome Extension. By combining deterministic lexical heuristics, strict tab-isolation safeguards, and transparent user education, the project delivers an effective, beginner-friendly defensive tool that satisfies all academic requirements for mini-project presentation.
