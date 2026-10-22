# PhishGuard AI — Chrome Phishing Protection Extension
> **Mini Project:** AI-Assisted Cybersecurity Threat Model  
> **Architecture:** Google Chrome Extension (Manifest V3) + Local JavaScript Detection Engine  
> **Operating Environment:** 100% Offline / Local Execution — Zero External API Keys or Paid Services Required

---

## 1. Overview

**PhishGuard AI** is a lightweight, real-time phishing protection Chrome extension designed for college cybersecurity mini-project evaluation. As users browse the web, PhishGuard AI inspects destination URLs in real-time, identifies deceptive domain structures, calculates a risk score from 0 to 100, and safeguards users against credential harvesting attacks.

### Key Capabilities:
- **Manifest V3 Architecture:** Uses a non-blocking background service worker with event-driven navigation listeners.
- **Two Protection Modes:**
  - **Safe Mode (Default):** Intercepts malicious destinations and renders a custom high-visibility warning page (`warning.html`) without abruptly closing tabs.
  - **Auto-Close Mode:** Confirms phishing threats, triggers a brief native alert notification, and closes **only the affected tab** while leaving all unrelated tabs completely untouched.
- **Exclusion Safeguards:** Strictly ignores and protects internal browser schemes (`chrome://`, `chrome-extension://`, `about:`, `edge://`).
- **Controlled Test Fixtures:** Pre-configured test fixtures (`phishing-test.example`, `bank-verify-security.test`, etc.) allow immediate, safe demonstration without visiting live dangerous websites.
- **Scan History & Metrics:** Persistent local storage of recent scans, risk ratings, and total blocked threat metrics with 1-click history purge.

---

## 2. Project File Structure

```
phishguard-ai-extension/
├── manifest.json         # Manifest V3 extension configuration
├── background.js         # Service worker: navigation monitor & tab safety controller
├── detector.js           # Modular heuristic detection engine & demonstration fixtures
├── storage.js            # chrome.storage.local helper for settings, counters & history
├── popup.html            # Dark-navy cybersecurity popup interface
├── popup.css             # Cyber styling, toggles, badges, metric cards & score gauge
├── popup.js              # Popup controller: master switch, mode selector & live tab scanner
├── warning.html          # Intercepted warning page shown for blocked destinations
├── warning.css           # Warning page styles with glowing alert shield and threat cards
├── warning.js            # Warning page logic: close tab, safety redirect & override controls
├── icons/                # Extension icons (16px, 48px, 128px PNGs + SVG shield)
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   └── shield.svg
├── tests/
│   ├── test_detector.js  # Node.js automated test runner verifying 12 test specifications
│   └── run_tests.bat     # Windows 1-click test launcher
├── README.md             # Complete setup, testing, and permissions documentation
└── PROJECT_REPORT.md     # Academic mini-project report for college evaluation
```

---

## 3. Installation Guide (Google Chrome)

Follow these steps to load PhishGuard AI into Google Chrome:

1. Open **Google Chrome**.
2. Navigate to `chrome://extensions` in the address bar (or go to `Menu (⋮) > Extensions > Manage Extensions`).
3. In the top-right corner, toggle **Developer mode** to **ON**.
4. In the top-left corner, click the **Load unpacked** button.
5. In the file picker dialog, browse to:
   ```
   c:\Users\suraj\Desktop\ST-MiniProj\phishguard-ai-extension
   ```
   Select the folder and click **Select Folder**.
6. The **PhishGuard AI — Phishing Protection** extension will appear in your extensions list.
7. Click the Chrome **Puzzle icon** (Extensions) in the browser toolbar and pin **PhishGuard AI** for quick access.

---

## 4. How to Demonstrate During College Evaluation

The extension includes built-in test fixtures using standard reserved domain names (`.example` and `.test`), ensuring **zero risk** of visiting real malware during your presentation.

### Scenario A: Safe Mode Demonstration (Default)
1. Click the **PhishGuard AI** icon in the toolbar.
2. Ensure **Protection Mode** is set to **Safe Mode (Default)**.
3. In a browser tab, open:
   ```
   http://phishing-test.example
   ```
   *(Or click the `phishing-test.example` button inside the extension popup under "Evaluation Test Fixtures")*
4. **Result:** The extension immediately intercepts the navigation and renders `warning.html` showing:
   - **Risk Level:** Very High Risk (Score: 100/100)
   - **Blocked Hostname:** `phishing-test.example`
   - **Why Blocked:** Matched high-confidence phishing simulation fixture
   - **Detected Indicators:** Confirmed Phishing Simulation Target
   - **Actions:** Click **Close Tab** to close the tab, or **Return to Safety** to redirect to Google.

### Scenario B: Auto-Close Mode Demonstration
1. Click the **PhishGuard AI** icon in the toolbar.
2. Select **Auto-Close Mode** in the mode selector.
3. Open a new tab and navigate to:
   ```
   http://phishing-test.example
   ```
4. **Result:** 
   - A native desktop notification pops up: *"PhishGuard AI: Phishing Website Blocked — Confirmed threat detected at phishing-test.example. Tab was automatically closed for your safety."*
   - The affected tab is **immediately closed**.
   - All your other tabs remain open and unaffected.

### Scenario C: Suspicious Website (User Discretion / No Auto-Close)
1. In any mode, navigate to:
   ```
   http://suspicious-deals.xyz
   ```
2. **Result:** The website triggers **Suspicious** (Score: 55/100).
   - Because it is heuristic and **not confirmed malicious**, Auto-Close is intentionally inhibited.
   - The warning page gives an **Advanced: Proceed at own risk** option, respecting user autonomy.

### Scenario D: Normal, Legitimate Website
1. Navigate to `https://en.wikipedia.org` or `https://example.com`.
2. **Result:** Allowed immediately without disruption.
3. Open the extension popup: displays **Low Risk (Score: 0–10/100)** with green status.

### Scenario E: Detection Service Unavailable Outage Test
1. Navigate to `http://unavailable-service.example`.
2. **Result:** Simulates an external threat intelligence timeout.
   - Shows a notification: *"Threat Check Inconclusive"*.
   - **The tab is NOT closed**, satisfying the critical safety requirement that detection failures must never abruptly terminate user sessions.

### Scenario F: Browser System Page Exemption
1. Open `chrome://extensions` or `chrome://settings`.
2. Open popup: displays **"Browser System / Internal Page — Exempt"**.
3. Internal pages are strictly excluded from network interception.

---

## 5. Automated Unit Tests

PhishGuard AI includes an automated unit test suite verifying 12 key detection rules and edge cases.

### Running Tests from Command Line:
```powershell
cd c:\Users\suraj\Desktop\ST-MiniProj\phishguard-ai-extension
node tests/test_detector.js
```

Or double-click:
```
tests\run_tests.bat
```

### Verified Test Cases:
1. `chrome://` internal scheme exemption
2. `about:blank` internal scheme exemption
3. Normal legitimate website classification (`en.wikipedia.org` -> Low Risk, Score < 30)
4. Confirmed phishing demonstration fixture (`phishing-test.example` -> Confirmed, Score 100)
5. Confirmed banking scam fixture (`bank-verify-security.test` -> Confirmed, Score 95)
6. Suspicious site simulation (`suspicious-deals.xyz` -> Suspicious, No Auto-Close)
7. Service outage handling (`unavailable-service.example` -> Inconclusive, No Auto-Close)
8. Raw IP-address hostname heuristic (`http://192.168.1.100/login` -> Score >= 45)
9. Deceptive `@` symbol in URL authority
10. Brand impersonation with risky TLD (`http://paypal-security-update.xyz/login`)
11. Empty URL string input safety
12. Null / malformed input safety

---

## 6. Permissions Disclosure

Manifest V3 follows the principle of least privilege. The required permissions are:

| Permission | Purpose & Justification |
| :--- | :--- |
| `storage` | Persists user settings (protection toggle, selected mode, block counter, scan history) locally via `chrome.storage.local`. |
| `tabs` | Required to read the active tab URL for the popup scanner and to close the affected tab when Auto-Close Mode is enabled. |
| `webNavigation` | Required to monitor top-level frame navigation events (`onBeforeNavigate`) and intercept threats before malicious payloads load. |
| `notifications` | Displays native notifications when a phishing site is blocked or when detection is unavailable in Auto-Close Mode. |
| `<all_urls>` | Enables URL inspection across arbitrary public web destinations visited by the user. Internal schemes are filtered out in code. |

---

## 7. Educational & Ethical Disclaimer

PhishGuard AI is an educational project created to demonstrate cybersecurity threat modeling and heuristic detection principles. It is not intended to replace commercial enterprise endpoint detection solutions. Zero detected heuristic indicators does not guarantee that a destination is completely benign. Always verify unexpected communications through verified out-of-band channels.
