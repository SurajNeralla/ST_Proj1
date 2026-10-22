# PhishGuard AI — Cybersecurity Threat Model & Phishing Protection System
> **College Mini Project 3:** AI-Assisted Cybersecurity Threat Model  
> **Repository:** [https://github.com/SurajNeralla/ST_Proj1](https://github.com/SurajNeralla/ST_Proj1)  
> **Architecture:** Chrome Extension (Manifest V3) + Python Flask Web App + SQLite + Phishing.Database Feed  
> **Execution:** 100% Offline & Local — No Paid API Keys Required

---

## 📌 Project Overview

**PhishGuard AI** is a multi-tier cybersecurity defense system designed to evaluate and mitigate phishing threats in real time. The project consists of two complementary implementations:

1. **Chrome Extension (Manifest V3):** Real-time web navigation monitor with heuristic risk scoring (0–100), automated ad/redirect defense, clickjacking neutralization, and user-configurable enforcement (**Safe Mode** vs. **Auto-Close Mode**).
2. **Web Application (Python Flask + SQLite):** Interactive message analyzer for emails, SMS, and WhatsApp messages, dynamic threat model matrix, and persistent analysis history tracking.
3. **Live Threat Intelligence Feed:** Integrated with the open-source [Phishing-Database](https://github.com/Phishing-Database/Phishing.Database) repository, pre-loaded with active verified phishing domains.

---

## 📂 Repository Structure

```
ST_Proj1/
├── phishguard-ai-extension/      # Chrome Extension (Manifest V3)
│   ├── manifest.json             # Manifest V3 extension configuration
│   ├── background.js             # Service worker: navigation, popup & tab controller
│   ├── content.js                # In-page ad/popup/clickjacking defense (runs at document_start)
│   ├── detector.js               # Modular heuristic detection engine & threat signatures
│   ├── storage.js                # chrome.storage.local helper for settings & history
│   ├── phishing_db.js            # O(1) in-memory threat feed (Phishing.Database)
│   ├── popup.html / .css / .js   # Cybersecurity-themed popup dashboard
│   ├── warning.html / .css / .js # Threat intercept warning screen
│   ├── icons/                    # Shield icons (16px, 48px, 128px PNGs + SVG)
│   ├── tests/                    # 16 automated unit test specifications
│   │   ├── test_detector.js
│   │   └── run_tests.bat
│   ├── README.md                 # Extension setup & evaluation guide
│   └── PROJECT_REPORT.md         # Formal academic mini-project documentation
│
├── phishguard-ai/                # Python Flask Web Application
│   ├── app.py                    # Flask server, rule engine & SQLite management
│   ├── requirements.txt          # Python dependencies (Flask)
│   ├── database.db               # SQLite database (auto-generated on first run)
│   ├── templates/
│   │   └── index.html            # Cyber-themed web UI
│   └── static/
│       ├── style.css             # Dark navy & cyan theme styling
│       └── script.js             # Frontend API controller & dynamic charts
│
├── scripts/
│   └── sync_phishing_database.py # Live threat feed sync tool from GitHub
│
├── .gitignore                    # Git ignore configuration
└── README.md                     # Root project documentation
```

---

## 🚀 Quick Start Guide

### 1. Load the Chrome Extension
1. Open **Google Chrome** and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** (top-left button).
4. Select the `phishguard-ai-extension` directory from this repository.
5. The **PhishGuard AI** extension is now active in Chrome!

### 2. Run the Web Application
```powershell
cd phishguard-ai
pip install -r requirements.txt
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

### 3. Run Automated Unit Tests
```powershell
cd phishguard-ai-extension
node tests/test_detector.js
```
*(All 16 unit tests verify 100% pass rate covering IP hosts, brand spoofing, rogue streaming mirrors, ad networks, and threat feed matches.)*

### 4. Sync Fresh Phishing Threat Intelligence
```powershell
python scripts/sync_phishing_database.py 8000
```

---

## 🛡️ Key Features

- **Safe Mode vs. Auto-Close Mode:** Safe Mode displays an educational intercept page; Auto-Close Mode automatically closes confirmed malicious tabs with a native desktop notification.
- **Rogue Mirror & Malvertising Defense:** Detects numbered evasion domains (`5movierulz`, `123movies`), abused TLDs (`.recipes`, `.stream`), and kills intrusive ad popups.
- **Clickjacking & Pop-Under Shield:** Neutralizes transparent full-screen click traps and overrides unprompted `window.open` calls in the page context.
- **Zero API Dependency:** 100% local operation with offline datasets and deterministic heuristics.

---

## 📜 License & Academic Integrity
Developed as a college mini project demonstrating AI-assisted cybersecurity threat modeling and browser extension security. All testing fixtures utilize reserved IANA domains (`.example` and `.test`) for safe demonstration.
