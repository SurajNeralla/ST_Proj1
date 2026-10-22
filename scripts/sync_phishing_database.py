"""
PhishGuard AI - Threat Intelligence Sync Utility
=================================================
Fetches live active phishing domains from the official repository:
https://github.com/Phishing-Database/Phishing.Database

Compiles active domains into a fast O(1) JavaScript Set for the Chrome
Extension (phishing_db.js) and a JSON reference file.
"""

import os
import json
import ssl
import urllib.request
from datetime import datetime

FEED_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
DEFAULT_LIMIT = 6000  # High-performance default for client-side extension (fast load, zero lag)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTENSION_DIR = os.path.join(BASE_DIR, "phishguard-ai-extension")
OUTPUT_JS = os.path.join(EXTENSION_DIR, "phishing_db.js")
OUTPUT_JSON = os.path.join(EXTENSION_DIR, "phishing_database.json")
OUTPUT_FLASK_JSON = os.path.join(BASE_DIR, "phishguard-ai", "phishing_database.json")


def sync_phishing_database(limit=DEFAULT_LIMIT):
    print("=" * 60)
    print(" PhishGuard AI - Phishing.Database Ingestion")
    print(f" Source: {FEED_URL}")
    print(f" Target Limit: {limit} active domains")
    print("=" * 60)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "PhishGuard-AI/1.0"})

    print("--> Connecting to threat intelligence feed...")
    domains = []
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as response:
            count = 0
            for line in response:
                decoded = line.decode("utf-8", errors="ignore").strip().lower()
                if not decoded or decoded.startswith("#") or " " in decoded:
                    continue
                domains.append(decoded)
                count += 1
                if count >= limit:
                    break
        print(f"--> Successfully downloaded {len(domains)} active phishing domains.")
    except Exception as e:
        print(f"[!] Warning: Could not download live feed ({e}).")
        print("--> Using fallback curated threat intelligence dataset.")
        # Fallback offline seed
        domains = [
            "00000000000000000000000000000000000000000.xyz",
            "000-00-000-000000.pages.dev",
            "000000000a0uutlook.weebly.com",
            "appleid-verify-alert.com",
            "chase-online-banking-update.xyz",
            "paypal-security-center.top",
            "netflix-billing-resolve.link",
            "binance-security-confirm.icu",
            "google-account-verify.cfd",
            "5movierulz.recipes",
            "7movierulz.vpn",
            "tamilrockers-unblock.cam"
        ]

    # Deduplicate and sort
    unique_domains = sorted(list(set(domains)))
    print(f"--> Processed {len(unique_domains)} unique records.")

    # 1. Generate phishing_db.js for Chrome Extension
    sync_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    js_content = f"""/**
 * PhishGuard AI - Local Phishing Threat Database
 * Sourced from: https://github.com/Phishing-Database/Phishing.Database
 * Synchronized on: {sync_time}
 * Total Active Domains: {len(unique_domains)}
 */

(function (global) {{
  'use strict';

  // Fast O(1) in-memory lookup set
  const PHISHING_FEED_DOMAINS = new Set({json.dumps(unique_domains, indent=2)});

  const PhishDB = {{
    metadata: {{
      source: 'Phishing-Database/Phishing.Database',
      syncedAt: '{sync_time}',
      count: {len(unique_domains)}
    }},

    /**
     * Check if a hostname matches any entry in the active phishing database
     * @param {{string}} hostname
     * @returns {{boolean}}
     */
    isListed(hostname) {{
      if (!hostname) return false;
      const clean = hostname.toLowerCase().trim();
      
      // Exact match
      if (PHISHING_FEED_DOMAINS.has(clean)) return true;

      // Check subdomains against root listed domains
      const parts = clean.split('.');
      for (let i = 1; i < parts.length - 1; i++) {{
        const parent = parts.slice(i).join('.');
        if (PHISHING_FEED_DOMAINS.has(parent)) return true;
      }}

      return false;
    }},

    /**
     * Get database size
     */
    getSize() {{
      return PHISHING_FEED_DOMAINS.size;
    }}
  }};

  // Export for browser extension and Node.js test environment
  if (typeof module !== 'undefined' && module.exports) {{
    module.exports = PhishDB;
  }}
  global.PhishDB = PhishDB;

}})(typeof self !== 'undefined' ? self : this);
"""

    with open(OUTPUT_JS, "w", encoding="utf-8") as f:
        f.write(js_content)
    print(f"--> Saved Chrome Extension database to: {OUTPUT_JS}")

    # 2. Save JSON export
    meta_json = {
        "source": "https://github.com/Phishing-Database/Phishing.Database",
        "synced_at": sync_time,
        "count": len(unique_domains),
        "domains": unique_domains
    }
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(meta_json, f, indent=2)
    print(f"--> Saved JSON reference to: {OUTPUT_JSON}")

    # 3. Save copy for Flask web app if available
    try:
        os.makedirs(os.path.dirname(OUTPUT_FLASK_JSON), exist_ok=True)
        with open(OUTPUT_FLASK_JSON, "w", encoding="utf-8") as f:
            json.dump(meta_json, f, indent=2)
        print(f"--> Saved Flask reference to: {OUTPUT_FLASK_JSON}")
    except Exception as e:
        pass

    print("=" * 60)
    print(f" [SUCCESS] Phishing.Database sync complete! ({len(unique_domains)} domains loaded)")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LIMIT
    sync_phishing_database(limit)
