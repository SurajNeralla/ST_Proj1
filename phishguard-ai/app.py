"""
PhishGuard AI - Basic AI-Assisted Phishing Threat Model & Detection
-------------------------------------------------------------------
A beginner-friendly, educational web application for detecting phishing indicators,
understanding cyber threats, and managing analysis history using Flask & SQLite.
"""

import os
import re
import json
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Database file location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'database.db')
PHISHING_DB_PATH = os.path.join(BASE_DIR, 'phishing_database.json')

# Load Phishing.Database threat intelligence feed
PHISHING_DOMAINS_SET = set()
if os.path.exists(PHISHING_DB_PATH):
    try:
        with open(PHISHING_DB_PATH, 'r', encoding='utf-8') as f:
            feed_data = json.load(f)
            PHISHING_DOMAINS_SET = set(feed_data.get('domains', []))
            print(f"[Threat Feed] Loaded {len(PHISHING_DOMAINS_SET)} active domains from Phishing.Database.")
    except Exception as e:
        print(f"[Threat Feed Warning] Could not load feed: {e}")


# ==============================================================================
# DATABASE FUNCTIONS (SQLite)
# ==============================================================================

def get_db():
    """Connect to the SQLite database and return connection with row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables if they do not exist."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_preview TEXT NOT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                indicators TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        conn.commit()


# ==============================================================================
# PHISHING DETECTION ENGINE (Rule-Based Heuristics)
# ==============================================================================

class PhishAnalyzer:
    """
    Evaluates messages against multiple phishing threat indicators.
    Uses regex pattern matching, URL inspection, and context synergy scoring.
    """

    # 1. Urgent or Threatening Language
    URGENT_PATTERNS = [
        (r'\b(urgent|urgently|immediate|immediately|action required)\b', 'Urgent Call to Action',
         'Demands immediate attention to cause panic and bypass critical thinking.'),
        (r'\b(within\s+\d+\s*(hours?|hrs?|minutes?|mins?|days?)|24\s*hours?|48\s*hours?)\b', 'Strict Deadline Pressure',
         'Creates artificial time pressure (e.g., within 24 hours) to rush user response.'),
        (r'\b(final notice|last warning|legal action|lawsuit|arrest|police|court summons)\b', 'Threatening Consequences',
         'Uses intimidating legal or punitive language to intimidate the recipient.'),
        (r'\b(act now|time is running out|don\'?t delay|limited time)\b', 'Scarcity / Pressure Tactic',
         'Uses pressure tactics common in social engineering attacks.')
    ]

    # 2. Requests for Passwords, OTPs or Credentials
    CREDENTIAL_PATTERNS = [
        (r'\b(otp|one[- ]time password|verification code|security code)\b', 'OTP / Verification Code Request',
         'Asks for one-time verification codes. Legitimate providers never ask for OTPs via unsolicited messages.'),
        (r'\b(password|passcode|secret pin|login pin)\b', 'Password / PIN Request',
         'Prompts the recipient to disclose or submit confidential credentials.'),
        (r'\b(confirm your password|enter your password|reset your password|verify credentials)\b', 'Credential Harvesting Trigger',
         'Directs the recipient to supply their login credentials.'),
    ]

    # 3. Requests for Banking & Financial Information
    FINANCIAL_PATTERNS = [
        (r'\b(credit card|debit card|cvv|cvv2|card expiry|card expiration)\b', 'Payment Card Details Request',
         'Requests sensitive payment card data including CVV or expiration details.'),
        (r'\b(bank account|routing number|atm pin|account number)\b', 'Banking Information Request',
         'Solicits private banking or account identification numbers.'),
        (r'\b(wire transfer|western union|moneygram|crypto wallet|bitcoin address)\b', 'Untraceable Payment Method',
         'Suggests high-risk, irreversible transfer mechanisms.')
    ]

    # 4. Fake Prizes, Rewards & Lotteries
    REWARD_PATTERNS = [
        (r'\b(congratulations|you(\'ve| have) won|lucky winner|selected as (a|the) winner)\b', 'Unsolicited Prize / Reward',
         'Claims the user has won a sweepstakes, contest, or prize they likely never entered.'),
        (r'\b(claim your (prize|reward|gift card|voucher|cash)|lottery|jackpot)\b', 'Lure to Claim Reward',
         'Entices users to click links or share data in exchange for a fake reward.'),
        (r'\b(free gift|free money|\$1,?000,?000|1000000|inheritance)\b', 'Unrealistic Financial Promise',
         'Offers large sums of money or free incentives to attract engagement.')
    ]

    # 5. Immediate Payment & Debt Demands
    PAYMENT_PATTERNS = [
        (r'\b(pay now|pay immediately|outstanding balance|unpaid invoice|settle payment)\b', 'Immediate Payment Demand',
         'Claims pending invoices, unpaid bills, or fees that must be settled right away.'),
        (r'\b(processing fee|transfer fee|release fee|customs duty)\b', 'Advance-Fee Scam Trigger',
         'Requires an upfront fee before releasing a supposed package, prize, or service.')
    ]

    # 6. Account Suspension Warnings
    SUSPENSION_PATTERNS = [
        (r'\b(account (has been )?suspended|account locked|temporary suspension|terminated)\b', 'Account Suspension Warning',
         'Falsely warns that the user\'s account is frozen or blocked.'),
        (r'\b(unauthorized (access|activity|sign[- ]in)|unusual activity detected|suspicious login)\b', 'Fake Security Alert',
         'Fabricates security incidents to manipulate the user into "verifying" credentials.'),
        (r'\b(verify your (account|identity)|prevent (account )?deactivation|reactivate account)\b', 'Re-verification Coercion',
         'Commands the user to re-verify identity or lose access.')
    ]

    # Suspicious domain extensions (TLDs often abused in phishing)
    SUSPICIOUS_TLDS = {
        '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov',
        '.country', '.click', '.work', '.rest', '.buzz', '.surf', '.icu'
    }

    # Known URL shorteners
    SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
        't.co', 'cutt.ly', 'rb.gy', 'shorturl.at'
    }

    # High-profile brand names frequently spoofed
    TARGET_BRANDS = ['paypal', 'google', 'apple', 'microsoft', 'netflix', 'amazon', 'chase', 'wellsfargo', 'bankofamerica', 'facebook', 'instagram']

    @classmethod
    def extract_urls(cls, text):
        """Extract all URLs or web addresses from text."""
        # Find URLs with protocol or www or bare domain patterns
        url_regex = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
        return re.findall(url_regex, text, re.IGNORECASE)

    @classmethod
    def inspect_url(cls, raw_url):
        """Analyze a URL for phishing characteristics."""
        flags = []
        parsed_url = raw_url
        if not raw_url.startswith(('http://', 'https://')):
            parsed_url = 'http://' + raw_url

        try:
            parsed = urlparse(parsed_url)
            hostname = (parsed.hostname or '').lower()
            netloc = parsed.netloc.lower()

            # Check 0: Phishing.Database feed match
            if hostname in PHISHING_DOMAINS_SET:
                flags.append({
                    'title': 'Phishing.Database Threat Feed Match',
                    'severity': 'Critical',
                    'explanation': f'Domain ({hostname}) is confirmed active in the global Phishing.Database open-source threat intelligence feed.'
                })

            # Check 1: IP address used instead of domain name
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, hostname):
                flags.append({
                    'title': 'IP Address in Link',
                    'severity': 'High',
                    'explanation': f'Link ({raw_url[:35]}...) uses a raw IP address instead of a recognized domain name, a hallmark of malicious phishing hosts.'
                })

            # Check 2: Known URL shortener
            for shortener in cls.SHORTENERS:
                if shortener in hostname:
                    flags.append({
                        'title': 'URL Shortener Detected',
                        'severity': 'Medium',
                        'explanation': f'Link ({raw_url[:35]}...) hides the true destination using shortener "{shortener}". Often used to bypass email security filters.'
                    })
                    break

            # Check 3: Suspicious TLD
            for tld in cls.SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    flags.append({
                        'title': f'Risky Top-Level Domain ({tld})',
                        'severity': 'Medium',
                        'explanation': f'Domain uses extension "{tld}", commonly associated with cheap, disposable spam and phishing domains.'
                    })
                    break

            # Check 4: Username / '@' symbol in URL
            if '@' in netloc:
                flags.append({
                    'title': 'Deceptive "@" Symbol in URL',
                    'severity': 'High',
                    'explanation': 'URL contains an "@" sign, which can mislead users about the real server address being reached.'
                })

            # Check 5: Brand spoofing in domain or path
            for brand in cls.TARGET_BRANDS:
                if brand in hostname:
                    # Check if it's not the official domain (e.g. not paypal.com)
                    official_domain = f'{brand}.com'
                    if not hostname.endswith(official_domain) and not hostname.endswith('.' + official_domain):
                        flags.append({
                            'title': f'Potential Brand Spoofing ({brand.capitalize()})',
                            'severity': 'High',
                            'explanation': f'Domain ({hostname}) contains brand name "{brand}", but is not an official domain of that brand.'
                        })
                        break

            # Check 6: Unencrypted HTTP link
            if raw_url.startswith('http://') and not raw_url.startswith('https://'):
                flags.append({
                    'title': 'Unencrypted HTTP Link',
                    'severity': 'Low',
                    'explanation': 'The link uses insecure HTTP without modern SSL/TLS encryption.'
                })

        except Exception:
            flags.append({
                'title': 'Malformed or Suspicious URL',
                'severity': 'Medium',
                'explanation': f'The message contains an irregular web address format: {raw_url[:30]}'
            })

        return flags

    @classmethod
    def redact_sensitive_data(cls, text):
        """Mask OTPs, credit cards, and passwords before logging to SQLite."""
        # Redact 4-8 digit numbers that appear near OTP or code keywords
        redacted = re.sub(
            r'(?i)(otp|code|pin|verification\s*code|passcode)\s*(is|:|=|-)?\s*([0-9]{4,8})',
            r'\1: [REDACTED_CODE]',
            text
        )
        # Redact 13-16 digit card sequences
        redacted = re.sub(
            r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            '[REDACTED_CARD_NUMBER]',
            redacted
        )
        # Redact passwords
        redacted = re.sub(
            r'(?i)(password|passcode)\s*(is|:|=|-)?\s*([^\s]{4,})',
            r'\1: [REDACTED_PASSWORD]',
            redacted
        )
        return redacted

    @classmethod
    def analyze(cls, text):
        """
        Runs comprehensive analysis against input message.
        Returns dictionary containing classification, score, warnings, rationale, and mitigations.
        """
        if not text or not text.strip():
            return {
                'error': 'Message content cannot be empty.'
            }

        cleaned_text = text.strip()
        lower_text = cleaned_text.lower()
        warnings = []
        score = 0

        # Category tracking for synergy detection
        detected_categories = set()

        # 1. Urgent language check
        for pattern, title, explanation in cls.URGENT_PATTERNS:
            if re.search(pattern, lower_text):
                warnings.append({
                    'title': title,
                    'category': 'Urgency & Pressure',
                    'severity': 'Medium',
                    'explanation': explanation
                })
                detected_categories.add('urgency')
                score += 15
                break

        # 2. Credential & OTP check
        for pattern, title, explanation in cls.CREDENTIAL_PATTERNS:
            if re.search(pattern, lower_text):
                warnings.append({
                    'title': title,
                    'category': 'Credential Harvesting',
                    'severity': 'High',
                    'explanation': explanation
                })
                detected_categories.add('credentials')
                score += 28
                break

        # 3. Financial requests check
        for pattern, title, explanation in cls.FINANCIAL_PATTERNS:
            if re.search(pattern, lower_text):
                warnings.append({
                    'title': title,
                    'category': 'Financial Data',
                    'severity': 'High',
                    'explanation': explanation
                })
                detected_categories.add('financial')
                score += 25
                break

        # 4. Fake prizes & lottery check
        for pattern, title, explanation in cls.REWARD_PATTERNS:
            if re.search(pattern, lower_text):
                warnings.append({
                    'title': title,
                    'category': 'Rewards & Lottery Lure',
                    'severity': 'High',
                    'explanation': explanation
                })
                detected_categories.add('rewards')
                score += 24
                break

        # 5. Immediate payments check
        for pattern, title, explanation in cls.PAYMENT_PATTERNS:
            if re.search(pattern, lower_text):
                warnings.append({
                    'title': title,
                    'category': 'Payment Demand',
                    'severity': 'Medium',
                    'explanation': explanation
                })
                detected_categories.add('payment')
                score += 20
                break

        # 6. Account suspension check
        for pattern, title, explanation in cls.SUSPENSION_PATTERNS:
            if re.search(pattern, lower_text):
                warnings.append({
                    'title': title,
                    'category': 'Account Suspension Threat',
                    'severity': 'High',
                    'explanation': explanation
                })
                detected_categories.add('suspension')
                score += 22
                break

        # 7. URL and Link Analysis
        extracted_urls = cls.extract_urls(cleaned_text)
        if extracted_urls:
            detected_categories.add('links')
            score += 10  # Base presence of links in suspicious contexts
            for url in extracted_urls:
                url_flags = cls.inspect_url(url)
                for flag in url_flags:
                    warnings.append({
                        'title': flag['title'],
                        'category': 'Suspicious Link',
                        'severity': flag['severity'],
                        'explanation': flag['explanation']
                    })
                    if flag['severity'] == 'Critical':
                        score += 45
                    elif flag['severity'] == 'High':
                        score += 22
                    elif flag['severity'] == 'Medium':
                        score += 15
                    else:
                        score += 8

        # --- CONTEXT SYNERGY (Multi-Indicator Multiplier) ---
        # Phishing attacks rarely rely on one sign; dangerous combinations compound risk
        synergy_notes = []

        if 'urgency' in detected_categories and 'credentials' in detected_categories:
            score += 18
            synergy_notes.append('Urgency combined with OTP / password request significantly elevates risk of credential harvesting.')

        if 'links' in detected_categories and ('credentials' in detected_categories or 'suspension' in detected_categories):
            score += 16
            synergy_notes.append('Direct link combined with account security / login warnings is a standard credential capture pattern.')

        if 'rewards' in detected_categories and ('financial' in detected_categories or 'payment' in detected_categories or 'links' in detected_categories):
            score += 15
            synergy_notes.append('Prize claims demanding immediate action, fees, or link clicks are characteristic of advance-fee / lottery fraud.')

        # Cap score between 0 and 100
        risk_score = min(100, max(0, score))

        # Determine Classification
        if risk_score >= 65:
            classification = 'Likely Phishing'
            risk_level = 'high'
        elif risk_score >= 30:
            classification = 'Suspicious'
            risk_level = 'medium'
        else:
            classification = 'No Strong Indicators Detected'
            risk_level = 'low'

        # Generate summary explanation
        if classification == 'Likely Phishing':
            explanation = (
                f"High-confidence threat: The message exhibits {len(warnings)} distinct phishing indicators, "
                f"including {', '.join(sorted(detected_categories)) if detected_categories else 'dangerous patterns'}. "
                "Strong probability of an active phishing, credential harvesting, or financial fraud attempt."
            )
        elif classification == 'Suspicious':
            explanation = (
                f"Caution advised: The message triggered {len(warnings)} warning sign(s). While not definitively "
                "conclusive on its own, it displays behavioral patterns frequently used in spam or social engineering."
            )
        else:
            explanation = (
                "No strong phishing patterns or credential traps were detected in this message. "
                "However, sophisticated spear-phishing campaigns can mimic normal conversations. Always verify unexpected requests."
            )

        # Recommended Safety Actions
        mitigations = [
            "Never share passwords, PINs, or One-Time Passwords (OTPs) with anyone.",
            "Do not click unsolicited links. Visit the service directly by typing its official address.",
            "Verify urgent requests independently using verified phone numbers or official applications."
        ]
        if 'links' in detected_categories:
            mitigations.append("Hover over or inspect links carefully before interacting with them.")
        if 'financial' in detected_categories or 'payment' in detected_categories:
            mitigations.append("Never send payments or card credentials based on an unsolicited email, SMS, or WhatsApp message.")
        if 'credentials' in detected_categories or 'suspension' in detected_categories:
            mitigations.append("Enable Multi-Factor Authentication (MFA) across your critical accounts.")

        return {
            'classification': classification,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'warnings': warnings,
            'warning_count': len(warnings),
            'explanation': explanation,
            'synergy_notes': synergy_notes,
            'mitigations': mitigations,
            'detected_categories': list(detected_categories),
            'disclaimer': (
                "Initial Assessment Notice: This result is an educational estimate produced by heuristic rules "
                "and does not constitute a security guarantee. No automated scanner can label any message 100% safe."
            )
        }


# ==============================================================================
# FLASK WEB ROUTES & APIS
# ==============================================================================

@app.route('/')
def index():
    """Render the main PhishGuard AI application interface."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    Endpoint to analyze a submitted message.
    Stores redacted excerpt into SQLite database and returns assessment JSON.
    """
    data = request.get_json(silent=True) or {}
    message = data.get('message', '')

    if not isinstance(message, str) or not message.strip():
        return jsonify({
            'success': False,
            'error': 'Please enter or paste a message to analyze.'
        }), 400

    # Perform rule-based analysis
    result = PhishAnalyzer.analyze(message)

    # Sanitize & redact preview for safe SQLite storage
    redacted_message = PhishAnalyzer.redact_sensitive_data(message)
    preview = redacted_message.strip()
    if len(preview) > 140:
        preview = preview[:137] + '...'

    indicator_names = [w['title'] for w in result.get('warnings', [])]
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Save to SQLite
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO analysis_history (message_preview, classification, risk_score, indicators, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                preview,
                result['classification'],
                result['risk_score'],
                json.dumps(indicator_names),
                timestamp
            ))
            conn.commit()
            record_id = cursor.lastrowid
    except Exception as e:
        record_id = None
        # Non-fatal: analysis still returns even if DB log fails
        print(f"[Database Error]: {e}")

    result['history_id'] = record_id
    result['timestamp'] = timestamp
    return jsonify({
        'success': True,
        'data': result
    })


@app.route('/api/history', methods=['GET'])
def api_history():
    """Retrieve recent analysis history from SQLite."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, message_preview, classification, risk_score, indicators, timestamp
                FROM analysis_history
                ORDER BY id DESC
                LIMIT 50
            ''')
            rows = cursor.fetchall()
            history = []
            for row in rows:
                history.append({
                    'id': row['id'],
                    'message_preview': row['message_preview'],
                    'classification': row['classification'],
                    'risk_score': row['risk_score'],
                    'indicators': json.loads(row['indicators']) if row['indicators'] else [],
                    'timestamp': row['timestamp']
                })
            return jsonify({'success': True, 'history': history})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/history/clear', methods=['POST'])
def api_clear_history():
    """Clear all analysis history records from SQLite after user confirmation."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM analysis_history')
            conn.commit()
            return jsonify({'success': True, 'message': 'Analysis history cleared successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Calculate dashboard summary statistics from SQLite history."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Total messages analyzed
            cursor.execute('SELECT COUNT(*) FROM analysis_history')
            total = cursor.fetchone()[0]

            # Likely Phishing count
            cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE classification = 'Likely Phishing'")
            likely_phishing = cursor.fetchone()[0]

            # Suspicious count
            cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE classification = 'Suspicious'")
            suspicious = cursor.fetchone()[0]

            # No Strong Indicators count
            cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE classification = 'No Strong Indicators Detected'")
            low_indicators = cursor.fetchone()[0]

            # Average risk score
            cursor.execute('SELECT AVG(risk_score) FROM analysis_history')
            avg_score = cursor.fetchone()[0]
            avg_score_val = round(avg_score, 1) if avg_score is not None else 0

            return jsonify({
                'success': True,
                'stats': {
                    'total': total,
                    'likely_phishing': likely_phishing,
                    'suspicious': suspicious,
                    'low_indicators': low_indicators,
                    'avg_risk_score': avg_score_val
                }
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

if __name__ == '__main__':
    # Initialize the database on startup
    init_db()
    print("====================================================")
    print(" PhishGuard AI - Web Server Started")
    print(" URL: http://127.0.0.1:5000")
    print(" SQLite Database initialized at:", DATABASE_PATH)
    print("====================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
