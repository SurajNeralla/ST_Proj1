/**
 * PhishGuard AI - Automated Unit Test Suite
 * Tests URL inspection heuristics, classification bands, test fixtures, and safety rules.
 * Run with: node tests/test_detector.js
 */

const PhishDetector = require('../detector.js');

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passedTests++;
  } else {
    console.error(`[FAIL] ${testName} - Details: ${details}`);
    failedTests++;
  }
}

console.log('====================================================');
console.log(' PhishGuard AI - Running Automated Test Suite');
console.log('====================================================\n');

// Test Case 1: Browser Internal URLs must be exempt (never scanned or closed)
const chromeUrlResult = PhishDetector.analyzeUrl('chrome://extensions');
assert(
  chromeUrlResult.shouldScan === false,
  'Exemption of chrome:// internal scheme',
  JSON.stringify(chromeUrlResult)
);

const aboutBlankResult = PhishDetector.analyzeUrl('about:blank');
assert(
  aboutBlankResult.shouldScan === false,
  'Exemption of about:blank scheme',
  JSON.stringify(aboutBlankResult)
);

// Test Case 2: Normal, legitimate website evaluation
const normalUrlResult = PhishDetector.analyzeUrl('https://en.wikipedia.org/wiki/Phishing', true);
assert(
  normalUrlResult.shouldScan === true && normalUrlResult.riskLevel === 'Low Risk' && normalUrlResult.riskScore < 30,
  'Normal website classified as Low Risk',
  `Risk: ${normalUrlResult.riskLevel}, Score: ${normalUrlResult.riskScore}`
);

// Test Case 3: Confirmed Phishing Demonstration Target
const confirmedPhishResult = PhishDetector.analyzeUrl('http://phishing-test.example/login', true);
assert(
  confirmedPhishResult.isConfirmedPhishing === true && confirmedPhishResult.riskScore >= 90 && confirmedPhishResult.canAutoClose === true,
  'Demonstration target (phishing-test.example) confirmed as Phishing',
  `Score: ${confirmedPhishResult.riskScore}, Confirmed: ${confirmedPhishResult.isConfirmedPhishing}`
);

// Test Case 4: Confirmed Banking Scam Demonstration Target
const bankScamResult = PhishDetector.analyzeUrl('http://bank-verify-security.test', true);
assert(
  bankScamResult.isConfirmedPhishing === true && bankScamResult.canAutoClose === true,
  'Demonstration target (bank-verify-security.test) confirmed as Threat',
  `Score: ${bankScamResult.riskScore}`
);

// Test Case 4b: Rogue Malvertising & Illicit Streaming Clone (e.g. 5movierulz.recipes)
const movieRulzResult = PhishDetector.analyzeUrl('https://www.5movierulz.recipes/');
assert(
  movieRulzResult.riskScore >= 85 && movieRulzResult.isConfirmedPhishing === true && movieRulzResult.canAutoClose === true,
  'Rogue malvertising mirror (5movierulz.recipes) classified as Confirmed Threat (100/100)',
  `Score: ${movieRulzResult.riskScore}, Indicators: ${movieRulzResult.indicators.map(i => i.name).join(', ')}`
);

// Test Case 4c: Domain from Phishing.Database threat intelligence feed
const phishDbResult = PhishDetector.analyzeUrl('http://00000000000000000000000000000000000000000.xyz');
assert(
  phishDbResult.riskScore === 100 && phishDbResult.isConfirmedPhishing === true && phishDbResult.detectionMethod.includes('Phishing.Database'),
  'Phishing.Database active feed domain identified with score 100/100',
  `Method: ${phishDbResult.detectionMethod}`
);

// Test Case 4d: Malvertising & Ad Network Detection
const adNetworkResult = PhishDetector.analyzeUrl('https://syndication.propellerads.com/popup');
assert(
  adNetworkResult.riskScore >= 70 && adNetworkResult.indicators.some(i => i.name.includes('PropellerAds') || i.name.includes('Ad')),
  'Malvertising ad network (PropellerAds) classified as Threat',
  `Score: ${adNetworkResult.riskScore}`
);

// Test Case 4e: Deceptive Redirect Gateway Parameter Detection
const redirectResult = PhishDetector.analyzeUrl('https://example-portal.com/redirect.php?url=http://malicious-site.xyz');
assert(
  redirectResult.riskScore >= 45 && redirectResult.indicators.some(i => i.name.includes('Redirect')),
  'Deceptive redirect gateway parameter detected and flagged',
  `Score: ${redirectResult.riskScore}`
);

// Test Case 5: Suspicious Site Simulation (Must NOT be confirmed or auto-closed)
const suspiciousResult = PhishDetector.analyzeUrl('http://suspicious-deals.xyz', true);
assert(
  suspiciousResult.riskLevel === 'Suspicious' && suspiciousResult.isConfirmedPhishing === false && suspiciousResult.canAutoClose === false,
  'Suspicious website requires user choice and must NOT auto-close',
  `Risk: ${suspiciousResult.riskLevel}, canAutoClose: ${suspiciousResult.canAutoClose}`
);

// Test Case 6: Simulated Detection Service Outage
const outageResult = PhishDetector.analyzeUrl('http://unavailable-service.example', true);
assert(
  outageResult.status === 'unavailable' && outageResult.canAutoClose === false,
  'Detection Unavailable handled gracefully without closing tab',
  `Status: ${outageResult.status}, canAutoClose: ${outageResult.canAutoClose}`
);

// Test Case 7: Heuristic Rule - Raw IP Address Hostname
const ipResult = PhishDetector.analyzeUrl('http://192.168.1.100/login', false);
const hasIpIndicator = ipResult.indicators && ipResult.indicators.some(i => i.name.includes('IP Address'));
assert(
  hasIpIndicator && ipResult.riskScore >= 45,
  'Heuristic: Raw IP address flagged with high severity',
  `Score: ${ipResult.riskScore}, Indicators: ${JSON.stringify(ipResult.indicators)}`
);

// Test Case 8: Heuristic Rule - Deceptive "@" in URL
const atSymbolResult = PhishDetector.analyzeUrl('http://trusted-brand.com@attacker-server.com/signin', false);
const hasAtIndicator = atSymbolResult.indicators && atSymbolResult.indicators.some(i => i.name.includes('@'));
assert(
  hasAtIndicator,
  'Heuristic: Deceptive "@" character flagged',
  `Indicators: ${JSON.stringify(atSymbolResult.indicators)}`
);

// Test Case 9: Heuristic Rule - Brand Impersonation in Unofficial Domain
const brandSpoofResult = PhishDetector.analyzeUrl('http://paypal-security-update.xyz/login', false);
const hasBrandIndicator = brandSpoofResult.indicators && brandSpoofResult.indicators.some(i => i.name.includes('Brand'));
assert(
  hasBrandIndicator && brandSpoofResult.riskScore >= 60,
  'Heuristic: Brand impersonation in risky TLD flagged',
  `Score: ${brandSpoofResult.riskScore}`
);

// Test Case 10: Empty / Malformed Input Safety
const emptyResult = PhishDetector.analyzeUrl('');
assert(
  emptyResult.shouldScan === false,
  'Empty URL handled safely without throwing exceptions',
  JSON.stringify(emptyResult)
);

const nullResult = PhishDetector.analyzeUrl(null);
assert(
  nullResult.shouldScan === false,
  'Null URL handled safely without crashing',
  JSON.stringify(nullResult)
);

console.log('\n====================================================');
console.log(` Summary: ${passedTests} Passed, ${failedTests} Failed`);
console.log('====================================================');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log(' All unit test specifications verified successfully!');
  process.exit(0);
}
