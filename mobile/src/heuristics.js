// Offline quick check: runs on the phone when the analysis server can't be reached.
// Deliberately simple and transparent - every point added is shown to the user.
// It is NOT the ML engine; the UI labels its result as a lower-confidence check.

const SUSPICIOUS_TLDS = ['top', 'xyz', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'click', 'link', 'rest',
  'zip', 'mov', 'country', 'kim', 'loan', 'win', 'bid', 'icu', 'cyou', 'buzz', 'sbs', 'shop', 'live'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'cutt.ly', 'is.gd', 't.ly', 'rb.gy', 'shorturl.at',
  'ow.ly', 'rebrand.ly', 'tiny.cc', 'goo.su', 's.id'];
const BRANDS = ['sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe', 'gpay', 'googlepay',
  'amazon', 'flipkart', 'paypal', 'apple', 'microsoft', 'netflix', 'aadhaar', 'uidai', 'incometax',
  'epfo', 'npci', 'bhim', 'indiapost', 'bluedart', 'delhivery', 'airtel', 'jio', 'whatsapp', 'irctc'];
const OFFICIAL_SUFFIXES = ['.gov.in', '.nic.in', '.sbi', '.bank.in', '.edu.in'];
const URL_WORDS = ['login', 'verify', 'update', 'secure', 'account', 'kyc', 'otp', 'reward',
  'refund', 'claim', 'unblock', 'suspend', 'bonus', 'free', 'gift', 'wallet', 'pan', 'aadhar'];
const PRESSURE = [
  /\b(blocked|suspended|deactivated|expire[sd]?|expiring)\b/i,
  /\b(within|in) \d+ ?(hours?|hrs?|minutes?|mins?)\b/i,
  /\b(urgent|immediately|last (date|chance)|final (notice|warning))\b/i,
  /\b(kyc|pan|aadhaa?r)\b.*\b(update|link|verify)\b/i,
  /\b(electricity|power)\b.*\b(disconnect|cut)/i,
  /\b(won|winner|lottery|cashback|reward points?)\b/i,
  /\b(share|send|tell).{0,20}\b(otp|pin|cvv|password)\b/i,
];

const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?)/gi;

export function extractUrls(text) {
  const out = [];
  for (const m of String(text).matchAll(URL_RE)) {
    let u = m[1].replace(/[),.;!?]+$/, '');
    if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
    try { out.push(new URL(u)); } catch { /* not a URL */ }
  }
  return out;
}

function scoreUrl(u) {
  const reasons = [];
  let s = 0;
  const host = u.hostname.toLowerCase();
  const labels = host.split('.');
  const tld = labels[labels.length - 1];
  const official = OFFICIAL_SUFFIXES.some(x => host.endsWith(x));

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { s += 30; reasons.push('The link points to a raw IP address instead of a website name.'); }
  if (host.startsWith('xn--') || host.includes('.xn--')) { s += 25; reasons.push('The website name uses look-alike characters (punycode).'); }
  if (SUSPICIOUS_TLDS.includes(tld)) { s += 25; reasons.push(`The address ends in .${tld}, an ending often used by scam sites.`); }
  if (SHORTENERS.includes(host)) { s += 15; reasons.push('It is a shortened link, which hides the real destination.'); }
  const brand = BRANDS.find(b => host.includes(b));
  if (brand && !official) {
    // brand name appears, but not as the real registered domain (e.g. sbi-kyc-update.top).
    // Treat "hdfcbank.com" / "icicibank.co.in" as the brand's own; anything with
    // hyphens, a risky ending, or the brand only in a sub-domain is impersonation.
    const twoPartTld = ['co', 'org', 'net', 'gov', 'ac', 'edu'].includes(labels[labels.length - 2]);
    const sld = labels[labels.length - (twoPartTld ? 3 : 2)] || '';
    const ownsName = sld.startsWith(brand) && !sld.includes('-') && !SUSPICIOUS_TLDS.includes(tld);
    if (!ownsName) {
      s += 30; reasons.push(`It uses the name "${brand}" but is not that organisation's real website.`);
    }
  }
  if (labels.length >= 5) { s += 10; reasons.push('The address has an unusually long chain of sub-domains.'); }
  if ((host.match(/-/g) || []).length >= 2) { s += 10; reasons.push('The website name is stitched together with several hyphens.'); }
  const path = (u.pathname + u.search).toLowerCase();
  const words = URL_WORDS.filter(w => (host + path).includes(w));
  if (words.length) { s += Math.min(20, words.length * 7); reasons.push(`The link contains words scammers use: ${words.slice(0, 4).join(', ')}.`); }
  if (u.href.includes('@')) { s += 20; reasons.push('The link contains "@", a trick to disguise the real destination.'); }
  if (u.protocol === 'http:' && !official) { s += 5; reasons.push('The link is not secured with HTTPS.'); }
  if (path.endsWith('.apk')) { s += 40; reasons.push('The link downloads an Android app (.apk) from outside the Play Store.'); }
  if (official && s < 30) { s = Math.max(0, s - 20); }
  return { score: Math.min(100, s), reasons };
}

export function quickCheck(text) {
  const urls = extractUrls(text);
  const reasons = [];
  let score = 0;
  for (const u of urls.slice(0, 5)) {
    const r = scoreUrl(u);
    if (r.score > score) score = r.score;
    for (const x of r.reasons) if (!reasons.includes(x)) reasons.push(x);
  }
  const pressure = PRESSURE.filter(re => re.test(text)).length;
  const asksForSecret = PRESSURE[6].test(text);
  if (asksForSecret) {
    score = Math.min(100, score + 45);
    reasons.push('It asks you to share an OTP, PIN, CVV or password. Banks and companies never ask for these.');
  }
  if (pressure) {
    score = Math.min(100, score + pressure * 12);
    reasons.push(pressure > 1
      ? 'The message pressures you with threats, deadlines or rewards.'
      : 'The message uses pressure language common in scams.');
  }
  if (!urls.length && !pressure) {
    return { level: 'UNKNOWN', score: 0, reasons: ['No link or scam wording found to check offline.'], urls: [] };
  }
  const level = score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
  if (level === 'LOW' && !reasons.length) reasons.push('No common scam patterns found in the link.');
  return { level, score, reasons, urls: urls.map(u => u.href) };
}
