// Second Look: deterministic scam signals. Plain code, no AI, no network. Every flag says where it came from.

const BRANDS = {
  paypal: 'paypal.com', apple: 'apple.com', icloud: 'icloud.com', amazon: 'amazon.com', microsoft: 'microsoft.com', outlook: 'outlook.com',
  google: 'google.com', gmail: 'gmail.com', netflix: 'netflix.com', facebook: 'facebook.com', instagram: 'instagram.com', whatsapp: 'whatsapp.com',
  usps: 'usps.com', fedex: 'fedex.com', ups: 'ups.com', dhl: 'dhl.com', irs: 'irs.gov', chase: 'chase.com', wellsfargo: 'wellsfargo.com',
  bankofamerica: 'bankofamerica.com', citi: 'citi.com', coinbase: 'coinbase.com', binance: 'binance.com', ebay: 'ebay.com', walmart: 'walmart.com',
  docusign: 'docusign.com', dropbox: 'dropbox.com', linkedin: 'linkedin.com', venmo: 'venmo.com', zelle: 'zellepay.com', costco: 'costco.com',
};
const NAME = { paypal: 'PayPal', usps: 'USPS', irs: 'IRS', dhl: 'DHL', ups: 'UPS', fedex: 'FedEx', icloud: 'iCloud', whatsapp: 'WhatsApp', linkedin: 'LinkedIn', bankofamerica: 'Bank of America', wellsfargo: 'Wells Fargo', docusign: 'DocuSign', ebay: 'eBay' };
export const brandName = (b) => NAME[b] ?? b[0].toUpperCase() + b.slice(1);
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 's.id']);
const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'icu', 'click', 'link', 'support', 'help', 'live', 'shop', 'cfd', 'sbs', 'rest', 'quest', 'buzz', 'gq', 'tk', 'ml', 'cf', 'ga']);
// Two-part public suffixes we care about; good enough to find the registrable domain.
const SUFFIX2 = new Set(['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'com.br', 'com.tr', 'co.jp', 'co.in', 'com.mx', 'co.za']);

export const registrable = (host) => {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  return SUFFIX2.has(last2) ? parts.slice(-3).join('.') : last2;
};

const HOMO = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', rn: 'm', vv: 'w', 'ı': 'i', 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'і': 'i', 'ӏ': 'l' };
const skeleton = (s) => {
  let t = s.toLowerCase();
  for (const [k, v] of Object.entries(HOMO)) t = t.split(k).join(v);
  return t.replace(/[^a-z]/g, '');
};

function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

/** Finds URLs (with or without scheme) and bare domains like "paypal-secure.com/login". */
export function findLinks(text) {
  const out = [];
  const re = /\b((?:https?:\/\/|www\.)[^\s<>"')]+|[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.(?:[a-z]{2,24}|xn--[a-z0-9-]+)(?:\/[^\s<>"')]*)?)/gi;
  let m;
  while ((m = re.exec(text))) {
    let raw = m[1].replace(/[.,;:!?]+$/, '');
    if (/@/.test(text.slice(Math.max(0, m.index - 1), m.index))) continue; // part of an email address
    const url = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    let host;
    try { host = new URL(url).hostname; } catch { continue; }
    if (!host.includes('.') || /^\d+\.\d+$/.test(host)) continue;
    if (/\.(jpg|png|gif|pdf|txt|doc)$/i.test(host)) continue;
    out.push({ raw, url, host, domain: registrable(host) });
  }
  return out;
}

export const findEmails = (text) => [...text.matchAll(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g)].map((m) => ({ raw: m[0], domain: registrable(m[1]) }));

/** Which brand a domain is pretending to be, if any (not the real domain). */
export function impersonates(domain) {
  const host = domain.toLowerCase();
  const label = host.split('.')[0];
  const sk = skeleton(host.replace(/\.[^.]+$/, ''));
  for (const [brand, real] of Object.entries(BRANDS)) {
    if (host === real || host.endsWith('.' + real)) return null;
    if (sk.includes(brand) && sk !== brand) return { brand, real, how: 'contains the name' };
    if (skeleton(label) === brand) return { brand, real, how: 'uses look-alike characters' };
    if (brand.length >= 5 && lev(skeleton(label), brand) === 1) return { brand, real, how: 'is one letter off' };
  }
  return null;
}

const PATTERNS = [
  ['urgency', 'Pressure to act fast', /\b(urgent|immediately|within (?:24|48) hours|today only|final (?:notice|warning)|act now|right away|expires? (?:today|soon)|last chance|account will be (?:closed|suspended|locked))\b/i],
  ['threat', 'Threat of a penalty or arrest', /\b(suspended|locked|arrest|warrant|legal action|lawsuit|penalt(?:y|ies)|fine of|police|deport)/i],
  ['payment', 'Asks for an unusual payment method', /\b(gift ?cards?|itunes card|google play card|steam card|bitcoin|crypto|usdt|wire transfer|western union|moneygram|zelle me|cash app me)\b/i],
  ['credentials', 'Asks for passwords, codes or card details', /\b(password|passcode|one[- ]time code|verification code|otp|pin\b|card number|cvv|security code|social security|ssn|login details|confirm your (?:identity|account|details))/i],
  ['prize', 'Too good to be true', /\b(you(?:'ve| have) won|winner|prize|lottery|inheritance|claim your (?:reward|refund|prize)|free (?:iphone|gift)|guaranteed (?:return|profit))\b/i],
  ['delivery', 'Fake delivery problem', /\b(package|parcel|shipment|delivery)\b[^.]{0,60}\b(failed|held|on hold|could not be delivered|address (?:incomplete|issue)|redelivery|customs fee)/i],
  ['family', '"Hi mum/dad, new number" pattern', /\b(hi (?:mum|mom|dad)|this is my new number|new phone|lost my phone)\b/i],
  ['money', 'Asks you to send money', /\b(send|transfer|lend|wire)\b[^.?!]{0,40}(?:[£$€]\s?\d[\d,.]*|\d[\d,.]*\s?(?:dollars|pounds|euros|usd|eur))/i],
  ['secrecy', 'Asks you to keep it secret', /\b(don'?t tell|keep this (?:between us|confidential|secret)|do not share this)\b/i],
  ['refund', 'Unexpected refund or charge', /\b(refund of|you (?:were|have been) charged|unauthori[sz]ed (?:charge|transaction|purchase)|order #?\w+ (?:confirmed|placed)) /i],
];

/**
 * All code-found signals for a message. Returns flags [{ id, label, detail, weight }] and the parts that matter.
 */
export function analyzeSignals(text) {
  const links = findLinks(text);
  const emails = findEmails(text);
  const flags = [];
  const add = (id, label, detail, weight) => { if (!flags.some((f) => f.id === id && f.detail === detail)) flags.push({ id, label, detail, weight }); };
  for (const l of links) {
    const imp = impersonates(l.domain) ?? (l.host !== l.domain ? impersonates(l.host.split('.').slice(0, -2).join('.') + '.x') : null);
    if (imp) add('lookalike', `Link pretends to be ${brandName(imp.brand)}`, `${l.host} ${imp.how} "${imp.brand}", but ${brandName(imp.brand)}'s real site is ${imp.real}`, 4);
    if (SHORTENERS.has(l.domain)) add('shortener', 'Shortened link hides where it goes', l.host, 2);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(l.host)) add('ip', 'Link goes to a raw IP address', l.host, 3);
    if (l.host.startsWith('xn--') || l.host.includes('.xn--')) add('punycode', 'Link uses disguised international characters', l.host, 3);
    const tld = l.domain.split('.').pop();
    if (RISKY_TLDS.has(tld)) add('tld', `Unusual web address ending (.${tld})`, l.host, 1);
    if (/@/.test(l.raw.replace(/^https?:\/\//, '').split('/')[0])) add('userinfo', 'Link hides the real address after an @', l.raw, 3);
  }
  for (const e of emails) {
    const imp = impersonates(e.domain);
    if (imp) add('sender', `Email address pretends to be ${brandName(imp.brand)}`, `${e.raw} is not from ${imp.real}`, 4);
  }
  for (const [id, label, re] of PATTERNS) {
    const m = text.match(re);
    if (m) add(id, label, `"${m[0].trim()}"`, id === 'payment' || id === 'credentials' || id === 'money' ? 3 : 2);
  }
  const score = flags.reduce((s, f) => s + f.weight, 0);
  return { flags, links, emails, score };
}

/** Verdict from code alone (used to cross-check the model and when no model is reachable). */
export const codeVerdict = (score) => (score >= 6 ? 'likely_scam' : score >= 3 ? 'suspicious' : 'no_red_flags');

/**
 * What the cloud may see when there is no on-device model: the message with personal data removed.
 * Names after greetings, emails, phone numbers, long digit runs, amounts stay as categories; link HOSTS stay (they're the evidence).
 */
export function redact(text) {
  return text
    .replace(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g, (_, d) => `[email at ${d}]`)
    .replace(/\+?\d[\d ()-]{7,}\d/g, '[phone]')
    .replace(/\b\d{6,}\b/g, '[number]')
    .replace(/\b([Hh]i|[Hh]ello|[Dd]ear|[Hh]ey)\s+([A-Z][a-z]+)(?:\s+[A-Z][a-z]+)?/g, '$1 [name]')
    .replace(/(https?:\/\/[^\s/]+)\/\S*/gi, '$1/[path]')
    .slice(0, 4000);
}

export const VERDICT_TEXT = {
  likely_scam: { title: 'This looks like a scam', tone: 'bad' },
  suspicious: { title: 'Be careful with this one', tone: 'warn' },
  no_red_flags: { title: 'No red flags found', tone: 'ok' },
};

/** Safe, generic next steps. Never "click the link to check". */
export function nextSteps(verdict, flags) {
  const ids = new Set(flags.map((f) => f.id));
  const steps = [];
  if (verdict !== 'no_red_flags') {
    steps.push("Don't click links, open attachments or reply.");
    if (ids.has('lookalike') || ids.has('sender') || ids.has('delivery') || ids.has('refund') || ids.has('credentials')) steps.push('If you think it might be real, go to the company yourself: type their address or use their app, never the link in the message.');
    if (ids.has('payment')) steps.push('No real company or government agency asks to be paid in gift cards or crypto.');
    if (ids.has('family')) steps.push('Call your family member on the number you already have for them before sending anything.');
    if (ids.has('credentials')) steps.push('Never share codes sent to your phone. If you already did, change that password now and call your bank.');
    steps.push('Report it: forward scam texts to 7726 (SPAM) in the US/UK, and use reportfraud.ftc.gov or your country\'s fraud line.');
  } else {
    steps.push('Nothing typical of scams stood out, but stay alert: scammers change their wording all the time.');
    steps.push('If it asks you to log in, pay or share a code, go to the company directly instead of using a link.');
  }
  return steps;
}
