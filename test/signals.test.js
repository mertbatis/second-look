import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSignals, codeVerdict, findLinks, impersonates, nextSteps, redact, registrable } from '../src/signals.js';

test('registrable domain and links', () => {
  assert.equal(registrable('secure.login.paypal.com'), 'paypal.com');
  assert.equal(registrable('www.royalmail.co.uk'), 'royalmail.co.uk');
  const l = findLinks('Pay here: https://paypa1-billing.com/verify?id=9, or visit usps-redelivery.top/track. Email me at bob@example.com');
  assert.deepEqual(l.map((x) => x.domain), ['paypa1-billing.com', 'usps-redelivery.top']);
});

test('look-alike detection', () => {
  assert.equal(impersonates('paypal.com'), null);
  assert.equal(impersonates('paypa1.com').brand, 'paypal');
  assert.equal(impersonates('amaz0n-support.net').brand, 'amazon');
  assert.equal(impersonates('netfliix.com').brand, 'netflix');
  assert.equal(impersonates('wikipedia.org'), null);
  const s = analyzeSignals('Your account is limited: http://paypal.com.secure-login.ru/confirm');
  assert.ok(s.flags.some((f) => f.id === 'lookalike'), JSON.stringify(s.flags));
});

test('classic scams score high, normal messages low', () => {
  const scams = [
    'USPS: Your package could not be delivered due to an incomplete address. Update within 24 hours: https://usps-redelivery.top/track',
    'Hi mum, this is my new number, I lost my phone. Can you send me £300 today? Don\'t tell dad.',
    'IRS FINAL NOTICE: a warrant has been issued. Pay the penalty with Google Play gift cards immediately to avoid arrest.',
    'Amazon: an unauthorized purchase of $949.99 was made. If this wasn\'t you, confirm your identity at amaz0n-security.com and enter the verification code we send you.',
  ];
  for (const m of scams) assert.equal(codeVerdict(analyzeSignals(m).score), 'likely_scam', m);
  const normal = [
    'Hey, are we still on for dinner at 7? I booked the table at Luigi\'s.',
    'Your dentist appointment is confirmed for Tuesday 14:30. Reply C to cancel.',
    'The quarterly report is attached. Let me know if the numbers look right.',
  ];
  for (const m of normal) assert.equal(codeVerdict(analyzeSignals(m).score), 'no_red_flags', m);
});

test('redaction keeps evidence, drops personal data', () => {
  const r = redact('Dear John Smith, call +1 (415) 555-0199 or email john.smith@gmail.com. Order 88213377. Visit https://paypa1.com/login/john?token=abc');
  assert.ok(!/John|Smith|415|555|88213377|token=abc|john\.smith/.test(r), r);
  assert.match(r, /paypa1\.com/);
  assert.match(r, /\[email at gmail\.com\]/);
});

test('next steps never tell you to click', () => {
  for (const v of ['likely_scam', 'suspicious', 'no_red_flags']) for (const s of nextSteps(v, [{ id: 'credentials' }, { id: 'payment' }])) assert.ok(!/click the link|use the link/i.test(s));
});
