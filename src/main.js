import { analyzeSignals, codeVerdict, nextSteps, VERDICT_TEXT } from './signals.js';
import { deviceStatus, downloadDeviceModel, judge, loadConfig } from './ai.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const RANK = { no_red_flags: 0, suspicious: 1, likely_scam: 2 };

const EXAMPLES = [
  'USPS: Your package could not be delivered due to an incomplete address. Please update your details within 24 hours: https://usps-redelivery.top/track',
  "Hi Mum, it's me, I dropped my phone in the bath so this is my new number. Can you send me £280 for the rent today? I'll pay you back Friday. Don't tell Dad, he'll worry x",
  'Amazon: An unauthorized purchase of $949.99 (iPhone 17 Pro) was placed on your account. If this was not you, confirm your identity at amaz0n-security.com and enter the verification code we send you.',
  "Hey! Are we still on for dinner at 7? I booked a table at Luigi's on Main Street. See you there.",
];

let device = 'unsupported';
const FORCE_CLOUD = new URLSearchParams(location.search).get('mode') === 'cloud'; // try the redacted cloud path on a device that has Gemini Nano
async function refreshDevice() {
  device = FORCE_CLOUD ? 'unavailable' : await deviceStatus();
  const el = $('#device');
  el.textContent = {
    available: 'Private mode: Gemini Nano on this device',
    downloadable: 'Turn on private mode (one-time download)',
    downloading: 'Downloading Gemini Nano…',
    unavailable: FORCE_CLOUD ? 'Cloud mode (demo): personal details removed first' : 'Cloud mode: personal details removed first',
    unsupported: 'Cloud mode: personal details removed first',
  }[device];
  el.className = `pill ${device === 'available' ? 'ok' : device.startsWith('download') ? 'warn' : 'cloud'}`;
  el.disabled = device !== 'downloadable';
  $('#privacy').innerHTML = device === 'available'
    ? '🔒 Your message stays on this device. Gemini Nano reads it right here in Chrome.'
    : '☁️ This device has no on-device model, so names, phone numbers, emails and link paths are removed before anything is sent to Gemini in the cloud.';
}
$('#device').addEventListener('click', async () => {
  try { await downloadDeviceModel((p) => { $('#device').textContent = `Downloading Gemini Nano… ${Math.round(p * 100)}%`; }); } catch (e) { alert(e.message); }
  refreshDevice();
});

function render(message, s, ai, error) {
  const code = codeVerdict(s.score);
  const final = ai && RANK[ai.verdict] > RANK[code] ? ai.verdict : code;
  const v = VERDICT_TEXT[final];
  const flags = [
    ...s.flags.map((f) => ({ label: f.label, detail: f.detail, by: 'code' })),
    ...(ai?.red_flags ?? []).filter((f) => !s.flags.some((c) => c.label.toLowerCase() === f.label.toLowerCase())).map((f) => ({ label: f.label, detail: `"${f.quote}"`, by: ai.where })),
  ];
  const by = (w) => (w === 'code' ? '<span class="src code">checked by code</span>' : w === 'device' ? '<span class="src device">Gemini Nano, on this device</span>' : '<span class="src cloud">Gemini in the cloud, redacted</span>');
  $('#result').hidden = false;
  $('#result').className = `result ${v.tone}`;
  $('#result').innerHTML = `
    <div class="verdict"><span class="icon">${v.tone === 'bad' ? '⛔' : v.tone === 'warn' ? '⚠️' : '✅'}</span><div><h2>${v.title}</h2>
    ${ai ? `<p class="explain">${esc(ai.explanation)}</p>` : error ? `<p class="explain">The AI check didn't run (${esc(error)}). This verdict is from the code checks only.</p>` : '<p class="explain"><span class="spin"></span> Gemini is reading the message…</p>'}</div></div>
    ${flags.length ? `<h3>Why</h3><ul class="flags">${flags.map((f) => `<li><b>${esc(f.label)}</b><span>${esc(f.detail)}</span>${by(f.by)}</li>`).join('')}</ul>` : ''}
    <h3>What to do</h3><ol class="steps">${nextSteps(final, s.flags).map((t) => `<li>${esc(t)}</li>`).join('')}</ol>
    ${ai ? `<p class="where">${ai.where === 'device' ? '🔒 Checked on this device. Nothing was sent anywhere.' : `☁️ Checked in the cloud with personal details removed. <details><summary>See exactly what was sent</summary><pre>${esc(ai.sentPreview ?? '')}</pre></details>`}</p>` : ''}`;
}

async function check() {
  const message = $('#msg').value.trim();
  if (!message) return;
  const s = analyzeSignals(message);
  render(message, s, null, null);
  $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const ai = await judge(message, s.flags, device);
    const { calls } = await import('./ai.js');
    ai.sentPreview = calls[0]?.sent ?? '';
    render(message, s, ai, null);
  } catch (e) {
    render(message, s, null, e.message.slice(0, 120));
  }
}

$('#check').addEventListener('click', check);
document.querySelectorAll('[data-ex]').forEach((b) => b.addEventListener('click', () => { $('#msg').value = EXAMPLES[Number(b.dataset.ex)]; check(); }));

// Text sent from the browser extension arrives in the URL fragment, which browsers never send to a server.
const fromHash = new URLSearchParams(location.hash.slice(1)).get('t');
if (fromHash) { $('#msg').value = fromHash; history.replaceState(null, '', location.pathname); }

loadConfig();
refreshDevice().then(() => { if (fromHash) check(); });
