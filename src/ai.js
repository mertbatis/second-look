// Second Look: Firebase AI Logic hybrid inference with an explicit privacy route.
// Raw message text is only ever given to the on-device model (ONLY_ON_DEVICE). When Gemini Nano isn't available,
// the cloud model (ONLY_IN_CLOUD) gets a redacted copy. Every call is logged with response.inferenceSource.
import { initializeApp } from 'firebase/app';
import { getAI, getGenerativeModel, GoogleAIBackend, InferenceMode, Schema } from 'firebase/ai';
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from 'firebase/app-check';
import { getRemoteConfig, fetchAndActivate, getValue } from 'firebase/remote-config';
import { firebaseConfig, recaptchaSiteKey } from './firebase-config.js';
import { redact } from './signals.js';

const app = initializeApp(firebaseConfig);
if (import.meta.env.VITE_APPCHECK_DEBUG) self.FIREBASE_APPCHECK_DEBUG_TOKEN = true;
if (recaptchaSiteKey) initializeAppCheck(app, { provider: new ReCaptchaEnterpriseProvider(recaptchaSiteKey), isTokenAutoRefreshEnabled: true });
const ai = getAI(app, { backend: new GoogleAIBackend() });

const rc = getRemoteConfig(app);
rc.settings.minimumFetchIntervalMillis = 3600_000;
rc.defaultConfig = { cloud_model: 'gemini-3.5-flash-lite', reading_level: 'a friendly neighbour explaining to someone who is not technical' };
export const config = { cloudModel: rc.defaultConfig.cloud_model, readingLevel: rc.defaultConfig.reading_level };
export async function loadConfig() {
  try { await fetchAndActivate(rc); } catch { /* offline: defaults */ }
  config.cloudModel = getValue(rc, 'cloud_model').asString() || config.cloudModel;
  config.readingLevel = getValue(rc, 'reading_level').asString() || config.readingLevel;
}

const ENGLISH = { expectedInputs: [{ type: 'text', languages: ['en'] }], expectedOutputs: [{ type: 'text', languages: ['en'] }] };
export async function deviceStatus() {
  if (typeof LanguageModel === 'undefined') return 'unsupported';
  try { return await LanguageModel.availability(ENGLISH); } catch { return 'unavailable'; }
}
export async function downloadDeviceModel(onProgress) {
  const s = await LanguageModel.create({ ...ENGLISH, monitor(m) { m.addEventListener('downloadprogress', (e) => onProgress?.(e.loaded)); } });
  s.destroy();
}

export const calls = [];
const listeners = new Set();
export const onCall = (fn) => listeners.add(fn);

const VERDICTS = ['likely_scam', 'suspicious', 'no_red_flags'];
const judgeJson = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: VERDICTS },
    red_flags: { type: 'array', items: { type: 'object', properties: { label: { type: 'string' }, quote: { type: 'string' } }, required: ['label', 'quote'] } },
    explanation: { type: 'string' },
  },
  required: ['verdict', 'red_flags', 'explanation'],
};
const judgeSchema = Schema.object({
  properties: {
    verdict: Schema.enumString({ enum: VERDICTS }),
    red_flags: Schema.array({ items: Schema.object({ properties: { label: Schema.string(), quote: Schema.string() } }) }),
    explanation: Schema.string(),
  },
});

let deviceModel;
let cloudModel;
const model = (where) => {
  if (where === 'device') return (deviceModel ??= getGenerativeModel(ai, { mode: InferenceMode.ONLY_ON_DEVICE, onDeviceParams: { createOptions: ENGLISH, promptOptions: { responseConstraint: judgeJson } } }));
  return (cloudModel ??= getGenerativeModel(ai, { mode: InferenceMode.ONLY_IN_CLOUD, inCloudParams: { model: config.cloudModel, generationConfig: { temperature: 0.1, responseMimeType: 'application/json', responseSchema: judgeSchema } } }));
};

const prompt = (message, codeFlags) => [
  'You check messages for scams (phishing, fake delivery, impersonation, family emergency, investment, romance, tech support, prize scams).',
  `Write the explanation like ${config.readingLevel}: two or three short sentences, no jargon, no blame.`,
  'Return verdict likely_scam, suspicious or no_red_flags. red_flags: each with a short label and the exact quote from the message that shows it. Only quote words that appear in the message. Do not invent links or facts.',
  codeFlags.length ? `Plain code already found: ${codeFlags.map((f) => f.label).join('; ')}.` : 'Plain code found no technical red flags (links, sender, payment method).',
  'MESSAGE:',
  message,
].join('\n');

/** Judges a message. 'device' sends the raw text to Gemini Nano; otherwise the cloud gets a redacted copy. */
export async function judge(message, codeFlags, device) {
  const where = device === 'available' ? 'device' : 'cloud';
  const sentText = where === 'device' ? message : redact(message);
  const p = prompt(sentText, codeFlags);
  const t0 = performance.now();
  const res = await model(where).generateContent(p);
  const r = res.response;
  const source = r.inferenceSource === 'on_device' ? 'device' : 'cloud';
  calls.unshift({ at: new Date(), where: source, ms: Math.round(performance.now() - t0), sent: source === 'cloud' ? p : null });
  listeners.forEach((fn) => fn(calls));
  let out;
  try { out = JSON.parse(r.text().replace(/^```(?:json)?|```$/g, '').trim()); } catch { out = { verdict: 'suspicious', red_flags: [], explanation: r.text().slice(0, 400) }; }
  if (!VERDICTS.includes(out.verdict)) out.verdict = 'suspicious';
  // Keep only quotes that really appear in what the model saw (no invented evidence).
  out.red_flags = (out.red_flags ?? []).filter((f) => f && f.quote && sentText.toLowerCase().includes(String(f.quote).toLowerCase().slice(0, 60))).slice(0, 6);
  return { ...out, where: source, redacted: where === 'cloud' };
}
