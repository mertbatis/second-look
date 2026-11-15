# Second Look: Devpost submission draft (#BuildHybridAI 2026)

## Inspiration
People lose billions to scam messages every year: fake parcel texts, "Hi Mum, new number", fake bank alerts. The person who gets the message usually feels something is off but has nobody to ask in that moment, and pasting a private message into a random website feels wrong too. We wanted a second pair of eyes that's always there, explains things like a patient friend, and never takes the message anywhere.

## What it does
Paste a message (or right-click selected text with the Chrome extension) and press one big button. Second Look:

- **Checks the technical tells with plain code:**
  - links that pretend to be a brand (`amaz0n-security.com`, `paypal.com.secure-login.ru`, `netfliix-billing.com`)
  - shortened links, raw IP addresses and disguised international characters
  - email senders that impersonate companies
  - requests for gift cards, crypto or codes
  - pressure and threats, "Hi Mum, new number" patterns, secrecy
- **Reads the message with Gemini Nano on the device** and explains the verdict in two or three plain sentences, like a friend would. Every red flag the model reports must quote words that are really in the message.
- **Gives a clear verdict** ("This looks like a scam" / "Be careful with this one" / "No red flags found"), a list of why, each tagged *checked by code* or *Gemini Nano, on this device*, and safe next steps: don't click, contact the company yourself, call your family member on the number you already have, report it.
- **Stays private.** With Gemini Nano, nothing is sent anywhere. Without it, only a redacted copy goes to Gemini in the cloud (names, emails, phone numbers, long numbers and link paths removed), and the page shows exactly what was sent.
- **Chrome extension.** Right-click selected text and choose *Check with Second Look*. The text travels in the URL fragment, which is never sent to a server.

## How we built it
- **Firebase AI Logic hybrid inference with an explicit privacy route.** `ONLY_ON_DEVICE` (Gemini Nano via Chrome's built-in AI) gets the raw message. `ONLY_IN_CLOUD` gets the redacted one. Both use structured output: a JSON-schema `responseConstraint` on device and a `responseSchema` in the cloud. `response.inferenceSource` labels each result. We chose explicit modes over `PREFER_ON_DEVICE` on purpose: an automatic fallback could carry the raw message to the cloud, and for this app that's the one thing that must not happen.
- **Deterministic signal engine** (`src/signals.js`): URL and email extraction, registrable domains, brand impersonation by substring, homoglyph skeleton and edit distance, shorteners, risky TLDs, punycode, plus pattern families for urgency, threats, payment methods, credentials, prizes, delivery, family emergency, secrecy and money requests. Unit tests cover four classic scams (all "likely scam") and three normal messages (all clear), plus redaction.
- **Safety by design:** the final verdict is never milder than the code checks; quotes that don't appear in the message are dropped; the advice never says "click the link to check".
- **Firebase App Check** (Fraud Defense / reCAPTCHA Enterprise) protects AI Logic; **Remote Config** sets the cloud model and the reading level of explanations; **Firebase Hosting** serves the app; a Manifest V3 extension adds the right-click entry.

## Challenges we ran into
- **Hybrid without leaking.** The convenient automatic fallback is exactly the wrong default for private messages, so the route is decided before the call, and the redaction runs in code, not in a model.
- **Models invent evidence.** Small models sometimes "quote" words that aren't in the message. Requiring exact quotes and filtering in code made the red-flag list trustworthy.
- **Writing for everyone.** The explanations are tuned for someone who isn't technical: short, calm, no jargon, no blame.

## Accomplishments that we're proud of
With Gemini Nano available, a message is checked in about a second without leaving the device. The four classic scams in our tests (fake parcel, "Hi Mum", fake Amazon charge, IRS gift cards) are all caught, and an ordinary dinner message stays clear.

## What we learned
On-device AI changes what people are willing to check: a private message you'd never upload is fine to paste when nothing leaves the laptop. Pairing it with transparent code checks makes the answer something people can trust.

## What's next
- Screenshots of messages (on-device text extraction).
- A share target on Android so people can send a suspicious SMS straight to Second Look.
- More languages for the code checks and explanations.

## Try it
- Live app: https://second-look-kronides.web.app (desktop Chrome for on-device mode; click the pill once if it says "Turn on private mode". Add `?mode=cloud` to try the redacted cloud path.)
- Chrome extension: https://second-look-kronides.web.app/second-look-extension.zip (unzip, chrome://extensions, Developer mode, Load unpacked)
- Code: https://github.com/mertbatis/second-look (Apache-2.0)

## Built with
firebase-ai-logic, gemini-nano, gemini-api, firebase-app-check, recaptcha-enterprise, firebase-remote-config, firebase-hosting, chrome-built-in-ai, chrome-extension, javascript, vite
