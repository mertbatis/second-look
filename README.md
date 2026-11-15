# Second Look

**Is this message a scam? Check it privately.** Paste a text message, email or chat you're not sure about. Second Look tells you, in plain words, whether it looks like a scam, why, and what to do. It's built for the people scammers target most, so it uses large type, one big button and no jargon.

Your message is the most private thing you could paste into a website: it can contain your name, your bank and your family. So Second Look uses **Firebase AI Logic hybrid inference** with an explicit privacy route:

| Step | Where | What it sees |
|---|---|---|
| Links, sender, payment method, pressure tactics (look-alike domains like `amaz0n-security.com`, shorteners, raw IPs, disguised characters, gift-card/crypto requests, "within 24 hours"...) | plain code, in the tab | the message, locally |
| Reading the message and explaining it | **Gemini Nano on the device** (`ONLY_ON_DEVICE`) | the message, never sent anywhere |
| Same, when this device has no on-device model | Gemini in the cloud (`ONLY_IN_CLOUD`) | a **redacted** copy: names, emails, phone numbers, long numbers and link paths removed (you can see exactly what was sent) |

The model's red flags must quote words that are really in the message; invented evidence is dropped. The final verdict is never milder than what the code checks found.

## Chrome extension
`extension/` (also downloadable at https://second-look-kronides.web.app/second-look-extension.zip): select text anywhere, right-click → **Check with Second Look**. The text travels in the URL fragment (`#t=...`), which browsers never send to a server, and the page clears it from the address bar after reading. To install: unzip, open `chrome://extensions`, turn on Developer mode, **Load unpacked**.

## Firebase
- **Firebase AI Logic** (`firebase/ai`, Gemini Developer API backend): `ONLY_ON_DEVICE` with a JSON-schema `responseConstraint`, and `ONLY_IN_CLOUD` with `responseSchema`; `response.inferenceSource` labels every result. See [`src/ai.js`](src/ai.js).
- **App Check** with Fraud Defense (reCAPTCHA Enterprise), enforced for AI Logic.
- **Remote Config**: cloud model and the reading level of explanations.
- **Firebase Hosting**: https://second-look-kronides.web.app

## Run it
```bash
npm install
npm run dev
npm test        # signal engine: look-alike domains, redaction, verdicts on classic scams vs normal messages
```
Add `?mode=cloud` to the URL to try the redacted cloud path on a device that has Gemini Nano.

## Limits
Second Look points out warning signs; it can't promise that a message is safe. It never tells you to click a link "to check". If in doubt, contact the company or person through a number or app you already trust.

## License
Apache-2.0
