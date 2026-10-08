# PrivacyFirst — Demo Site

Static marketing/demo site for **PrivacyFirst**, a local-first tool that masks PII and
secrets before they reach an AI model, then restores them locally in the reply.

No build step, no framework, no backend, no CDN. Open `index.html` and it runs.

---

## Why this exists

Every prompt and every coding-agent request carries more than it needs to. A tax
question contains a name, a PAN and an Aadhaar number. A coding agent reading your
`.env` sends a production database URL and live API keys to a model provider — and
usually puts them in your git history as well.

PrivacyFirst reduces that exposure. It runs detection **locally**, replaces sensitive
values with typed placeholders (`[PAN_01]`, `[SECRET_02]`), and restores the real values
in the AI's response before you ever see it. Only the sanitized text leaves the device.

---

## Run it

```
# Option 1 — just open it
start index.html

# Option 2 — local server (recommended if using the bring-your-own-key panel)
npx serve .
```

Works from `file://`. All fonts and libraries are vendored locally, so the page makes
**zero network requests** until you explicitly press *Send sanitized* with your own key.

---

## Pages

| Page | What it does |
|---|---|
| `index.html` | Hero, problem framing, detector table, architecture diagram, honest claims/limitations, roadmap |
| `demo.html` | The working part: animated walkthrough + a live engine running in your browser |
| `usecases.html` | Six concrete before/after use cases (developers, tax, support, freelance, enterprise, education) |
| `howitworks.html` | Technical breakdown: pipeline, vault determinism, stream restorer, proxy internals, auto-protect config |
| `get-started.html` | Install paths and system requirements |

---

## Detection engine

`js/engine.js` is a dependency-free port of the TypeScript engine in the desktop app.

| Type | Method |
|---|---|
| AADHAAR | 12 digits + **Verhoeff checksum** — invalid numbers are not masked |
| CARD | 13–19 digits + **Luhn** — invalid numbers are not masked |
| PAN | `[A-Z]{5}[0-9]{4}[A-Z]` |
| EMAIL / IFSC / GSTIN / UPI | regex + validation |
| PHONE | Indian 10-digit, tolerates `+91` and `98765 43210` grouping |
| SECRET | `*_KEY=`/`*_TOKEN=`/`*_PASSWORD=` suffixes, connection strings, and standalone `sk-…`, `sk_live_…`, `AKIA…`, `ghp_…`, JWT |
| IP | IPv4, skipping loopback and `0.x` |
| PERSON | context phrases (`my name is`, `Customer:`, `Name:`, …) **plus** a local NER pass |

### Two-pass name detection

The regex PERSON detector needs a context phrase, so it misses bare names. `js/ner.js`
adds a second pass using [compromise](https://github.com/spencermountain/compromise)
(vendored in `js/vendor/`, MIT licensed) plus a small gazetteer for names the library
doesn't know.

Names found this way are tagged **`inferred`** in the findings table, because they are a
best-effort guess rather than a confirmed match:

- regex match → `inferred: false`, `confidence: 1`
- NER match → `inferred: true`, `confidence: 0.7–0.9`

Context-phrase matches always win over inferred ones, and the NER pass never re-reports
a span another detector already claimed. You can toggle the whole NER pass off in the
live demo to compare.

### Core invariants

- **Deterministic** — the same value always maps to the same placeholder.
- **Normalized** — `2345 6789 0124` and `234567890124` share `[AADHAAR_01]`.
- **Overlap resolution** — longest match wins, so a phone number inside a card number
  never masks part of it.
- **No raw values logged** — findings carry counts and types only.

---

## Bring-your-own-key (optional)

The live demo can call a real model, which is the only thing that touches the network.
Supported: **OpenAI**, **Anthropic**, **Gemini**, **Ollama** (local), or any
OpenAI-compatible custom endpoint.

Your key goes **directly from the browser to the provider**. There is no server here.
It is held in JS memory only — never `localStorage`, never a cookie, gone when you close
the tab.

Provider quirks are handled in `demo.html`:

- Anthropic needs `anthropic-dangerous-direct-browser-access: true` (sent automatically)
- Ollama needs `OLLAMA_ORIGINS` set to allow browser origins
- Some providers reject calls from a `file://` origin — serve the site over HTTP if a
  request fails

With no key entered, the demo falls back to a mock reply so it never dead-ends.

---

## What we claim

- Detection runs locally — no text is sent to any server for scanning
- The placeholder-to-original map stays on your device, in memory
- You can see exactly what the AI receives before it is sent
- Detection is user-initiated; nothing is masked without your knowledge

## What we do not claim

- **Not anonymization.** Inferred names are a best-effort guess.
- **Not 100% detection.** It reduces exposure; it does not eliminate risk.
- **Not attachment scanning.** Text only — no PDFs, images, or screenshots.
- **Not protection against model memorization.**

## Known gaps

1. **Sentence-initial names** — `Priya Menon called` can be missed; compromise doesn't tag
   it and the gazetteer only extends a *second* word when the first is already known.
2. **Quasi-identifiers** — salary + location + age can re-identify someone with no
   individual PII present.
3. **Attachments and non-text modalities** — not covered.
4. **Antigravity IDE** — unsupported. It talks to Google's internal `v1internal` endpoints
   with OAuth-bound tokens and exposes no base-URL override; only reverse-engineered
   binary-patch hacks exist, which break on every update.

---

## Project layout

```
privacyfirst-site/
├─ index.html            landing page
├─ demo.html             animated walkthrough + live engine
├─ usecases.html         before/after use cases
├─ howitworks.html       technical breakdown
├─ get-started.html      install paths
├─ css/styles.css        design system (dark, sharp corners, hairline borders)
├─ fonts/                Geist Sans + Geist Mono (self-hosted)
└─ js/
   ├─ engine.js          detectors, vault, sanitize/restore
   ├─ ner.js             local NER pass (context-free names)
   ├─ components.js      shared nav, footer, expand cards
   └─ vendor/compromise.js
```

No dependencies to install, no bundler, no framework.

---

## Third-party

`js/vendor/compromise.js` — [compromise](https://github.com/spencermountain/compromise),
MIT license, vendored so the site works offline. License text in
`js/vendor/compromise-LICENSE.txt`.

Geist Sans and Geist Mono are licensed under the [SIL Open Font License 1.1](https://openfontlicense.org/).

---

## Related

The desktop app (TypeScript engine + local proxy + Electron UI) lives in the
sibling `PrivacyFirst/` repository. This site is a static, standalone demo of the same
detection behaviour.