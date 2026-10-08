/**
 * PrivacyFirst — Local Detection Engine (JS port of the app engine)
 * Implements: Verhoeff, Luhn, 12 detectors, vault, overlap resolution,
 * sanitize, restore, allow-list
 *
 * ZERO dependencies. Runs in-browser and offline.
 */

(function (global) {
  'use strict';

  // ── Verhoeff algorithm (Aadhaar checksum) ─────────────────────────────
  const VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
  ];
  const VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8],
  ];
  const VERHOEFF_INV = [0,4,3,2,1,9,8,7,6,5];

  function verhoeffCheck(num) {
    const digits = String(num).replace(/\s/g, '').split('').reverse().map(Number);
    let c = 0;
    for (let i = 0; i < digits.length; i++) {
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits[i]]];
    }
    return c === 0;
  }

  // ── Luhn algorithm (card numbers) ─────────────────────────────────────
  function luhnCheck(num) {
    const digits = String(num).replace(/[\s\-]/g, '');
    if (!/^\d{13,19}$/.test(digits)) return false;
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = parseInt(digits[i], 10);
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  // ── Normalise / strip helpers ──────────────────────────────────────────
  function digits(s) { return s.replace(/\D/g, ''); }

  // ── Detectors ─────────────────────────────────────────────────────────
  // Each detector: { type, label, regex, validate? }
  // validate(match) → false = skip, true = mask
  const DETECTORS = [
    // PAN (India) — AAAAA0000A pattern
    {
      type: 'PAN',
      label: 'PAN',
      regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
      validate: null,
    },
    // Aadhaar — 12 digits (with optional spaces every 4)
    {
      type: 'AADHAAR',
      label: 'Aadhaar',
      regex: /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b/g,
      validate: (m) => {
        const d = digits(m);
        return d.length === 12 && verhoeffCheck(d);
      },
    },
    // Credit/Debit card — 13–19 digits, optional separators
    {
      type: 'CARD',
      label: 'Card',
      regex: /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4}(?:[\s\-]?\d{1,3})?)\b/g,
      validate: (m) => luhnCheck(m),
    },
    // Email
    {
      type: 'EMAIL',
      label: 'Email',
      regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
      validate: null,
    },
    // Phone (Indian — 10 digits, optional +91 / 0, optional space/hyphen mid-number)
    {
      type: 'PHONE',
      label: 'Phone',
      regex: /(?:\+91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5}\b/g,
      validate: null,
    },
    // UPI ID
    {
      type: 'UPI',
      label: 'UPI ID',
      regex: /\b[\w.\-]{2,256}@[a-zA-Z]{2,64}\b/g,
      validate: (m) => /[a-zA-Z]/.test(m.split('@')[0]) && m.split('@')[0].length >= 3,
    },
    // IFSC code
    {
      type: 'IFSC',
      label: 'IFSC',
      regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
      validate: null,
    },
    // GSTIN
    {
      type: 'GSTIN',
      label: 'GSTIN',
      regex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g,
      validate: null,
    },
    // IPv4
    {
      type: 'IP',
      label: 'IP Address',
      regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
      validate: (m) => !m.startsWith('127.') && !m.startsWith('0.'),
    },
    // Secret / API key — env-style: KEY=value or "key": "value".
    // Allows the keyword anywhere in the key name so STRIPE_SECRET_KEY=,
    // DB_PASSWORD=, OPENAI_API_KEY= etc. all match.
    {
      type: 'SECRET',
      label: 'Secret',
      regex: /(?:[A-Za-z0-9_\-]*(?:api[_\-]?key|secret|token|password|passwd|pwd|auth|bearer|credential|private[_\-]?key|access[_\-]?key|session[_\-]?key|client[_\-]?secret)[A-Za-z0-9_\-]*\s*[:=]\s*["']?)([A-Za-z0-9\/+_\-\.]{16,})/gi,
      validate: null,
      captureGroup: 1,
    },
    // Standalone well-known credential formats (no KEY= prefix required)
    {
      type: 'SECRET',
      label: 'Secret',
      regex: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b/g,
      validate: null,
    },
    // DATABASE_URL / connection strings
    {
      type: 'SECRET',
      label: 'DB URL',
      regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`,;)]+/gi,
      validate: null,
    },
    // Person name heuristic — "My name is X Y", "I am X Y", "Name: X Y", "Customer: X Y".
    // Context phrases are spelled case-tolerantly instead of using an 'i' flag,
    // so the captured name must still be capitalised (lowercase words never match).
    {
      type: 'PERSON',
      label: 'Person',
      regex: /\b(?:[Mm]y name is|[Ii] am|[Ii]'m|[Nn]ame\s*[:=]|[Uu]ser\s*[:=]|[Cc]ustomer\s*[:=]|[Cc]ontact(?:ed)?\s*[:=]|[Ff]rom\s*[:=])\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})/g,
      validate: null,
      captureGroup: 1,
    },
  ];

  // ── Vault ──────────────────────────────────────────────────────────────
  class Vault {
    constructor() {
      this._map = new Map();   // placeholder → { original, type }
      this._rev = new Map();   // normalizedOriginal → placeholder
      this._counters = {};
    }

    _normalize(original, type) {
      if (type === 'AADHAAR' || type === 'CARD') {
        return digits(original);
      }
      return original.trim().toLowerCase();
    }

    _nextId(type) {
      this._counters[type] = (this._counters[type] || 0) + 1;
      return `[${type}_${String(this._counters[type]).padStart(2, '0')}]`;
    }

    store(original, type) {
      const key = this._normalize(original, type);
      if (this._rev.has(key)) return this._rev.get(key);
      const ph = this._nextId(type);
      this._map.set(ph, { original, type });
      this._rev.set(key, ph);
      return ph;
    }

    restore(text) {
      let out = text;
      for (const [ph, { original }] of this._map) {
        out = out.split(ph).join(original);
      }
      return out;
    }

    entries() {
      return Array.from(this._map.entries()).map(([ph, v]) => ({
        placeholder: ph,
        original: v.original,
        type: v.type,
      }));
    }

    clear() {
      this._map.clear();
      this._rev.clear();
      this._counters = {};
    }
  }

  // ── Overlap resolution ─────────────────────────────────────────────────
  // Given array of {start, end, ...} spans, remove overlapping ones
  // keeping the longest span.
  function resolveOverlaps(spans) {
    spans.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    let last = -1;
    for (const s of spans) {
      if (s.start >= last) {
        out.push(s);
        last = s.end;
      }
    }
    return out;
  }

  // ── Allow-list ────────────────────────────────────────────────────────
  const DEFAULT_ALLOW = new Set(); // can be populated by UI

  // ── Core sanitize ─────────────────────────────────────────────────────
  /**
   * sanitize(text, vault, allowSet?, options?)
   * options.ner — set false to skip the local NER pass
   * Returns { sanitized, findings }
   * findings: [{ type, original, placeholder, inferred, confidence, ... }]
   */
  function sanitize(text, vault, allowSet, options) {
    const allow = allowSet || DEFAULT_ALLOW;
    const opts = options || {};
    const allSpans = [];

    for (const det of DETECTORS) {
      const re = new RegExp(det.regex.source, det.regex.flags.replace('g', '') + 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        const fullMatch = m[0];
        const value = det.captureGroup != null ? m[det.captureGroup] : fullMatch;
        if (!value) continue;

        // Find actual position of the captured group if needed
        const start = det.captureGroup != null ? m.index + fullMatch.indexOf(value) : m.index;
        const end = start + value.length;

        if (allow.has(value)) continue;
        if (det.validate && !det.validate(value)) continue;

        allSpans.push({ type: det.type, label: det.label, original: value, start, end });
      }
    }

    const resolved = resolveOverlaps(allSpans);

    // ── Second pass: local NER for names with no context phrase ──────────
    // Catches bare names like "John called me" that the regex PERSON
    // detector cannot see. Only fills gaps the regex pass left open, so
    // context-rule matches always keep precedence.
    if (opts.ner !== false && global.PFNer && typeof global.PFNer.findNames === 'function') {
      for (const hit of global.PFNer.findNames(text, resolved)) {
        const value = hit.text;
        if (!value || allow.has(value)) continue;
        allSpans.push({
          type: 'PERSON',
          label: 'Person',
          original: value,
          start: hit.start,
          end: hit.end,
          inferred: true,
          confidence: hit.confidence,
        });
      }
    }

    // Re-resolve so NER spans compete with, and lose to, the regex spans
    const finalSpans = resolveOverlaps(allSpans);

    // Build sanitized string and findings
    let out = '';
    let cursor = 0;
    const findings = [];

    for (const span of finalSpans) {
      out += text.slice(cursor, span.start);
      const ph = vault.store(span.original, span.type);
      out += ph;
      cursor = span.end;
      findings.push({
        type: span.type,
        label: span.label,
        original: span.original,
        placeholder: ph,
        action: 'MASK',
        inferred: Boolean(span.inferred),
        confidence: span.confidence == null ? 1 : span.confidence,
      });
    }
    out += text.slice(cursor);

    return { sanitized: out, findings };
  }

  // ── Restore ────────────────────────────────────────────────────────────
  function restore(text, vault) {
    return vault.restore(text);
  }

  // ── Export ─────────────────────────────────────────────────────────────
  global.PFEngine = { Vault, sanitize, restore, verhoeffCheck, luhnCheck };

})(typeof window !== 'undefined' ? window : global);
