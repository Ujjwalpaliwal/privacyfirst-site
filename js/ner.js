/**
 * PrivacyFirst — Local NER (Named Entity Recognition)
 *
 * Second-pass name detection using compromise (vendored locally in
 * js/vendor/compromise.js — no CDN, no model download, runs offline).
 *
 * This closes the "names without context phrases" gap: the regex PERSON
 * detector needs a cue ("my name is", "Customer:"), while this pass finds
 * bare names anywhere, e.g. "John called me".
 *
 * Findings produced here are tagged `inferred: true` so the UI can
 * distinguish them from context-rule matches.
 *
 * Degrades gracefully: if compromise is unavailable, findNames() returns
 * [] and the regex PERSON detector keeps working on its own.
 */

(function (global) {
  'use strict';

  // Tokens that compromise can tag as Person but are never a real name
  // in prompt context. Keeps the detector conservative.
  const NOT_NAMES = new Set([
    'i', 'me', 'my', 'we', 'us', 'our', 'you', 'your', 'they', 'them',
    'he', 'she', 'his', 'her', 'this', 'that', 'these', 'those',
    'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
    'january', 'february', 'march', 'april', 'may', 'june', 'july',
    'august', 'september', 'october', 'november', 'december',
    'please', 'thanks', 'thank', 'hello', 'hi', 'dear', 'regards',
    'team', 'support', 'admin', 'system', 'user', 'users', 'customer',
    'account', 'server', 'database', 'error', 'warning', 'note', 'info',
    'status', 'order', 'invoice', 'payment', 'request', 'response',
    'api', 'url', 'http', 'https', 'json', 'html', 'sql', 'node',
    'python', 'java', 'react', 'docker', 'linux', 'windows', 'github',
    'monday', 'ist', 'utc', 'gmt', 'iso', 'utc',
  ]);

  const isNamey = (word) => {
    if (!word) return false;
    const w = word.replace(/[^A-Za-z'-]/g, '');
    if (w.length < 2) return false;
    if (NOT_NAMES.has(w.toLowerCase())) return false;
    // Must start with an uppercase letter (real names are capitalised)
    return /^[A-Z]/.test(w);
  };

  // ── Supplemental given-name gazetteer ──────────────────────────────────
  // compromise ships an English-centric name lexicon, so names like
  // "Ananya" or "Lakshmi" are invisible to it. This list catches the
  // common ones for the Indian/South-Asian audience this tool targets.
  const KNOWN_FIRST_NAMES = new Set([
    // Indian - male
    'aarav', 'abhay', 'aditya', 'akash', 'amit', 'anand', 'aniket', 'anil',
    'arjun', 'ashish', 'ashok', 'bala', 'balaji', 'bhaskar', 'chandan',
    'chetan', 'dinesh', 'ganesh', 'gopal', 'hari', 'hemant', 'kailash',
    'karan', 'karthik', 'kavin', 'kiran', 'krishna', 'mahesh', 'manish',
    'mohit', 'mukesh', 'naveen', 'nikhil', 'nilesh', 'pankaj', 'prakash',
    'prashant', 'prem', 'rahul', 'raj', 'raja', 'rajesh', 'rakesh', 'ram',
    'ramesh', 'ravi', 'rohit', 'sachin', 'sandeep', 'sanjay', 'satish',
    'shankar', 'shubham', 'suresh', 'tapan', 'tarun', 'vijay', 'vikas',
    'vinod', 'vivek',
    // Indian - female
    'aditi', 'anjali', 'anita', 'anupama', 'asha', 'ananya', 'deepa', 'divya',
    'geeta', 'anjana', 'ishita', 'jaya', 'kavita', 'lakshmi', 'lata',
    'madhavi', 'manisha', 'meera', 'mita', 'namrata', 'nisha', 'padma',
    'pooja', 'priya', 'radha', 'rekha', 'sandhya', 'sarita', 'seema',
    'shalini', 'shreya', 'sunita', 'swati', 'anushka', 'malati', 'kiran',
    // International / English (names compromise's lexicon does not know)
    'ananya', 'charlotte', 'daniel', 'elena', 'fatima', 'hassan', 'ivan',
    'julia', 'lucia', 'mateo', 'noah', 'olivia', 'sofia', 'yusuf', 'aisha',
    'zara', 'hannah', 'sophia', 'isabella', 'mia', 'chloe', 'ethan',
  ]);

  // Names that are also ordinary English words. Masking these on a bare
  // capitalised token produces too many false positives, so they are only
  // accepted when paired with a second capitalised word ("Bill Gates").
  const AMBIGUOUS_NAMES = new Set([
    'will', 'mark', 'bill', 'grace', 'may', 'august', 'rose', 'jack', 'art',
    'mary', 'jane', 'anna', 'martha', 'april', 'june', 'amber', 'summer',
    'dawn', 'hope', 'faith', 'joe', 'tom', 'max', 'alex', 'sam', 'chris',
    'alan', 'adam', 'ben', 'dan', 'ian', 'jo', 'ken', 'leo', 'ned', 'pat',
    'ray', 'ted', 'victor', 'norman', 'susan', 'irene', 'helen', 'joyce',
  ]);

  const splitTokens = (text) => {
    const out = [];
    const re = /[A-Za-z][A-Za-z'-]*/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      out.push({ text: m[0], start: m.index, end: m.index + m[0].length });
    }
    return out;
  };

  // A token counts as sentence-initial when only punctuation/whitespace
  // separate it from the start of the text or a previous sentence break.
  const isSentenceInitial = (text, token) => {
    let i = token.start - 1;
    while (i >= 0) {
      const c = text[i];
      if (c === '.' || c === '!' || c === '?' || c === '\n') return true;
      if (!/\s/.test(c)) return false;
      i--;
    }
    return true;
  };

  /**
   * Gazetteer pass: find capitalised tokens that are known given names,
   * extending to an adjacent capitalised word (likely a surname).
   */
  function findGazetteerNames(text, excludeSpans) {
    const tokens = splitTokens(text);
    const taken = excludeSpans || [];
    const overlapsTaken = (start, end) => taken.some((s) => start < s.end && end > s.start);

    const claimed = [];
    const out = [];
    const overlapsClaimed = (start, end) => claimed.some((s) => start < s.end && end > s.start);

    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      const lower = tok.text.toLowerCase();

      if (NOT_NAMES.has(lower)) continue;
      if (AMBIGUOUS_NAMES.has(lower)) continue;
      const known = KNOWN_FIRST_NAMES.has(lower);
      if (!known) continue;
      // Must actually be capitalised in the source
      if (!/^[A-Z]/.test(tok.text)) continue;

      // Extend across an adjacent capitalised word -> "Rahul Sharma"
      let end = tok.end;
      let words = 1;
      const next = tokens[i + 1];
      if (
        next &&
        next.start === end + 1 &&               // single space between them
        /^[A-Z]/.test(next.text) &&
        !NOT_NAMES.has(next.text.toLowerCase()) &&
        !AMBIGUOUS_NAMES.has(next.text.toLowerCase()) &&
        next.text.length > 1
      ) {
        end = next.end;
        words = 2;
      }

      // Bare ambiguous-at-start single token is not enough evidence
      if (words === 1 && isSentenceInitial(text, tok) && !known) continue;
      if (overlapsTaken(tok.start, end) || overlapsClaimed(tok.start, end)) continue;

      claimed.push({ start: tok.start, end });
      out.push({
        start: tok.start,
        end,
        text: text.slice(tok.start, end),
        confidence: words > 1 ? 0.85 : 0.7,
      });
    }

    return out;
  }

  /**
   * Compute the character span of a person match from its term offsets.
   * Returns { start, end } or null when the span cannot be determined.
   */
  function spanFromTerms(terms) {
    if (!terms || !terms.length) return null;

    const offsets = terms
      .map((t) => t.offset)
      .filter((o) => o && typeof o.start === 'number' && typeof o.length === 'number');

    if (!offsets.length) return null;

    // Terms are contiguous in the source, so take the first start and the last end.
    const start = offsets[0].start;
    const end = offsets[offsets.length - 1].start + offsets[offsets.length - 1].length;

    if (!(end > start)) return null;
    return { start, end };
  }

  /**
   * Find person names in text without relying on context phrases.
   * @param {string} text
   * @param {Array<{start:number,end:number}>} excludeSpans spans already claimed
   *        by other detectors, so NER never re-reports the same region
   * @returns {Array<{start:number,end:number,text:string,confidence:number}>}
   */
  function findNames(text, excludeSpans) {
    const nlp = global.nlp;
    if (typeof nlp !== 'function' || !text) return [];

    const taken = excludeSpans || [];
    const overlapsTaken = (start, end) =>
      taken.some((s) => start < s.end && end > s.start);

    let out = [];

    try {
      const doc = nlp(text);
      const people = doc.people();

      for (let i = 0; i < people.length; i++) {
        const match = people.eq(i);
        const data = match.json({ offset: true })[0];
        if (!data) continue;

        const span = spanFromTerms(data.terms);
        if (!span) continue;

        // Exact text as it appears in the source, punctuation excluded
        const raw = text.slice(span.start, span.end);
        const words = raw.split(/\s+/).filter(Boolean);

        if (!words.length) continue;
        // Every word in a reported name must look like a name
        if (!words.every(isNamey)) continue;
        // Already claimed by a higher-confidence detector
        if (overlapsTaken(span.start, span.end)) continue;

        out.push({
          start: span.start,
          end: span.end,
          text: raw,
          confidence: words.length > 1 ? 0.9 : 0.75,
        });
      }
    } catch (err) {
      // compromise unavailable or threw — fall back to the gazetteer only
      return dedupe(findGazetteerNames(text, taken));
    }

    // Gazetteer fills the lexicon gaps (e.g. names compromise doesn't know)
    for (const hit of findGazetteerNames(text, taken.concat(out))) {
      out.push(hit);
    }

    return dedupe(out);
  }

  // Keep the longest span when two passes report the same region
  function dedupe(spans) {
    const sorted = spans.slice().sort((a, b) => b.end - b.start - (a.end - a.start));
    const kept = [];
    for (const s of sorted) {
      if (!kept.some((k) => s.start < k.end && s.end > k.start)) kept.push(s);
    }
    return kept.sort((a, b) => a.start - b.start);
  }

  const Ner = { findNames, isNamey, spanFromTerms };
  if (typeof module !== 'undefined' && module.exports) module.exports = Ner;
  global.PFNer = Ner;
})(typeof window !== 'undefined' ? window : globalThis);