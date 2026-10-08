/**
 * PrivacyFirst — Shared site components
 * Header, footer, active nav, expand-card logic
 */

(function () {
  'use strict';

  // ── Navigation markup ──────────────────────────────────────────────────
  const NAV_HTML = `
<nav class="nav" role="navigation" aria-label="Main navigation">
  <div class="nav-inner">
    <a href="index.html" class="nav-logo">
      <span class="nav-logo-dot"></span>
      PrivacyFirst
    </a>
    <ul class="nav-links" role="list">
      <li><a href="demo.html">Demo</a></li>
      <li><a href="usecases.html">Use Cases</a></li>
      <li><a href="howitworks.html">How It Works</a></li>
      <li><a href="get-started.html">Get Started</a></li>
    </ul>
    <div class="nav-cta">
      <a href="get-started.html">Download</a>
      <a href="demo.html" class="btn btn-primary btn-sm">Try Demo</a>
    </div>
  </div>
</nav>`;

  // ── Footer markup ──────────────────────────────────────────────────────
  const FOOTER_HTML = `
<footer class="footer" role="contentinfo">
  <div class="container">
    <div class="footer-inner">
      <span class="footer-brand">PrivacyFirst</span>
      <ul class="footer-links" role="list">
        <li><a href="index.html">Home</a></li>
        <li><a href="demo.html">Demo</a></li>
        <li><a href="usecases.html">Use Cases</a></li>
        <li><a href="howitworks.html">How It Works</a></li>
        <li><a href="get-started.html">Get Started</a></li>
      </ul>
      <span class="footer-note">Detection runs locally. Nothing leaves your device unsanitized.</span>
    </div>
  </div>
</footer>`;

  // ── Inject nav ─────────────────────────────────────────────────────────
  function injectNav() {
    const placeholder = document.getElementById('nav-placeholder');
    if (!placeholder) return;
    const tmp = document.createElement('div');
    tmp.innerHTML = NAV_HTML;
    placeholder.replaceWith(tmp.firstElementChild);
  }

  // ── Inject footer ──────────────────────────────────────────────────────
  function injectFooter() {
    const placeholder = document.getElementById('footer-placeholder');
    if (!placeholder) return;
    const tmp = document.createElement('div');
    tmp.innerHTML = FOOTER_HTML;
    placeholder.replaceWith(tmp.firstElementChild);
  }

  // ── Mark active nav link ───────────────────────────────────────────────
  function markActiveLink() {
    const page = location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-links a').forEach(a => {
      const href = a.getAttribute('href');
      if (href === page || (page === '' && href === 'index.html')) {
        a.classList.add('active');
      }
    });
  }

  // ── Expand-card accordion ──────────────────────────────────────────────
  function initExpandCards() {
    document.querySelectorAll('.expand-header').forEach(header => {
      header.addEventListener('click', () => {
        const card = header.closest('.expand-card');
        const isOpen = card.classList.contains('open');

        // Close all other cards in the same group
        const group = card.closest('[data-expand-group]');
        if (group) {
          group.querySelectorAll('.expand-card.open').forEach(c => {
            if (c !== card) c.classList.remove('open');
          });
        }

        card.classList.toggle('open', !isOpen);
      });
    });
  }

  // ── Init on DOM ready ──────────────────────────────────────────────────
  function init() {
    injectNav();
    injectFooter();
    markActiveLink();
    initExpandCards();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
