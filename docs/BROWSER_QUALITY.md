# Browser quality and accessibility gate

The frontend has a blocking real-browser gate on every push and pull request.
It runs the exact committed assets in Chromium, against the repository's nginx
Content-Security-Policy, without external network access.

## Coverage

The matrix exercises four viewports:

| Project | Viewport | Purpose |
|---|---:|---|
| `mobile-320` | 320 × 800 | narrow phone and long labels |
| `mobile-375` | 375 × 812 | common touch layout |
| `tablet-768` | 768 × 1024 | breakpoint boundary |
| `desktop-1440` | 1440 × 1000 | wide desktop layout |

Forty generated cases cover the public scanner, login, registration and the
authenticated admin dashboard. The checks enforce:

- axe-core WCAG 2.0/2.1/2.2 A+AA rules on every page and viewport;
- no document-level horizontal overflow or visible element outside the viewport;
- minimum 24 × 24 CSS-pixel mobile targets for visible interactive controls;
- semantic headings, associated form labels and a keyboard-visible skip link;
- visible global focus indication, modal focus entry/trap/return, mobile-menu
  `aria-expanded` state and Escape behavior;
- `prefers-reduced-motion` reducing animations and transitions to effectively
  static behavior;
- production CSP allowing tracked scripts while blocking injected inline code;
- malicious admin-audit and notification fixture values rendering as text;
- no first-party `document.write` sink; investigation reports open through a
  `blob:` URL with `noopener noreferrer`.

The test server derives its CSP from
`ops/nginx/snippets/swift-csp.conf`, serves only repository assets from
loopback, and emits the production security-header shape. API responses are
deterministic local fixtures, so this is a frontend/browser gate rather than a
substitute for the Vapor integration tests.

## Reproducibility and local use

Dependencies are exact lockfile pins:

- `@playwright/test` 1.62.1;
- `@axe-core/playwright` 4.13.0;
- official multi-architecture Playwright image
  `sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e`.

The wrapper drops every Linux capability, enables `no-new-privileges`, mounts
the repository read-only, uses read-only container storage and disables the
container network. Run it with:

```bash
cd frontend
npm ci --ignore-scripts
cd ..
browser_output="$(mktemp -d)"
scripts/run-browser-tests.sh "$browser_output"
```

On failure, screenshots, video, trace and the HTML report are written under the
given output directory. CI uploads that evidence for seven days. Successful
runs do not retain screenshots, avoiding brittle pixel snapshots and user-data
capture.

After changing inline scripts or compiled CSS, rebuild `tailwind.css`, refresh
the admin SRI value and regenerate the exact CSP script hashes. `npm test` and
`scripts/tests/csp-hashes.test.sh` fail on drift.

## Current visual/accessibility changes

- accessible muted-text and green action tokens meet the 4.5:1 small-text ratio;
- 320 px layouts retain the existing compact visual hierarchy without overflow;
- login/register expose real `h1` headings and explicit label associations;
- all primary pages expose skip navigation and keyboard focus that remains
  visible even where older utility classes removed outlines;
- reduced-motion users no longer receive scan loops or long transitions;
- the keyboard-help dialog announces its title and returns focus on close.

## Limits and live acceptance

Automated axe checks find only a subset of accessibility defects. Manual
screen-reader, zoom/reflow, voice-control, high-contrast and cognitive review
remain necessary before claiming complete WCAG conformance.

The repository gate also cannot prove that Cloudflare has injected JavaScript
Detections with the matching nonce or that production nginx serves the accepted
hashes. A live browser run with zero CSP console/report events remains a Phase 0
acceptance item. Inline scripts and `style-src 'unsafe-inline'` also remain to be
eliminated before enabling Trusted Types or claiming a fully static strict CSP.
