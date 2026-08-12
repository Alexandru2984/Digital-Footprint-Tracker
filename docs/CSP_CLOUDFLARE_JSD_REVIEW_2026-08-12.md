# CISO review: CSP-compatible Cloudflare JavaScript Detections

**Date:** 2026-08-12

## Threat model

- Top threat: **DoS** — a discovered origin address bypasses edge mitigation.
  Likelihood: medium; impact: high. JavaScript Detections is useful bot signal,
  but Cloudflare DDoS controls and an origin allowlist are the availability
  boundary.
- **Tampering / elevation of privilege** — weakening `script-src` with
  `unsafe-inline` turns an HTML injection into script execution. Likelihood:
  medium; impact: high.
- **Spoofing** — automated clients evade classification, or JSD produces a
  result that no WAF rule consumes. Likelihood: medium; impact: medium.

## Blast radius

Worst case is public-site unavailability, provider quota exhaustion, or
browser-side access to the authenticated user's visible scan/account data after
a successful XSS. The repository contains no reliable user-count, revenue or
incident-cost inputs, so a defensible FAIR annual-loss estimate cannot be
calculated without inventing data.

## Detection

- Target MTTD for availability attacks: five minutes through edge/origin
  request-rate and target-down alerts.
- Target MTTD for CSP/JSD regression: the deployment smoke test, before rollout
  completion.
- Current residual gap: there is no deployed CSP violation collector/alert;
  browser-console validation remains a release gate rather than continuous
  detection.

## Response

- CSP rollback: documented and automated by the root-owned installer.
- DDoS/origin-bypass incident runbook: not demonstrated.
- Tabletop evidence: not demonstrated.

## Regulatory

The policy change collects no new data and adds no vendor. If a related browser
compromise exposes personal data, GDPR's applicable supervisory-authority
notification deadline is 72 hours after awareness, unless the breach is
unlikely to risk individuals' rights and freedoms.

## Vendors

Cloudflare is an existing trust boundary. No new subprocessor is introduced.
DPA and vendor-review status were not available in the repository and remain an
operational governance check.

## Decision

**MITIGATE THEN SHIP** for the complete production hardening programme; **SHIP**
this narrowly scoped CSP fix after syntax and edge tests pass. Keep JavaScript
Detections, add an unpredictable per-response nonce, retain exact hashes for
application inline scripts, and never allow `script-src 'unsafe-inline'`.
Separately verify that a Cloudflare WAF/bot rule acts on the JSD result, because
signal collection by itself does not block a request.

## Primary references

- [Cloudflare JavaScript Detections and CSP nonces](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)
- [Cloudflare security-feature interoperability and DDoS protection](https://developers.cloudflare.com/waf/feature-interoperability/)
- [nginx `$request_id` (16 random bytes)](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_id)
