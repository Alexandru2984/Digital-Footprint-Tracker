# Timeline intelligence

The repository exposes a normalized, evidence-aware chronology at
`GET /scans/:scanID/timeline`. The same events remain embedded in the synthesized
identity response for backward-compatible UI and report rendering.

## Evidence adapters

The builder consumes only allow-listed structured metadata:

- account creation dates from GitHub, GitLab, Hacker News, Reddit, Mastodon and
  Steam;
- breach disclosure dates from the HIBP-style `breachDates` field;
- RDAP registration, last-change and expiration events;
- earliest certificate `not_before` date per CT hostname, with the log entry
  timestamp used only when `not_before` is absent; live CT parsing rejects
  malformed and out-of-apex hostnames before downstream surface enumeration;
- first and last Wayback capture days.

Provider timestamps are reduced to valid Gregorian calendar days in UTC. A
four-digit provider year remains year-precision. Invalid dates, dates outside
1970–2100 and unsupported free-form values are dropped. Steam's English
`MMMM d, yyyy` and abbreviated-month equivalent are normalized to ISO days.

## Confidence and conflicts

Events with the same logical identity and normalized date are merged. Their
highest source confidence is retained and distinct-source corroboration adds
`0.05` per extra source, capped at a `0.15` boost and a final confidence of
`1.0`. Repeated observations from one source increase `evidenceCount`, but do
not masquerade as independent corroboration.

If the same logical event is reported on different dates, each dated event is
retained and marked `conflicting`, with up to eight normalized alternatives in
`conflictDates`. The summary reports the number of affected logical groups.
This is an analyst-review signal, not an automatic choice of a winning date.

`breachEventCount` counts distinct dated breach names. `breachRecurrenceCount`
is the number after the first, and `breachYears` reports the distinct affected
years. It measures repeated exposure of the scanned subject; it is not a claim
that two provider records belong to the same underlying breach incident.

## Privacy and resource bounds

The response never copies finding `rawData` or arbitrary metadata. Labels are
assembled from a small allow-list of fields; labels and source identifiers are
control-character stripped and length bounded. The owner/capability rules are
identical to `/identity/:id`, API-key access requires `scans:read`, and all
responses are `no-store`.

Processing is capped at 10,000 findings, 250 breach dates per finding and 5,000
candidate observations. At most 500 chronological events are returned, 12
sources are retained per event and eight alternatives are retained per
conflict. `summary.totalEventCount` and `summary.truncated` disclose output
truncation without exposing dropped evidence.

## UI behavior

The responsive timeline panel displays category, normalized date, confidence,
provenance, observation count and conflict detail. It supports category
filtering and an expand/reduce control. Browser rendering uses DOM `textContent`
for every provider-controlled value and is covered by the DOM-XSS and viewport
quality gate.

## Known limits

This repository stage does not infer historical DNS/BGP ownership, resolve
provider disagreements, preserve full source licensing/freshness provenance, or
compare timeline changes across scans. Those remain separate evidence-history
and provenance work; the current report deliberately avoids inventing dates or
cross-source identity relationships.
