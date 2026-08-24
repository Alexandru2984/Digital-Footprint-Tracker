# Route authorization and tenant-isolation gates

The stateless API-key surface is an exact compiled inventory, not a permissive
first-path-segment switch. `APIKeyRoutePolicy.rules` contains one method/path
rule for every route registered by Vapor and assigns one of three reviewed
outcomes:

- public even when a valid API key is present;
- require one named least-privilege API-key scope;
- deny API keys and leave access to the browser-session, administrator,
  capability-token, or metrics-token checks in the endpoint.

Anything without an exact rule becomes `unclassified` and fails closed. The
test `testEveryRegisteredRouteHasAnExplicitAPIKeyPolicy` compares the compiled
table to `app.routes.all`, rejects duplicate rules, and verifies that an unknown
route cannot inherit a broad prefix decision. A route addition, removal, method
change, or path change therefore requires a visible policy-table diff before CI
can pass.

## Cross-tenant property matrix

`testCrossTenantResourceAndCollectionIsolationMatrix` creates a fresh owner and
attacker with randomized resource UUIDs on every run. It issues 37 valid
identifier-bearing probes across GET, POST, PUT, PATCH, and DELETE for scans,
results, streams, reports, legacy and asynchronous exports, identity and diffs,
tags and scan-tag relationships, shares, schedules, notifications, API keys,
investigation boards, and dark-web jobs.

The test requires the endpoint-specific 403 or privacy-preserving 404, rejects
every 2xx response, and then verifies that none of the target rows or
relationships changed. It also reads 11 owner-filtered collection/export paths
as the attacker and rejects any owner sentinel or randomized resource ID in the
response. This covers both direct-object access and list/export leakage.

Anonymous scans and public share tokens remain deliberate capability resources;
they are not mislabeled as tenant-owned rows. The matrix does not replace
PostgreSQL integration checks, proxy tests, or production authorization
monitoring.

## Adding a route

1. Add the Vapor route and its controller-level public/session/admin/owner check.
2. Add one exact `APIKeyRoutePolicy.Rule` with the narrowest applicable scope or
   explicit denial.
3. If it accepts or returns a tenant resource, extend the mutation and/or
   collection matrix with another-account data and post-request invariants.
4. Run the route-policy, API-scope, and cross-tenant tests before committing.
