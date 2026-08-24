import Vapor

/// Exact, deny-by-default authorization inventory for stateless API keys.
///
/// Every registered route must have one rule. `AppTests` compares this table to
/// Vapor's live route inventory, so adding or changing an endpoint fails CI
/// until its API-key exposure is reviewed explicitly.
enum APIKeyRoutePolicy {
    enum Decision: Equatable, Sendable {
        case allowPublic
        case require(APIKey.Scope)
        case deny
        case unclassified
    }

    struct Rule: Sendable {
        let method: HTTPMethod
        let path: [String]
        let decision: Decision

        init(_ method: HTTPMethod, _ path: String, _ decision: Decision) {
            self.method = method
            self.path = path.split(separator: "/").map(String.init)
            self.decision = decision
        }

        var fingerprint: String {
            "\(method.rawValue) /\(path.joined(separator: "/"))"
        }

        func matches(method candidateMethod: HTTPMethod, path candidatePath: [String]) -> Bool {
            guard method == candidateMethod, path.count == candidatePath.count else { return false }
            return zip(path, candidatePath).allSatisfy { expected, actual in
                expected.hasPrefix(":") || expected == "*" || expected == actual
            }
        }
    }

    // Keep this table in the same order as `Run routes` to make reviews and
    // diffs readable. A valid key sent to a browser-only endpoint is denied;
    // callers without API-key authorization continue to the controller's
    // normal public/session/admin/owner checks.
    static let rules: [Rule] = [
        Rule(.GET, "/", .allowPublic),
        Rule(.GET, "/openapi.yaml", .allowPublic),
        Rule(.POST, "/scan", .require(.scansWrite)),
        Rule(.GET, "/results/:id", .require(.scansRead)),
        Rule(.GET, "/stream/:id", .require(.scansRead)),
        Rule(.GET, "/plugins", .allowPublic),
        Rule(.GET, "/stats", .require(.scansRead)),

        Rule(.POST, "/auth/register", .deny),
        Rule(.POST, "/auth/login", .deny),
        Rule(.POST, "/auth/reauth", .deny),
        Rule(.POST, "/auth/logout", .deny),
        Rule(.GET, "/auth/me", .require(.scansRead)),
        Rule(.GET, "/auth/verify-email", .deny),
        Rule(.POST, "/auth/resend-verification", .deny),
        Rule(.POST, "/auth/webhook", .deny),
        Rule(.POST, "/auth/retention", .deny),
        Rule(.PATCH, "/auth/settings", .deny),
        Rule(.POST, "/auth/notifications/test", .deny),
        Rule(.POST, "/auth/2fa/setup", .deny),
        Rule(.POST, "/auth/2fa/enable", .deny),
        Rule(.POST, "/auth/2fa/disable", .deny),
        Rule(.POST, "/auth/2fa/verify", .deny),

        Rule(.GET, "/my-scans", .require(.scansRead)),
        Rule(.GET, "/admin/scans", .deny),
        Rule(.GET, "/report/:id", .require(.scansRead)),
        Rule(.GET, "/admin/dashboard", .deny),
        Rule(.GET, "/admin/audit", .deny),
        Rule(.GET, "/admin/audit/integrity", .deny),
        Rule(.GET, "/admin/notification-deliveries", .deny),
        Rule(.POST, "/admin/notification-deliveries/:id/retry", .deny),

        Rule(.GET, "/export/:id", .require(.scansRead)),
        Rule(.GET, "/export/:id/graph", .require(.scansRead)),
        Rule(.GET, "/export/:id/report", .require(.scansRead)),
        Rule(.GET, "/export/:id/report.html", .require(.scansRead)),
        Rule(.POST, "/export-jobs", .require(.scansRead)),
        Rule(.GET, "/export-jobs", .require(.scansRead)),
        Rule(.GET, "/export-jobs/:id", .require(.scansRead)),
        Rule(.GET, "/export-jobs/:id/manifest", .require(.scansRead)),
        Rule(.GET, "/export-jobs/:id/download", .require(.scansRead)),
        Rule(.POST, "/export-jobs/:id/cancel", .require(.scansRead)),

        Rule(.GET, "/tags", .require(.scansRead)),
        Rule(.POST, "/tags", .require(.scansWrite)),
        Rule(.DELETE, "/tags/:id", .require(.scansWrite)),
        Rule(.GET, "/tags/:id/scans", .require(.scansRead)),
        Rule(.POST, "/scans/:scanID/tags/:tagID", .require(.scansWrite)),
        Rule(.DELETE, "/scans/:scanID/tags/:tagID", .require(.scansWrite)),
        Rule(.GET, "/scans/:scanID/tags", .require(.scansRead)),

        Rule(.GET, "/scheduled-scans", .require(.automationRead)),
        Rule(.POST, "/scheduled-scans", .require(.automationWrite)),
        Rule(.DELETE, "/scheduled-scans/:id", .require(.automationWrite)),
        Rule(.PATCH, "/scheduled-scans/:id/toggle", .require(.automationWrite)),
        Rule(.GET, "/correlations", .require(.scansRead)),
        Rule(.GET, "/identity/:id", .require(.scansRead)),
        Rule(.GET, "/scans/:scanID/timeline", .require(.scansRead)),
        Rule(.GET, "/scans/:scanID/diff/:otherId", .require(.scansRead)),
        Rule(.GET, "/scans/:scanID/exposure-diff", .require(.scansRead)),

        Rule(.GET, "/notifications", .require(.automationRead)),
        Rule(.POST, "/notifications/:id/read", .require(.automationWrite)),
        Rule(.POST, "/notifications/read-all", .require(.automationWrite)),
        Rule(.GET, "/auth/api-keys", .deny),
        Rule(.POST, "/auth/api-keys", .deny),
        Rule(.DELETE, "/auth/api-keys/:id", .deny),

        Rule(.GET, "/health", .allowPublic),
        Rule(.GET, "/ready", .deny),
        Rule(.GET, "/metrics", .deny),
        Rule(.POST, "/geolocate", .allowPublic),
        Rule(.POST, "/scans/:scanID/share", .require(.scansWrite)),
        Rule(.GET, "/scans/:scanID/shares", .require(.scansRead)),
        Rule(.DELETE, "/shares/:shareID", .require(.scansWrite)),
        Rule(.GET, "/share/:token", .allowPublic),
        Rule(.POST, "/share", .allowPublic),
        Rule(.POST, "/share/:token", .allowPublic),
        Rule(.POST, "/scan/bulk", .require(.scansWrite)),

        Rule(.GET, "/account/export", .deny),
        Rule(.DELETE, "/account", .deny),
        Rule(.GET, "/investigations", .require(.investigationsRead)),
        Rule(.POST, "/investigations", .require(.investigationsWrite)),
        Rule(.GET, "/investigations/index", .require(.investigationsRead)),
        Rule(.GET, "/investigations/:id", .require(.investigationsRead)),
        Rule(.PUT, "/investigations/:id", .require(.investigationsWrite)),
        Rule(.DELETE, "/investigations/:id", .require(.investigationsWrite)),
        Rule(.PUT, "/investigations/:id/watch", .require(.investigationsWrite)),

        Rule(.GET, "/dark-web/status", .deny),
        Rule(.GET, "/dark-web/investigations", .deny),
        Rule(.POST, "/dark-web/investigations", .deny),
        Rule(.GET, "/dark-web/investigations/:id", .deny),
        Rule(.POST, "/dark-web/investigations/:id/cancel", .deny),
        Rule(.DELETE, "/dark-web/investigations/:id", .deny),
    ]

    static var reviewedRouteFingerprints: [String] {
        rules.map(\.fingerprint)
    }

    static func decision(method: HTTPMethod, pathComponents: [String]) -> Decision {
        rules.first { $0.matches(method: method, path: pathComponents) }?.decision
            ?? .unclassified
    }
}
