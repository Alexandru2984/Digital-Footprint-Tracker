import Foundation

/// The kind(s) of identifier a scan target looks like.
///
/// Computed once per candidate and matched against each plugin's declared
/// `FootprintPlugin.accepts` set, so the engine never spends a cache round-trip
/// — or a metered API call — running a plugin against an input it structurally
/// cannot act on. Before this existed every plugin ran on every candidate: a
/// two-candidate email scan spent ~50 pointless cache lookups *and* ~50 empty
/// cache writes on the plugins that immediately `return []`, `ShodanPlugin`
/// burned a query on usernames and emails, and scanning a domain fired the
/// 480-site Sherlock username sweep at it.
///
/// Deliberately a **superset** filter: a shape is reported whenever a plugin of
/// that family could plausibly act on the value, and each plugin keeps its own
/// stricter internal guard as the authority (Telegram's 5–32-character rule,
/// the domain regex, the IPv4 check, …). Declaring a shape too broadly costs
/// only the pre-existing no-op; the classifier therefore falls back to *every*
/// shape for anything it cannot categorize, so an unrecognized input can never
/// silently lose coverage.
///
/// Input reaching here has already passed `InputValidator`, whose whitelist is
/// alphanumerics plus `@._+-` — no spaces, no control or shell characters — so
/// these checks can stay simple.
enum TargetShape: String, Sendable, CaseIterable {
    /// `alice@example.com`
    case email
    /// `example.com`, `sub.example.co.uk`
    case domain
    /// `203.0.113.7`
    case ipv4
    /// A bare handle: `alice`, `alice_doe`, `dev-2`
    case username
    /// E.164 or a bare 7–15 digit run: `+40712345678`, `0712345678`
    case phone

    /// Every shape — the protocol default, i.e. "no declared narrowing, run me
    /// on anything" (the behaviour of every plugin before `accepts` existed).
    static let all: Set<TargetShape> = Set(Self.allCases)

    private static let ipv4Pattern = #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#
    private static let phonePattern = #"^\+?[0-9]{7,15}$"#

    /// Classifies `value`. Never returns an empty set: an input matching none of
    /// the rules falls back to `all` so it keeps reaching every plugin.
    static func shapes(of value: String) -> Set<TargetShape> {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return all }

        // An email is only ever an email. `MailSecurityPlugin` grades the domain
        // half of one, so it declares `.email` alongside `.domain` rather than
        // this returning `.domain` here — which would drag all fourteen
        // host-infrastructure plugins onto every email scan.
        if trimmed.contains("@") { return [.email] }

        if matches(trimmed, phonePattern) {
            // A bare digit run is also a legal handle on most platforms, so keep
            // the username family in play. A `+` prefix is not: no username
            // regex in the plugin set admits it.
            return trimmed.hasPrefix("+") ? [.phone] : [.phone, .username]
        }

        if matches(trimmed, ipv4Pattern) { return [.ipv4] }

        // A dotted name with at least one letter is a hostname. Note this
        // deliberately excludes `.username`: a domain is not a plausible handle,
        // and admitting it is what sent the 480-site sweep after `example.com`.
        if trimmed.contains("."), trimmed.range(of: "[a-z]", options: .regularExpression) != nil {
            return [.domain]
        }

        if !trimmed.contains(".") { return [.username] }

        return all
    }

    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: pattern, options: .regularExpression) != nil
    }
}
