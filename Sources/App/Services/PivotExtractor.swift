import Foundation

/// Mines first-round findings for *new* identifiers to scan in a second round —
/// the transitive-enrichment pivot. A GitHub profile yields an address harvested
/// from public commit metadata; a Gravatar profile yields a linked Twitter
/// handle; a domain yields the address it resolves to. Those become fresh scan
/// targets. Bounded to one extra round and a small candidate cap so the chain
/// can't explode.
enum PivotExtractor {

    /// Structured-metadata keys whose values are themselves scannable identities.
    ///
    /// Every key here must actually be emitted by a plugin — a test walks the
    /// plugin sources and fails otherwise. Seven platform-named keys (`github`,
    /// `reddit`, `hackernews`, `mastodon`, `gitlab`, `steam`, `telegram`) used
    /// to sit in this set and matched nothing at all: plugins record a platform
    /// hit as `platform` + `username`, so that intent is already served by
    /// `username`, and the extra keys only made the pivot look wider than it was.
    ///
    /// `ip` closes a real gap in the other direction. A scan of a domain resolves
    /// its A records, but the address itself was never scanned, so the IP
    /// reputation plugins — AbuseIPDB, VirusTotal, Shodan — never saw where the
    /// domain actually points.
    private static let pivotKeys: Set<String> = [
        "email", "username", "twitter", "ip"
    ]

    /// Read-only view for the coverage test above; the set itself stays private.
    static var pivotKeysForTesting: Set<String> { pivotKeys }

    /// Hard cap on second-round seeds.
    static let maxPivots = 5

    /// Only pivot on findings the plugin itself is confident about. A weak /
    /// false-positive match (e.g. a Sherlock `status_code` hit at 0.7) would seed
    /// a second-round scan of an unrelated identity and pollute the results with
    /// someone else's footprint — the opposite of what enrichment should do.
    static let minPivotConfidence = 0.8

    /// Returns up to `maxPivots` new identifiers found in `results` that are not
    /// already in `alreadyScanned` (the first-round candidate set, lowercased).
    /// Only high-confidence findings contribute, and stronger anchors win the
    /// limited budget: emails first (a hard identity link), then by confidence.
    static func candidates(from results: [PluginResult], alreadyScanned: Set<String>) -> [String] {
        var scored: [(value: String, priority: Double)] = []
        var seen = alreadyScanned

        for result in results {
            guard result.confidenceScore >= minPivotConfidence, let meta = result.metadata else { continue }
            for (key, rawValue) in meta where pivotKeys.contains(key.lowercased()) {
                var value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if value.hasPrefix("@") { value.removeFirst() }
                guard value.count >= 3, value.count <= 254,
                      isScannable(value),
                      // The same gate the front door applies. Transport-level
                      // SSRF protection would already refuse to fetch a private
                      // address, but a domain whose A record points inside would
                      // still cost a whole pivot round to discover that, and put
                      // internal addressing into the results on the way.
                      !SSRFGuard.isInternalTarget(value),
                      seen.insert(value).inserted
                else { continue }
                // Emails are a far stronger identity anchor than a bare handle on
                // some platform — rank them above handles, then by confidence.
                let priority = (value.contains("@") ? 1.0 : 0.0) + result.confidenceScore
                scored.append((value, priority))
            }
        }
        return scored.sorted { $0.priority > $1.priority }.prefix(maxPivots).map { $0.value }
    }

    /// A bare username/handle, or an email address.
    private static func isScannable(_ value: String) -> Bool {
        value.range(
            of: "^[a-z0-9._%+-]+(@[a-z0-9.-]+\\.[a-z]{2,})?$",
            options: .regularExpression
        ) != nil
    }
}
