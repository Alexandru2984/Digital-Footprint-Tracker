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
        "email", "username", "twitter", "ip", "phone"
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
    /// Attribution an account needs before the accounts and sites it points
    /// to are followed, when the scan's links are known (`context`).
    static let minOwnerAttribution = 80

    /// - Parameters:
    ///   - context: every finding of the scan so far, with provenance; when
    ///     given, an account's links are followed if the account is likely
    ///     the target's by its strongest chain, not only by its own match.
    ///   - target: the scan's input, the origin of that chain.
    static func candidates(
        from results: [PluginResult], alreadyScanned: Set<String>,
        context: [PluginResult] = [], target: String? = nil
    ) -> [String] {
        let attribution: [String: Int]
        if let target, !context.isEmpty {
            let inputs = context.map {
                IdentitySynthesizer.Input(source: $0.source, type: $0.type, confidence: $0.confidenceScore,
                                          metadata: $0.metadata ?? [:], rawData: $0.rawData)
            }
            let links = IdentityLinks.build(from: inputs, target: target.lowercased())
            attribution = Dictionary(IdentityLinks.attribute(links, target: target).map { ($0.node, $0.score) },
                                     uniquingKeysWith: max)
        } else {
            attribution = [:]
        }
        func ownedByTarget(_ meta: [String: String], type: String) -> Bool {
            if let kind = meta["matchKind"].flatMap(IdentityLinks.Kind.init(rawValue:)), kind >= .declared { return true }
            let from = (meta["queriedAs"] ?? target ?? "").lowercased()
            guard let node = IdentityLinks.node(for: meta, from: from, type: type) else { return false }
            return (attribution[node] ?? 0) >= minOwnerAttribution
        }

        var scored: [(value: String, priority: Double)] = []
        var seen = alreadyScanned

        func consider(_ rawValue: String, priority: Double) {
            var value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if value.hasPrefix("@") { value.removeFirst() }
            // A pivot value is a scan target that no user typed: it comes
            // from a third party's page, API response or commit metadata, so
            // it is attacker-controlled in exactly the way `/scan` input is.
            // It therefore goes through the same validator, which enforces
            // the character whitelist, the length cap and the SSRF gate —
            // and, critically, the leading-hyphen rule that exists so a
            // target can never be read as a flag by an argv-based tool.
            // `isScannable` alone permitted `-x@evil.test`, which reached
            // holehe's argv as an option.
            guard value.count >= 3,
                  isScannable(value),
                  let validated = try? InputValidator.validateScanInput(value),
                  validated == value,
                  // A handle that is a name under a shared platform
                  // (`ana.bsky.social`) reads as a domain, but scanning it
                  // describes the platform's servers, not the person.
                  !IdentityLinks.isOnSharedHost(value),
                  // Likewise a CDN's address: it is the provider's machine.
                  !SharedEdge.contains(value),
                  seen.insert(value).inserted
            else { return }
            scored.append((value, priority))
        }

        for result in results {
            guard result.confidenceScore >= minPivotConfidence, let meta = result.metadata else { continue }
            // A value a platform confirmed belongs to the target (a login
            // GitHub tied to a verified email, a second address on the same
            // OpenPGP key) outranks everything; then emails, a far stronger
            // anchor than a bare handle; then confidence.
            let verified = meta["matchKind"] == "verified" || meta["linkKind"] == "verified"
            for (key, rawValue) in meta where pivotKeys.contains(key.lowercased()) {
                // A phone only in international form, and only one not already
                // scanned in another spelling.
                if key.lowercased() == "phone" {
                    guard let phone = IdentityLinks.internationalPhone(rawValue),
                          !seen.contains(where: { $0.filter(\.isNumber) == phone.filter(\.isNumber) }) else { continue }
                    consider(phone, priority: (verified ? 2.0 : 0.0) + result.confidenceScore)
                    continue
                }
                let email = rawValue.trimmingCharacters(in: .whitespaces).dropFirst().contains("@")
                consider(rawValue, priority: (verified ? 2.0 : 0.0) + (email ? 1.0 : 0.0) + result.confidenceScore)
            }
            // What a confirmed account points to: its proven accounts and
            // domains, the website it lists. Only from an account whose own
            // tie to the target is confirmed: a same-name stranger's website
            // would send the scan into someone else's life.
            // A homepage's links are left out: on an employer's site (reached
            // through the address's domain) they are the company's accounts.
            guard result.type != "site_identity", ownedByTarget(meta, type: result.type) else { continue }
            for value in IdentityLinks.pivotableLinks(meta) {
                consider(value, priority: (meta["linkKind"] == "verified" ? 2.0 : 1.0) + result.confidenceScore)
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
