import Foundation

/// Mines first-round findings for *new* identifiers to scan in a second round —
/// the transitive-enrichment pivot. A GitHub username yields a commit email; a
/// Gravatar profile yields a linked Twitter handle; those become fresh scan
/// targets. Bounded to one extra round and a small candidate cap so the chain
/// can't explode.
enum PivotExtractor {

    /// Structured-metadata keys whose values are themselves scannable identities.
    private static let pivotKeys: Set<String> = [
        "email", "username", "twitter", "github", "reddit",
        "hackernews", "mastodon", "gitlab", "steam", "telegram"
    ]

    /// Hard cap on second-round seeds.
    static let maxPivots = 5

    /// Returns up to `maxPivots` new identifiers found in `results` that are not
    /// already in `alreadyScanned` (the first-round candidate set, lowercased).
    static func candidates(from results: [PluginResult], alreadyScanned: Set<String>) -> [String] {
        var out: [String] = []
        var seen = alreadyScanned

        for result in results {
            guard let meta = result.metadata else { continue }
            for (key, rawValue) in meta where pivotKeys.contains(key.lowercased()) {
                var value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if value.hasPrefix("@") { value.removeFirst() }
                guard value.count >= 3, value.count <= 254,
                      isScannable(value),
                      seen.insert(value).inserted
                else { continue }
                out.append(value)
                if out.count >= maxPivots { return out }
            }
        }
        return out
    }

    /// A bare username/handle, or an email address.
    private static func isScannable(_ value: String) -> Bool {
        value.range(
            of: "^[a-z0-9._%+-]+(@[a-z0-9.-]+\\.[a-z]{2,})?$",
            options: .regularExpression
        ) != nil
    }
}
