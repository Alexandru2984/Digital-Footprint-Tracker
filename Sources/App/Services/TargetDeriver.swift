import Foundation

/// Derives the set of identity candidates to scan from a single validated input.
///
/// The headline case: an email address almost always shares its local-part with
/// the person's username on other platforms (Steam, Reddit, GitHub, the 480-site
/// Sherlock sweep, …). Those plugins gate on `!input.contains("@")`, so scanning
/// an email alone never reaches them. Deriving the local-part as a username
/// candidate closes that gap. A secondary pivot: a username containing a `_`/`-`
/// separator implies sibling handles (`john_doe` → `johndoe`, `john-doe`).
///
/// Each candidate carries an `Origin` that drives how its findings are recorded
/// (confidence discount + provenance note) and whether *heavy* plugins run on it
/// — see `FootprintPlugin.heavy`. This keeps the 480-site sweep bounded to one
/// run even when several candidates are derived.
enum TargetDeriver {

    enum Origin: Sendable, Equatable {
        case primary          // the original input
        case emailLocalPart   // the local-part of an email — a strong inference
        case variant          // a separator/dot variant — a weaker guess
        case pivoted          // an entity discovered by a first-round finding

        var derived: Bool { self != .primary }

        /// Heavy plugins (e.g. the Sherlock sweep) run only on these origins, so
        /// fan-out can't multiply an expensive run across speculative variants or
        /// the second-round pivot set.
        var heavyEligible: Bool { self == .primary || self == .emailLocalPart }

        /// Multiplier applied to a finding's confidence: derived links are real
        /// accounts but inferred ownership.
        var confidenceFactor: Double {
            switch self {
            case .primary:        return 1.0
            case .emailLocalPart: return 0.75
            case .variant:        return 0.6
            case .pivoted:        return 0.6
            }
        }

        /// Prefixed to `rawData` so the provenance is visible in results/exports.
        var note: String? {
            switch self {
            case .primary:        return nil
            case .emailLocalPart: return "[via email local-part]"
            case .variant:        return "[via derived variant]"
            case .pivoted:        return "[via pivot]"
            }
        }
    }

    struct Candidate: Sendable, Equatable {
        let value: String
        let origin: Origin
    }

    /// Local-parts / handles shorter than this are too ambiguous to pivot on.
    private static let minUsernameLength = 3
    /// Hard cap on derived candidates so a pathological input can't fan out.
    private static let maxDerived = 3

    static func candidates(for input: String) -> [Candidate] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        var out: [Candidate] = [Candidate(value: trimmed, origin: .primary)]
        var seen: Set<String> = [trimmed.lowercased()]

        func add(_ value: String, _ origin: Origin) {
            guard out.count <= maxDerived,
                  value.count >= minUsernameLength,
                  value.range(of: "^[a-z0-9._-]+$", options: .regularExpression) != nil,
                  seen.insert(value).inserted
            else { return }
            out.append(Candidate(value: value, origin: origin))
        }

        if let at = trimmed.firstIndex(of: "@") {
            // Email → username from the local-part (drop a "+tag" sub-address).
            let local = String(trimmed[..<at]).lowercased()
            let base = local.split(separator: "+", maxSplits: 1).first.map(String.init) ?? local
            add(base, .emailLocalPart)
            // Dot-stripped variant (Gmail ignores dots): john.doe ↔ johndoe.
            add(base.replacingOccurrences(of: ".", with: ""), .variant)
        } else if !trimmed.contains("."), trimmed.contains("_") || trimmed.contains("-") {
            // Username with a separator → sibling handles. Restricted to `_`/`-`
            // (and no dot) so domains/IPs/emails are never mistaken for usernames.
            let lower = trimmed.lowercased()
            let stripped = lower.replacingOccurrences(of: "_", with: "").replacingOccurrences(of: "-", with: "")
            add(stripped, .variant)
            add(lower.replacingOccurrences(of: "_", with: "-"), .variant)
            add(lower.replacingOccurrences(of: "-", with: "_"), .variant)
        }

        return out
    }
}
