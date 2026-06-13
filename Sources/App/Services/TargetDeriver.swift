import Foundation

/// Derives the set of identity candidates to scan from a single validated input.
///
/// The headline case: an email address almost always shares its local-part with
/// the person's username on other platforms (Steam, Reddit, GitHub, the 480-site
/// Sherlock sweep, …). Those plugins gate on `!input.contains("@")`, so scanning
/// an email alone never reaches them. Deriving the local-part as a username
/// candidate closes that gap — the footprint is no longer limited to the handful
/// of email-aware sources.
///
/// Username-shaped candidates are flagged `derived` so the runner can mark their
/// findings as *inferred* (the account certainly exists; that it belongs to the
/// email's owner is a strong-but-unproven link), lowering their confidence and
/// annotating them.
enum TargetDeriver {
    struct Candidate: Sendable, Equatable {
        let value: String
        let derived: Bool
    }

    /// Local-parts shorter than this are too ambiguous to pivot on.
    private static let minUsernameLength = 3

    static func candidates(for input: String) -> [Candidate] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        var out: [Candidate] = [Candidate(value: trimmed, derived: false)]

        // Email → username candidates from the local-part.
        if let at = trimmed.firstIndex(of: "@") {
            let local = String(trimmed[..<at]).lowercased()
            // Drop a "+tag" sub-address suffix (e.g. alice+news → alice).
            let base = local.split(separator: "+", maxSplits: 1).first.map(String.init) ?? local

            var seen = Set<String>()
            // The raw local-part and a dot-stripped variant (Gmail ignores dots,
            // so john.doe and johndoe are the same mailbox and likely handle).
            for variant in [base, base.replacingOccurrences(of: ".", with: "")] {
                guard variant.count >= minUsernameLength,
                      variant.range(of: "^[a-z0-9._-]+$", options: .regularExpression) != nil,
                      seen.insert(variant).inserted
                else { continue }
                out.append(Candidate(value: variant, derived: true))
            }
        }
        return out
    }
}
