import Foundation

/// How the identifiers in a scan connect, and how much each connection is
/// worth. Identity synthesis collects names, emails and accounts; this keeps
/// the edges between them, because in OSINT the strength of a link is the
/// finding: "GitHub verified that this address is dtolnay's" is a fact, "an
/// account called dtolnay exists on Steam" is a guess.
///
/// Built from finding metadata:
/// - `queriedAs` / `via` (set by the runner): the identifier a finding was
///   looked up as, and how that identifier was reached;
/// - `matchKind` / `matchReason` (set by a plugin): the platform itself ties
///   the identifier looked up to the account it returned;
/// - `linked` (`platform:value,...`) with `linkKind` / `linkReason`: further
///   accounts the found one points to (Keybase proofs, profile links).
///
/// A finding without `matchKind` connects by name alone and is `inferred`.
enum IdentityLinks {
    enum Kind: String, Codable, Sendable, Comparable {
        /// A platform confirmed the connection (verified email, signed proof,
        /// proven domain).
        case verified
        /// The person published the connection themselves (a profile link).
        case declared
        /// Seen in the account's own activity (author addresses of its commits).
        case observed
        /// Same name or a derived name; nothing confirms it is the same person.
        case inferred

        private var rank: Int {
            switch self {
            case .verified: return 3
            case .declared: return 2
            case .observed: return 1
            case .inferred: return 0
            }
        }
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
    }

    struct Link: Codable, Sendable, Equatable {
        let from: String
        let to: String
        let kind: Kind
        let source: String
        let reason: String
    }

    static let maxLinks = 80
    static let identityTypes: Set<String> = [
        "account_presence", "social_media", "identity_proof", "avatar_presence", "developer_identity", "email"
    ]

    static func build(from inputs: [IdentitySynthesizer.Input], target: String?) -> [Link] {
        var best: [String: Link] = [:]
        var order: [String] = []
        func add(_ link: Link) {
            guard !link.from.isEmpty, !link.to.isEmpty, link.from != link.to else { return }
            let key = "\(link.from)\u{1}\(link.to)"
            if let existing = best[key], existing.kind >= link.kind { return }
            if best[key] == nil { order.append(key) }
            best[key] = link
        }

        for input in inputs where identityTypes.contains(input.type) {
            let meta = input.metadata
            let from = (nonEmpty(meta["queriedAs"]) ?? target ?? "target").lowercased()
            guard let node = node(for: meta, from: from, type: input.type) else { continue }
            let kind = nonEmpty(meta["matchKind"]).flatMap(Kind.init(rawValue:)) ?? .inferred
            let reason = nonEmpty(meta["matchReason"])
                ?? inferredReason(via: meta["via"], platform: nonEmpty(meta["platform"]) ?? input.source)
            add(Link(from: from, to: node, kind: kind, source: input.source, reason: reason))

            let linkKind = nonEmpty(meta["linkKind"]).flatMap(Kind.init(rawValue:)) ?? .declared
            let linkReason = nonEmpty(meta["linkReason"]) ?? "linked from this profile"
            for linked in parseLinked(meta["linked"]) {
                add(Link(from: node, to: linked, kind: linkKind, source: input.source, reason: linkReason))
            }
        }

        return order.compactMap { best[$0] }
            .enumerated()
            .sorted { ($0.element.kind, -$0.offset) > ($1.element.kind, -$1.offset) }
            .prefix(maxLinks)
            .map(\.element)
    }

    /// What a finding connects `from` to: an account (`platform: name`), or
    /// another email address.
    static func node(for meta: [String: String], from: String, type: String = "") -> String? {
        // An address harvested from an account's activity is the thing found.
        if type == "email", let email = nonEmpty(meta["email"])?.lowercased(), email.contains("@"), email != from {
            return email
        }
        if let platform = nonEmpty(meta["platform"]), let username = nonEmpty(meta["username"]) {
            return "\(platform.lowercased()): \(username.lowercased())"
        }
        if let email = nonEmpty(meta["email"])?.lowercased(), email.contains("@"), email != from {
            return email
        }
        return nil
    }

    /// `"github:dtolnay, twitter:@dtolnay"` → `["github: dtolnay", "twitter: dtolnay"]`.
    static func parseLinked(_ raw: String?) -> [String] {
        guard let raw else { return [] }
        return raw.split(separator: ",").compactMap { entry -> String? in
            let parts = entry.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
            var value = parts[1].lowercased()
            if value.hasPrefix("@") { value.removeFirst() }
            return "\(parts[0].lowercased()): \(value)"
        }.prefix(20).map { $0 }
    }

    static func inferredReason(via: String?, platform: String) -> String {
        switch via {
        case "emailLocalPart": return "same name as the email's local part, on \(platform)"
        case "variant": return "a spelling variant of the name exists on \(platform)"
        case "pivot": return "name found while following another lead; exists on \(platform)"
        default: return "same name exists on \(platform); nothing confirms it is the same person"
        }
    }

    /// Builds a `linked` value from platform/value pairs, skipping empties.
    static func linked(_ pairs: [(String, String?)]) -> String? {
        let entries = pairs.compactMap { platform, value -> String? in
            guard let value = nonEmpty(value)?.replacingOccurrences(of: ",", with: " ") else { return nil }
            return "\(platform):\(value)"
        }
        return entries.isEmpty ? nil : entries.joined(separator: ",")
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }
}
