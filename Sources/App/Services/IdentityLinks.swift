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

        // Connect the identifiers the scan looked things up as. Without these
        // edges a derived name ("dtolnay" from dtolnay@gmail.com) or a pivot
        // floats unattached: its accounts are drawn, but not how the scan got
        // to it.
        let anchor = (target ?? "target").lowercased()
        var queried: [String: String] = [:]
        for input in inputs {
            guard let value = nonEmpty(input.metadata["queriedAs"])?.lowercased(), value != anchor else { continue }
            queried[value] = queried[value] ?? nonEmpty(input.metadata["via"]) ?? "input"
        }
        for (value, via) in queried.sorted(by: { $0.key < $1.key }) {
            switch via {
            case "emailLocalPart":
                add(Link(from: anchor, to: value, kind: .inferred, source: "derived",
                         reason: "the local part of the email address"))
            case "variant":
                add(Link(from: anchor, to: value, kind: .inferred, source: "derived",
                         reason: "a spelling variant of the name"))
            default:
                break
            }
            // An account whose own tie to the target is confirmed, and whose
            // username this is: the strongest reason the name belongs here, and
            // how a pivot was reached. An account tied only by its name (found
            // by looking this very name up, or with no recorded provenance)
            // confirms nothing; counting it would dress a guess as a fact.
            for input in inputs where identityTypes.contains(input.type) {
                let meta = input.metadata
                guard let matchKind = nonEmpty(meta["matchKind"]).flatMap(Kind.init(rawValue:)),
                      matchKind != .inferred,
                      nonEmpty(meta["queriedAs"])?.lowercased() != value,
                      nonEmpty(meta["username"])?.lowercased() == value,
                      let owner = node(for: meta, from: nonEmpty(meta["queriedAs"])?.lowercased() ?? anchor, type: input.type),
                      owner != value else { continue }
                add(Link(from: owner, to: value, kind: .verified, source: input.source,
                         reason: "the username of this account"))
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
