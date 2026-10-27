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
        /// 0–1: how much the link is worth as evidence; see `strength(_:via:)`.
        var strength: Double

        init(from: String, to: String, kind: Kind, source: String, reason: String, via: String? = nil) {
            self.from = from
            self.to = to
            self.kind = kind
            self.source = source
            self.reason = reason
            self.strength = IdentityLinks.strength(kind, via: via)
        }
    }

    static let maxLinks = 80
    static let identityTypes: Set<String> = [
        "account_presence", "social_media", "identity_proof", "avatar_presence", "developer_identity", "email",
        "pgp_key_uid", "domain_registrant", "ssh_key_match", "site_identity", "avatar_match",
        "tracking_id", "shared_tracker", "microsoft_tenant", "shared_certificate"
    ]

    static func build(from inputs: [IdentitySynthesizer.Input], target: String?) -> [Link] {
        var best: [String: Link] = [:]
        var order: [String] = []
        func add(_ link: Link) {
            guard !link.from.isEmpty, !link.to.isEmpty, link.from != link.to else { return }
            let key = "\(link.from)\u{1}\(link.to)"
            if let existing = best[key], existing.kind > link.kind
                || (existing.kind == link.kind && existing.strength >= link.strength) { return }
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
            // A same-name edge is worth the same however the name was reached:
            // the derivation has its own edge, and counting it here too would
            // charge for it twice along one chain.
            // A match between two accounts, or the sites an ID is on, says
            // nothing about whose the first one is.
            if !["avatar_match", "shared_tracker"].contains(input.type) {
                add(Link(from: from, to: node, kind: kind, source: input.source, reason: reason))
            }

            let linkKind = nonEmpty(meta["linkKind"]).flatMap(Kind.init(rawValue:)) ?? .declared
            let linkReason = nonEmpty(meta["linkReason"]) ?? "linked from this profile"
            for linked in parseLinked(meta["linked"]) {
                add(Link(from: node, to: linked, kind: linkKind, source: input.source, reason: linkReason))
            }
            for linked in parseLinked(meta["bioLinked"]) {
                add(Link(from: node, to: linked, kind: .declared, source: input.source,
                         reason: "written on this profile (bio or README)"))
            }
            if let site = websiteDomain(meta["blog"]) {
                add(Link(from: node, to: "web: \(site)", kind: .declared, source: input.source,
                         reason: "the website listed on this profile"))
            }
        }

        // The same full name on accounts sharing a handle, on independent
        // platforms, is better evidence than the handle alone. Anchored on the
        // name of an account confirmed to be the target's when there is one,
        // so a stranger's consistent name across sites never counts.
        var named: [(from: String, node: String, name: String, display: String, kind: Kind)] = []
        for input in inputs where identityTypes.contains(input.type) {
            let meta = input.metadata
            let from = (nonEmpty(meta["queriedAs"]) ?? target ?? "target").lowercased()
            guard let name = fullName(meta["name"]), let node = node(for: meta, from: from, type: input.type) else { continue }
            named.append((from, node, name, nonEmpty(meta["name"]) ?? name,
                          nonEmpty(meta["matchKind"]).flatMap(Kind.init(rawValue:)) ?? .inferred))
        }
        let anchored = Set(named.filter { $0.kind > .inferred }.map(\.name))
        let platformsByName = Dictionary(grouping: named, by: \.name)
            .mapValues { Set($0.map { $0.node.split(separator: ":").first.map(String.init) ?? $0.node }) }
        for entry in named where entry.kind == .inferred {
            let corroborated = anchored.isEmpty
                ? (platformsByName[entry.name]?.count ?? 0) >= 2
                : anchored.contains(entry.name)
            guard corroborated else { continue }
            add(Link(from: entry.from, to: entry.node, kind: .inferred, source: "derived",
                     reason: "the same handle and the same full name (\(entry.display)) as on another platform",
                     via: "sameName"))
        }

        // The same picture on two accounts found by the same handle: like the
        // same full name, better evidence than the handle alone, for both.
        for input in inputs where input.type == "avatar_match" {
            guard let first = node(for: input.metadata, from: "") else { continue }
            for end in [first] + parseLinked(input.metadata["linked"]) {
                let reached = order.compactMap { best[$0] }.filter { $0.to == end && $0.kind == .inferred }
                for link in reached {
                    add(Link(from: link.from, to: end, kind: .inferred, source: "derived",
                             reason: "the same handle and the same profile picture as another account found for it",
                             via: "samePicture"))
                }
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
                         reason: "the local part of the email address", via: via))
            case "variant":
                add(Link(from: anchor, to: value, kind: .inferred, source: "derived",
                         reason: "a spelling variant of the name", via: via))
            case "emailDomain":
                add(Link(from: anchor, to: value, kind: .inferred, source: "derived",
                         reason: "the domain of the email address: theirs, or where they work", via: via))
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

        // A pivot the scan followed from a linked account or domain is that
        // account's name or that domain: tie the two, or everything found by
        // the pivot floats unattached.
        // Only an account reached some other way: one found by looking this
        // very name up is what the pivot produced, tied to it by name alone.
        for (value, via) in queried.sorted(by: { $0.key < $1.key }) where via == "pivot" {
            for link in order.compactMap({ best[$0] }) where identifier(of: link.to) == value && link.from != value {
                add(Link(from: link.to, to: value, kind: .verified, source: "derived",
                         reason: "the same identifier, followed as a lead"))
            }
        }

        return order.compactMap { best[$0] }
            .enumerated()
            .sorted { ($0.element.kind, -$0.offset) > ($1.element.kind, -$1.offset) }
            .prefix(maxLinks)
            .map(\.element)
    }

    /// One name per platform, whichever source reported it: the profile
    /// plugins say `twitter` and `devto`, the 480-site sweep "Twitter" and
    /// "DEV Community", Holehe `twitter.com`. Without this one account was
    /// three accounts, three nodes, and a handle "seen on" three platforms.
    static func canonicalPlatform(_ raw: String) -> String {
        var name = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let alias = platformAliases[name] { return alias }
        guard name.contains("."), !name.contains(" ") else { return name }
        // A site named by its domain (Holehe): the name the domain is for.
        for prefix in ["www.", "en.", "m.", "app."] where name.hasPrefix(prefix) { name.removeFirst(prefix.count) }
        if let alias = platformAliases[name] { return alias }
        var labels = name.split(separator: ".").map(String.init)
        if labels.count >= 2 { labels.removeLast() }
        let stem = labels.joined(separator: ".")
        return platformAliases[stem] ?? stem
    }

    private static let platformAliases: [String: String] = [
        "x": "twitter", "x.com": "twitter", "twitter.com": "twitter",
        "dev community": "devto", "dev.to": "devto", "dev": "devto",
        "docker hub": "dockerhub", "hub.docker.com": "dockerhub",
        "hacker news": "hackernews", "news.ycombinator.com": "hackernews",
        "steam community (user)": "steam", "steamcommunity.com": "steam",
        "npmjs.com": "npm", "npmjs": "npm", "pypi.org": "pypi",
        "crates.io": "crates.io", "crates": "crates.io",
        "keybase.io": "keybase", "t.me": "telegram", "bsky.app": "bluesky", "bsky": "bluesky",
        "lobste.rs": "lobsters", "lobste": "lobsters", "mastodon.social": "mastodon",
        "linktr.ee": "linktree", "linktr": "linktree", "hugging face": "huggingface", "huggingface.co": "huggingface",
        // Other Mastodon instances hold other accounts: they keep their name.
        "mastodon.cloud": "mastodon.cloud", "mastodon.xyz": "mastodon.xyz",
        "github.com": "github", "gitlab.com": "gitlab", "codeberg.org": "codeberg",
        // A proven domain (Keybase's `dns`, `generic_web_site`) is the same site a
        // profile lists: one node.
        "dns": "web", "generic_web_site": "web",
    ]

    /// What a finding connects `from` to: an account (`platform: name`), or
    /// another email address.
    static func node(for meta: [String: String], from: String, type: String = "") -> String? {
        // An address harvested from an account's activity is the thing found.
        if type == "email", let email = nonEmpty(meta["email"])?.lowercased(), email.contains("@"), email != from {
            return email
        }
        if let platform = nonEmpty(meta["platform"]), let username = nonEmpty(meta["username"]) ?? nonEmpty(meta["account"]) {
            return "\(canonicalPlatform(platform)): \(username.lowercased())"
        }
        if let email = nonEmpty(meta["email"])?.lowercased(), email.contains("@"), email != from {
            return email
        }
        return nil
    }

    /// Platforms whose linked value is a domain, and those whose value is a
    /// handle worth scanning by name.
    static let domainPlatforms: Set<String> = ["dns", "generic_web_site", "web"]
    static let handlePlatforms: Set<String> = [
        "github", "twitter", "reddit", "hackernews", "gitlab", "linktree", "instagram", "tiktok", "youtube", "twitch",
        "substack",
    ]

    /// The scannable identifier behind a `platform: value` node: the domain
    /// for a website or proven domain, the handle for an account on a
    /// platform people reuse names across. Nil for anything else.
    static func identifier(of node: String) -> String? {
        let parts = node.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2 else { return node.contains("@") ? node : nil }
        if domainPlatforms.contains(parts[0]) { return websiteDomain(parts[1]) }
        return handlePlatforms.contains(parts[0]) && !parts[1].contains("@") ? parts[1] : nil
    }

    /// What an account points to that is worth scanning next: proven accounts
    /// and domains from `linked`, and the domain of the website it lists.
    static func pivotableLinks(_ meta: [String: String]) -> [String] {
        var values = (parseLinked(meta["linked"]) + parseLinked(meta["bioLinked"])).compactMap(identifier(of:))
        if let site = websiteDomain(meta["blog"]) { values.append(site) }
        return values
    }

    /// A phone number in international form (`+` and digits), or nil when it
    /// is not one: a national number cannot be scanned without guessing its
    /// country. `00` is the international prefix written out.
    static func internationalPhone(_ raw: String?) -> String? {
        guard var text = nonEmpty(raw) else { return nil }
        if text.lowercased().hasPrefix("tel:") { text.removeFirst(4) }
        text = text.trimmingCharacters(in: .whitespaces)
        let international = text.hasPrefix("+") || text.hasPrefix("00")
        var digits = text.filter(\.isNumber)
        if text.hasPrefix("00") { digits.removeFirst(2) }
        guard international, (8...15).contains(digits.count), !digits.hasPrefix("0"),
              text.allSatisfy({ $0.isNumber || " +-.()/".contains($0) }) else { return nil }
        return "+" + digits
    }

    /// Hosts where a website is a page on someone else's platform: scanning
    /// the domain would describe the platform, not the person.
    static let sharedHosts: [String] = [
        "github.com", "github.io", "gitlab.com", "gitlab.io", "codeberg.org", "codeberg.page", "bitbucket.org",
        "twitter.com", "x.com", "linkedin.com", "facebook.com", "instagram.com", "youtube.com", "youtu.be",
        "tiktok.com", "twitch.tv", "reddit.com", "medium.com", "substack.com", "dev.to", "hashnode.dev",
        "t.me", "bsky.app", "bsky.social", "mastodon.social", "keybase.io", "google.com", "blogspot.com",
        "wordpress.com", "tumblr.com", "linktr.ee", "about.me", "notion.site", "vercel.app", "netlify.app",
        "huggingface.co", "hf.co", "hf.space",
        "pages.dev", "herokuapp.com", "stackoverflow.com", "npmjs.com", "pypi.org", "crates.io", "docs.rs",
        "docker.com", "sourceforge.net", "wikipedia.org", "carrd.co", "wixsite.com", "squarespace.com",
        // Invites, tip jars, stores and short links: pages on others' sites.
        "discord.gg", "discord.com", "patreon.com", "ko-fi.com", "buymeacoffee.com", "paypal.me", "paypal.com",
        "amazon.com", "amzn.to", "bit.ly", "spotify.com", "apple.com", "soundcloud.com", "snapchat.com",
        "threads.net", "pinterest.com", "linkin.bio", "beacons.ai", "solo.to", "wattpad.com", "leetcode.com",
        "codeforces.com", "gravatar.com", "lichess.org", "speedrun.com",
    ]

    /// The account or site a profile link stands for: `github.com/ana` is
    /// the GitHub account `ana`, `bsky.app/profile/ana.dev` the Bluesky handle,
    /// `social.example/@ana` a Mastodon account; any other page, its domain.
    /// Nil for a link that is neither (a post, a search, plain http).
    static func account(at link: String) -> (String, String?)? {
        guard let url = URLComponents(string: link.trimmingCharacters(in: .whitespaces)), url.scheme == "https",
              let host = url.host?.lowercased() else { return nil }
        let bare = host.hasPrefix("www.") || host.hasPrefix("m.") ? String(host.split(separator: ".", maxSplits: 1)[1]) : host
        let path = url.path.split(separator: "/").map(String.init)
        func name(_ index: Int, dropping prefix: String = "") -> String? {
            guard path.count > index else { return nil }
            var value = path[index]
            if !prefix.isEmpty {
                guard value.hasPrefix(prefix) else { return nil }
                value.removeFirst(prefix.count)
            }
            return value.range(of: #"^[A-Za-z0-9_.-]{1,64}$"#, options: .regularExpression) != nil ? value : nil
        }
        let firstSegment: [String: String] = [
            "github.com": "github", "gitlab.com": "gitlab", "codeberg.org": "codeberg", "twitter.com": "twitter",
            "x.com": "twitter", "keybase.io": "keybase", "instagram.com": "instagram", "facebook.com": "facebook",
            "twitch.tv": "twitch", "news.ycombinator.com": "hackernews", "t.me": "telegram", "tiktok.com": "tiktok",
            "linktr.ee": "linktree", "huggingface.co": "huggingface", "gravatar.com": "gravatar",
        ]
        switch bare {
        case _ where firstSegment[bare] != nil:
            let reserved: Set<String> = ["orgs", "sponsors", "settings", "search", "explore", "topics", "home",
                                         "intent", "share", "i", "hashtag", "p", "reel", "watch", "groups",
                                         "sharer", "sharer.php", "dialog", "plugins", "login", "signup", "about",
                                         "features", "pricing", "join", "tos", "privacy", "policies", "legal",
                                         "datasets", "spaces", "models", "docs", "blog", "papers", "collections", "posts",
                                         "avatar"]
            guard let first = path.first, !reserved.contains(first.lowercased()) else { return nil }
            let handle = name(0).map { $0.hasPrefix("@") ? String($0.dropFirst()) : $0 } ?? name(0, dropping: "@")
            return handle.map { (firstSegment[bare] ?? bare, $0) }
        case "linkedin.com": return path.first == "in" ? name(1).map { ("linkedin", $0) } : nil
        case "reddit.com": return ["user", "u"].contains(path.first ?? "") ? name(1).map { ("reddit", $0) } : nil
        case "bsky.app": return path.first == "profile" ? name(1).map { ("bluesky", $0) } : nil
        case "youtube.com": return name(0, dropping: "@").map { ("youtube", $0) }
        case "npmjs.com": return name(0, dropping: "~").map { ("npm", $0) }
        case "leetcode.com": return path.first == "u" ? name(1).map { ("leetcode", $0) } : nil
        case "codeforces.com": return path.first == "profile" ? name(1).map { ("codeforces", $0) } : nil
        case "wattpad.com": return path.first == "user" ? name(1).map { ("wattpad", $0) } : nil
        case "lichess.org": return path.first == "@" ? name(1).map { ("lichess", $0) } : nil
        case "speedrun.com": return path.first == "users" ? name(1).map { ("speedrun", $0) } : nil
        case "substack.com": return name(0, dropping: "@").map { ("substack", $0) }
        default:
            // A Mastodon-style profile on any instance: https://instance/@name.
            // Medium, Substack and the like use the same shape for their own users.
            let shared = bare != "mastodon.social" && sharedHosts.contains { bare == $0 || bare.hasSuffix(".\($0)") }
            if path.count == 1, !shared, let user = name(0, dropping: "@") {
                // The instance this app looks people up on names them without it.
                return ("mastodon", bare == "mastodon.social" ? user : "\(user)@\(bare)")
            }
            return websiteDomain(link).map { ("web", $0) }
        }
    }

    /// Whether `host` is, or sits under, one of the shared platforms.
    static func isOnSharedHost(_ host: String) -> Bool {
        let lower = host.lowercased()
        guard lower.contains("."), !lower.contains("@") else { return false }
        return sharedHosts.contains { lower == $0 || lower.hasSuffix(".\($0)") }
    }

    /// The domain a profile's website lives on, without `www.`; nil when it
    /// is not a domain or sits on a shared platform.
    static func websiteDomain(_ raw: String?) -> String? {
        guard let raw = nonEmpty(raw), raw.count <= 512 else { return nil }
        let url = raw.contains("://") ? raw : "https://\(raw)"
        guard var host = URLComponents(string: url)?.host?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")),
              host.range(of: #"^[a-z0-9.-]+\.[a-z]{2,}$"#, options: .regularExpression) != nil else { return nil }
        if host.hasPrefix("www.") { host.removeFirst(4) }
        guard host.contains("."), !sharedHosts.contains(where: { host == $0 || host.hasSuffix(".\($0)") }) else { return nil }
        return host
    }

    /// `"github:dtolnay, twitter:@dtolnay"` → `["github: dtolnay", "twitter: dtolnay"]`.
    static func parseLinked(_ raw: String?) -> [String] {
        guard let raw else { return [] }
        return raw.split(separator: ",").compactMap { entry -> String? in
            let parts = entry.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
            var value = parts[1].lowercased()
            if value.hasPrefix("@") { value.removeFirst() }
            // An address is its own node, however it was found.
            if parts[0].lowercased() == "email" { return value.contains("@") ? value : nil }
            return "\(canonicalPlatform(parts[0])): \(value)"
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
        var seen: Set<String> = []
        let unique = entries.filter { seen.insert($0.lowercased()).inserted }
        return unique.isEmpty ? nil : unique.joined(separator: ",")
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }

    // MARK: - Attribution

    /// How likely an identifier is to belong to the target, and the chain of
    /// links that says so.
    struct Attribution: Codable, Sendable, Equatable {
        let node: String
        /// 0–100: the product of the link strengths along the strongest chain.
        let score: Int
        /// The chain from the target to `node`, both ends included.
        let path: [String]
    }

    /// How much one link is worth. A shared name is weak evidence on its own,
    /// and how the name was reached matters: the local part of an email is a
    /// better guess than a spelling variant.
    static func strength(_ kind: Kind, via: String?) -> Double {
        switch kind {
        case .verified: return 0.98
        case .declared: return 0.9
        case .observed: return 0.8
        case .inferred:
            switch via {
            case "emailLocalPart": return 0.55
            // A mailbox there shows a tie to the domain, not who holds it.
            case "emailDomain": return 0.55
            case "variant": return 0.35
            // The handle and a full name, both matching another platform's.
            case "sameName": return 0.7
            // The handle and a picture, both matching another account found for it.
            case "samePicture": return 0.7
            default: return 0.4
            }
        }
    }

    /// A display name specific enough to tell people apart: two or more words
    /// of letters, folded for comparison. Nil for a bare handle or initials.
    static func fullName(_ raw: String?) -> String? {
        guard let raw = nonEmpty(raw), raw.count <= 80 else { return nil }
        let words = raw.lowercased().split(whereSeparator: { $0.isWhitespace })
            .map { $0.filter(\.isLetter) }.filter { !$0.isEmpty }
        guard words.count >= 2, words.allSatisfy({ $0.count >= 2 }) else { return nil }
        return words.joined(separator: " ")
    }

    /// The strongest chain from `target` to every identifier the links reach.
    /// "Same person" is symmetric, so links are walked both ways; the best
    /// chain maximises the product of strengths (Dijkstra over −log).
    static func attribute(_ links: [Link], target: String) -> [Attribution] {
        let origin = target.lowercased()
        var adjacency: [String: [(String, Double)]] = [:]
        for link in links {
            let weight = link.strength
            adjacency[link.from, default: []].append((link.to, weight))
            adjacency[link.to, default: []].append((link.from, weight))
        }
        guard adjacency[origin] != nil else { return [] }

        var best: [String: Double] = [origin: 1]
        var previous: [String: String] = [:]
        var settled: Set<String> = []
        while let (current, score) = best.filter({ !settled.contains($0.key) }).max(by: { $0.value < $1.value }) {
            settled.insert(current)
            for (next, weight) in adjacency[current] ?? [] where !settled.contains(next) {
                let candidate = score * weight
                if candidate > (best[next] ?? 0) {
                    best[next] = candidate
                    previous[next] = current
                }
            }
        }

        return best.filter { $0.key != origin }.map { node, score in
            var path = [node]
            while let step = previous[path[0]] { path.insert(step, at: 0) }
            return Attribution(node: node, score: Int((score * 100).rounded()), path: path)
        }
        .sorted { ($0.score, $1.node) > ($1.score, $0.node) }
    }
}
