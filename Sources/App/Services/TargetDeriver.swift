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
        case emailDomain      // the email's own domain, when it is not a mail provider's
        case variant          // a separator/dot variant — a weaker guess
        case pivoted          // an entity discovered by a first-round finding

        var derived: Bool { self != .primary }

        /// Stable name stored with each finding (`via`), so connections can say
        /// how the identifier that found it was reached.
        var key: String {
            switch self {
            case .primary:        return "input"
            case .emailLocalPart: return "emailLocalPart"
            case .emailDomain:    return "emailDomain"
            case .variant:        return "variant"
            case .pivoted:        return "pivot"
            }
        }

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
            case .emailDomain:    return 0.75
            case .variant:        return 0.6
            case .pivoted:        return 0.6
            }
        }

        /// Prefixed to `rawData` so the provenance is visible in results/exports.
        var note: String? {
            switch self {
            case .primary:        return nil
            case .emailLocalPart: return "[via email local-part]"
            case .emailDomain:    return "[via email domain]"
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
                  // No leading hyphen: derived targets reach the same tools the
                  // validated input does, so they keep the same invariant.
                  value.range(of: "^[a-z0-9._][a-z0-9._-]*$", options: .regularExpression) != nil,
                  seen.insert(value).inserted
            else { return }
            out.append(Candidate(value: value, origin: origin))
        }

        if let at = trimmed.firstIndex(of: "@") {
            // Email → username from the local-part (drop a "+tag" sub-address).
            let local = String(trimmed[..<at]).lowercased()
            let base = local.split(separator: "+", maxSplits: 1).first.map(String.init) ?? local
            add(base, .emailLocalPart)
            // A mailbox on a domain of its own (ana@popescu.ro, or an
            // employer's): the domain's records, registrant and site are about
            // the person or where they work. A mail provider's are not.
            let domain = String(trimmed[trimmed.index(after: at)...]).lowercased()
            if domain.contains("."), !isMailProvider(domain) { add(domain, .emailDomain) }
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

    /// Free mail, ISP and disposable domains: their records describe the
    /// provider, never the person with a mailbox there.
    static func isMailProvider(_ domain: String) -> Bool {
        let host = domain.lowercased()
        if EmailIntelPlugin.disposableDomains.contains(host) { return true }
        if mailProviders.contains(host) { return true }
        // Regional variants: yahoo.co.uk, hotmail.fr, gmx.at, yandex.kz …
        let label = host.split(separator: ".").first.map(String.init) ?? host
        return ["yahoo", "hotmail", "outlook", "live", "gmx", "yandex", "aol", "msn", "libero", "orange", "virgilio"]
            .contains(label)
    }

    private static let mailProviders: Set<String> = [
        "gmail.com", "googlemail.com", "ymail.com", "rocketmail.com", "icloud.com", "me.com", "mac.com",
        "proton.me", "protonmail.com", "protonmail.ch", "pm.me", "tutanota.com", "tutanota.de", "tuta.io",
        "tuta.com", "fastmail.com", "fastmail.fm", "hey.com", "zoho.com", "zohomail.com", "mail.com",
        "email.com", "web.de", "t-online.de", "freenet.de", "posteo.de", "mailbox.org", "ya.ru",
        "mail.ru", "bk.ru", "inbox.ru", "list.ru", "rambler.ru", "qq.com", "163.com", "126.com",
        "sina.com", "naver.com", "daum.net", "rediffmail.com", "free.fr", "laposte.net", "sfr.fr",
        "wanadoo.fr", "seznam.cz", "wp.pl", "o2.pl", "onet.pl", "interia.pl", "btinternet.com",
        "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "cox.net", "charter.net",
        "earthlink.net", "juno.com", "gmx.net", "gmx.com", "skynet.be", "telenet.be", "bluewin.ch",
        "rdslink.ro", "digi.ro", "clicknet.ro", "upcmail.ro", "xnet.ro", "mail.bg", "abv.bg",
        "aim.com", "lycos.com", "inbox.com", "hushmail.com", "disroot.org", "riseup.net",
        "cock.li", "duck.com", "simplelogin.com", "simplelogin.co", "anonaddy.com", "anonaddy.me",
        "privaterelay.appleid.com", "users.noreply.github.com",
    ]
}
