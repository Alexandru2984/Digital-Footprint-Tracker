import Foundation

/// The profile at a glance: who the target is, which accounts are theirs by
/// how sure the links make us, what of theirs has leaked and over what span
/// of time. The rest of a report is the evidence for these lines.
enum Dossier {
    struct Entry: Codable, Sendable, Equatable {
        let label: String
        /// 0–100: how likely it is the target's (see `IdentityLinks.attribute`).
        let score: Int
    }

    struct Summary: Codable, Sendable, Equatable {
        let headline: String
        let name: String?
        /// Accounts at least 80% likely the target's.
        let confirmed: [Entry]
        /// 50–79%.
        let probable: [Entry]
        /// Found, but tied to the target by little more than a shared name.
        let unconfirmedCount: Int
        /// Websites and domains at least 50% likely the target's.
        let sites: [Entry]
        let emails: [String]
        let phones: [String]
        let locations: [String]
        let organizations: [String]
        let breachCount: Int
        /// The leaked kinds of data that harm most: passwords, payment and
        /// identity documents, and the like.
        let sensitiveData: [String]
        let latestBreach: String?
        let firstSeen: String?
        let lastSeen: String?

        static var empty: Summary { Dossier.emptySummary }
    }

    static let confirmedScore = 80
    static let emptySummary = Summary(
        headline: "", name: nil, confirmed: [], probable: [], unconfirmedCount: 0, sites: [], emails: [], phones: [],
        locations: [], organizations: [], breachCount: 0, sensitiveData: [], latestBreach: nil, firstSeen: nil, lastSeen: nil)
    static let probableScore = 50
    private static let siteKinds: Set<String> = ["dns", "web", "domain", "generic_web_site"]
    private static let sensitiveMarkers = [
        "password", "credit card", "bank", "financial", "payment", "passport", "social security",
        "government", "national id", "driver", "date of birth", "physical address", "security question",
        "auth token", "health",
    ]

    struct Inputs {
        let name: String?
        let attributions: [IdentityLinks.Attribution]
        let accounts: [IdentitySynthesizer.Account]
        let emails: [String]
        let phones: [String]
        let locations: [String]
        let organizations: [String]
        let breaches: [String]
        let breachTotal: Int
        let dataClasses: [String]
        let breachYears: [String]
        let timelineDates: [String]
    }

    static func summarize(_ input: Inputs) -> Summary {
        var confirmed: [Entry] = []
        var probable: [Entry] = []
        var sites: [Entry] = []
        var unconfirmed = 0
        if input.attributions.isEmpty {
            // A scan from before provenance was recorded: confidence is all there is.
            for account in input.accounts {
                let entry = Entry(label: "\(account.platform.lowercased()): \(account.reference)",
                                  score: Int((account.confidence * 100).rounded()))
                if entry.score >= confirmedScore { confirmed.append(entry) } else { unconfirmed += 1 }
            }
        } else {
            for attribution in input.attributions {
                let parts = attribution.node.split(separator: ":", maxSplits: 1)
                guard parts.count == 2 else { continue } // a bare name or address
                let entry = Entry(label: attribution.node, score: attribution.score)
                if siteKinds.contains(String(parts[0])) {
                    if entry.score >= probableScore { sites.append(entry) }
                } else if entry.score >= confirmedScore {
                    confirmed.append(entry)
                } else if entry.score >= probableScore {
                    probable.append(entry)
                } else {
                    unconfirmed += 1
                }
            }
        }
        let sensitive = input.dataClasses.filter { cls in
            let lower = cls.lowercased()
            return sensitiveMarkers.contains { lower.contains($0) }
        }
        let breachCount = max(input.breachTotal, input.breaches.count)
        let dates = input.timelineDates.sorted()

        var headline = input.name ?? "Unnamed target"
        var clauses: [String] = []
        if !confirmed.isEmpty || !probable.isEmpty {
            var accounts = "\(confirmed.count) confirmed account\(confirmed.count == 1 ? "" : "s")"
            if !probable.isEmpty { accounts += ", \(probable.count) probable" }
            clauses.append(accounts)
        }
        if breachCount > 0 {
            var breaches = "in \(breachCount) breach\(breachCount == 1 ? "" : "es")"
            if !sensitive.isEmpty { breaches += " (\(sensitive.prefix(3).joined(separator: ", ").lowercased()))" }
            clauses.append(breaches)
        }
        if let first = dates.first?.prefix(4), let last = dates.last?.prefix(4) {
            clauses.append(first == last ? "seen in \(first)" : "seen \(first)–\(last)")
        }
        if !clauses.isEmpty { headline += " — " + clauses.joined(separator: "; ") }

        return Summary(
            headline: headline, name: input.name,
            confirmed: Array(confirmed.prefix(40)), probable: Array(probable.prefix(40)), unconfirmedCount: unconfirmed,
            sites: Array(sites.prefix(20)),
            emails: input.emails, phones: input.phones, locations: input.locations, organizations: input.organizations,
            breachCount: breachCount, sensitiveData: sensitive, latestBreach: input.breachYears.max(),
            firstSeen: dates.first, lastSeen: dates.last
        )
    }
}
