import Foundation

/// The executive summary's sentences, written once for both report formats.
/// Each renderer passes how it neutralises a remote value (`text`) and how it
/// emphasises one already neutralised (`strong`); the wording cannot drift
/// between the Markdown and the HTML report.
enum ExecutiveSummary {
    static func prose(input: String,
                      profile: IdentitySynthesizer.IdentityProfile,
                      surface: ExposureDiff.Snapshot,
                      text: (String) -> String,
                      strong: (String) -> String) -> String {
        // Item by item, so a separator can never be mistaken for markup.
        func list<S: Sequence>(_ items: S) -> String where S.Element == String {
            items.map(text).joined(separator: ", ")
        }
        var s = ["\(strong(text(input))) carries a \(strong(text(profile.riskLevel.lowercased()))) exposure risk (\(profile.riskScore)/100)."]
        if let n = profile.likelyName { s.append("The most likely identity is \(strong(text(n))).") }
        if !profile.confirmedAccounts.isEmpty {
            s.append("\(profile.confirmedAccounts.count) account(s) were confirmed across platforms.")
        }
        if !profile.breaches.isEmpty {
            s.append("The target appears in \(profile.breaches.count) known breach(es): \(list(profile.breaches.prefix(5))).")
        }
        if !profile.exposedDataClasses.isEmpty {
            s.append("Leaked data categories include \(list(profile.exposedDataClasses.prefix(6))).")
        }
        let totalPorts = surface.portsByIP.values.reduce(0) { $0 + $1.count }
        let totalCVEs = surface.cvesByIP.values.reduce(0) { $0 + $1.count }
        if totalPorts > 0 || totalCVEs > 0 {
            s.append("Across \(surface.portsByIP.count) host(s), \(totalPorts) open port(s) and \(totalCVEs) known CVE(s) are exposed.")
        }
        if !surface.subdomains.isEmpty { s.append("\(surface.subdomains.count) subdomain(s) were discovered.") }
        if let first = profile.timeline.first { s.append("The earliest dated footprint is from \(text(first.date)).") }
        return s.joined(separator: " ")
    }
}
