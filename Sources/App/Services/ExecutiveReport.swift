import Foundation

/// Renders a scan into a shareable executive report in Markdown — the human-readable
/// counterpart to the JSON / GraphML exports. It folds together everything the engine
/// synthesises: the identity (names, emails, handles, accounts), the attack surface
/// (exposed hosts → ports / CVEs, web-posture grades, subdomains), known breaches and
/// the overall risk. Markdown renders anywhere (GitHub, any viewer) and converts
/// cleanly to PDF/HTML, with no Python/subprocess dependency.
///
/// Pure — built from the synthesized `IdentityProfile` and an `ExposureDiff.Snapshot`,
/// so it unit-tests offline.
enum ExecutiveReport {

    static func markdown(input: String,
                         profile: IdentitySynthesizer.IdentityProfile,
                         surface: ExposureDiff.Snapshot,
                         generatedAt: Date) -> String {
        var out = "# Digital Footprint Report — \(line(input))\n\n"
        out += "- **Generated:** \(readableDate(generatedAt))\n"
        out += "- **Risk:** \(profile.riskLevel) (\(profile.riskScore)/100)\n"
        out += "- **Findings analysed:** \(profile.resultCount)\n\n"

        out += "## Executive summary\n\n\(summary(input: input, profile: profile, surface: surface))\n\n"

        // ── Identity ──────────────────────────────────────────────────────────────
        if profile.likelyName != nil || !profile.emails.isEmpty || !profile.handles.isEmpty
            || !profile.confirmedAccounts.isEmpty || !profile.locations.isEmpty {
            out += "## Identity\n\n"
            if let n = profile.likelyName { out += "- **Likely name:** \(line(n))\n" }
            if profile.names.count > 1 { out += "- **Names seen:** \(joined(profile.names))\n" }
            if !profile.locations.isEmpty { out += "- **Locations:** \(joined(profile.locations))\n" }
            if !profile.organizations.isEmpty { out += "- **Organisations:** \(joined(profile.organizations))\n" }
            if !profile.emails.isEmpty { out += "- **Emails:** \(joined(profile.emails))\n" }
            if !profile.phones.isEmpty { out += "- **Phones:** \(joined(profile.phones))\n" }
            out += "\n"

            if !profile.handles.isEmpty {
                out += "### Handles\n\n| Handle | Platforms | Confidence |\n|---|---|---|\n"
                for h in profile.handles.prefix(25) {
                    out += "| \(cell(h.handle)) | \(cell(h.platforms.joined(separator: ", "))) | \(pct(h.confidence)) |\n"
                }
                out += "\n"
            }
            if !profile.confirmedAccounts.isEmpty {
                out += "### Confirmed accounts\n\n| Platform | Reference | Confidence |\n|---|---|---|\n"
                for a in profile.confirmedAccounts.prefix(40) {
                    out += "| \(cell(a.platform)) | \(cell(a.reference)) | \(pct(a.confidence)) |\n"
                }
                out += "\n"
            }
        }

        // ── Breaches ──────────────────────────────────────────────────────────────
        if !profile.breaches.isEmpty || !profile.exposedDataClasses.isEmpty {
            out += "## Breaches\n\n"
            if !profile.breaches.isEmpty {
                out += profile.breaches.map { "- \(line($0))" }.joined(separator: "\n") + "\n\n"
            }
            if !profile.exposedDataClasses.isEmpty {
                out += "**Exposed data classes:** \(joined(profile.exposedDataClasses))\n\n"
            }
        }

        // ── Exposure timeline ─────────────────────────────────────────────────────
        if !profile.timeline.isEmpty {
            out += "## Exposure timeline\n\n| Date | Event |\n|---|---|\n"
            for e in profile.timeline.prefix(60) {
                out += "| \(cell(e.date)) | \(cell(e.label)) |\n"
            }
            out += "\n"
        }

        // ── Attack surface ────────────────────────────────────────────────────────
        let hostIPs = Set(surface.portsByIP.keys).union(surface.cvesByIP.keys).sorted()
        if !hostIPs.isEmpty || !surface.subdomains.isEmpty || !surface.gradeByDomain.isEmpty {
            out += "## Attack surface\n\n"
            if !hostIPs.isEmpty {
                out += "### Exposed hosts\n\n| Host | Open ports | Known CVEs |\n|---|---|---|\n"
                for ip in hostIPs {
                    let ports = (surface.portsByIP[ip] ?? []).sorted { (Int($0) ?? 0, $0) < (Int($1) ?? 0, $1) }.joined(separator: ", ")
                    let cves = (surface.cvesByIP[ip] ?? []).sorted().joined(separator: ", ")
                    out += "| \(cell(ip)) | \(cell(ports.isEmpty ? "—" : ports)) | \(cell(cves.isEmpty ? "—" : cves)) |\n"
                }
                out += "\n"
            }
            if !surface.gradeByDomain.isEmpty {
                out += "### Web posture\n\n| Domain | Grade |\n|---|---|\n"
                for dom in surface.gradeByDomain.keys.sorted() {
                    out += "| \(cell(dom)) | \(cell(surface.gradeByDomain[dom] ?? "?")) |\n"
                }
                out += "\n"
            }
            if !surface.subdomains.isEmpty {
                out += "### Subdomains (\(surface.subdomains.count))\n\n"
                out += surface.subdomains.sorted().prefix(80).map { "- \(line($0))" }.joined(separator: "\n") + "\n\n"
            }
        }

        out += "---\n_Generated by Digital Footprint Tracker._\n"
        return out
    }

    // MARK: - Summary prose

    private static func summary(input: String,
                                profile: IdentitySynthesizer.IdentityProfile,
                                surface: ExposureDiff.Snapshot) -> String {
        var s = ["**\(line(input))** carries a **\(profile.riskLevel.lowercased())** exposure risk (\(profile.riskScore)/100)."]
        if let n = profile.likelyName { s.append("The most likely identity is **\(line(n))**.") }
        if !profile.confirmedAccounts.isEmpty {
            s.append("\(profile.confirmedAccounts.count) account(s) were confirmed across platforms.")
        }
        if !profile.breaches.isEmpty {
            s.append("The target appears in \(profile.breaches.count) known breach(es): \(joined(profile.breaches.prefix(5).map { $0 })).")
        }
        if !profile.exposedDataClasses.isEmpty {
            s.append("Leaked data categories include \(joined(profile.exposedDataClasses.prefix(6).map { $0 })).")
        }
        let totalPorts = surface.portsByIP.values.reduce(0) { $0 + $1.count }
        let totalCVEs = surface.cvesByIP.values.reduce(0) { $0 + $1.count }
        if totalPorts > 0 || totalCVEs > 0 {
            s.append("Across \(surface.portsByIP.count) host(s), \(totalPorts) open port(s) and \(totalCVEs) known CVE(s) are exposed.")
        }
        if !surface.subdomains.isEmpty { s.append("\(surface.subdomains.count) subdomain(s) were discovered.") }
        if let first = profile.timeline.first { s.append("The earliest dated footprint is from \(line(first.date)).") }
        return s.joined(separator: " ")
    }

    // MARK: - Formatting helpers

    private static func readableDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm 'UTC'"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: date)
    }

    /// Inline text: collapse newlines so a value can't break the document structure.
    private static func line(_ s: String) -> String {
        s.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespaces)
    }

    /// Table-cell text: also escape the pipe that would otherwise split the column.
    private static func cell(_ s: String) -> String {
        line(s).replacingOccurrences(of: "|", with: "\\|")
    }

    private static func joined<S: Sequence>(_ items: S) -> String where S.Element == String {
        items.map(line).joined(separator: ", ")
    }

    private static func pct(_ d: Double) -> String {
        "\(Int((max(0, min(1, d)) * 100).rounded()))%"
    }
}
