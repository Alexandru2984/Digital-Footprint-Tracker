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

    /// The dossier lines: who, which accounts are theirs, what leaked, when.
    static func glance(_ dossier: Dossier.Summary) -> String {
        var out = "## At a glance\n\n**\(line(dossier.headline))**\n\n"
        func entries(_ list: [Dossier.Entry]) -> String {
            list.prefix(25).map { "\(line($0.label)) (\($0.score)%)" }.joined(separator: ", ")
        }
        if !dossier.confirmed.isEmpty { out += "- **Confirmed accounts (80%+):** \(entries(dossier.confirmed))\n" }
        if !dossier.probable.isEmpty { out += "- **Probable accounts (50–79%):** \(entries(dossier.probable))\n" }
        if dossier.unconfirmedCount > 0 {
            out += "- **Unconfirmed:** \(dossier.unconfirmedCount) more found by name alone\n"
        }
        if !dossier.sites.isEmpty { out += "- **Sites and domains:** \(entries(dossier.sites))\n" }
        if !dossier.emails.isEmpty { out += "- **Emails:** \(joined(dossier.emails))\n" }
        if !dossier.phones.isEmpty { out += "- **Phones:** \(joined(dossier.phones))\n" }
        if !dossier.locations.isEmpty { out += "- **Locations:** \(joined(dossier.locations))\n" }
        if !dossier.organizations.isEmpty { out += "- **Organisations:** \(joined(dossier.organizations))\n" }
        if dossier.breachCount > 0 {
            var leak = "\(dossier.breachCount) breach\(dossier.breachCount == 1 ? "" : "es")"
            if let latest = dossier.latestBreach { leak += ", latest \(latest)" }
            if !dossier.sensitiveData.isEmpty { leak += "; leaked: \(joined(dossier.sensitiveData))" }
            out += "- **Exposure:** \(line(leak))\n"
        }
        return out + "\n"
    }

    static func markdown(input: String,
                         profile: IdentitySynthesizer.IdentityProfile,
                         surface: ExposureDiff.Snapshot,
                         generatedAt: Date,
                         unavailableSources: [String] = []) -> String {
        var out = "# Digital Footprint Report — \(line(input))\n\n"
        out += "- **Generated:** \(readableDate(generatedAt))\n"
        out += "- **Risk:** \(profile.riskLevel) (\(profile.riskScore)/100)\n"
        if let factors = ExecutiveSummary.riskFactors(profile.riskFactors, text: line) {
            out += "- **Risk made of:** \(factors)\n"
        }
        out += "- **Findings analysed:** \(profile.resultCount)\n\n"
        if let notice = ExecutiveSummary.unavailableNotice(unavailableSources, text: line) {
            out += "> **\(notice)**\n\n"
        }

        out += glance(profile.dossier)
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
                out += "### Accounts found\n\n| Platform | Reference | Confidence |\n|---|---|---|\n"
                for a in profile.confirmedAccounts.prefix(40) {
                    out += "| \(cell(a.platform)) | \(cell(a.reference)) | \(pct(a.confidence)) |\n"
                }
                out += "\n"
            }
        }

        // ── Attribution ───────────────────────────────────────────────────────────
        let owned = profile.attributions.filter { $0.node.contains(": ") || $0.node.contains("@") }
        if !owned.isEmpty {
            out += "## Whose accounts these are\n\n| Account | Likely the target's | Strongest chain |\n|---|---|---|\n"
            for attribution in owned.prefix(40) {
                out += "| \(cell(attribution.node)) | \(attribution.score)% | \(cell(attribution.path.joined(separator: " → "))) |\n"
            }
            out += "\n"
        }

        // ── Connections ───────────────────────────────────────────────────────────
        if !profile.links.isEmpty {
            out += "## How these are connected\n\n| From | To | Strength | Why |\n|---|---|---|---|\n"
            for link in profile.links.prefix(60) {
                out += "| \(cell(link.from)) | \(cell(link.to)) | \(link.kind.rawValue) | \(cell("\(link.reason) (\(link.source))")) |\n"
            }
            out += "\n"
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
        ExecutiveSummary.prose(input: input, profile: profile, surface: surface,
                               text: line, strong: { "**\($0)**" })
    }

    // MARK: - Formatting helpers

    private static func readableDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm 'UTC'"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: date)
    }

    /// Inline text: collapse newlines and neutralise both raw HTML and Markdown
    /// punctuation. Report values come from remote OSINT sources, so they must be
    /// treated as plain text even when the exported file is opened by a renderer
    /// that supports embedded HTML, images, or links.
    private static func line(_ s: String) -> String {
        let singleLine = s
            .split(whereSeparator: \.isNewline)
            .joined(separator: " ")
            .trimmingCharacters(in: .whitespaces)

        var escaped = singleLine.replacingOccurrences(of: "&", with: "&amp;")
        escaped = escaped.replacingOccurrences(of: "<", with: "&lt;")
        escaped = escaped.replacingOccurrences(of: ">", with: "&gt;")
        escaped = escaped.replacingOccurrences(of: "\\", with: "\\\\")
        for character in ["`", "*", "_", "{", "}", "[", "]", "(", ")", "!", "|"] {
            escaped = escaped.replacingOccurrences(of: character, with: "\\" + character)
        }
        return escaped
    }

    /// `line` already escapes pipes, so table values cannot create extra cells.
    private static func cell(_ s: String) -> String {
        line(s)
    }

    private static func joined<S: Sequence>(_ items: S) -> String where S.Element == String {
        items.map(line).joined(separator: ", ")
    }

    private static func pct(_ d: Double) -> String {
        "\(Int((max(0, min(1, d)) * 100).rounded()))%"
    }
}
