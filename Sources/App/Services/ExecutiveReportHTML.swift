import Foundation

/// Renders a scan into a self-contained, print-ready HTML report — the same content
/// as the Markdown export, styled for the browser's "Save as PDF". This is the
/// server-side report path with no Python/subprocess dependency: one HTML document
/// with embedded CSS that prints to a clean PDF.
///
/// Every interpolated value is HTML-escaped: a scan can contain attacker-influenced
/// strings (names, breach titles, hostnames), so nothing dynamic reaches the markup
/// unescaped. Pure, so it unit-tests offline.
enum ExecutiveReportHTML {

    static func html(input: String,
                     profile: IdentitySynthesizer.IdentityProfile,
                     surface: ExposureDiff.Snapshot,
                     generatedAt: Date) -> String {
        var b = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        b += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        b += "<title>Digital Footprint Report — \(esc(input))</title>\n<style>\(css)</style>\n"
        b += "</head>\n<body>\n<main class=\"report\">\n"

        // Header.
        b += "<header>\n<h1>Digital Footprint Report</h1>\n"
        b += "<div class=\"target\">\(esc(input))</div>\n<div class=\"meta\">"
        b += "<span class=\"risk risk-\(riskClass(profile.riskLevel))\">Risk \(profile.riskScore)/100 · \(esc(profile.riskLevel))</span>"
        b += "<span>Generated \(esc(readableDate(generatedAt)))</span>"
        b += "<span>\(profile.resultCount) findings</span></div>\n</header>\n"

        // Executive summary.
        b += "<section><h2>Executive summary</h2><p>\(summary(input: input, profile: profile, surface: surface))</p></section>\n"

        // Identity.
        if profile.likelyName != nil || !profile.emails.isEmpty || !profile.handles.isEmpty
            || !profile.confirmedAccounts.isEmpty || !profile.locations.isEmpty {
            var s = ""
            if let n = profile.likelyName { s += kv("Likely name", n) }
            if profile.names.count > 1 { s += kv("Names seen", profile.names.joined(separator: ", ")) }
            if !profile.locations.isEmpty { s += kv("Locations", profile.locations.joined(separator: ", ")) }
            if !profile.organizations.isEmpty { s += kv("Organisations", profile.organizations.joined(separator: ", ")) }
            if !profile.emails.isEmpty { s += kv("Emails", profile.emails.joined(separator: ", ")) }
            if !profile.phones.isEmpty { s += kv("Phones", profile.phones.joined(separator: ", ")) }
            if !profile.handles.isEmpty {
                s += "<h3>Handles</h3>"
                s += table(["Handle", "Platforms", "Confidence"], profile.handles.prefix(25).map {
                    [$0.handle, $0.platforms.joined(separator: ", "), pct($0.confidence)]
                })
            }
            if !profile.confirmedAccounts.isEmpty {
                s += "<h3>Confirmed accounts</h3>"
                s += table(["Platform", "Reference", "Confidence"], profile.confirmedAccounts.prefix(40).map {
                    [$0.platform, $0.reference, pct($0.confidence)]
                })
            }
            b += "<section><h2>Identity</h2>\(s)</section>\n"
        }

        // Breaches + leaked data classes.
        if !profile.breaches.isEmpty || !profile.exposedDataClasses.isEmpty {
            var s = ""
            if !profile.breaches.isEmpty { s += list(profile.breaches) }
            if !profile.exposedDataClasses.isEmpty {
                s += kv("Exposed data classes", profile.exposedDataClasses.joined(separator: ", "))
            }
            b += "<section><h2>Breaches</h2>\(s)</section>\n"
        }

        // Attack surface.
        let hostIPs = Set(surface.portsByIP.keys).union(surface.cvesByIP.keys).sorted()
        if !hostIPs.isEmpty || !surface.subdomains.isEmpty || !surface.gradeByDomain.isEmpty {
            var s = ""
            if !hostIPs.isEmpty {
                s += "<h3>Exposed hosts</h3>"
                s += table(["Host", "Open ports", "Known CVEs"], hostIPs.map { ip in
                    let ports = (surface.portsByIP[ip] ?? []).sorted { (Int($0) ?? 0, $0) < (Int($1) ?? 0, $1) }.joined(separator: ", ")
                    let cves = (surface.cvesByIP[ip] ?? []).sorted().joined(separator: ", ")
                    return [ip, ports.isEmpty ? "—" : ports, cves.isEmpty ? "—" : cves]
                })
            }
            if !surface.gradeByDomain.isEmpty {
                s += "<h3>Web posture</h3>"
                s += table(["Domain", "Grade"], surface.gradeByDomain.keys.sorted().map { [$0, surface.gradeByDomain[$0] ?? "?"] })
            }
            if !surface.subdomains.isEmpty {
                s += "<h3>Subdomains (\(surface.subdomains.count))</h3>"
                s += list(surface.subdomains.sorted().prefix(80).map { $0 })
            }
            b += "<section><h2>Attack surface</h2>\(s)</section>\n"
        }

        b += "<footer>Generated by Digital Footprint Tracker.</footer>\n</main>\n</body>\n</html>\n"
        return b
    }

    // MARK: - Summary prose (HTML)

    private static func summary(input: String,
                                profile: IdentitySynthesizer.IdentityProfile,
                                surface: ExposureDiff.Snapshot) -> String {
        var s = ["<strong>\(esc(input))</strong> carries a <strong>\(esc(profile.riskLevel.lowercased()))</strong> exposure risk (\(profile.riskScore)/100)."]
        if let n = profile.likelyName { s.append("The most likely identity is <strong>\(esc(n))</strong>.") }
        if !profile.confirmedAccounts.isEmpty { s.append("\(profile.confirmedAccounts.count) account(s) were confirmed across platforms.") }
        if !profile.breaches.isEmpty {
            s.append("The target appears in \(profile.breaches.count) known breach(es): \(esc(profile.breaches.prefix(5).joined(separator: ", "))).")
        }
        if !profile.exposedDataClasses.isEmpty {
            s.append("Leaked data categories include \(esc(profile.exposedDataClasses.prefix(6).joined(separator: ", "))).")
        }
        let totalPorts = surface.portsByIP.values.reduce(0) { $0 + $1.count }
        let totalCVEs = surface.cvesByIP.values.reduce(0) { $0 + $1.count }
        if totalPorts > 0 || totalCVEs > 0 {
            s.append("Across \(surface.portsByIP.count) host(s), \(totalPorts) open port(s) and \(totalCVEs) known CVE(s) are exposed.")
        }
        if !surface.subdomains.isEmpty { s.append("\(surface.subdomains.count) subdomain(s) were discovered.") }
        return s.joined(separator: " ")
    }

    // MARK: - Markup helpers

    private static func kv(_ label: String, _ value: String) -> String {
        "<div class=\"kv\"><b>\(esc(label)):</b> \(esc(value))</div>"
    }

    private static func list<S: Sequence>(_ items: S) -> String where S.Element == String {
        "<ul>" + items.map { "<li>\(esc($0))</li>" }.joined() + "</ul>"
    }

    private static func table(_ headers: [String], _ rows: [[String]]) -> String {
        var t = "<table><thead><tr>" + headers.map { "<th>\(esc($0))</th>" }.joined() + "</tr></thead><tbody>"
        for row in rows {
            t += "<tr>" + row.map { "<td>\(esc($0))</td>" }.joined() + "</tr>"
        }
        return t + "</tbody></table>"
    }

    private static func riskClass(_ level: String) -> String {
        switch level.lowercased() {
        case "critical": return "critical"
        case "high":     return "high"
        case "medium":   return "medium"
        default:         return "low"
        }
    }

    private static func pct(_ d: Double) -> String { "\(Int((max(0, min(1, d)) * 100).rounded()))%" }

    private static func readableDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm 'UTC'"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: date)
    }

    /// HTML-escape — order matters: ampersand first.
    private static func esc(_ s: String) -> String {
        var out = s.replacingOccurrences(of: "&", with: "&amp;")
        out = out.replacingOccurrences(of: "<", with: "&lt;")
        out = out.replacingOccurrences(of: ">", with: "&gt;")
        out = out.replacingOccurrences(of: "\"", with: "&quot;")
        out = out.replacingOccurrences(of: "'", with: "&#39;")
        return out
    }

    private static let css = """
    :root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#f1f5f9;color:#0f172a;font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
    .report{max-width:880px;margin:24px auto;background:#fff;padding:32px 40px;border:1px solid #e2e8f0;border-radius:12px}
    header{border-bottom:2px solid #0f172a;padding-bottom:16px;margin-bottom:8px}
    h1{font-size:22px;margin:0 0 4px}
    .target{font:600 16px ui-monospace,SFMono-Regular,Menlo,monospace;color:#334155;word-break:break-all}
    .meta{display:flex;flex-wrap:wrap;gap:8px 16px;margin-top:12px;font-size:12px;color:#64748b;align-items:center}
    .risk{font-weight:700;padding:2px 10px;border-radius:6px}
    .risk-low{background:#dcfce7;color:#166534}.risk-medium{background:#fef9c3;color:#854d0e}
    .risk-high{background:#ffedd5;color:#9a3412}.risk-critical{background:#fee2e2;color:#991b1b}
    section{margin:22px 0}h2{font-size:16px;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin:0 0 12px}
    h3{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;margin:16px 0 6px}
    table{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0}
    th,td{text-align:left;padding:6px 10px;border:1px solid #e2e8f0;vertical-align:top;word-break:break-word}
    th{background:#f8fafc;font-weight:600}ul{margin:6px 0;padding-left:20px}.kv{margin:2px 0}.kv b{color:#334155}
    footer{margin-top:28px;padding-top:12px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px}
    @media print{body{background:#fff}.report{border:0;margin:0;max-width:none;padding:0}section,tr{break-inside:avoid}}
    """
}
