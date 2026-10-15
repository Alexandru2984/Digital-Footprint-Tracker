import Vapor
import Foundation

/// Recon over a site's **declared** metadata files — distinct from `ExposedFiles`,
/// which hunts for *leaked* files. Two high-signal, intentionally-public sources:
///
///   • `/.well-known/security.txt` (RFC 9116) — surfaces a domain's security
///     contact / disclosure policy, and signals a mature security program.
///   • `/robots.txt` — the `Disallow` paths a site asks crawlers to skip are a
///     classic recon lead (admin panels, backups, staging), and `Sitemap:` lines
///     enumerate its content map.
///
/// `SiteMeta.*` parsers are pure + unit-testable; the plugin only performs the
/// SSRF-guarded fetches.
enum SiteMeta {
    /// Parse a security.txt body into its contact(s) + expiry. Returns nil if it
    /// isn't a real security.txt (no `Contact:` line, or an HTML error page).
    static func parseSecurityTxt(_ body: String) -> (contacts: [String], expires: String?)? {
        let head = body.prefix(512).lowercased()
        if head.contains("<html") || head.contains("<!doctype") { return nil }
        var contacts: [String] = []
        var expires: String?
        for raw in body.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") || line.isEmpty { continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let field = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if value.isEmpty { continue }
            switch field {
            case "contact": contacts.append(value)
            case "expires": expires = value
            default: break
            }
        }
        return contacts.isEmpty ? nil : (contacts, expires)
    }

    /// Paths a robots.txt asks crawlers to avoid that look security-relevant.
    static let sensitivePattern = #"(?i)/(admin|backup|config|internal|private|staging|dev|db|sql|secret|token|login|wp-admin|phpmyadmin|\.git|\.env|\.svn|cgi-bin|old|test|logs?)"#

    /// Parse robots.txt into (disallowed paths, sitemap URLs), deduped.
    static func parseRobots(_ body: String) -> (disallowed: [String], sitemaps: [String]) {
        let head = body.prefix(512).lowercased()
        if head.contains("<html") || head.contains("<!doctype") { return ([], []) }
        var disallowed: [String] = [], sitemaps: [String] = []
        var seenD = Set<String>(), seenS = Set<String>()
        for raw in body.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") { continue }
            let lc = line.lowercased()
            if lc.hasPrefix("disallow:") {
                let p = line.dropFirst("disallow:".count).trimmingCharacters(in: .whitespaces)
                if !p.isEmpty, p != "/", seenD.insert(p).inserted { disallowed.append(p) }
            } else if lc.hasPrefix("sitemap:") {
                let s = line.dropFirst("sitemap:".count).trimmingCharacters(in: .whitespaces)
                if !s.isEmpty, seenS.insert(s).inserted { sitemaps.append(s) }
            }
        }
        return (disallowed, sitemaps)
    }

    static func interesting(_ paths: [String]) -> [String] {
        paths.filter { $0.range(of: sensitivePattern, options: .regularExpression) != nil }
    }

    /// Who a homepage says runs it: its `rel="me"` links (the IndieWeb way
    /// a site names its owner's accounts), the other profiles it links to,
    /// its contact address and the author it names. A site's own words, so
    /// `declared`; nil when the page says none of it.
    static func homepageIdentity(html: String, domain: String) -> PluginResult? {
        func attribute(_ name: String, in tag: Substring) -> String? {
            guard let range = tag.range(of: #"\#(name)\s*=\s*("[^"]*"|'[^']*')"#, options: [.regularExpression, .caseInsensitive])
            else { return nil }
            let value = tag[range].drop { $0 != "\"" && $0 != "'" }.dropFirst().dropLast()
            return String(value).replacingOccurrences(of: "&amp;", with: "&").trimmingCharacters(in: .whitespaces)
        }
        var tags: [Substring] = []
        var cursor = html.startIndex
        while tags.count < 2_000,
              let range = html.range(of: #"<(a|link|meta)\s[^>]{1,2000}>"#, options: [.regularExpression, .caseInsensitive],
                                     range: cursor..<html.endIndex) {
            tags.append(html[range])
            cursor = range.upperBound
        }

        var proven: [(String, String?)] = []
        var profiles: [(String, String?)] = []
        var email: String?
        var phone: String?
        var author: String?
        for tag in tags {
            if tag.lowercased().hasPrefix("<meta") {
                if attribute("name", in: tag)?.lowercased() == "author",
                   let content = attribute("content", in: tag), content.count <= 80, !content.contains("@") {
                    author = author ?? content
                }
                continue
            }
            guard let href = attribute("href", in: tag) else { continue }
            if href.lowercased().hasPrefix("tel:") {
                phone = phone ?? IdentityLinks.internationalPhone(href)
                continue
            }
            if href.lowercased().hasPrefix("mailto:") {
                let address = String(href.dropFirst(7).split(separator: "?").first ?? "").lowercased()
                if email == nil, address.range(of: #"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"#, options: .regularExpression) != nil {
                    email = address
                }
                continue
            }
            guard let account = IdentityLinks.account(at: href), account.0 != "web" else { continue }
            let rel = attribute("rel", in: tag)?.lowercased().split(separator: " ") ?? []
            if rel.contains("me") { proven.append(account) } else { profiles.append(account) }
        }
        // A page that marks its owner's profiles with rel=me has said which
        // links are its owner's; the rest are anything else it links to.
        let linked = IdentityLinks.linked(Array((proven.isEmpty ? profiles : proven).prefix(12)))
        guard linked != nil || email != nil || phone != nil || author != nil else { return nil }

        var parts = ["Homepage of \(domain)"]
        if let author { parts.append("Author: \(author)") }
        if let email { parts.append("Contact: \(email)") }
        if let phone { parts.append("Phone: \(phone)") }
        if let linked { parts.append("Profiles: " + linked.replacingOccurrences(of: ",", with: ", ")) }
        var meta = ["platform": "web", "account": domain, "domain": domain, "matchKind": "verified",
                    "matchReason": "the website served at this domain"]
        if let author { meta["name"] = author }
        if let email { meta["email"] = email }
        if let phone { meta["phone"] = phone }
        if let linked {
            meta["linked"] = linked
            meta["linkKind"] = proven.isEmpty ? "declared" : "verified"
            meta["linkReason"] = proven.isEmpty ? "linked from the site's homepage"
                : "linked from the site's homepage, marked rel=me as its owner's"
        }
        return PluginResult(source: "SiteMeta", type: "site_identity", confidenceScore: 0.85,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }

    /// Pull a bare email out of a security.txt Contact value (`mailto:x` or `x`).
    static func contactEmail(_ contacts: [String]) -> String? {
        for c in contacts {
            let v = (c.hasPrefix("mailto:") ? String(c.dropFirst(7)) : c).lowercased()
            if v.contains("@"), v.contains("."), !v.contains(" "), !v.contains("/") { return v }
        }
        return nil
    }
}

struct SiteMetaPlugin: FootprintPlugin {
    let name = "SiteMeta"
    let description = "Declared-file recon — security.txt contact + robots.txt sensitive paths"
    /// Fetches a hostname's homepage metadata.
    let accepts: Set<TargetShape> = [.domain]
    let cacheTTL: TimeInterval = 14_400 // 4 h
    /// v2: the homepage's phone (`tel:` links).
    let cacheVersion = 2

    private static let ipv4Pattern = #"^\d{1,3}(\.\d{1,3}){3}$"#

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let domain = CrtShPlugin.normalizeDomain(input)
        guard !domain.contains("@"), domain.contains("."),
              domain.range(of: Self.ipv4Pattern, options: .regularExpression) == nil,
              domain.range(of: #"^[a-z0-9.\-]+$"#, options: .regularExpression) != nil,
              domain.range(of: #"[a-z]"#, options: .regularExpression) != nil else { return [] }

        // One offloaded SSRF check, then fetch with `hostPreChecked` (mirrors
        // ExposedFiles — a blocking resolve must never sit on a cooperative thread).
        let isInternal = await Task.detached { SSRFGuard.resolvesToInternal(domain) }.value
        guard !isInternal else { return [] }

        let base = "https://\(domain)"
        var out: [PluginResult] = []

        func fetch(_ path: String) async -> String? {
            guard let url = URL(string: base + path),
                  let resp = try? await SafeHTTP.get(url: url, timeout: 6, wantBody: true, hostPreChecked: true, on: app),
                  resp.status == 200 || resp.status == 206 else { return nil }
            return resp.bodyPrefix
        }

        // security.txt
        if let body = await fetch("/.well-known/security.txt"), let sec = SiteMeta.parseSecurityTxt(body) {
            var meta = ["domain": domain, "contact": sec.contacts.first ?? ""]
            if let email = SiteMeta.contactEmail(sec.contacts) { meta["email"] = email }
            out.append(PluginResult(
                source: name, type: "security_txt", confidenceScore: 0.7,
                rawData: "security.txt for \(domain): contact \(sec.contacts.prefix(2).joined(separator: ", "))"
                    + (sec.expires.map { " (expires \($0))" } ?? ""),
                metadata: meta))
        }

        // The homepage, whole enough to reach the footer where profiles sit.
        if let url = URL(string: base + "/"),
           let page = try? await OutboundHTTP.request(url, timeout: 8, bodyMode: .prefix(maxBytes: 512 * 1_024),
                                                      maxRedirects: 3, hostPreChecked: true, on: app),
           page.status == 200,
           let identity = SiteMeta.homepageIdentity(html: String(decoding: page.data, as: UTF8.self), domain: domain) {
            out.append(identity)
        }

        // robots.txt
        if let body = await fetch("/robots.txt") {
            let r = SiteMeta.parseRobots(body)
            let hot = SiteMeta.interesting(r.disallowed)
            if !hot.isEmpty {
                out.append(PluginResult(
                    source: name, type: "disallowed_path", confidenceScore: 0.6,
                    rawData: "robots.txt hides sensitive paths on \(domain): \(hot.prefix(8).joined(separator: ", "))",
                    metadata: ["domain": domain, "paths": hot.prefix(15).joined(separator: ",")]))
            }
            for sm in r.sitemaps.prefix(3) {
                out.append(PluginResult(
                    source: name, type: "sitemap", confidenceScore: 0.4,
                    rawData: "Sitemap for \(domain): \(sm)",
                    metadata: ["domain": domain, "url": sm]))
            }
        }
        return out
    }
}
