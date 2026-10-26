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

    /// What each kind of tracking ID is, by its prefix.
    static func trackerLabel(_ id: String) -> String {
        let upper = id.uppercased()
        if upper.hasPrefix("UA-") { return "Google Analytics" }
        if upper.hasPrefix("GTM-") { return "Google Tag Manager" }
        if upper.hasPrefix("G-") { return "Google Analytics 4" }
        if upper.hasPrefix("PUB-") { return "Google AdSense" }
        if upper.hasPrefix("FBPIXEL-") { return "Meta Pixel" }
        return "Tracking"
    }

    /// The analytics and advertising account IDs a page embeds. The same ID on
    /// two sites is one owner's: one Analytics account, one Tag Manager
    /// container, one AdSense publisher (who gets paid), one Meta pixel. An
    /// Analytics property keeps only its account (`UA-123-4` → `UA-123`).
    static func trackingIDs(html: String) -> [String] {
        var found: [String] = []
        func add(_ id: String) { if !found.contains(id) { found.append(id) } }
        for match in html.matches(of: #/\bUA-(\d{4,10})-\d{1,4}\b/#) { add("UA-\(match.output.1)") }
        for match in html.matches(of: #/(?:gtag/js\?id=|['"]config['"]\s*,\s*['"])(G-[A-Z0-9]{6,12})\b/#) {
            add(String(match.output.1))
        }
        for match in html.matches(of: #/\b(GTM-[A-Z0-9]{4,9})\b/#) { add(String(match.output.1)) }
        for match in html.matches(of: #/\b(?:ca-)?pub-(\d{10,20})\b/#) { add("pub-\(match.output.1)") }
        for match in html.matches(of: #/fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]/#) { add("fbpixel-\(match.output.1)") }
        return Array(found.prefix(10))
    }

    static func trackingResult(ids: [String], domain: String) -> PluginResult? {
        guard !ids.isEmpty else { return nil }
        let described = ids.map { "\(trackerLabel($0)) \($0)" }
        return PluginResult(
            source: "SiteMeta", type: "tracking_id", confidenceScore: 0.8,
            rawData: "\(domain) embeds \(described.joined(separator: ", ")): another site with the same ID has the same owner",
            metadata: ["platform": "web", "account": domain, "domain": domain, "ids": ids.joined(separator: ","),
                       "matchKind": "verified", "matchReason": "the website served at this domain",
                       "linked": ids.map { "tracker:\($0)" }.joined(separator: ","), "linkKind": "observed",
                       "linkReason": "the same analytics or advertising account ID, embedded in the site"])
    }

    /// Other sites hackertarget saw with `id`: one per line, the domain first.
    /// Linked only when few share it; an ID on dozens of sites is an agency's
    /// or a platform's, and says nothing about one owner.
    static func sharedTracker(id: String, domain: String, body: String) -> PluginResult? {
        guard !body.contains("API count exceeded"), !body.lowercased().hasPrefix("error") else { return nil }
        var others: [String] = []
        for line in body.split(whereSeparator: \.isNewline) {
            guard let first = line.split(whereSeparator: { $0 == "\t" || $0 == "," }).first else { continue }
            var host = first.trimmingCharacters(in: .whitespaces).lowercased()
            if host.hasPrefix("www.") { host.removeFirst(4) }
            guard host.range(of: #"^[a-z0-9.-]+\.[a-z]{2,}$"#, options: .regularExpression) != nil,
                  host != domain, !host.hasSuffix(".\(domain)"), !domain.hasSuffix(".\(host)"),
                  !others.contains(host) else { continue }
            others.append(host)
        }
        guard !others.isEmpty else { return nil }
        let label = trackerLabel(id)
        var meta = ["platform": "tracker", "username": id, "domain": domain, "domains": others.prefix(25).joined(separator: ",")]
        let raw: String
        if others.count <= 10 {
            meta["linked"] = others.map { "web:\($0)" }.joined(separator: ",")
            meta["linkKind"] = "observed"
            meta["linkReason"] = "the same \(label) ID (\(id)) is embedded there"
            raw = "\(label) \(id) of \(domain) is also on: \(others.joined(separator: ", "))"
        } else {
            raw = "\(label) \(id) of \(domain) is on \(others.count)+ other sites (\(others.prefix(5).joined(separator: ", ")), …):"
                + " an agency's or a platform's ID, not linked"
        }
        return PluginResult(source: "SiteMeta", type: "shared_tracker", confidenceScore: 0.75, rawData: raw, metadata: meta)
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
    let description = "Declared-file recon — security.txt contact, robots.txt paths, homepage owner and tracking IDs"
    /// Fetches a hostname's homepage metadata.
    let accepts: Set<TargetShape> = [.domain]
    let cacheTTL: TimeInterval = 14_400 // 4 h
    /// v2: the homepage's phone (`tel:` links).
    /// v3: analytics and advertising IDs, and the other sites that carry them.
    let cacheVersion = 3

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
           page.status == 200 {
            let html = String(decoding: page.data, as: UTF8.self)
            if let identity = SiteMeta.homepageIdentity(html: html, domain: domain) { out.append(identity) }
            let ids = SiteMeta.trackingIDs(html: html)
            if let tracking = SiteMeta.trackingResult(ids: ids, domain: domain) { out.append(tracking) }
            // Which other sites carry the same IDs: the publisher and Analytics
            // accounts first, the strongest owner ties. Two lookups at most, from
            // a small free daily quota.
            let ordered = ids.filter { $0.hasPrefix("pub-") } + ids.filter { $0.hasPrefix("UA-") }
                + ids.filter { $0.hasPrefix("GTM-") }
            for id in ordered.prefix(2) {
                guard let url = URL(string: "https://api.hackertarget.com/analyticslookup/?q=\(id)"),
                      let response = await PluginHTTP.request(url, timeout: 12, bodyMode: .complete(maxBytes: 128 * 1_024), on: app),
                      response.status == 200 else { continue }
                if let shared = SiteMeta.sharedTracker(id: id, domain: domain, body: String(decoding: response.data, as: UTF8.self)) {
                    out.append(shared)
                }
            }
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
