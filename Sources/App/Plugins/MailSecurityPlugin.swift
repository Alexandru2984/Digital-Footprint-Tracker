import Vapor
import Foundation

/// Precise email-authentication posture for a domain: can mail *from* this domain
/// be spoofed? A footprint/exposure tool should answer that exactly, not just dump
/// the raw TXT records (which `DomainPlugin` already does). `EmailAuth.analyze` is
/// a pure grader over the DNS signals so the verdict logic is unit-testable; the
/// plugin only performs the (read-only) DNS lookups via `DoHResolver`.
///
/// Checks: SPF policy strength, DMARC enforcement, DKIM presence, MTA-STS + TLS-RPT,
/// DNSSEC, and CAA — each turned into an actionable finding plus one headline
/// "spoofability" grade.
enum EmailAuth {
    struct Signals {
        var spf: String?
        var dmarc: String?
        /// The organizational domain whose DMARC record applies, when the
        /// scanned name has none of its own (RFC 7489 §6.6.3).
        var dmarcInheritedFrom: String?
        var dkimSelectors: [String] = []
        var mtaSts: Bool = false
        var tlsRpt: Bool = false
        var dnssec: Bool = false
        var caa: [String] = []
    }

    struct Finding {
        let type: String
        let confidence: Double
        let rawData: String
        var metadata: [String: String] = [:]
    }

    /// SPF `all` qualifier strength.
    static func spfPolicy(_ record: String?) -> (verdict: String, spoofable: Bool)? {
        guard let r = record?.lowercased() else { return nil }
        if r.contains("-all") { return ("hard fail (-all) — enforced", false) }
        if r.contains("~all") { return ("soft fail (~all) — weak, spoofed mail may still deliver", true) }
        if r.contains("?all") { return ("neutral (?all) — effectively no protection", true) }
        if r.contains("+all") { return ("pass-all (+all) — anyone may send as this domain", true) }
        return ("no explicit `all` — implicit neutral", true)
    }

    /// DMARC policy (`p=`).
    static func dmarcPolicy(_ record: String?) -> (policy: String, enforced: Bool)? {
        guard let r = record?.lowercased() else { return nil }
        // p=… is the first policy tag; sp=… (subdomain) is separate.
        guard let range = r.range(of: #"(^|;)\s*p\s*=\s*(none|quarantine|reject)"#, options: .regularExpression) else {
            return ("present but no p= tag", false)
        }
        let match = String(r[range])
        if match.contains("reject") { return ("reject — fully enforced", true) }
        if match.contains("quarantine") { return ("quarantine — enforced (spam-foldered)", true) }
        return ("none — monitoring only, receivers take no action", false)
    }

    /// A parent's record as it applies to a subdomain: `sp=` when set, else `p=`.
    static func subdomainView(_ record: String) -> String {
        let lower = record.lowercased()
        guard let sp = lower.range(of: #"(^|;)\s*sp\s*=\s*(none|quarantine|reject)"#, options: .regularExpression),
              let value = lower[sp].split(separator: "=").last?.trimmingCharacters(in: .whitespaces) else { return record }
        return lower.replacingOccurrences(of: #"(^|;)\s*p\s*=\s*(none|quarantine|reject)"#,
                                          with: "$1p=\(value)", options: .regularExpression)
    }

    /// The names a subdomain's DMARC falls back to, nearest first, down to two
    /// labels: `a.b.example.com` → `b.example.com`, `example.com`.
    static func dmarcParents(of domain: String) -> [String] {
        let labels = domain.split(separator: ".")
        guard labels.count > 2 else { return [] }
        return (1...(labels.count - 2)).map { labels[$0...].joined(separator: ".") }
    }

    static func analyze(domain: String, _ s: Signals) -> [Finding] {
        var out: [Finding] = []
        let spf = spfPolicy(s.spf)
        let dmarc = dmarcPolicy(s.dmarcInheritedFrom == nil ? s.dmarc : s.dmarc.map(subdomainView))
        let inherited = s.dmarcInheritedFrom.map { " (inherited from \($0))" } ?? ""

        // ── SPF ──
        if let spf {
            out.append(Finding(type: "email_auth_spf", confidence: 0.9,
                rawData: "SPF for \(domain): \(spf.verdict)",
                metadata: ["domain": domain, "spoofable": spf.spoofable ? "yes" : "no", "record": String((s.spf ?? "").prefix(300))]))
        } else {
            out.append(Finding(type: "email_auth_spf_missing", confidence: 0.9,
                rawData: "\(domain) has NO SPF record — sender IPs are unrestricted",
                metadata: ["domain": domain, "spoofable": "yes"]))
        }

        // ── DMARC ──
        if let dmarc {
            out.append(Finding(type: "email_auth_dmarc", confidence: 0.9,
                rawData: "DMARC for \(domain): p=\(dmarc.policy)\(inherited)",
                metadata: ["domain": domain, "enforced": dmarc.enforced ? "yes" : "no", "record": String((s.dmarc ?? "").prefix(300))]))
        } else {
            out.append(Finding(type: "email_auth_dmarc_missing", confidence: 0.9,
                rawData: "\(domain) has NO DMARC record — spoofed mail is not rejected",
                metadata: ["domain": domain, "enforced": "no"]))
        }

        // ── DKIM ──
        if !s.dkimSelectors.isEmpty {
            out.append(Finding(type: "email_auth_dkim", confidence: 0.75,
                rawData: "DKIM configured for \(domain) (selectors: \(s.dkimSelectors.joined(separator: ", ")))",
                metadata: ["domain": domain, "selectors": s.dkimSelectors.joined(separator: ",")]))
        }

        // ── Transport hardening ──
        if s.mtaSts {
            out.append(Finding(type: "email_auth_mta_sts", confidence: 0.7,
                rawData: "\(domain) publishes MTA-STS — inbound mail is forced over TLS",
                metadata: ["domain": domain]))
        }
        if s.dnssec {
            out.append(Finding(type: "dnssec_enabled", confidence: 0.8,
                rawData: "\(domain) is DNSSEC-signed (DS record present)",
                metadata: ["domain": domain]))
        }
        if !s.caa.isEmpty {
            out.append(Finding(type: "dns_caa", confidence: 0.6,
                rawData: "CAA for \(domain): only \(s.caa.joined(separator: ", ")) may issue certificates",
                metadata: ["domain": domain, "cas": s.caa.joined(separator: ",")]))
        }

        // ── Headline spoofability grade ──
        // Distinct types so RiskScorer can treat a spoofable domain as exposure
        // and a locked-down one as a clean (zero-risk) signal.
        let spfStrong = spf?.spoofable == false
        let dmarcStrong = dmarc?.enforced == true
        let grade: String, verdict: String, type: String
        switch (spfStrong, dmarcStrong) {
        case (true, true):
            grade = "A"; type = "email_auth_ok"
            verdict = "hard to spoof (SPF enforced + DMARC enforced)"
        case (true, false), (false, true):
            grade = "C"; type = "email_spoofable"
            verdict = "partially spoofable (one of SPF/DMARC not enforced)"
        default:
            grade = "F"; type = "email_spoofable"
            verdict = "EASILY SPOOFABLE — neither SPF nor DMARC is enforced"
        }
        out.append(Finding(type: type, confidence: 0.9,
            rawData: "Email spoofability for \(domain): grade \(grade) — \(verdict)",
            metadata: ["domain": domain, "grade": grade,
                       "spf_enforced": spfStrong ? "yes" : "no",
                       "dmarc_enforced": dmarcStrong ? "yes" : "no"]))
        return out
    }

    /// DKIM selectors worth probing — the defaults the big providers publish.
    static let commonDKIMSelectors = [
        "google", "default", "selector1", "selector2", "s1", "s2",
        "k1", "mail", "dkim", "mandrill", "mailjet", "zoho", "smtp", "sig1"
    ]
}

struct MailSecurityPlugin: FootprintPlugin {
    let name = "MailSecurity"
    let description = "Email spoofability grade — SPF/DMARC/DKIM/MTA-STS/DNSSEC/CAA"
    /// Grades a domain's mail posture, and strips an email's local-part to reach it.
    let accepts: Set<TargetShape> = [.email, .domain]
    let cacheTTL: TimeInterval = 21_600 // 6 h
    /// v2: a mail provider's domain is not graded for one of its users.
    /// v3: a subdomain without its own DMARC record inherits its parent's.
    let cacheVersion = 3

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        // Domain targets only. Strip an email local-part so scanning
        // "alice@example.com" still grades example.com.
        var domain = input.lowercased().trimmingCharacters(in: .whitespaces)
        if let at = domain.firstIndex(of: "@") {
            domain = String(domain[domain.index(after: at)...])
            // gmail.com's mail policy is Google's, not the person's with a
            // mailbox there: grading it says nothing about them.
            if TargetDeriver.isMailProvider(domain) { return [] }
        }
        guard domain.contains("."), !domain.contains("@"),
              domain.range(of: #"^[a-z0-9.\-]+$"#, options: .regularExpression) != nil,
              domain.range(of: #"[a-z]"#, options: .regularExpression) != nil,
              domain.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) == nil else { return [] }

        var signals = EmailAuth.Signals()

        // Every lookup at once: one after another they cost a scan ~5 s.
        async let spf = DoHResolver.resolve(domain, type: "TXT", on: app)
        async let dmarc = DoHResolver.resolve("_dmarc.\(domain)", type: "TXT", on: app)
        async let mtaSts = DoHResolver.resolve("_mta-sts.\(domain)", type: "TXT", on: app)
        async let tlsRpt = DoHResolver.resolve("_smtp._tls.\(domain)", type: "TXT", on: app)
        async let ds = DoHResolver.resolve(domain, type: "DS", on: app)
        async let caa = DoHResolver.resolve(domain, type: "CAA", on: app)
        // DKIM: probe common selectors; a hit is a TXT with DKIM markers.
        async let dkim: [String] = withTaskGroup(of: String?.self) { group in
            for sel in EmailAuth.commonDKIMSelectors {
                group.addTask {
                    let recs = await DoHResolver.resolve("\(sel)._domainkey.\(domain)", type: "TXT", on: app)
                    let hit = recs.contains { let l = $0.lowercased(); return l.contains("v=dkim1") || l.contains("k=rsa") || l.contains("p=") }
                    return hit ? sel : nil
                }
            }
            var found: [String] = []
            for await sel in group { if let sel { found.append(sel) } }
            return found.sorted()
        }

        // SPF: a v=spf1 TXT at the apex. DMARC: a v=DMARC1 TXT at _dmarc.<domain>.
        signals.spf = await spf.first { $0.lowercased().hasPrefix("v=spf1") }
        signals.dmarc = await dmarc.first { $0.lowercased().hasPrefix("v=dmarc1") }
        if signals.dmarc == nil {
            for parent in EmailAuth.dmarcParents(of: domain).prefix(3) {
                let found = await DoHResolver.resolve("_dmarc.\(parent)", type: "TXT", on: app)
                if let record = found.first(where: { $0.lowercased().hasPrefix("v=dmarc1") }) {
                    signals.dmarc = record
                    signals.dmarcInheritedFrom = parent
                    break
                }
            }
        }
        signals.dkimSelectors = await dkim
        // MTA-STS + TLS-RPT.
        signals.mtaSts = await mtaSts.contains { $0.lowercased().hasPrefix("v=stsv1") }
        signals.tlsRpt = await tlsRpt.contains { $0.lowercased().hasPrefix("v=tlsrptv1") }
        // DNSSEC (DS present at the parent) + CAA.
        signals.dnssec = !(await ds).isEmpty
        signals.caa = (await caa).compactMap { rec in
            // CAA data looks like `0 issue "letsencrypt.org"`; pull the CA host.
            rec.split(separator: "\"").dropFirst().first.map(String.init)
        }

        return EmailAuth.analyze(domain: domain, signals).map {
            PluginResult(source: name, type: $0.type, confidenceScore: $0.confidence, rawData: $0.rawData, metadata: $0.metadata)
        }
    }
}
