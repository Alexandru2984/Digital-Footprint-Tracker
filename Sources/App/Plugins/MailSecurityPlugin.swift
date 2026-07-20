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

    static func analyze(domain: String, _ s: Signals) -> [Finding] {
        var out: [Finding] = []
        let spf = spfPolicy(s.spf)
        let dmarc = dmarcPolicy(s.dmarc)

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
                rawData: "DMARC for \(domain): p=\(dmarc.policy)",
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
    let cacheTTL: TimeInterval = 21_600 // 6 h

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        // Domain targets only. Strip an email local-part so scanning
        // "alice@example.com" still grades example.com.
        var domain = input.lowercased().trimmingCharacters(in: .whitespaces)
        if let at = domain.firstIndex(of: "@") { domain = String(domain[domain.index(after: at)...]) }
        guard domain.contains("."), !domain.contains("@"),
              domain.range(of: #"^[a-z0-9.\-]+$"#, options: .regularExpression) != nil,
              domain.range(of: #"[a-z]"#, options: .regularExpression) != nil,
              domain.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) == nil else { return [] }

        var signals = EmailAuth.Signals()

        // SPF: a v=spf1 TXT at the apex.
        signals.spf = await DoHResolver.resolve(domain, type: "TXT", on: app)
            .first { $0.lowercased().hasPrefix("v=spf1") }

        // DMARC: a v=DMARC1 TXT at _dmarc.<domain>.
        signals.dmarc = await DoHResolver.resolve("_dmarc.\(domain)", type: "TXT", on: app)
            .first { $0.lowercased().hasPrefix("v=dmarc1") }

        // DKIM: probe common selectors concurrently; a hit is a TXT with DKIM markers.
        await withTaskGroup(of: String?.self) { group in
            for sel in EmailAuth.commonDKIMSelectors {
                group.addTask {
                    let recs = await DoHResolver.resolve("\(sel)._domainkey.\(domain)", type: "TXT", on: app)
                    let hit = recs.contains { let l = $0.lowercased(); return l.contains("v=dkim1") || l.contains("k=rsa") || l.contains("p=") }
                    return hit ? sel : nil
                }
            }
            for await sel in group { if let sel { signals.dkimSelectors.append(sel) } }
        }
        signals.dkimSelectors.sort()

        // MTA-STS + TLS-RPT.
        signals.mtaSts = await DoHResolver.resolve("_mta-sts.\(domain)", type: "TXT", on: app)
            .contains { $0.lowercased().hasPrefix("v=stsv1") }
        signals.tlsRpt = await DoHResolver.resolve("_smtp._tls.\(domain)", type: "TXT", on: app)
            .contains { $0.lowercased().hasPrefix("v=tlsrptv1") }

        // DNSSEC (DS present at the parent) + CAA.
        signals.dnssec = !(await DoHResolver.resolve(domain, type: "DS", on: app)).isEmpty
        signals.caa = (await DoHResolver.resolve(domain, type: "CAA", on: app)).compactMap { rec in
            // CAA data looks like `0 issue "letsencrypt.org"`; pull the CA host.
            rec.split(separator: "\"").dropFirst().first.map(String.init)
        }

        return EmailAuth.analyze(domain: domain, signals).map {
            PluginResult(source: name, type: $0.type, confidenceScore: $0.confidence, rawData: $0.rawData, metadata: $0.metadata)
        }
    }
}
