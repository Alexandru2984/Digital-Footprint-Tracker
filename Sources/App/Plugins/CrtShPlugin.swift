import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct CrtShPlugin: FootprintPlugin {
    private static let maximumEntries = 10_000
    private static let maximumNamesPerEntry = 250

    let name = "CertificateTransparency"
    let description = "Certificate Transparency subdomain enumeration (crt.sh)"
    /// Certificate transparency is indexed by domain name, not by IP.
    let accepts: Set<TargetShape> = [.domain]
    let cacheTTL: TimeInterval = 14_400 // 4 h
    /// v2: the other domains the same certificates name.
    /// v3: a certificate about to expire without a logged renewal.
    let cacheVersion = 3

    private struct CrtEntry: Decodable {
        let name_value: String
        let not_before: String?
        let not_after: String?
        let entry_timestamp: String?
        let issuer_name: String?
    }

    struct CertificateEvidence: Equatable {
        let hostname: String
        let firstSeen: String?
    }

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("."), !input.contains("@"), !input.hasPrefix("http") else { return [] }
        let domain = Self.normalizeDomain(input)
        let found = await Self.fetchCertificates(domain: domain, limit: 50, app: app)
        var out = found.evidence.map { evidence in
            var metadata = ["subdomain": evidence.hostname, "domain": domain]
            metadata["certificateNotBefore"] = evidence.firstSeen
            return PluginResult(
                source: found.provider,
                type: "subdomain",
                confidenceScore: 0.9,
                rawData: evidence.hostname,
                metadata: metadata
            )
        }
        if let shared = Self.sharedCertificateResult(domain: domain, others: found.coCertified, provider: found.provider) {
            out.append(shared)
        }
        if let expiring = Self.certificateExpiryResult(domain: domain, newest: found.newestExpiry, provider: found.provider) {
            out.append(expiring)
        }
        return out
    }

    /// Days ahead of expiry at which a certificate with no logged successor is
    /// flagged. Automatic renewal (Let's Encrypt, cloud providers) replaces a
    /// certificate about thirty days ahead, so one still newest this close to
    /// its end means renewal has stopped.
    static let expiryWarningDays = 21

    /// When the newest certificate naming `domain` (itself, or a wildcard on
    /// its parent) expires. Nil when no certificate names it.
    static func newestExpiry(_ certificates: [(names: [String], notAfter: String?)], domain: String) -> Date? {
        let host = domain.lowercased()
        let wildcard = host.split(separator: ".").count > 2
            ? "*." + host.split(separator: ".").dropFirst().joined(separator: ".") : nil
        return certificates.compactMap { certificate -> Date? in
            let names = certificate.names.map { $0.lowercased().trimmingCharacters(in: .whitespaces) }
            guard names.contains(host) || (wildcard.map(names.contains) ?? false) else { return nil }
            return certificate.notAfter.flatMap(day)
        }.max()
    }

    /// A finding when the newest certificate for `domain` ends within
    /// `expiryWarningDays`, or ended in the last two weeks (a site that stopped
    /// serving HTTPS long ago is not a renewal to fix).
    static func certificateExpiryResult(domain: String, newest: Date?, provider: String, now: Date = Date()) -> PluginResult? {
        guard let newest else { return nil }
        let days = Int((newest.timeIntervalSince(now) / 86_400).rounded(.down))
        guard (-14...expiryWarningDays).contains(days) else { return nil }
        let date = ISO8601DateFormatter.string(from: newest, timeZone: .gmt, formatOptions: [.withFullDate])
        let raw = days < 0
            ? "The newest TLS certificate for \(domain) expired on \(date), and no renewal has been logged"
            : "The newest TLS certificate for \(domain) expires on \(date) (\(days) day\(days == 1 ? "" : "s")), "
                + "and no renewal has been logged"
        return PluginResult(source: provider, type: "certificate_expiring", confidenceScore: 0.85, rawData: raw,
                            metadata: ["domain": domain, "expires": date, "days": String(days)])
    }

    private static func day(_ value: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        let trimmed = String(value.prefix(19))
        return formatter.date(from: trimmed)
    }

    /// Strips scheme and path down to the bare host.
    static func normalizeDomain(_ input: String) -> String {
        input.lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? input
    }

    /// Fetches and parses CT-log subdomains for a domain (deduped, capped). Network.
    /// Exposed so other infrastructure plugins (e.g. AttackSurface) reuse one
    /// enumerator instead of re-implementing the crt.sh call.
    static func enumerate(domain: String, limit: Int, app: Application) async -> [String] {
        await fetchEvidenceWithProvider(domain: domain, limit: limit, app: app).evidence.map(\.hostname)
    }

    /// crt.sh first; CertSpotter only when crt.sh fails to answer (it serves
    /// 502s for minutes at a time). A crt.sh answer with no certificates is an
    /// answer, not a failure, and is not second-guessed. CertSpotter's free
    /// tier lists only unexpired certificates and allows ten queries an hour,
    /// which is why it is the fallback rather than the source.
    static func fetchEvidenceWithProvider(domain: String, limit: Int, app: Application)
        async -> (evidence: [CertificateEvidence], provider: String) {
        let found = await fetchCertificates(domain: domain, limit: limit, app: app)
        return (found.evidence, found.provider)
    }

    /// What the certificate logs say about a domain.
    struct CertificateFetch {
        /// The subdomains, with when each was first certified.
        let evidence: [CertificateEvidence]
        let provider: String
        /// Other domains named on the same certificates.
        let coCertified: [String]
        /// When the newest certificate naming the domain expires.
        let newestExpiry: Date?
    }

    static func fetchCertificates(domain: String, limit: Int, app: Application) async -> CertificateFetch {
        if let data = await fetchCrtSh(domain: domain, app: app) {
            let entries = (try? JSONDecoder().decode([CrtEntry].self, from: data))?.prefix(maximumEntries) ?? []
            let certificates = entries.map {
                (names: $0.name_value.split(separator: "\n").map(String.init), issuer: $0.issuer_name)
            }
            let expiries = entries.map { (names: $0.name_value.split(separator: "\n").map(String.init), notAfter: $0.not_after) }
            return CertificateFetch(evidence: parseEvidence(data, limit: limit, domain: domain), provider: "crt.sh",
                                    coCertified: coCertified(certificates, domain: domain),
                                    newestExpiry: newestExpiry(expiries, domain: domain))
        }
        var components = URLComponents(string: "https://api.certspotter.com/v1/issuances")
        components?.queryItems = [
            URLQueryItem(name: "domain", value: domain),
            URLQueryItem(name: "include_subdomains", value: "true"),
            URLQueryItem(name: "expand", value: "dns_names"),
        ]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 20,
                bodyMode: .complete(maxBytes: 8 * 1_024 * 1_024), on: app
              ),
              response.status == 200
        else { return CertificateFetch(evidence: [], provider: "crt.sh", coCertified: [], newestExpiry: nil) }
        let issuances = (try? JSONSerialization.jsonObject(with: response.data) as? [[String: Any]]) ?? []
        let certificates = issuances.prefix(maximumEntries).map {
            (names: $0["dns_names"] as? [String] ?? [], issuer: String?.none)
        }
        let expiries = issuances.prefix(maximumEntries).map {
            (names: $0["dns_names"] as? [String] ?? [], notAfter: $0["not_after"] as? String)
        }
        return CertificateFetch(evidence: parseCertSpotter(response.data, limit: limit, domain: domain), provider: "CertSpotter",
                                coCertified: coCertified(certificates, domain: domain),
                                newestExpiry: newestExpiry(expiries, domain: domain))
    }

    /// Names on one certificate were each proved by whoever asked for it, so
    /// another domain on a certificate of `domain` had the same operator when
    /// it was issued. Left out: CDN certificates bundling unrelated customers
    /// (Cloudflare's, or any naming dozens of hosts or several sites), and the
    /// domain's own subdomains and parents. Each other domain by its highest
    /// name seen, the most certified first.
    static func coCertified(_ certificates: [(names: [String], issuer: String?)], domain: String) -> [String] {
        guard let apex = normalizedHostname(domain[...], scopedTo: nil), isApexLike(apex) else { return [] }
        var count: [String: Int] = [:]
        var order: [String] = []
        for certificate in certificates {
            guard certificate.names.count <= 40, !(certificate.issuer ?? "").lowercased().contains("cloudflare") else { continue }
            let names = Set(certificate.names.compactMap { normalizedHostname($0[...], scopedTo: nil) })
            guard !names.contains(where: { $0.hasSuffix("cloudflaressl.com") }) else { continue }
            let foreign = names.filter { $0 != apex && !$0.hasSuffix(".\(apex)") && !apex.hasSuffix(".\($0)") }
            let roots = foreign.filter { name in !foreign.contains { name.hasSuffix(".\($0)") } }
            guard roots.count <= 5 else { continue }
            for root in roots.sorted() {
                if count[root] == nil { order.append(root) }
                count[root, default: 0] += 1
            }
        }
        let all = Set(order)
        return order.filter { name in !all.contains { name.hasSuffix(".\($0)") } }
            .enumerated().sorted { (count[$0.element] ?? 0, -$0.offset) > (count[$1.element] ?? 0, -$1.offset) }
            .map(\.element).prefix(40).map { $0 }
    }

    /// A registrable name, not a subdomain: two labels, or three under a
    /// second-level suffix such as `co.uk`. A subdomain's certificates name its
    /// siblings, which are not other sites.
    static func isApexLike(_ host: String) -> Bool {
        let labels = host.split(separator: ".")
        if labels.count == 2 { return true }
        return labels.count == 3 && labels[2].count == 2
            && ["co", "com", "org", "net", "ac", "gov", "edu", "nom", "ltd", "plc", "or", "ne", "go"].contains(String(labels[1]))
    }

    static func sharedCertificateResult(domain: String, others: [String], provider: String) -> PluginResult? {
        guard !others.isEmpty else { return nil }
        var meta = ["platform": "web", "account": domain, "domain": domain, "domains": others.joined(separator: ","),
                    "matchKind": "verified", "matchReason": "the domain itself"]
        if others.count <= 15 {
            meta["linked"] = others.prefix(10).map { "web:\($0)" }.joined(separator: ",")
            meta["linkKind"] = "observed"
            meta["linkReason"] = "named on the same TLS certificate as \(domain)"
        }
        return PluginResult(
            source: provider, type: "shared_certificate", confidenceScore: 0.8,
            rawData: "Certificates of \(domain) also name \(others.prefix(15).joined(separator: ", "))"
                + (others.count > 15 ? ", …" : "") + ": whoever asked for them controlled both",
            metadata: meta)
    }

    /// CertSpotter issuances: `[{"dns_names": [...], "not_before": "..."}]`.
    /// Same scoping and de-duplication as the crt.sh parser.
    static func parseCertSpotter(_ data: Data, limit: Int, domain: String) -> [CertificateEvidence] {
        guard limit > 0,
              let issuances = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
              let scope = normalizedHostname(domain[...], scopedTo: nil) else { return [] }
        var indexByHostname: [String: Int] = [:]
        var out: [CertificateEvidence] = []
        for issuance in issuances.prefix(maximumEntries) {
            let firstSeen = (issuance["not_before"] as? String).flatMap(TimelineIntelligence.normalizedDate)?.value
            for name in (issuance["dns_names"] as? [String] ?? []).prefix(maximumNamesPerEntry) {
                guard let cleaned = normalizedHostname(name[...], scopedTo: scope) else { continue }
                if let index = indexByHostname[cleaned] {
                    if let firstSeen, out[index].firstSeen.map({ firstSeen < $0 }) ?? true {
                        out[index] = CertificateEvidence(hostname: cleaned, firstSeen: firstSeen)
                    }
                } else if out.count < limit {
                    indexByHostname[cleaned] = out.count
                    out.append(CertificateEvidence(hostname: cleaned, firstSeen: firstSeen))
                }
            }
        }
        return out
    }

    /// nil when crt.sh did not answer; an empty list when it found nothing.
    private static func fetchCrtSh(domain: String, app: Application) async -> Data? {
        guard let url = URL(string: "https://crt.sh/?q=%25.\(domain)&output=json") else { return nil }
        // crt.sh answers a domain it has not queried lately in ~25 s and the
        // same query moments later in under one, from its own cache. The shared
        // 15 s default gave up on the slow first answer every time.
        guard let resp = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                timeout: 30,
                maxRetries: 1,
                bodyMode: .complete(maxBytes: 8 * 1_024 * 1_024),
                on: app
              ),
              resp.status == 200 else { return nil }
        return resp.data
    }

    /// Pure: CT-log JSON → unique subdomain hostnames (lowercased, wildcard-stripped).
    /// Reads every SAN line in each `name_value`, not just the first. Unit-testable.
    static func parseSubdomains(_ data: Data, limit: Int) -> [String] {
        parseEvidence(data, limit: limit).map(\.hostname)
    }

    /// Pure CT-log parser retaining the earliest certificate `not_before` date
    /// for each hostname. `entry_timestamp` is used only as a fallback.
    static func parseEvidence(_ data: Data, limit: Int, domain: String? = nil) -> [CertificateEvidence] {
        guard limit > 0 else { return [] }
        guard let entries = try? JSONDecoder().decode([CrtEntry].self, from: data) else { return [] }
        let scope = domain.flatMap { normalizedHostname($0[...], scopedTo: nil) }
        guard domain == nil || scope != nil else { return [] }
        var indexByHostname: [String: Int] = [:]
        var out: [CertificateEvidence] = []
        for entry in entries.prefix(maximumEntries) {
            let firstSeen = entry.not_before.flatMap(TimelineIntelligence.normalizedDate)?.value
                ?? entry.entry_timestamp.flatMap(TimelineIntelligence.normalizedDate)?.value
            for piece in entry.name_value.split(
                separator: "\n",
                maxSplits: maximumNamesPerEntry - 1
            ) {
                guard let cleaned = normalizedHostname(piece, scopedTo: scope) else { continue }
                if let index = indexByHostname[cleaned] {
                    let current = out[index]
                    if let firstSeen, current.firstSeen.map({ firstSeen < $0 }) ?? true {
                        out[index] = CertificateEvidence(hostname: cleaned, firstSeen: firstSeen)
                    }
                } else if out.count < limit {
                    indexByHostname[cleaned] = out.count
                    out.append(CertificateEvidence(hostname: cleaned, firstSeen: firstSeen))
                }
            }
        }
        return out
    }

    /// CT is untrusted remote input. Keep only syntactically valid DNS names and,
    /// for live enumeration, names inside the requested apex. This prevents a
    /// poisoned response from expanding attack-surface lookups to another domain.
    private static func normalizedHostname(_ raw: Substring, scopedTo domain: String?) -> String? {
        guard raw.utf8.prefix(254).count <= 253 else { return nil }
        var candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if candidate.hasPrefix("*.") { candidate.removeFirst(2) }
        if candidate.hasSuffix(".") { candidate.removeLast() }
        guard candidate.utf8.count <= 253, candidate.contains("."),
              candidate.range(
                of: #"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"#,
                options: .regularExpression
              ) != nil else { return nil }

        if let domain {
            let apex = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard candidate == apex || candidate.hasSuffix(".\(apex)") else { return nil }
        }
        return candidate
    }
}
