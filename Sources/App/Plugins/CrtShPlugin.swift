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
    let cacheTTL: TimeInterval = 14_400 // 4 h

    private struct CrtEntry: Decodable {
        let name_value: String
        let not_before: String?
        let entry_timestamp: String?
    }

    struct CertificateEvidence: Equatable {
        let hostname: String
        let firstSeen: String?
    }

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("."), !input.contains("@"), !input.hasPrefix("http") else { return [] }
        let domain = Self.normalizeDomain(input)
        return await Self.fetchEvidence(domain: domain, limit: 50, app: app).map { evidence in
            var metadata = ["subdomain": evidence.hostname, "domain": domain]
            metadata["certificateNotBefore"] = evidence.firstSeen
            return PluginResult(
                source: "crt.sh",
                type: "subdomain",
                confidenceScore: 0.9,
                rawData: evidence.hostname,
                metadata: metadata
            )
        }
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
        await fetchEvidence(domain: domain, limit: limit, app: app).map(\.hostname)
    }

    private static func fetchEvidence(domain: String, limit: Int, app: Application) async -> [CertificateEvidence] {
        guard let url = URL(string: "https://crt.sh/?q=%25.\(domain)&output=json") else { return [] }
        guard let resp = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                bodyMode: .complete(maxBytes: 8 * 1_024 * 1_024),
                on: app
              ),
              resp.status == 200 else { return [] }
        return parseEvidence(resp.data, limit: limit, domain: domain)
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
