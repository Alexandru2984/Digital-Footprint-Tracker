import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct CrtShPlugin: FootprintPlugin {
    let name = "CertificateTransparency"
    let description = "Certificate Transparency subdomain enumeration (crt.sh)"
    let cacheTTL: TimeInterval = 14_400 // 4 h

    private struct CrtEntry: Decodable { let name_value: String }

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("."), !input.contains("@"), !input.hasPrefix("http") else { return [] }
        let domain = Self.normalizeDomain(input)
        return await Self.enumerate(domain: domain, limit: 50).map { sub in
            PluginResult(
                source: "crt.sh",
                type: "subdomain",
                confidenceScore: 0.9,
                rawData: sub,
                metadata: ["subdomain": sub, "domain": domain]
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
    static func enumerate(domain: String, limit: Int) async -> [String] {
        guard let url = URL(string: "https://crt.sh/?q=%25.\(domain)&output=json") else { return [] }
        guard let resp = await PluginHTTP.request(url, headers: ["Accept": "application/json"]),
              resp.status == 200 else { return [] }
        return parseSubdomains(resp.data, limit: limit)
    }

    /// Pure: CT-log JSON → unique subdomain hostnames (lowercased, wildcard-stripped).
    /// Reads every SAN line in each `name_value`, not just the first. Unit-testable.
    static func parseSubdomains(_ data: Data, limit: Int) -> [String] {
        guard let entries = try? JSONDecoder().decode([CrtEntry].self, from: data) else { return [] }
        var seen = Set<String>()
        var out: [String] = []
        for entry in entries {
            for piece in entry.name_value.split(separator: "\n") {
                let cleaned = piece.trimmingCharacters(in: .whitespaces)
                    .replacingOccurrences(of: "*.", with: "")
                    .lowercased()
                guard !cleaned.isEmpty, cleaned.contains("."), seen.insert(cleaned).inserted else { continue }
                out.append(cleaned)
                if out.count >= limit { return out }
            }
        }
        return out
    }
}
