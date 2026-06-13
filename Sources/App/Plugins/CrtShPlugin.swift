import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct CrtShPlugin: FootprintPlugin {
    let name = "CertificateTransparency"
    let description = "Certificate Transparency subdomain enumeration (crt.sh)"
    let cacheTTL: TimeInterval = 14_400 // 4 h

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("."), !input.contains("@"),
              !input.hasPrefix("http") else { return [] }

        let domain = input.lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? input

        guard let url = URL(string: "https://crt.sh/?q=%25.\(domain)&output=json") else { return [] }
        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("DigitalFootprintTracker/1.0", forHTTPHeaderField: "User-Agent")

        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return [] }

        struct CrtEntry: Decodable {
            let name_value: String
        }

        guard let entries = try? JSONDecoder().decode([CrtEntry].self, from: data) else { return [] }

        var seen = Set<String>()
        var results: [PluginResult] = []
        for entry in entries {
            let subdomain = entry.name_value
                .split(separator: "\n").first.map(String.init) ?? entry.name_value
            let cleaned = subdomain.trimmingCharacters(in: .whitespaces)
                .replacingOccurrences(of: "*.", with: "")
            guard !cleaned.isEmpty, cleaned.contains("."), seen.insert(cleaned).inserted else { continue }
            if results.count >= 50 { break }
            results.append(PluginResult(
                source: "crt.sh",
                type: "subdomain",
                confidenceScore: 0.9,
                rawData: cleaned,
                metadata: ["subdomain": cleaned, "domain": domain]
            ))
        }
        return results
    }
}
