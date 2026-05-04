import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct ShodanPlugin: FootprintPlugin {
    let name = "Shodan"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let apiKey = Environment.get("SHODAN_API_KEY"), !apiKey.isEmpty else { return [] }

        let query = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? input
        guard let url = URL(string: "https://api.shodan.io/shodan/host/search?key=\(apiKey)&query=\(query)&minify=true") else { return [] }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue("DigitalFootprintTracker/1.0", forHTTPHeaderField: "User-Agent")

        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let matches = json["matches"] as? [[String: Any]],
              !matches.isEmpty else { return [] }

        var results: [PluginResult] = []
        for match in matches.prefix(10) {
            var parts: [String] = []
            if let ip = match["ip_str"] as? String { parts.append("IP: \(ip)") }
            if let port = match["port"] as? Int { parts.append("Port: \(port)") }
            if let transport = match["transport"] as? String { parts.append(transport.uppercased()) }
            if let org = match["org"] as? String { parts.append("Org: \(org)") }
            if let country = (match["location"] as? [String: Any])?["country_name"] as? String {
                parts.append("Country: \(country)")
            }
            if let vulns = match["vulns"] as? [String: Any], !vulns.isEmpty {
                let cves = vulns.keys.prefix(3).joined(separator: ", ")
                parts.append("CVEs: \(cves)")
            }
            if let product = match["product"] as? String { parts.append("Product: \(product)") }
            if !parts.isEmpty {
                results.append(PluginResult(
                    source: "Shodan",
                    type: "exposed_service",
                    confidenceScore: 0.9,
                    rawData: parts.joined(separator: " | ")
                ))
            }
        }
        return results
    }
}
