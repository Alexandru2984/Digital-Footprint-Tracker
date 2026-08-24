import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct ShodanPlugin: FootprintPlugin {
    let name = "Shodan"
    let description = "Exposed ports and services (requires API key)"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let apiKey = try RuntimeSecret.value("SHODAN_API_KEY"), !apiKey.isEmpty else { return [] }

        let query = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? input
        guard let url = URL(string: "https://api.shodan.io/shodan/host/search?key=\(apiKey)&query=\(query)&minify=true") else { return [] }

        guard let resp = await PluginHTTP.request(url, on: app), resp.status == 200,
              let json = try? JSONSerialization.jsonObject(with: resp.data) as? [String: Any],
              let matches = json["matches"] as? [[String: Any]],
              !matches.isEmpty else { return [] }

        var results: [PluginResult] = []
        for match in matches.prefix(10) {
            var parts: [String] = []
            var meta: [String: String] = [:]
            if let ip = match["ip_str"] as? String { parts.append("IP: \(ip)"); meta["ip"] = ip }
            if let port = match["port"] as? Int { parts.append("Port: \(port)"); meta["port"] = String(port) }
            if let transport = match["transport"] as? String { parts.append(transport.uppercased()); meta["transport"] = transport }
            if let org = match["org"] as? String { parts.append("Org: \(org)"); meta["org"] = org }
            if let country = (match["location"] as? [String: Any])?["country_name"] as? String {
                parts.append("Country: \(country)"); meta["country"] = country
            }
            if let vulns = match["vulns"] as? [String: Any], !vulns.isEmpty {
                let cves = vulns.keys.prefix(3).joined(separator: ", ")
                parts.append("CVEs: \(cves)"); meta["cves"] = cves
            }
            if let product = match["product"] as? String { parts.append("Product: \(product)"); meta["product"] = product }
            if !parts.isEmpty {
                results.append(PluginResult(
                    source: "Shodan",
                    type: "exposed_service",
                    confidenceScore: 0.9,
                    rawData: parts.joined(separator: " | "),
                    metadata: meta
                ))
            }
        }
        return results
    }
}
