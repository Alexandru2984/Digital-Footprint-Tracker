import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct VirusTotalPlugin: FootprintPlugin {
    let name = "VirusTotal"

    private static let ipRegex = try! NSRegularExpression(pattern: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#)

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let apiKey = Environment.get("VIRUS_TOTAL_API_KEY"), !apiKey.isEmpty else { return [] }

        let isIP = Self.ipRegex.firstMatch(in: input, range: NSRange(input.startIndex..., in: input)) != nil
        if isIP {
            return await scanIP(input, apiKey: apiKey)
        }
        if input.contains(".") && !input.contains("@") {
            return await scanDomain(input, apiKey: apiKey)
        }
        return []
    }

    private func scanDomain(_ domain: String, apiKey: String) async -> [PluginResult] {
        guard let url = URL(string: "https://www.virustotal.com/api/v3/domains/\(domain)") else { return [] }
        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")

        guard let (responseData, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
              let dataDict = json["data"] as? [String: Any],
              let attributes = dataDict["attributes"] as? [String: Any] else { return [] }

        let stats = attributes["last_analysis_stats"] as? [String: Any]
        let malicious  = stats?["malicious"]  as? Int ?? 0
        let suspicious = stats?["suspicious"] as? Int ?? 0
        let harmless   = stats?["harmless"]   as? Int ?? 0
        let reputation = attributes["reputation"] as? Int ?? 0
        let categories = attributes["categories"] as? [String: String] ?? [:]
        let catList = Array(Set(categories.values)).sorted().prefix(5).joined(separator: ", ")

        let rawData = "VirusTotal domain: \(domain) | malicious: \(malicious), suspicious: \(suspicious), harmless: \(harmless) | reputation: \(reputation) | categories: \(catList)"

        let confidence: Double = malicious > 0 ? 0.95 : suspicious > 0 ? 0.7 : 0.3
        return [PluginResult(source: "VirusTotal", type: "domain_reputation", confidenceScore: confidence, rawData: rawData)]
    }

    private func scanIP(_ ip: String, apiKey: String) async -> [PluginResult] {
        guard let url = URL(string: "https://www.virustotal.com/api/v3/ip_addresses/\(ip)") else { return [] }
        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")

        guard let (responseData, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
              let dataDict = json["data"] as? [String: Any],
              let attributes = dataDict["attributes"] as? [String: Any] else { return [] }

        let stats = attributes["last_analysis_stats"] as? [String: Any]
        let malicious  = stats?["malicious"]  as? Int ?? 0
        let suspicious = stats?["suspicious"] as? Int ?? 0
        let reputation = attributes["reputation"] as? Int ?? 0
        let asOwner    = attributes["as_owner"] as? String ?? "unknown"
        let country    = attributes["country"]  as? String ?? "unknown"

        let rawData = "VirusTotal IP: \(ip) | malicious: \(malicious) | reputation: \(reputation) | AS: \(asOwner) | country: \(country)"

        let confidence: Double = malicious > 0 ? 0.95 : suspicious > 0 ? 0.7 : 0.3
        return [PluginResult(source: "VirusTotal", type: "ip_reputation", confidenceScore: confidence, rawData: rawData)]
    }
}
