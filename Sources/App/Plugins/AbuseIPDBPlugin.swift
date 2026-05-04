import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct AbuseIPDBPlugin: FootprintPlugin {
    let name = "AbuseIPDB"

    private static let ipRegex = try! NSRegularExpression(pattern: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#)

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let apiKey = Environment.get("ABUSEIPDB_API_KEY"), !apiKey.isEmpty else { return [] }

        let isIP = Self.ipRegex.firstMatch(in: input, range: NSRange(input.startIndex..., in: input)) != nil
        guard isIP else { return [] }

        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? input
        guard let url = URL(string: "https://api.abuseipdb.com/api/v2/check?ipAddress=\(encoded)&maxAgeInDays=90&verbose") else { return [] }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue(apiKey, forHTTPHeaderField: "Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        guard let (responseData, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
              let dataDict = json["data"] as? [String: Any] else { return [] }

        let abuseScore   = dataDict["abuseConfidenceScore"] as? Int ?? 0
        let totalReports = dataDict["totalReports"]         as? Int ?? 0
        let countryCode  = dataDict["countryCode"]          as? String ?? "unknown"
        let isp          = dataDict["isp"]                  as? String ?? "unknown"
        let usageType    = dataDict["usageType"]            as? String ?? "unknown"

        let rawData = "AbuseIPDB: \(input) | abuse score: \(abuseScore)% | reports: \(totalReports) | country: \(countryCode) | ISP: \(isp) | type: \(usageType)"

        let confidence = max(0.1, min(1.0, Double(abuseScore) / 100.0))
        return [PluginResult(source: "AbuseIPDB", type: "ip_abuse", confidenceScore: confidence, rawData: rawData)]
    }
}
