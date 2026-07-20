import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct AbuseIPDBPlugin: FootprintPlugin {
    let name = "AbuseIPDB"
    let description = "IP abuse reputation score (requires API key)"

    private static let ipRegex = try! NSRegularExpression(pattern: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#)

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let apiKey = Environment.get("ABUSEIPDB_API_KEY"), !apiKey.isEmpty else { return [] }

        let isIP = Self.ipRegex.firstMatch(in: input, range: NSRange(input.startIndex..., in: input)) != nil
        guard isIP else { return [] }

        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? input
        guard let url = URL(string: "https://api.abuseipdb.com/api/v2/check?ipAddress=\(encoded)&maxAgeInDays=90&verbose") else { return [] }

        guard let resp = await PluginHTTP.request(url, headers: [
            "Key": apiKey,
            "Accept": "application/json"
        ], on: app), resp.status == 200,
              let json = try? JSONSerialization.jsonObject(with: resp.data) as? [String: Any],
              let dataDict = json["data"] as? [String: Any] else { return [] }

        let abuseScore   = dataDict["abuseConfidenceScore"] as? Int ?? 0
        let totalReports = dataDict["totalReports"]         as? Int ?? 0
        let countryCode  = dataDict["countryCode"]          as? String ?? "unknown"
        let isp          = dataDict["isp"]                  as? String ?? "unknown"
        let usageType    = dataDict["usageType"]            as? String ?? "unknown"

        let rawData = "AbuseIPDB: \(input) | abuse score: \(abuseScore)% | reports: \(totalReports) | country: \(countryCode) | ISP: \(isp) | type: \(usageType)"

        let confidence = max(0.1, min(1.0, Double(abuseScore) / 100.0))
        return [PluginResult(source: "AbuseIPDB", type: "ip_abuse", confidenceScore: confidence, rawData: rawData,
                             metadata: ["ip": input, "country": countryCode, "org": isp, "abuseScore": String(abuseScore)])]
    }
}
