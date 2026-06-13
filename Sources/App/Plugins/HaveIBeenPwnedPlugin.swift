import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
struct HaveIBeenPwnedPlugin: FootprintPlugin {
    let name = "HaveIBeenPwned"
    let description = "Email breach database check (HIBP)"
    // Breach corpora move slowly; cache a full day to spare the paid API quota.
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }

        guard let apiKey = Environment.get("HIBP_API_KEY"), !apiKey.isEmpty else {
            app.logger.warning("HIBP_API_KEY not set; skipping HaveIBeenPwned check")
            return []
        }

        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? input
        let urlString = "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false"
        guard let url = URL(string: urlString) else { return [] }

        // Shared client: retries HIBP's 429 (it rate-limits aggressively) with
        // backoff honouring Retry-After.
        guard let resp = await PluginHTTP.request(url, headers: [
            "hibp-api-key": apiKey,
            "Accept": "application/json"
        ]) else { return [] }

        if resp.status == 404 {
            return [PluginResult(
                source: name,
                type: "breach_check",
                confidenceScore: 1.0,
                rawData: "No breaches found for this email address."
            )]
        }
        guard resp.status == 200 else { return [] }

        struct Breach: Decodable {
            let Name: String
            let Domain: String
            let BreachDate: String
            let PwnCount: Int
            let DataClasses: [String]
        }

        guard let breaches = try? JSONDecoder().decode([Breach].self, from: resp.data) else { return [] }
        guard !breaches.isEmpty else {
            return [PluginResult(
                source: name,
                type: "breach_check",
                confidenceScore: 1.0,
                rawData: "No breaches found for this email address."
            )]
        }

        let summary = breaches.map { b in
            "\(b.Name) (\(b.BreachDate), \(b.PwnCount) accounts)"
        }.joined(separator: "; ")

        return [PluginResult(
            source: name,
            type: "data_breach",
            confidenceScore: 1.0,
            rawData: "Found in \(breaches.count) breach(es): \(summary)"
        )]
    }
}
