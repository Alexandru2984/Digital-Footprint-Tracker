import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
struct HaveIBeenPwnedPlugin: FootprintPlugin {
    let name = "HaveIBeenPwned"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }

        guard let apiKey = Environment.get("HIBP_API_KEY"), !apiKey.isEmpty else {
            app.logger.warning("HIBP_API_KEY not set; skipping HaveIBeenPwned check")
            return []
        }

        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? input
        let urlString = "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false"
        guard let url = URL(string: urlString) else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 15)
        req.setValue(apiKey, forHTTPHeaderField: "hibp-api-key")
        req.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { return [] }

            if http.statusCode == 404 {
                return [PluginResult(
                    source: name,
                    type: "breach_check",
                    confidenceScore: 1.0,
                    rawData: "No breaches found for this email address."
                )]
            }
            guard http.statusCode == 200 else { return [] }

            struct Breach: Decodable {
                let Name: String
                let Domain: String
                let BreachDate: String
                let PwnCount: Int
                let DataClasses: [String]
            }

            let breaches = try JSONDecoder().decode([Breach].self, from: data)
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
        } catch {
            app.logger.error("HaveIBeenPwned request failed: \(error)")
            return []
        }
    }
}
