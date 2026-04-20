import Vapor

struct HaveIBeenPwnedPlugin: FootprintPlugin {
    let name = "HaveIBeenPwned"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }

        guard let apiKey = Environment.get("HIBP_API_KEY"), !apiKey.isEmpty else {
            app.logger.warning("HIBP_API_KEY not set; skipping HaveIBeenPwned check")
            return []
        }

        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? input
        let url = "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false"

        var headers = HTTPHeaders()
        headers.add(name: "hibp-api-key", value: apiKey)
        headers.add(name: .userAgent, value: "Digital-Footprint-Tracker/1.0")

        do {
            let response = try await app.client.get(URI(string: url), headers: headers)

            if response.status == .notFound {
                return [PluginResult(
                    source: name,
                    type: "breach_check",
                    confidenceScore: 1.0,
                    rawData: "No breaches found for this email address."
                )]
            }

            guard response.status == .ok else {
                return []
            }

            struct Breach: Decodable {
                let Name: String
                let Domain: String
                let BreachDate: String
                let PwnCount: Int
                let DataClasses: [String]
            }

            let breaches = try response.content.decode([Breach].self)
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
