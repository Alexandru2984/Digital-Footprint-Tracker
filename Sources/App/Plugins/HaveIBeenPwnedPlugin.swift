import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses the shared size-bounded outbound client.
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
        ], on: app) else { return [] }

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

        // Structured entities: breach names + the distinct data classes exposed
        // (passwords, emails, …) — high-signal for both scoring and export.
        var meta: [String: String] = [
            "breachCount": String(breaches.count),
            "breaches": breaches.map { $0.Name }.prefix(30).joined(separator: ", ")
        ]
        let dataClasses = Set(breaches.flatMap { $0.DataClasses }).sorted()
        if !dataClasses.isEmpty {
            meta["dataClasses"] = dataClasses.prefix(20).joined(separator: ", ")
        }
        // Per-breach dates ("Name|YYYY-MM-DD; …") so the identity timeline can show
        // when each exposure happened, not just that a breach occurred.
        let dated = breaches.prefix(30)
            .filter { !$0.BreachDate.isEmpty }
            .map { "\($0.Name)|\($0.BreachDate)" }
            .joined(separator: "; ")
        if !dated.isEmpty { meta["breachDates"] = dated }

        return [PluginResult(
            source: name,
            type: "data_breach",
            confidenceScore: 1.0,
            rawData: "Found in \(breaches.count) breach(es): \(summary)",
            metadata: meta
        )]
    }
}
