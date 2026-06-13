import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Foundation

/// Checks whether a Reddit account exists for a given username.
/// Uses the public JSON API (no key required).
/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
struct RedditPlugin: FootprintPlugin {
    let name = "Reddit"
    let description = "Reddit account lookup"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: "https://www.reddit.com/user/\(username)/about.json") else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("DigitalFootprintTracker/1.0 (OSINT research tool)", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { return [] }
            let meta = ["platform": "reddit", "username": username,
                        "profileURL": "https://www.reddit.com/user/\(username)"]
            switch http.statusCode {
            case 200:
                return [PluginResult(
                    source: "Reddit",
                    type: "account_presence",
                    confidenceScore: 1.0,
                    rawData: "Reddit account found. Profile: https://www.reddit.com/user/\(username)",
                    metadata: meta
                )]
            case 403:
                return [PluginResult(
                    source: "Reddit",
                    type: "account_presence",
                    confidenceScore: 0.9,
                    rawData: "Reddit account exists but is suspended/banned. Profile: https://www.reddit.com/user/\(username)",
                    metadata: meta
                )]
            default:
                return []
            }
        } catch {
            return []
        }
    }
}
