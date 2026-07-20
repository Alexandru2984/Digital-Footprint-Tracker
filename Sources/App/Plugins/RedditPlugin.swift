import Vapor
import Foundation

/// Checks whether a Reddit account exists for a given username.
/// Uses the public JSON API (no key required).
/// Uses a headers-only, size-bounded request.
struct RedditPlugin: FootprintPlugin {
    let name = "Reddit"
    let description = "Reddit account lookup"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: "https://www.reddit.com/user/\(username)/about.json") else { return [] }

        do {
            guard let response = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                timeout: 10,
                bodyMode: .prefix(maxBytes: 0),
                on: app
            ) else { return [] }
            let meta = ["platform": "reddit", "username": username,
                        "profileURL": "https://www.reddit.com/user/\(username)"]
            switch response.status {
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
