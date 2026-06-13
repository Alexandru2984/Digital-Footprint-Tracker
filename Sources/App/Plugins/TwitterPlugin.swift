import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Checks whether a Twitter/X account exists for a given username.
///
/// Uses Twitter's public CDN syndication endpoint — no API key required.
/// This endpoint is used by embedded tweet widgets and remains publicly
/// accessible without authentication.
///
/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle.
struct TwitterPlugin: FootprintPlugin {
    let name = "TwitterOSINT"
    let description = "Twitter/X profile search"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        // Skip emails and phone numbers.
        guard !input.contains("@"),
              input.range(of: #"^\+?[0-9]{7,15}$"#, options: .regularExpression) == nil
        else { return [] }

        // Skip inputs that look like domain names.
        guard input.range(of: #"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"#,
                          options: .regularExpression) == nil
        else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Twitter usernames: 1-15 alphanumeric + underscore characters.
        guard username.count <= 15,
              username.range(of: #"^[a-zA-Z0-9_]+$"#, options: .regularExpression) != nil
        else { return [] }

        let urlStr = "https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names=\(username)"
        guard let url = URL(string: urlStr) else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("DigitalFootprintTracker/1.0 (OSINT research tool)", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
                  let user = json.first
            else { return [] }

            // The endpoint returns an empty array when the account doesn't exist.
            guard !json.isEmpty else { return [] }

            let name        = user["name"]              as? String ?? username
            let followers   = user["followers_count"]   as? Int
            let verified    = user["verified"]          as? Bool ?? false
            let description = user["description"]       as? String ?? ""

            var parts = ["Twitter/X profile found: @\(username) (\(name))"]
            if let f = followers { parts.append("Followers: \(f)") }
            if verified { parts.append("✓ Verified") }
            if !description.isEmpty {
                let truncated = description.count > 120
                    ? String(description.prefix(120)) + "…"
                    : description
                parts.append("Bio: \(truncated)")
            }
            parts.append("URL: https://x.com/\(username)")

            return [PluginResult(
                source: "Twitter",
                type: "social_media",
                confidenceScore: 1.0,
                rawData: parts.joined(separator: " | "),
                metadata: ["platform": "twitter", "username": username, "profileURL": "https://x.com/\(username)"]
            )]
        } catch {
            return []
        }
    }
}
