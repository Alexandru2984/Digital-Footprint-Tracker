import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Looks up a username on Mastodon's largest instance (mastodon.social).
///
/// Uses the public account lookup API — no authentication required.
/// Only checks mastodon.social; federated instances are out of scope.
///
/// API: GET https://mastodon.social/api/v1/accounts/lookup?acct={username}
/// Returns 200 + JSON if found, 404 if not.
///
/// Uses URLSession — lifecycle-independent, safe from asyncShutdown races.
struct MastodonPlugin: FootprintPlugin {
    let name = "MastodonOSINT"
    let description = "Mastodon account search (mastodon.social)"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@"),
              input.range(of: #"^\+?[0-9]{7,15}$"#, options: .regularExpression) == nil,
              input.range(of: #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"#,
                          options: .regularExpression) == nil
        else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Mastodon usernames: letters, digits, underscores — no strict length limit but
        // mastodon.social enforces max 30 chars.
        guard username.count >= 1, username.count <= 30,
              username.range(of: #"^[a-zA-Z0-9_]+$"#, options: .regularExpression) != nil
        else { return [] }

        guard let url = URL(string: "https://mastodon.social/api/v1/accounts/lookup?acct=\(username)") else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 12)
        req.setValue("DigitalFootprintTracker/1.0 (OSINT research tool)", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }

            let displayName  = json["display_name"]  as? String ?? ""
            let acct         = json["acct"]           as? String ?? username
            let followersCount = json["followers_count"] as? Int
            let statusesCount  = json["statuses_count"]  as? Int
            let note         = json["note"]           as? String ?? ""
            let profileURL   = json["url"]            as? String ?? "https://mastodon.social/@\(acct)"
            let locked       = json["locked"]         as? Bool ?? false

            // Strip HTML tags from the bio (Mastodon returns HTML in `note`)
            let cleanNote = note
                .replacingOccurrences(of: #"<[^>]+>"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)

            var parts = ["Mastodon account found: \(profileURL)"]
            if !displayName.isEmpty { parts.append("Display name: \(displayName)") }
            if let f = followersCount { parts.append("Followers: \(f)") }
            if let s = statusesCount  { parts.append("Posts: \(s)") }
            if locked { parts.append("🔒 Locked account") }
            if !cleanNote.isEmpty {
                let truncNote = cleanNote.count > 120 ? String(cleanNote.prefix(120)) + "…" : cleanNote
                parts.append("Bio: \(truncNote)")
            }

            return [PluginResult(
                source: "Mastodon",
                type: "social_media",
                confidenceScore: 1.0,
                rawData: parts.joined(separator: " | ")
            )]
        } catch {
            return []
        }
    }
}
