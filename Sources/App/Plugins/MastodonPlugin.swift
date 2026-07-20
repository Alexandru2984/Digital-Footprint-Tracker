import Vapor
import Foundation

/// Looks up a username on Mastodon's largest instance (mastodon.social).
///
/// Uses the public account lookup API — no authentication required.
/// Only checks mastodon.social; federated instances are out of scope.
///
/// API: GET https://mastodon.social/api/v1/accounts/lookup?acct={username}
/// Returns 200 + JSON if found, 404 if not.
///
/// Uses the shared size-bounded outbound client.
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

        do {
            guard let response = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                timeout: 12,
                bodyMode: .complete(maxBytes: 512 * 1_024),
                on: app
            ), response.status == 200 else { return [] }
            let data = response.data
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
                rawData: parts.joined(separator: " | "),
                metadata: ["platform": "mastodon", "username": acct, "profileURL": profileURL]
            )]
        } catch {
            return []
        }
    }
}
