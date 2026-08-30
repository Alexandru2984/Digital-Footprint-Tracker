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
    /// Mastodon handles only.
    let accepts: Set<TargetShape> = [.username]

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

        guard let response = await PluginHTTP.request(
            url,
            headers: ["Accept": "application/json"],
            timeout: 12,
            bodyMode: .complete(maxBytes: 512 * 1_024),
            on: app
        ), response.status == 200 else { return [] }
        guard let acct = Self.parseAccount(from: response.data, fallbackUsername: username) else { return [] }

        var parts = ["Mastodon account found: \(acct.profileURL)"]
        if !acct.displayName.isEmpty { parts.append("Display name: \(acct.displayName)") }
        if let f = acct.followers { parts.append("Followers: \(f)") }
        if let s = acct.statuses  { parts.append("Posts: \(s)") }
        if let joinedDate = acct.joinedDate { parts.append("Joined: \(joinedDate)") }
        if acct.locked { parts.append("🔒 Locked account") }
        if !acct.bio.isEmpty {
            let truncNote = acct.bio.count > 120 ? String(acct.bio.prefix(120)) + "…" : acct.bio
            parts.append("Bio: \(truncNote)")
        }

        var meta: [String: String] = ["platform": "mastodon", "username": acct.acct, "profileURL": acct.profileURL]
        // Feed the display name into identity synthesis — a self-set nickname on
        // Mastodon is still identity signal, weighted and corroborated there.
        if !acct.displayName.isEmpty { meta["name"] = acct.displayName }
        if let joinedDate = acct.joinedDate { meta["since"] = joinedDate }

        return [PluginResult(
            source: "Mastodon",
            type: "social_media",
            confidenceScore: 1.0,
            rawData: parts.joined(separator: " | "),
            metadata: meta
        )]
    }

    /// Parsed subset of a Mastodon account-lookup response.
    struct Account {
        let displayName: String
        let acct: String
        let bio: String
        let profileURL: String
        let followers: Int?
        let statuses: Int?
        let locked: Bool
        let joinedDate: String?
    }

    /// Decodes a `/accounts/lookup` JSON body. Pure + internal so the field
    /// extraction (including the HTML-stripped bio) is unit-testable offline.
    static func parseAccount(from data: Data, fallbackUsername: String) -> Account? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let acct = json["acct"] as? String ?? fallbackUsername
        let note = json["note"] as? String ?? ""
        // Strip HTML tags from the bio (Mastodon returns HTML in `note`).
        let cleanNote = note
            .replacingOccurrences(of: #"<[^>]+>"#, with: "", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return Account(
            displayName: (json["display_name"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
            acct: acct,
            bio: cleanNote,
            profileURL: json["url"] as? String ?? "https://mastodon.social/@\(acct)",
            followers: json["followers_count"] as? Int,
            statuses: json["statuses_count"] as? Int,
            locked: json["locked"] as? Bool ?? false,
            joinedDate: (json["created_at"] as? String)
                .flatMap { TimelineIntelligence.normalizedDate($0)?.value }
        )
    }
}
