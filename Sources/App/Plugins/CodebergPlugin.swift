import Vapor
import Foundation

/// Looks up a Codeberg account through its public Forgejo API (no key
/// required). Codeberg is the non-profit Git host much of the free-software
/// community moved to, so it finds developers GitHub and GitLab miss.
///
/// The API's `email` is a `@noreply.codeberg.org` alias unless the user chose
/// to publish a real one, so only a real address is kept.
///
/// API: GET https://codeberg.org/api/v1/users/{username} → 200 user | 404
struct CodebergPlugin: FootprintPlugin {
    let name = "Codeberg"
    let description = "Codeberg (Forgejo) account lookup"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = Self.username(for: input),
              let url = URL(string: "https://codeberg.org/api/v1/users/\(username)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 64 * 1_024), on: app
              ) else { return [] }
        return Self.evaluate(username: username, status: response.status, body: response.data).map { [$0] } ?? []
    }

    /// Forgejo usernames: letters, digits, `-`, `_` and `.`, starting and
    /// ending with a letter or digit, at most 40 characters.
    static func username(for input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.range(of: #"^[A-Za-z0-9]([A-Za-z0-9._-]{0,38}[A-Za-z0-9])?$"#, options: .regularExpression) != nil,
              value.range(of: #"^[0-9]+$"#, options: .regularExpression) == nil,
              !value.contains("..")
        else { return nil }
        return value
    }

    /// A result only for a 200 whose `login` is the username asked for.
    static func evaluate(username: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let login = json["login"] as? String,
              login.lowercased() == username.lowercased()
        else { return nil }
        func text(_ key: String) -> String {
            (json[key] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let fullName = text("full_name")
        let location = text("location")
        let website = text("website")
        let email = text("email")
        let publicEmail = email.contains("@") && !email.lowercased().hasSuffix("@noreply.codeberg.org") ? email : ""
        let bio = text("description").replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
        let joined = (json["created"] as? String).flatMap { TimelineIntelligence.normalizedDate($0)?.value }
        let profileURL = "https://codeberg.org/\(login)"

        var parts = ["Codeberg account found: \(profileURL)"]
        if !fullName.isEmpty { parts.append("Name: \(fullName)") }
        if !location.isEmpty { parts.append("Location: \(location)") }
        if !website.isEmpty { parts.append("Website: \(website)") }
        if !publicEmail.isEmpty { parts.append("Public email: \(publicEmail)") }
        if let followers = json["followers_count"] as? Int { parts.append("Followers: \(followers)") }
        if let joined { parts.append("Joined: \(joined)") }
        if !bio.isEmpty { parts.append("Bio: \(bio.count > 160 ? String(bio.prefix(160)) + "…" : bio)") }

        var meta = ["platform": "codeberg", "username": login, "profileURL": profileURL]
        if !fullName.isEmpty { meta["name"] = fullName }
        if !location.isEmpty { meta["location"] = location }
        if !website.isEmpty { meta["blog"] = website }
        if !publicEmail.isEmpty { meta["email"] = publicEmail }
        if let linked = BioLinks.linked(in: bio, excluding: "codeberg:\(login)") { meta["bioLinked"] = linked }
        if let joined { meta["since"] = joined }

        return PluginResult(source: "Codeberg", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
