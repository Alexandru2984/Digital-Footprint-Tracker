import Vapor
import Foundation

/// Duolingo, by username or by email address (no key required).
///
/// A username answers with the public profile: display name, when it joined
/// and the languages it learns. An email address answers with a redacted
/// record when an account is registered with it, which still says how it
/// signs in (Google, Facebook, Apple); an unregistered address answers with
/// no users.
///
/// API: GET https://www.duolingo.com/2017-06-30/users?username={u} | ?email={e}
struct DuolingoPlugin: FootprintPlugin {
    let name = "Duolingo"
    let description = "Duolingo profile by username, or whether an email has an account"
    let accepts: Set<TargetShape> = [.username, .email]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let query: URLQueryItem
        if let email = EmailAddress.normalize(input) {
            query = URLQueryItem(name: "email", value: email)
        } else if let username = CommunityHandle.validated(input) {
            query = URLQueryItem(name: "username", value: username)
        } else {
            return []
        }
        var components = URLComponents(string: "https://www.duolingo.com/2017-06-30/users")
        components?.queryItems = [query]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 512 * 1_024), on: app
              ),
              response.status == 200 else { return [] }
        if query.name == "email" {
            return Self.evaluate(email: query.value ?? "", body: response.data).map { [$0] } ?? []
        }
        return Self.evaluate(username: query.value ?? "", body: response.data).map { [$0] } ?? []
    }

    private static func firstUser(_ body: Data) -> [String: Any]? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let users = json["users"] as? [[String: Any]] else { return nil }
        return users.first
    }

    static func evaluate(username: String, body: Data) -> PluginResult? {
        guard let user = firstUser(body), let login = CommunityHandle.text(user["username"]),
              login.lowercased() == username.lowercased() else { return nil }
        let profileURL = "https://www.duolingo.com/profile/\(login)"
        var parts = ["Duolingo account found: \(profileURL)"]
        var meta = ["platform": "duolingo", "username": login, "profileURL": profileURL]
        if let name = CommunityHandle.text(user["name"]) { parts.append("Name: \(name)"); meta["name"] = name }
        if let created = user["creationDate"] as? Double, created > 0 {
            let joined = ISO8601DateFormatter.string(from: Date(timeIntervalSince1970: created), timeZone: .gmt,
                                                     formatOptions: [.withFullDate])
            parts.append("Joined: \(joined)")
            meta["since"] = joined
        }
        let languages = (user["courses"] as? [[String: Any]] ?? []).compactMap { CommunityHandle.text($0["title"]) }
        if !languages.isEmpty {
            parts.append("Learning: \(languages.prefix(8).joined(separator: ", "))")
            meta["languages"] = languages.prefix(8).joined(separator: ", ")
        }
        if let streak = user["streak"] as? Int, streak > 0 { parts.append("Streak: \(streak) days") }
        return PluginResult(source: "Duolingo", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }

    static func evaluate(email: String, body: Data) -> PluginResult? {
        guard let user = firstUser(body) else { return nil }
        let logins = [("hasGoogleId", "Google"), ("hasFacebookId", "Facebook"), ("hasAppleId", "Apple")]
            .filter { user[$0.0] as? Bool == true }.map(\.1)
        var raw = "Account registered with email on Duolingo"
        if !logins.isEmpty { raw += " | Signs in with \(logins.joined(separator: ", "))" }
        var meta = ["email": email, "platform": "duolingo", "account": email, "matchKind": "observed",
                    "matchReason": "Duolingo's user search recognises this address"]
        if !logins.isEmpty { meta["signIn"] = logins.joined(separator: ", ") }
        return PluginResult(source: "Duolingo", type: "account_presence", confidenceScore: 1.0, rawData: raw, metadata: meta)
    }
}
