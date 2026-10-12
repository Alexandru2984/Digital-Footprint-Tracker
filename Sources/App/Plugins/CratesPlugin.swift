import Vapor
import Foundation

/// Looks up a crates.io publisher and the Rust crates they own (no key
/// required).
///
/// crates.io signs users in only through GitHub, so a crates.io login is a
/// GitHub login: a hit also places the target on GitHub under that name, and
/// the API says whether the GitHub account still carries it
/// (`github_username_matches`).
///
/// API: GET https://crates.io/api/v1/users/{login}             → 200 user | 404
///      GET https://crates.io/api/v1/crates?user_id={id}&...   → owned crates
/// crates.io requires an identifying User-Agent, which the shared client sends.
struct CratesPlugin: FootprintPlugin {
    let name = "CratesPackages"
    let description = "crates.io (Rust) publisher and crates"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let login = Self.login(for: input),
              let url = URL(string: "https://crates.io/api/v1/users/\(login)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 64 * 1_024), on: app
              ),
              let user = Self.parseUser(status: response.status, body: response.data, login: login)
        else { return [] }

        var crates: Crates?
        if let cratesURL = URL(string: "https://crates.io/api/v1/crates?user_id=\(user.id)&per_page=5&sort=downloads"),
           let owned = await PluginHTTP.request(
            cratesURL, headers: ["Accept": "application/json"], timeout: 10,
            bodyMode: .complete(maxBytes: 256 * 1_024), on: app
           ), owned.status == 200 {
            crates = Self.parseCrates(owned.data)
        }
        return [Self.result(user: user, crates: crates)]
    }

    /// GitHub logins: letters, digits and single hyphens, at most 39
    /// characters, not starting or ending with a hyphen.
    static func login(for input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.range(of: #"^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$"#, options: .regularExpression) != nil,
              !value.contains("--"),
              value.range(of: #"^[0-9]+$"#, options: .regularExpression) == nil
        else { return nil }
        return value
    }

    struct User: Equatable {
        let id: Int
        let login: String
        let name: String
        let githubURL: String
        let githubMatches: Bool
        let joined: String?
    }

    struct Crates: Equatable {
        let total: Int
        let top: [String]
    }

    static func parseUser(status: Int, body: Data, login: String) -> User? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let user = json["user"] as? [String: Any],
              let id = user["id"] as? Int,
              let returned = user["login"] as? String,
              returned.lowercased() == login.lowercased()
        else { return nil }
        return User(
            id: id,
            login: returned,
            name: (user["name"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
            githubURL: user["url"] as? String ?? "",
            githubMatches: user["github_username_matches"] as? Bool ?? false,
            joined: (user["created_at"] as? String).flatMap { TimelineIntelligence.normalizedDate($0)?.value }
        )
    }

    static func parseCrates(_ body: Data) -> Crates? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let total = (json["meta"] as? [String: Any])?["total"] as? Int else { return nil }
        let names = (json["crates"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        return Crates(total: total, top: Array(names.prefix(5)))
    }

    static func result(user: User, crates: Crates?) -> PluginResult {
        let url = "https://crates.io/users/\(user.login)"
        var parts = ["crates.io publisher found: \(url)"]
        if !user.name.isEmpty { parts.append("Name: \(user.name)") }
        if user.githubMatches, !user.githubURL.isEmpty { parts.append("Signs in with GitHub: \(user.githubURL)") }
        if let joined = user.joined { parts.append("Joined: \(joined)") }
        if let crates {
            let top = crates.top.isEmpty ? "" : " (most downloaded: \(crates.top.joined(separator: ", ")))"
            parts.append("Crates owned: \(crates.total)\(top)")
        }

        var meta = ["platform": "crates.io", "username": user.login, "profileURL": url]
        if !user.name.isEmpty { meta["name"] = user.name }
        if let joined = user.joined { meta["since"] = joined }
        if user.githubMatches, !user.githubURL.isEmpty { meta["github"] = user.githubURL }

        return PluginResult(source: "crates.io", type: "developer_identity", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
