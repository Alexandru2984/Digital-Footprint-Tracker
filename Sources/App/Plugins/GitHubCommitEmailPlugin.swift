import Vapor
import Foundation

/// Finds the GitHub account behind an email address through the commits it
/// authored, using GitHub's commit search (no key required; an optional
/// `GITHUB_TOKEN` raises the search limit from 10 to 30 requests a minute).
///
/// What a hit means depends on one field. Anyone can write any address into a
/// commit, so the author name and the commit dates are only what the author
/// typed (dates as old as 1992 are common). But GitHub fills in `author.login`
/// only when the address is a *verified* email of that account, so a login is
/// GitHub's own statement that the address belongs to it: a hard identity link,
/// and the login becomes a pivot for every username source.
///
/// API: GET https://api.github.com/search/commits?q=author-email:{email}
struct GitHubCommitEmailPlugin: FootprintPlugin {
    let name = "GitHubCommitEmail"
    let description = "GitHub account and author name behind an email, from its commits"
    let accepts: Set<TargetShape> = [.email]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let email = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard email.range(of: #"^[^@\s"]+@[^@\s"]+\.[a-z]{2,}$"#, options: .regularExpression) != nil,
              var components = URLComponents(string: "https://api.github.com/search/commits")
        else { return [] }
        components.queryItems = [
            URLQueryItem(name: "q", value: "author-email:\(email)"),
            URLQueryItem(name: "per_page", value: "30"),
        ]
        var headers = ["Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"]
        if let token = try RuntimeSecret.value("GITHUB_TOKEN"), !token.isEmpty {
            headers["Authorization"] = "Bearer \(token)"
        }
        var results: [PluginResult] = []
        if let url = components.url,
           let response = await PluginHTTP.request(
            url, headers: headers, timeout: 15,
            bodyMode: .complete(maxBytes: 2 * 1_024 * 1_024), on: app
           ),
           response.status == 200 {
            results = Self.evaluate(email: email, body: response.data)
        }
        // No commit ties the address to an account: look for an account that
        // shows it as its public profile email instead.
        if !results.contains(where: { $0.metadata?["username"] != nil }),
           let profile = await Self.profileWithEmail(email, headers: headers, app: app) {
            results.removeAll { $0.metadata?["username"] == nil && $0.confidenceScore < 1 }
            results.insert(profile, at: 0)
        }
        return results
    }

    /// An account whose public profile email is exactly `email`. GitHub only
    /// lets a verified address be public, so a match is as strong as a
    /// verified commit email. User search matches loosely, so each candidate's
    /// profile is fetched and its email compared exactly.
    static func profileWithEmail(_ email: String, headers: [String: String], app: Application) async -> PluginResult? {
        var search = URLComponents(string: "https://api.github.com/search/users")
        search?.queryItems = [URLQueryItem(name: "q", value: "\(email) in:email"), URLQueryItem(name: "per_page", value: "3")]
        guard let url = search?.url,
              let response = await PluginHTTP.request(url, headers: headers, timeout: 15,
                                                      bodyMode: .complete(maxBytes: 256 * 1_024), on: app),
              response.status == 200,
              let json = try? JSONSerialization.jsonObject(with: response.data) as? [String: Any],
              let items = json["items"] as? [[String: Any]] else { return nil }
        for login in items.compactMap({ $0["login"] as? String }).prefix(2) {
            guard let profileURL = URL(string: "https://api.github.com/users/\(login)"),
                  let profile = await PluginHTTP.request(profileURL, headers: headers, timeout: 15,
                                                         bodyMode: .complete(maxBytes: 256 * 1_024), on: app),
                  profile.status == 200,
                  let result = profileResult(email: email, body: profile.data) else { continue }
            return result
        }
        return nil
    }

    static func profileResult(email: String, body: Data) -> PluginResult? {
        guard let user = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let login = user["login"] as? String,
              (user["email"] as? String)?.lowercased() == email else { return nil }
        let name = (user["name"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        var parts = ["\(email) is the public profile email of GitHub account \(login): https://github.com/\(login)"]
        if !name.isEmpty { parts.append("Name: \(name)") }
        var meta = ["platform": "github", "username": login, "profileURL": "https://github.com/\(login)", "email": email,
                    "matchKind": "verified",
                    "matchReason": "the account's public profile email (GitHub only allows a verified address there)"]
        if !name.isEmpty { meta["name"] = name }
        return PluginResult(source: "GitHub", type: "developer_identity", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }

    struct Authorship: Equatable {
        var logins: [String] = []
        var names: [String] = []
        var repositories: [String] = []
        var commits = 0
    }

    /// Collects what the commits whose author email is exactly `email` say.
    /// Logins, names and repositories keep their first-seen order and are
    /// deduplicated case-insensitively.
    static func authorship(email: String, body: Data) -> Authorship? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let items = json["items"] as? [[String: Any]] else { return nil }
        var found = Authorship()
        func add(_ value: String?, to list: inout [String]) {
            guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty,
                  !list.contains(where: { $0.lowercased() == value.lowercased() }) else { return }
            list.append(value)
        }
        for item in items {
            let author = (item["commit"] as? [String: Any])?["author"] as? [String: Any]
            // The search qualifier is loose; trust only an exact address match.
            guard (author?["email"] as? String)?.lowercased() == email else { continue }
            found.commits += 1
            add((item["author"] as? [String: Any])?["login"] as? String, to: &found.logins)
            add(author?["name"] as? String, to: &found.names)
            add((item["repository"] as? [String: Any])?["full_name"] as? String, to: &found.repositories)
        }
        return found.commits > 0 ? found : nil
    }

    static func evaluate(email: String, body: Data) -> [PluginResult] {
        guard let found = authorship(email: email, body: body) else { return [] }
        let names = found.names.prefix(3).joined(separator: ", ")
        let repos = found.repositories.prefix(5).joined(separator: ", ")

        // One result per account GitHub verified the address on (normally one).
        var results = found.logins.prefix(3).map { login -> PluginResult in
            var parts = ["\(email) is a verified email of GitHub account \(login): https://github.com/\(login)"]
            if !names.isEmpty { parts.append("Commit author name: \(names)") }
            if !repos.isEmpty { parts.append("Seen in: \(repos)") }
            var meta = ["platform": "github", "username": login, "profileURL": "https://github.com/\(login)",
                        "email": email, "matchKind": "verified",
                        "matchReason": "GitHub links a commit to an account only through a verified email"]
            if let name = found.names.first { meta["name"] = name }
            return PluginResult(source: "GitHub", type: "developer_identity", confidenceScore: 1.0,
                                rawData: parts.joined(separator: " | "), metadata: meta)
        }
        if results.isEmpty {
            // No account claims the address: only the self-written author name.
            var parts = ["\(email) authored \(found.commits) public commit(s) not linked to a GitHub account"]
            if !names.isEmpty { parts.append("Author name given: \(names)") }
            if !repos.isEmpty { parts.append("Seen in: \(repos)") }
            var meta = ["email": email]
            if let name = found.names.first { meta["name"] = name }
            results.append(PluginResult(source: "GitHub", type: "developer_identity", confidenceScore: 0.5,
                                        rawData: parts.joined(separator: " | "), metadata: meta))
        }
        return results
    }
}
