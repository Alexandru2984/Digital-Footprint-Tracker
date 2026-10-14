import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses the shared size-bounded outbound client.
struct UsernamePlugin: FootprintPlugin {
    let name = "GitHubAccountCheck"
    let description = "GitHub profile lookup"
    /// GitHub handles only.
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let cleanedUsername = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanedUsername.range(of: "^[a-zA-Z0-9_-]{1,39}$", options: .regularExpression) != nil else {
            return [PluginResult(
                source: name,
                type: "username_validation",
                confidenceScore: 0.0,
                rawData: "Invalid GitHub username format."
            )]
        }

        guard let url = URL(string: "https://api.github.com/users/\(cleanedUsername)") else { return [] }

        // Shared client: consistent UA + retry/backoff on GitHub's 429 (its
        // unauthenticated limit is only 60/h, so a transient 429 is common).
        let headers = Self.apiHeaders()
        guard let resp = await PluginHTTP.request(url, headers: headers, on: app) else { return [] }
        let data = resp.data

        if resp.status == 200 {
            struct GitHubUser: Decodable {
                let public_repos: Int?
                let followers: Int?
                let following: Int?
                let name: String?
                let company: String?
                let blog: String?
                let location: String?
                let bio: String?
                let twitter_username: String?
                let created_at: String?
                let type: String?
            }
            let user = try? JSONDecoder().decode(GitHubUser.self, from: data)
            let joinedDate = user?.created_at.flatMap { TimelineIntelligence.normalizedDate($0)?.value }

            var parts: [String] = [
                "GitHub profile: https://github.com/\(cleanedUsername)"
            ]
            if let n = user?.name, !n.isEmpty         { parts.append("Name: \(n)") }
            if let b = user?.bio, !b.isEmpty           { parts.append("Bio: \(b.prefix(120))") }
            if let loc = user?.location, !loc.isEmpty  { parts.append("Location: \(loc)") }
            if let co = user?.company, !co.isEmpty     { parts.append("Company: \(co)") }
            if let blog = user?.blog, !blog.isEmpty    { parts.append("Blog: \(blog)") }
            if let tw = user?.twitter_username, !tw.isEmpty { parts.append("Twitter: @\(tw)") }
            parts.append("Repos: \(user?.public_repos ?? 0)")
            parts.append("Followers: \(user?.followers ?? 0)")
            if let joinedDate { parts.append("Joined: \(joinedDate)") }

            // Structured entities for correlation / export.
            var meta: [String: String] = [
                "platform": "github",
                "username": cleanedUsername,
                "profileURL": "https://github.com/\(cleanedUsername)"
            ]
            if let n = user?.name, !n.isEmpty            { meta["name"] = n }
            if let loc = user?.location, !loc.isEmpty    { meta["location"] = loc }
            if let co = user?.company, !co.isEmpty       { meta["company"] = co }
            if let blog = user?.blog, !blog.isEmpty      { meta["blog"] = blog }
            var linked: [(String, String?)] = []
            if let tw = user?.twitter_username, !tw.isEmpty {
                meta["twitter"] = tw
                linked.append(("twitter", tw))
            }
            // The social accounts the owner added to the profile. One more
            // request, so only with a token: anonymously GitHub allows 60 an
            // hour, and the profile itself matters more.
            if headers["Authorization"] != nil,
               let socialURL = URL(string: "https://api.github.com/users/\(cleanedUsername)/social_accounts"),
               let social = await PluginHTTP.request(socialURL, headers: headers, on: app), social.status == 200 {
                let links = Self.socialAccounts(from: social.data)
                if !links.isEmpty { parts.append("Social accounts: " + links.prefix(6).joined(separator: ", ")) }
                linked += links.compactMap(IdentityLinks.account(at:))
            }
            if let joined = IdentityLinks.linked(linked) {
                meta["linked"] = joined
                meta["linkKind"] = "declared"
                meta["linkReason"] = "listed on the GitHub profile"
            }
            if let joinedDate { meta["since"] = joinedDate }

            var results = [PluginResult(
                source: name,
                type: "account_presence",
                confidenceScore: 1.0,
                rawData: parts.joined(separator: " | "),
                metadata: meta
            )]

            // Pivot: harvest emails from the user's public push events — commit
            // author addresses are exposed there. Best-effort; skipped on a
            // rate-limit or parse failure so it never breaks the profile result.
            if let evURL = URL(string: "https://api.github.com/users/\(cleanedUsername)/events/public"),
               let evResp = await PluginHTTP.request(evURL, headers: headers, on: app),
               evResp.status == 200 {
                for email in Self.extractCommitEmails(from: evResp.data).prefix(5) {
                    results.append(PluginResult(
                        source: "GitHub:commits",
                        type: "email",
                        confidenceScore: 0.9,
                        rawData: "Email exposed in public commits: \(email)",
                        metadata: ["email": email, "platform": "github", "username": cleanedUsername,
                                   "matchKind": "observed",
                                   "matchReason": "author address on the account's own public commits"]
                    ))
                }
            }
            return results
        } else if resp.status == 404 {
            return []
        } else {
            return [PluginResult(
                source: name,
                type: "api_rate_limit",
                confidenceScore: 0.5,
                rawData: "GitHub API limit reached or returned status: \(resp.status)"
            )]
        }
    }

    /// GitHub API headers, with `GITHUB_TOKEN` when configured: a token with
    /// no scopes at all lifts the limit from 60 requests an hour to 5,000.
    static func apiHeaders() -> [String: String] {
        var headers = ["Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"]
        if let token = try? RuntimeSecret.value("GITHUB_TOKEN"), !token.isEmpty {
            headers["Authorization"] = "Bearer \(token)"
        }
        return headers
    }

    /// Profile URLs from `/users/{name}/social_accounts`.
    static func socialAccounts(from data: Data) -> [String] {
        guard let items = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        return items.prefix(10).compactMap { $0["url"] as? String }
    }

    /// Extracts distinct real commit-author emails from a GitHub public-events
    /// JSON payload (PushEvent commits). GitHub `noreply` addresses are dropped.
    /// Pure + internal so it's unit-testable offline.
    static func extractCommitEmails(from data: Data) -> [String] {
        guard let events = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        var emails = Set<String>()
        for event in events {
            guard (event["type"] as? String) == "PushEvent",
                  let payload = event["payload"] as? [String: Any],
                  let commits = payload["commits"] as? [[String: Any]] else { continue }
            for commit in commits {
                guard let author = commit["author"] as? [String: Any],
                      let email = (author["email"] as? String)?.lowercased() else { continue }
                if email.hasSuffix("@users.noreply.github.com") { continue }
                if email.range(of: "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$", options: .regularExpression) != nil {
                    emails.insert(email)
                }
            }
        }
        return emails.sorted()
    }
}
