import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses the shared size-bounded outbound client.
struct UsernamePlugin: FootprintPlugin {
    let name = "GitHubAccountCheck"
    let description = "GitHub profile lookup"

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
        guard let resp = await PluginHTTP.request(url, headers: ["Accept": "application/vnd.github+json"], on: app) else { return [] }
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
            if let created = user?.created_at?.prefix(4) { parts.append("Joined: \(created)") }

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
            if let tw = user?.twitter_username, !tw.isEmpty { meta["twitter"] = tw }
            if let created = user?.created_at?.prefix(4) { meta["since"] = String(created) }

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
               let evResp = await PluginHTTP.request(evURL, headers: ["Accept": "application/vnd.github+json"], on: app),
               evResp.status == 200 {
                for email in Self.extractCommitEmails(from: evResp.data).prefix(5) {
                    results.append(PluginResult(
                        source: "GitHub:commits",
                        type: "email",
                        confidenceScore: 0.9,
                        rawData: "Email exposed in public commits: \(email)",
                        metadata: ["email": email, "platform": "github", "username": cleanedUsername]
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
