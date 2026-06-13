import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
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
        guard let resp = await PluginHTTP.request(url, headers: ["Accept": "application/vnd.github+json"]) else { return [] }
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

            return [PluginResult(
                source: name,
                type: "account_presence",
                confidenceScore: 1.0,
                rawData: parts.joined(separator: " | ")
            )]
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
}
