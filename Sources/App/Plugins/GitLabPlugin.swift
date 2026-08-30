import Vapor
import Foundation

struct GitLabPlugin: FootprintPlugin {
    let name = "GitLabAccountCheck"
    let description = "GitLab profile lookup"
    /// GitLab handles only.
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard username.range(of: "^[a-zA-Z0-9_.-]{1,255}$", options: .regularExpression) != nil else { return [] }

        guard let url = URL(string: "https://gitlab.com/api/v4/users?username=\(username)") else { return [] }
        guard let response = await PluginHTTP.request(
            url,
            headers: ["Accept": "application/json"],
            timeout: 10,
            bodyMode: .complete(maxBytes: 512 * 1_024),
            on: app
        ), response.status == 200 else { return [] }
        let data = response.data

        struct GitLabUser: Decodable {
            let id: Int?
            let username: String?
            let name: String?
            let state: String?
            let web_url: String?
            let bio: String?
            let location: String?
            let website_url: String?
            let followers: Int?
            let public_repos: Int?
            let created_at: String?
            let organization: String?
        }

        guard let users = try? JSONDecoder().decode([GitLabUser].self, from: data),
              let user = users.first else { return [] }
        let joinedDate = user.created_at.flatMap { TimelineIntelligence.normalizedDate($0)?.value }

        var parts: [String] = ["GitLab profile: \(user.web_url ?? "https://gitlab.com/\(username)")"]
        if let n = user.name, !n.isEmpty                    { parts.append("Name: \(n)") }
        if let b = user.bio, !b.isEmpty                     { parts.append("Bio: \(b.prefix(120))") }
        if let loc = user.location, !loc.isEmpty            { parts.append("Location: \(loc)") }
        if let org = user.organization, !org.isEmpty        { parts.append("Org: \(org)") }
        if let web = user.website_url, !web.isEmpty         { parts.append("Website: \(web)") }
        if let followers = user.followers                   { parts.append("Followers: \(followers)") }
        if let joinedDate                                  { parts.append("Joined: \(joinedDate)") }

        var meta: [String: String] = [
            "platform": "gitlab",
            "username": user.username ?? username,
            "profileURL": user.web_url ?? "https://gitlab.com/\(username)"
        ]
        if let n = user.name, !n.isEmpty             { meta["name"] = n }
        if let loc = user.location, !loc.isEmpty     { meta["location"] = loc }
        if let org = user.organization, !org.isEmpty { meta["company"] = org }
        if let web = user.website_url, !web.isEmpty  { meta["blog"] = web }
        if let joinedDate                            { meta["since"] = joinedDate }

        return [PluginResult(
            source: name,
            type: "account_presence",
            confidenceScore: 1.0,
            rawData: parts.joined(separator: " | "),
            metadata: meta
        )]
    }
}
