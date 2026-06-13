import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct GitLabPlugin: FootprintPlugin {
    let name = "GitLabAccountCheck"
    let description = "GitLab profile lookup"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard username.range(of: "^[a-zA-Z0-9_.-]{1,255}$", options: .regularExpression) != nil else { return [] }

        guard let url = URL(string: "https://gitlab.com/api/v4/users?username=\(username)") else { return [] }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }

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

            var parts: [String] = ["GitLab profile: \(user.web_url ?? "https://gitlab.com/\(username)")"]
            if let n = user.name, !n.isEmpty                    { parts.append("Name: \(n)") }
            if let b = user.bio, !b.isEmpty                     { parts.append("Bio: \(b.prefix(120))") }
            if let loc = user.location, !loc.isEmpty            { parts.append("Location: \(loc)") }
            if let org = user.organization, !org.isEmpty        { parts.append("Org: \(org)") }
            if let web = user.website_url, !web.isEmpty         { parts.append("Website: \(web)") }
            if let followers = user.followers                   { parts.append("Followers: \(followers)") }
            if let year = user.created_at?.prefix(4)           { parts.append("Joined: \(year)") }

            return [PluginResult(
                source: name,
                type: "account_presence",
                confidenceScore: 1.0,
                rawData: parts.joined(separator: " | ")
            )]
        } catch {
            return []
        }
    }
}
