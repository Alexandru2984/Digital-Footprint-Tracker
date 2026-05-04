import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
struct UsernamePlugin: FootprintPlugin {
    let name = "GitHubAccountCheck"

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
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { return [] }

            if http.statusCode == 200 {
                struct GitHubUser: Decodable { let public_repos: Int? }
                let repos = (try? JSONDecoder().decode(GitHubUser.self, from: data))?.public_repos ?? 0
                return [PluginResult(
                    source: name,
                    type: "account_presence",
                    confidenceScore: 1.0,
                    rawData: "Account found on GitHub! Profile: https://github.com/\(cleanedUsername) | Repos: \(repos)"
                )]
            } else if http.statusCode == 404 {
                return []
            } else {
                return [PluginResult(
                    source: name,
                    type: "api_rate_limit",
                    confidenceScore: 0.5,
                    rawData: "GitHub API limit reached or returned status: \(http.statusCode)"
                )]
            }
        } catch {
            return []
        }
    }
}
