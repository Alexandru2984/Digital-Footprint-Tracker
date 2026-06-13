import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Checks if a username exists on Hacker News via the Firebase REST API.
/// Returns karma, account age, and submission count — no API key required.
struct HackerNewsPlugin: FootprintPlugin {
    let name = "HackerNews"
    let description = "Hacker News profile lookup"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard username.range(of: #"^[a-zA-Z0-9_\-]{2,}$"#, options: .regularExpression) != nil else {
            return []
        }

        guard let url = URL(string: "https://hacker-news.firebaseio.com/v0/user/\(username).json") else {
            return []
        }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }

            // API returns `null` (JSON null) for non-existent users.
            if data == Data("null".utf8) { return [] }

            struct HNUser: Decodable {
                let id: String?
                let karma: Int?
                let created: Int?
                let submitted: [Int]?
            }

            guard let user = try? JSONDecoder().decode(HNUser.self, from: data),
                  let id = user.id else { return [] }

            let karma = user.karma ?? 0
            let submissions = user.submitted?.count ?? 0
            var parts = ["HackerNews account found: news.ycombinator.com/user?id=\(id)",
                         "Karma: \(karma)",
                         "Submissions: \(submissions)"]

            if let created = user.created {
                let date = Date(timeIntervalSince1970: TimeInterval(created))
                let year = Calendar.current.component(.year, from: date)
                parts.append("Member since: \(year)")
            }

            let confidence: Double = karma > 100 ? 1.0 : (karma > 0 ? 0.9 : 0.75)

            return [PluginResult(
                source: name,
                type: "account_presence",
                confidenceScore: confidence,
                rawData: parts.joined(separator: " | "),
                metadata: ["platform": "hackernews", "username": id,
                           "profileURL": "https://news.ycombinator.com/user?id=\(id)"]
            )]
        } catch {
            return []
        }
    }
}
