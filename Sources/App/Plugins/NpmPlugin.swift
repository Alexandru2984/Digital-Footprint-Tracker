import Vapor
import Foundation

/// Searches npm registry for packages maintained by a given username.
/// Uses the public npm search API — no API key required.
struct NpmPlugin: FootprintPlugin {
    let name = "NpmPackages"
    let description = "npm package author lookup"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // npm usernames: alphanumeric, hyphens, up to 214 chars
        guard username.range(of: "^[a-z0-9][a-z0-9._-]{0,213}$", options: .regularExpression) != nil else { return [] }

        let encoded = username.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? username
        guard let url = URL(string: "https://registry.npmjs.org/-/v1/search?text=maintainer:\(encoded)&size=5") else { return [] }

        guard let response = await PluginHTTP.request(
            url,
            headers: ["Accept": "application/json"],
            timeout: 10,
            bodyMode: .complete(maxBytes: 1 * 1_024 * 1_024),
            on: app
        ), response.status == 200 else { return [] }
        let data = response.data

        struct NpmObject: Decodable {
            struct Package: Decodable {
                let name: String?
                let description: String?
                let version: String?
                let links: Links?
                struct Links: Decodable {
                    let npm: String?
                }
            }
            let package: Package
        }
        struct NpmSearch: Decodable {
            let objects: [NpmObject]
            let total: Int
        }

        guard let result = try? JSONDecoder().decode(NpmSearch.self, from: data),
              result.total > 0 else { return [] }

        let packageList = result.objects.compactMap { obj -> String? in
            guard let name = obj.package.name else { return nil }
            if let desc = obj.package.description, !desc.isEmpty {
                return "\(name) — \(desc.prefix(80))"
            }
            return name
        }.joined(separator: "; ")

        return [PluginResult(
            source: name,
            type: "developer_identity",
            confidenceScore: 0.9,
            rawData: "npm maintainer: \(username) | \(result.total) package(s) found | Top: \(packageList)",
            metadata: ["platform": "npm", "username": username]
        )]
    }
}
