import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }

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
                rawData: "npm maintainer: \(username) | \(result.total) package(s) found | Top: \(packageList)"
            )]
        } catch {
            return []
        }
    }
}
