import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Checks if a PyPI user profile exists and retrieves their public packages.
/// Uses the public PyPI JSON API — no API key required.
struct PyPIPlugin: FootprintPlugin {
    let name = "PyPIPackages"
    let description = "PyPI package author lookup"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // PyPI usernames: alphanumeric + hyphens/underscores
        guard username.range(of: "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$", options: .regularExpression) != nil else { return [] }

        // Step 1: check if the user profile page exists
        guard let profileURL = URL(string: "https://pypi.org/user/\(username)/") else { return [] }
        var profileReq = URLRequest(url: profileURL, timeoutInterval: 10)
        profileReq.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")

        do {
            let (profileData, profileResponse) = try await URLSession.shared.data(for: profileReq)
            guard let http = profileResponse as? HTTPURLResponse, http.statusCode == 200 else { return [] }

            // Step 2: extract package names from profile HTML
            // PyPI profile page lists packages in links like /project/{name}/
            let html = String(decoding: profileData, as: UTF8.self)
            let packagePattern = #"/project/([a-zA-Z0-9._-]+)/"#
            var packageNames: [String] = []
            if let regex = try? NSRegularExpression(pattern: packagePattern) {
                let matches = regex.matches(in: html, range: NSRange(html.startIndex..., in: html))
                for match in matches.prefix(10) {
                    if let range = Range(match.range(at: 1), in: html) {
                        let pkg = String(html[range])
                        if !packageNames.contains(pkg) { packageNames.append(pkg) }
                    }
                }
            }

            var parts: [String] = ["PyPI profile: https://pypi.org/user/\(username)/"]
            if !packageNames.isEmpty {
                parts.append("\(packageNames.count) package(s): \(packageNames.prefix(5).joined(separator: ", "))")
            }

            return [PluginResult(
                source: name,
                type: "developer_identity",
                confidenceScore: packageNames.isEmpty ? 0.7 : 0.95,
                rawData: parts.joined(separator: " | "),
                metadata: ["platform": "pypi", "username": username,
                           "profileURL": "https://pypi.org/user/\(username)/"]
            )]
        } catch {
            return []
        }
    }
}
