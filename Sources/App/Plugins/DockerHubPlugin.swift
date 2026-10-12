import Vapor
import Foundation

/// Looks up a Docker Hub namespace (a personal account or an organization) and
/// the images it publishes, through the public Hub API (no key required).
///
/// Docker Hub now answers `/v2/users/{name}` with a 308 to `/v2/orgs/{name}`
/// for every namespace, people included; the shared client refuses redirects,
/// so the plugin asks the final endpoint directly.
///
/// API: GET https://hub.docker.com/v2/orgs/{name}             → 200 profile | 404
///      GET https://hub.docker.com/v2/repositories/{name}/   → public images
struct DockerHubPlugin: FootprintPlugin {
    let name = "DockerHub"
    let description = "Docker Hub account and published images"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let namespace = Self.namespace(for: input),
              let profileURL = URL(string: "https://hub.docker.com/v2/orgs/\(namespace)"),
              let response = await PluginHTTP.request(
                profileURL, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 64 * 1_024), on: app
              ) else { return [] }
        guard let profile = Self.parseProfile(status: response.status, body: response.data, namespace: namespace)
        else { return [] }

        var images: Images?
        // Hub's ordering is inverted from the usual convention: `pull_count`
        // sorts most-pulled first, `-pull_count` least-pulled first.
        if let reposURL = URL(string: "https://hub.docker.com/v2/repositories/\(namespace)/?page_size=5&ordering=pull_count"),
           let repos = await PluginHTTP.request(
            reposURL, headers: ["Accept": "application/json"], timeout: 10,
            bodyMode: .complete(maxBytes: 256 * 1_024), on: app
           ), repos.status == 200 {
            images = Self.parseImages(repos.data)
        }
        return [Self.result(profile: profile, images: images)]
    }

    /// Docker IDs are 4–30 lowercase letters and digits; organization names
    /// may also carry `-` and `_`. Anything else cannot be a namespace.
    static func namespace(for input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard value.range(of: #"^[a-z0-9][a-z0-9_-]{1,29}$"#, options: .regularExpression) != nil,
              value.range(of: #"^[0-9]+$"#, options: .regularExpression) == nil
        else { return nil }
        return value
    }

    struct Profile: Equatable {
        let namespace: String
        let fullName: String
        let location: String
        let company: String
        let website: String
        let joined: String?
        let verifiedPublisher: Bool
    }

    struct Images: Equatable {
        let count: Int
        let top: [String]
    }

    /// A profile only for a 200 naming exactly the namespace asked for.
    static func parseProfile(status: Int, body: Data, namespace: String) -> Profile? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              (json["orgname"] as? String)?.lowercased() == namespace
        else { return nil }
        func text(_ key: String) -> String {
            (json[key] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return Profile(
            namespace: namespace,
            fullName: text("full_name"),
            location: text("location"),
            company: text("company"),
            website: text("profile_url"),
            joined: (json["date_joined"] as? String).flatMap { TimelineIntelligence.normalizedDate($0)?.value },
            verifiedPublisher: text("badge") == "verified_publisher"
        )
    }

    static func parseImages(_ body: Data) -> Images? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let count = json["count"] as? Int else { return nil }
        let names = (json["results"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        return Images(count: count, top: Array(names.prefix(5)))
    }

    static func result(profile: Profile, images: Images?) -> PluginResult {
        let url = "https://hub.docker.com/u/\(profile.namespace)"
        var parts = ["Docker Hub account found: \(url)"]
        if !profile.fullName.isEmpty { parts.append("Name: \(profile.fullName)") }
        if !profile.company.isEmpty { parts.append("Company: \(profile.company)") }
        if !profile.location.isEmpty { parts.append("Location: \(profile.location)") }
        if !profile.website.isEmpty { parts.append("Website: \(profile.website)") }
        if let joined = profile.joined { parts.append("Joined: \(joined)") }
        if profile.verifiedPublisher { parts.append("Verified publisher") }
        if let images {
            let top = images.top.isEmpty ? "" : " (most pulled: \(images.top.joined(separator: ", ")))"
            parts.append("Public images: \(images.count)\(top)")
        }

        var meta = ["platform": "dockerhub", "username": profile.namespace, "profileURL": url]
        if !profile.fullName.isEmpty { meta["name"] = profile.fullName }
        if !profile.company.isEmpty { meta["company"] = profile.company }
        if !profile.location.isEmpty { meta["location"] = profile.location }
        if !profile.website.isEmpty { meta["blog"] = profile.website }
        if let joined = profile.joined { meta["since"] = joined }

        return PluginResult(source: "DockerHub", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
