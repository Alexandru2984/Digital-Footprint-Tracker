import Vapor
import Foundation

/// Developer communities whose public profiles list the person's other
/// accounts: what they declare there is the link.

/// DEV Community (dev.to) profile lookup (no key required).
///
/// API: GET https://dev.to/api/users/by_username?url={username} → 200 | 404
struct DevToPlugin: FootprintPlugin {
    let name = "DevTo"
    let description = "DEV Community profile, with the GitHub/Twitter accounts and site it lists"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input) else { return [] }
        var components = URLComponents(string: "https://dev.to/api/users/by_username")
        components?.queryItems = [URLQueryItem(name: "url", value: username)]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 128 * 1_024), on: app
              ) else { return [] }
        return Self.evaluate(username: username, status: response.status, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let login = json["username"] as? String, login.lowercased() == username.lowercased() else { return nil }
        let text = { (key: String) in CommunityHandle.text(json[key]) }
        let profileURL = "https://dev.to/\(login)"
        var parts = ["DEV Community account found: \(profileURL)"]
        var meta = ["platform": "devto", "username": login, "profileURL": profileURL]
        if let name = text("name") { parts.append("Name: \(name)"); meta["name"] = name }
        if let location = text("location") { parts.append("Location: \(location)"); meta["location"] = location }
        if let site = text("website_url") { parts.append("Website: \(site)"); meta["blog"] = site }
        if let joined = text("joined_at") { parts.append("Joined: \(joined)") }
        let linked = [("github", text("github_username")), ("twitter", text("twitter_username"))]
        if let declared = CommunityHandle.declare(linked, on: "DEV Community", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        return PluginResult(source: "DEV Community", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// Lobsters (lobste.rs) profile lookup (no key required). Invitation-only,
/// so an account there is a real person in the technical community.
///
/// API: GET https://lobste.rs/~{username}.json → 200 | 404
struct LobstersPlugin: FootprintPlugin {
    let name = "Lobsters"
    let description = "Lobsters profile, with the GitHub/Mastodon accounts and homepage it lists"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://lobste.rs/~\(username).json"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 128 * 1_024), on: app
              ) else { return [] }
        return Self.evaluate(username: username, status: response.status, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let login = json["username"] as? String, login.lowercased() == username.lowercased() else { return nil }
        let text = { (key: String) in CommunityHandle.text(json[key]) }
        let profileURL = "https://lobste.rs/~\(login)"
        var parts = ["Lobsters account found: \(profileURL)"]
        var meta = ["platform": "lobsters", "username": login, "profileURL": profileURL]
        if let inviter = text("invited_by_user") { parts.append("Invited by: \(inviter)") }
        if let homepage = text("homepage") { parts.append("Homepage: \(homepage)"); meta["blog"] = homepage }
        if let joined = (json["created_at"] as? String).flatMap({ TimelineIntelligence.normalizedDate($0)?.value }) {
            parts.append("Joined: \(joined)")
            meta["since"] = joined
        }
        // A Mastodon handle is only an account with its instance.
        let mastodon = text("mastodon_username").flatMap { $0.contains("@") ? $0 : nil }
        let linked = [("github", text("github_username")), ("twitter", text("twitter_username")), ("mastodon", mastodon)]
        if let declared = CommunityHandle.declare(linked, on: "Lobsters", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        return PluginResult(source: "Lobsters", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// Lichess profile lookup (no key required). Players often give their real
/// name and list their other accounts; streamers link their channels.
///
/// API: GET https://lichess.org/api/user/{username} → 200 | 404
struct LichessPlugin: FootprintPlugin {
    let name = "Lichess"
    let description = "Lichess profile, with the real name, country and accounts it lists"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://lichess.org/api/user/\(username)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 256 * 1_024), on: app
              ) else { return [] }
        return Self.evaluate(username: username, status: response.status, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              json["closed"] as? Bool != true, json["disabled"] as? Bool != true,
              let login = json["username"] as? String, login.lowercased() == username.lowercased() else { return nil }
        let profile = json["profile"] as? [String: Any] ?? [:]
        let text = { (key: String) in CommunityHandle.text(profile[key]) }
        let profileURL = "https://lichess.org/@/\(login)"
        var parts = ["Lichess account found: \(profileURL)"]
        var meta = ["platform": "lichess", "username": login, "profileURL": profileURL]
        if let title = CommunityHandle.text(json["title"]) { parts.append("Title: \(title)") }
        if let name = text("realName") { parts.append("Name: \(name)"); meta["name"] = name }
        if let location = text("location") { parts.append("Location: \(location)"); meta["location"] = location }
        if let flag = text("flag"), flag.count == 2, flag != "AQ",
           let country = Locale(identifier: "en_US").localizedString(forRegionCode: flag) {
            parts.append("Country: \(country)")
        }
        if let created = json["createdAt"] as? Double, created > 0 {
            let joined = ISO8601DateFormatter.string(from: Date(timeIntervalSince1970: created / 1_000), timeZone: .gmt,
                                                     formatOptions: [.withFullDate])
            parts.append("Joined: \(joined)")
            meta["since"] = joined
        }
        let streamer = json["streamer"] as? [String: Any] ?? [:]
        let channels = ["twitch", "youTube"].compactMap { (streamer[$0] as? [String: Any])?["channel"] as? String }
        let links = (profile["links"] as? String ?? "").split(whereSeparator: \.isNewline).map(String.init) + channels
        if let declared = CommunityHandle.declare(CommunityHandle.accounts(in: links), on: "Lichess", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        return PluginResult(source: "Lichess", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// speedrun.com profile lookup (no key required): country and region, and
/// the Twitch, YouTube and Twitter accounts the runner links.
///
/// API: GET https://www.speedrun.com/api/v1/users?lookup={username} (exact, any case)
struct SpeedrunPlugin: FootprintPlugin {
    let name = "Speedrun"
    let description = "speedrun.com profile, with the region and the channels it links"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input) else { return [] }
        var components = URLComponents(string: "https://www.speedrun.com/api/v1/users")
        components?.queryItems = [URLQueryItem(name: "lookup", value: username)]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 128 * 1_024), on: app
              ) else { return [] }
        return Self.evaluate(username: username, status: response.status, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let user = (json["data"] as? [[String: Any]])?.first,
              let login = (user["names"] as? [String: Any]).flatMap({ CommunityHandle.text($0["international"]) }),
              login.lowercased() == username.lowercased() else { return nil }
        let profileURL = CommunityHandle.text(user["weblink"]) ?? "https://www.speedrun.com/users/\(login)"
        var parts = ["speedrun.com account found: \(profileURL)"]
        var meta = ["platform": "speedrun", "username": login, "profileURL": profileURL]
        let location = user["location"] as? [String: Any]
        let place = ["region", "country"].lazy.compactMap { key in
            ((location?[key] as? [String: Any])?["names"] as? [String: Any]).flatMap { CommunityHandle.text($0["international"]) }
        }.first
        if let place { parts.append("Location: \(place)"); meta["location"] = place }
        if let signup = (user["signup"] as? String).flatMap({ TimelineIntelligence.normalizedDate($0)?.value }) {
            parts.append("Joined: \(signup)")
            meta["since"] = signup
        }
        let channels = ["twitch", "youtube", "twitter"].compactMap { (user[$0] as? [String: Any])?["uri"] as? String }
        if let declared = CommunityHandle.declare(CommunityHandle.accounts(in: channels), on: "speedrun.com", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        return PluginResult(source: "speedrun.com", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

enum CommunityHandle {
    /// Letters, digits, `_`, `-` and `.`; not a bare number (a phone shape).
    static func validated(_ input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.range(of: #"^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$"#, options: .regularExpression) != nil,
              value.range(of: #"^[0-9]+$"#, options: .regularExpression) == nil else { return nil }
        return value
    }

    static func text(_ value: Any?) -> String? {
        guard let string = (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !string.isEmpty,
              string.count <= 200 else { return nil }
        return string
    }

    /// Records the accounts a profile lists as declared links; returns them
    /// for display, nil when there are none.
    static func declare(_ pairs: [(String, String?)], on site: String, into meta: inout [String: String]) -> String? {
        guard let linked = IdentityLinks.linked(pairs.map { ($0.0, $0.1.map { $0.hasPrefix("@") ? String($0.dropFirst()) : $0 }) })
        else { return nil }
        meta["linked"] = linked
        meta["linkKind"] = "declared"
        meta["linkReason"] = "listed on the \(site) profile"
        if let twitter = pairs.first(where: { $0.0 == "twitter" })?.1 { meta["twitter"] = twitter }
        return linked.replacingOccurrences(of: ",", with: ", ")
    }

    /// The accounts profile links stand for (`github.com/ana`, a full URL),
    /// as pairs for `declare`; plain websites and unknown pages are left out.
    static func accounts(in links: [String]) -> [(String, String?)] {
        links.prefix(12).compactMap { raw -> (String, String?)? in
            let link = raw.trimmingCharacters(in: .whitespaces)
            guard !link.isEmpty, !link.hasPrefix("http://") else { return nil }
            let url = link.hasPrefix("https://") ? link : "https://\(link)"
            guard let (platform, value) = IdentityLinks.account(at: url), platform != "web" else { return nil }
            return (platform, value)
        }
    }
}
