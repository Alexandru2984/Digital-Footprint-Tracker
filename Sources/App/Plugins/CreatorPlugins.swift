import Vapor
import Foundation

/// TikTok profile lookup from the public profile page (no key required): the
/// display name, bio and bio link, whether TikTok verified the account, and
/// when it was created. The page embeds its data as JSON.
///
/// Page: GET https://www.tiktok.com/@{username} → 200 with `statusCode` 0
/// (found) or 10221 (no such user) in the embedded data.
struct TikTokPlugin: FootprintPlugin {
    let name = "TikTok"
    let description = "TikTok profile, with the name, bio, bio link and creation date"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://www.tiktok.com/@\(username)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "text/html", "Accept-Language": "en-US,en;q=0.9",
                               "User-Agent": CreatorPage.browserAgent],
                timeout: 12, bodyMode: .prefix(maxBytes: 2 * 1_024 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return String(bytes: response.data, encoding: .utf8).flatMap { Self.evaluate(username: username, html: $0) }.map { [$0] } ?? []
    }

    static func evaluate(username: String, html: String) -> PluginResult? {
        guard let match = html.firstMatch(of: #/<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>/#.dotMatchesNewlines()),
              let json = try? JSONSerialization.jsonObject(with: Data(match.output.1.utf8)) as? [String: Any],
              let detail = (json["__DEFAULT_SCOPE__"] as? [String: Any])?["webapp.user-detail"] as? [String: Any],
              detail["statusCode"] as? Int == 0,
              let user = (detail["userInfo"] as? [String: Any])?["user"] as? [String: Any],
              let login = CommunityHandle.text(user["uniqueId"]), login.lowercased() == username.lowercased() else { return nil }
        let profileURL = "https://www.tiktok.com/@\(login)"
        var parts = ["TikTok account found: \(profileURL)"]
        var meta = ["platform": "tiktok", "username": login, "profileURL": profileURL]
        if user["verified"] as? Bool == true { parts.append("Verified by TikTok") }
        if user["privateAccount"] as? Bool == true { parts.append("Private account") }
        if let name = CommunityHandle.text(user["nickname"]), name.lowercased() != login.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        if let created = user["createTime"] as? Double, created > 0 {
            let since = ISO8601DateFormatter.string(from: Date(timeIntervalSince1970: created), timeZone: .gmt,
                                                    formatOptions: [.withFullDate])
            parts.append("Created: \(since)")
            meta["since"] = since
        }
        let bio = (user["signature"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bio, !bio.isEmpty { parts.append("Bio: \(bio.prefix(160))") }
        if let link = CommunityHandle.text((user["bioLink"] as? [String: Any])?["link"]) {
            parts.append("Bio link: \(link)")
            CreatorPage.record(link, on: "TikTok", into: &meta)
        }
        // A signed address, longer than a profile field: valid for days.
        if let avatar = user["avatarLarger"] as? String, avatar.hasPrefix("https://"), avatar.count <= 1_000 {
            meta["avatar"] = avatar
        }
        if let written = BioLinks.linked(in: bio, excluding: "tiktok:\(login)") { meta["bioLinked"] = written }
        return PluginResult(source: "TikTok", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// YouTube channel lookup by handle from the channel's About page (no key
/// required): the channel name, description, country, join date, the links
/// the owner lists and the picture. The page embeds its data as JSON; a
/// consent cookie answers the EU consent page the way "reject all" does.
///
/// Page: GET https://www.youtube.com/@{handle}/about?hl=en → 200 | 404
struct YouTubePlugin: FootprintPlugin {
    let name = "YouTube"
    let description = "YouTube channel, with the name, description, country, join date and links"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://www.youtube.com/@\(username)/about?hl=en"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "text/html", "Accept-Language": "en-US,en;q=0.9",
                               "User-Agent": CreatorPage.browserAgent, "Cookie": "SOCS=CAI"],
                timeout: 12, bodyMode: .complete(maxBytes: 6 * 1_024 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return String(bytes: response.data, encoding: .utf8).flatMap { Self.evaluate(username: username, html: $0) }.map { [$0] } ?? []
    }

    static func evaluate(username: String, html: String) -> PluginResult? {
        guard let start = html.range(of: "var ytInitialData = "),
              let end = html.range(of: ";</script>", range: start.upperBound..<html.endIndex),
              let json = try? JSONSerialization.jsonObject(with: Data(html[start.upperBound..<end.lowerBound].utf8)) as? [String: Any],
              let channel = (json["metadata"] as? [String: Any])?["channelMetadataRenderer"] as? [String: Any],
              let vanity = CommunityHandle.text(channel["vanityChannelUrl"]),
              let handle = vanity.split(separator: "@").last.map(String.init),
              handle.lowercased() == username.lowercased() else { return nil }
        let profileURL = "https://www.youtube.com/@\(handle)"
        var parts = ["YouTube channel found: \(profileURL)"]
        var meta = ["platform": "youtube", "username": handle, "profileURL": profileURL]
        if let title = CommunityHandle.text(channel["title"]), title.lowercased() != handle.lowercased() {
            parts.append("Name: \(title)")
            meta["name"] = title
        }
        let about = first("aboutChannelViewModel", in: json) ?? [:]
        if let country = CommunityHandle.text(about["country"]) {
            parts.append("Country: \(country)")
            meta["location"] = country
        }
        if let joined = CommunityHandle.text((about["joinedDateText"] as? [String: Any])?["content"]),
           let since = joinDate(joined) {
            parts.append("Joined: \(since)")
            meta["since"] = since
        }
        if let subscribers = CommunityHandle.text(about["subscriberCountText"]) { parts.append(subscribers) }
        let links = (about["links"] as? [[String: Any]] ?? []).prefix(15).compactMap { entry -> String? in
            let link = (entry["channelExternalLinkViewModel"] as? [String: Any])?["link"] as? [String: Any]
            return CommunityHandle.text(link?["content"])
        }
        if let declared = CommunityHandle.declare(CommunityHandle.accounts(in: links), on: "YouTube", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        if let site = links.first(where: { IdentityLinks.account(at: "https://\($0)")?.0 == "web" }) { meta["blog"] = site }
        let thumbnails = (channel["avatar"] as? [String: Any])?["thumbnails"] as? [[String: Any]] ?? []
        if let avatar = thumbnails.last?["url"] as? String, avatar.hasPrefix("https://"), avatar.count <= 1_000 {
            meta["avatar"] = avatar
        }
        let bio = (channel["description"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bio, !bio.isEmpty { parts.append("Description: \(bio.prefix(160))") }
        if let written = BioLinks.linked(in: bio, excluding: "youtube:\(handle)") { meta["bioLinked"] = written }
        return PluginResult(source: "YouTube", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }

    /// "Joined Mar 21, 2008" → 2008-03-21.
    static func joinDate(_ text: String) -> String? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .gmt
        formatter.dateFormat = "MMM d, yyyy"
        let raw = text.hasPrefix("Joined ") ? String(text.dropFirst(7)) : text
        return formatter.date(from: raw).map {
            ISO8601DateFormatter.string(from: $0, timeZone: .gmt, formatOptions: [.withFullDate])
        }
    }

    /// The first value under `key` anywhere in `value`, depth first.
    static func first(_ key: String, in value: Any, depth: Int = 0) -> [String: Any]? {
        guard depth < 40 else { return nil }
        if let object = value as? [String: Any] {
            if let found = object[key] as? [String: Any] { return found }
            for child in object.values { if let found = first(key, in: child, depth: depth + 1) { return found } }
        } else if let array = value as? [Any] {
            for child in array { if let found = first(key, in: child, depth: depth + 1) { return found } }
        }
        return nil
    }
}

/// Substack profile lookup (no key required): the name, bio, the accounts the
/// writer connected (signed in to, so verified) or listed, and the domain of
/// their publication.
///
/// API: GET https://substack.com/api/v1/user/{handle}/public_profile → 200 | 404
struct SubstackPlugin: FootprintPlugin {
    let name = "Substack"
    let description = "Substack profile, with the name, bio, connected accounts and publication"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://substack.com/api/v1/user/\(username)/public_profile"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 1_024 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              json["profile_disabled"] as? Bool != true,
              let handle = CommunityHandle.text(json["handle"]), handle.lowercased() == username.lowercased() else { return nil }
        let profileURL = "https://substack.com/@\(handle)"
        var parts = ["Substack profile found: \(profileURL)"]
        var meta = ["platform": "substack", "username": handle, "profileURL": profileURL]
        if let name = CommunityHandle.text(json["name"]), name.lowercased() != handle.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        if let created = CommunityHandle.text(json["profile_set_up_at"]), created.count >= 10,
           TimelineIntelligence.normalizedDate(String(created.prefix(10))) != nil {
            meta["since"] = String(created.prefix(10))
        }
        if let photo = CommunityHandle.text(json["photo_url"]), photo.hasPrefix("https://") { meta["avatar"] = photo }
        let links = (json["userLinks"] as? [[String: Any]] ?? []).prefix(12)
        let connected = links.filter { $0["is_connected_account"] as? Bool == true }.compactMap { CommunityHandle.text($0["url"]) }
        let listed = links.filter { $0["is_connected_account"] as? Bool != true }.compactMap { CommunityHandle.text($0["url"]) }
        var verified = CommunityHandle.accounts(in: connected)
        if let twitter = CommunityHandle.text((json["twitterAccount"] as? [String: Any])?["screen_name"]),
           !verified.contains(where: { $0.0 == "twitter" }) {
            verified.append(("twitter", twitter))
        }
        if let linked = IdentityLinks.linked(verified) {
            meta["linked"] = linked
            meta["linkKind"] = "verified"
            meta["linkReason"] = "connected to the Substack profile by signing in"
            parts.append("Connected: \(linked.replacingOccurrences(of: ",", with: ", "))")
        }
        let publication = json["primaryPublication"] as? [String: Any] ?? [:]
        if let title = CommunityHandle.text(publication["name"]) { parts.append("Publication: \(title)") }
        if let domain = CommunityHandle.text(publication["custom_domain"]), IdentityLinks.websiteDomain(domain) != nil {
            parts.append("Site: \(domain)")
            meta["blog"] = domain
        }
        let bio = (json["bio"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bio, !bio.isEmpty { parts.append("Bio: \(bio.prefix(160))") }
        let written = BioLinks.merged(BioLinks.linked(in: bio, excluding: "substack:\(handle)"),
                                      IdentityLinks.linked(CommunityHandle.accounts(in: listed)))
        if let written { meta["bioLinked"] = written }
        return PluginResult(source: "Substack", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

enum CreatorPage {
    /// Profile pages serve their data to browsers; a bare client gets a shell.
    static let browserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

    /// A bio link: another account (a Linktree page, a channel) is declared;
    /// any other page is the owner's site.
    static func record(_ link: String, on site: String, into meta: inout [String: String]) {
        let url = link.hasPrefix("http") ? link : "https://\(link)"
        if let (platform, value) = IdentityLinks.account(at: url), platform != "web" {
            _ = CommunityHandle.declare([(platform, value)], on: site, into: &meta)
        } else if IdentityLinks.websiteDomain(link) != nil {
            meta["blog"] = link
        }
    }
}

/// Mixcloud profile lookup through its official API (no key required): the
/// name, city and country, bio and join date of a DJ or radio show.
///
/// API: GET https://api.mixcloud.com/{username}/ → 200 | 404
struct MixcloudPlugin: FootprintPlugin {
    let name = "Mixcloud"
    let description = "Mixcloud profile, with the name, city, country and join date"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://api.mixcloud.com/\(username)/"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 128 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let login = CommunityHandle.text(json["username"]), login.lowercased() == username.lowercased() else { return nil }
        let text = { (key: String) in CommunityHandle.text(json[key]) }
        let profileURL = "https://www.mixcloud.com/\(login)/"
        var parts = ["Mixcloud account found: \(profileURL)"]
        var meta = ["platform": "mixcloud", "username": login, "profileURL": profileURL]
        if let name = text("name"), name.lowercased() != login.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        let place = [text("city"), text("country")].compactMap { $0 }.joined(separator: ", ")
        if !place.isEmpty {
            parts.append("Location: \(place)")
            meta["location"] = place
        }
        if let created = text("created_time"), created.count >= 10,
           TimelineIntelligence.normalizedDate(String(created.prefix(10))) != nil {
            parts.append("Joined: \(created.prefix(10))")
            meta["since"] = String(created.prefix(10))
        }
        if let shows = json["cloudcast_count"] as? Int, shows > 0 { parts.append("Shows: \(shows)") }
        if let picture = CommunityHandle.text((json["pictures"] as? [String: Any])?["extra_large"]), picture.hasPrefix("https://") {
            meta["avatar"] = picture
        }
        let bio = (json["biog"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bio, !bio.isEmpty { parts.append("Bio: \(bio.prefix(160))") }
        if let written = BioLinks.linked(in: bio, excluding: "mixcloud:\(login)") { meta["bioLinked"] = written }
        return PluginResult(source: "Mixcloud", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
