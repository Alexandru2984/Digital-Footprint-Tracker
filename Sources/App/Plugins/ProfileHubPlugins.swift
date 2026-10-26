import Vapor
import Foundation

/// Linktree page lookup (no key required). A Linktree page is a person's own
/// list of where else they are: every social account on it is declared there.
///
/// Page: GET https://linktr.ee/{username} → 200 | 404; the page embeds its
/// data as JSON (`__NEXT_DATA__`).
struct LinktreePlugin: FootprintPlugin {
    let name = "Linktree"
    let description = "Linktree page, with every social account it lists"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://linktr.ee/\(username)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "text/html"], timeout: 10,
                bodyMode: .prefix(maxBytes: 3 * 1_024 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, html: String(decoding: response.data, as: UTF8.self)).map { [$0] } ?? []
    }

    static func evaluate(username: String, html: String) -> PluginResult? {
        guard let match = html.firstMatch(of: #/<script id="__NEXT_DATA__" type="application/json"[^>]*>(.*?)</script>/#.dotMatchesNewlines()),
              let json = try? JSONSerialization.jsonObject(with: Data(match.output.1.utf8)) as? [String: Any],
              let page = (json["props"] as? [String: Any])?["pageProps"] as? [String: Any],
              let login = CommunityHandle.text(page["username"]), login.lowercased() == username.lowercased()
        else { return nil }
        let account = page["account"] as? [String: Any] ?? [:]
        guard account["isActive"] as? Bool != false else { return nil }
        let profileURL = "https://linktr.ee/\(login)"
        var parts = ["Linktree page found: \(profileURL)"]
        var meta = ["platform": "linktree", "username": login, "profileURL": profileURL]
        if page["isProfileVerified"] as? Bool == true { parts.append("Verified by Linktree") }
        // The title is the page's own: a name when it is not just the handle.
        if let title = CommunityHandle.text(page["pageTitle"]), !title.hasPrefix("@"),
           title.lowercased() != login.lowercased() {
            parts.append("Title: \(title)")
            meta["name"] = title
        }
        let bio = CommunityHandle.text(page["description"])
        if let bio { parts.append("Bio: \(bio.prefix(160))") }
        if let created = account["createdAt"] as? Double, created > 0 {
            let joined = ISO8601DateFormatter.string(from: Date(timeIntervalSince1970: created / 1_000), timeZone: .gmt,
                                                     formatOptions: [.withFullDate])
            parts.append("Created: \(joined)")
            meta["since"] = joined
        }
        if let country = CommunityHandle.text(account["country"]), country.count == 2,
           let name = Locale(identifier: "en_US").localizedString(forRegionCode: country) {
            parts.append("Country: \(name)")
            meta["location"] = name
        }
        if let picture = CommunityHandle.text(account["profilePictureUrl"]), picture.hasPrefix("https://") {
            meta["avatar"] = picture
        }
        let listed = ((page["socialLinks"] as? [[String: Any]] ?? []) + (page["links"] as? [[String: Any]] ?? []))
            .compactMap { $0["url"] as? String }
        if let declared = CommunityHandle.declare(CommunityHandle.accounts(in: listed), on: "Linktree", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        if let written = BioLinks.linked(in: bio, excluding: "linktree:\(login)") { meta["bioLinked"] = written }
        return PluginResult(source: "Linktree", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// Hugging Face profile lookup (no key required): the full name, the
/// organisations, and the GitHub, Twitter, LinkedIn and Bluesky accounts and
/// homepage the user filled in. Those are on the profile page only, as the
/// props of its `UserProfile` component; an organisation's page has none.
///
/// Page: GET https://huggingface.co/{username} → 200 | 404
struct HuggingFacePlugin: FootprintPlugin {
    let name = "HuggingFace"
    let description = "Hugging Face profile, with the name, organisations and accounts it lists"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://huggingface.co/\(username)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "text/html"], timeout: 10,
                bodyMode: .prefix(maxBytes: 3 * 1_024 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, html: String(decoding: response.data, as: UTF8.self)).map { [$0] } ?? []
    }

    static func evaluate(username: String, html: String) -> PluginResult? {
        guard let match = html.firstMatch(of: #/data-target="UserProfile"[^>]*data-props="([^"]*)"/#),
              let json = try? JSONSerialization.jsonObject(with: Data(unescape(String(match.output.1)).utf8)) as? [String: Any],
              let user = json["u"] as? [String: Any],
              let login = CommunityHandle.text(user["user"]), login.lowercased() == username.lowercased()
        else { return nil }
        let signup = user["signup"] as? [String: Any] ?? [:]
        let text = { (key: String) in CommunityHandle.text(signup[key]) }
        let profileURL = "https://huggingface.co/\(login)"
        var parts = ["Hugging Face account found: \(profileURL)"]
        var meta = ["platform": "huggingface", "username": login, "profileURL": profileURL]
        if let name = CommunityHandle.text(user["fullname"]), name.lowercased() != login.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        if let bio = text("details") {
            parts.append("Bio: \(bio.prefix(160))")
            if let written = BioLinks.linked(in: bio, excluding: "huggingface:\(login)") { meta["bioLinked"] = written }
        }
        if let homepage = text("homepage"), IdentityLinks.websiteDomain(homepage) != nil {
            parts.append("Homepage: \(homepage)")
            meta["blog"] = homepage
        }
        let orgs = (user["orgs"] as? [[String: Any]] ?? []).prefix(15).compactMap { CommunityHandle.text($0["name"]) }
        if !orgs.isEmpty {
            parts.append("Organizations: \(orgs.joined(separator: ", "))")
            meta["orgs"] = orgs.joined(separator: ",")
        }
        if let avatar = CommunityHandle.text(user["avatarUrl"]), avatar.hasPrefix("https://") { meta["avatar"] = avatar }
        let linked = [("github", text("github")), ("twitter", text("twitter")), ("linkedin", text("linkedin")),
                      ("bluesky", text("bluesky"))]
        if let declared = CommunityHandle.declare(linked, on: "Hugging Face", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        return PluginResult(source: "Hugging Face", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }

    /// An HTML attribute's text: the five entities a JSON attribute uses.
    static func unescape(_ value: String) -> String {
        value.replacingOccurrences(of: "&quot;", with: "\"").replacingOccurrences(of: "&#39;", with: "'")
            .replacingOccurrences(of: "&#x27;", with: "'").replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">").replacingOccurrences(of: "&amp;", with: "&")
    }
}
