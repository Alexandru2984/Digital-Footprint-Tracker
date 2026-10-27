import Vapor
import Foundation

/// Codeforces profile lookup through its official API (no key required): the
/// name, city, country and organisation a contestant gives, and when they
/// registered. A handle is matched exactly; a renamed account's old handle is
/// not followed.
///
/// API: GET https://codeforces.com/api/user.info?handles={username}&checkHistoricHandles=false
/// → `{"status": "OK", "result": [{...}]}` | 400 `{"status": "FAILED"}`
struct CodeforcesPlugin: FootprintPlugin {
    let name = "Codeforces"
    let description = "Codeforces profile, with the name, city, country and organisation"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input) else { return [] }
        var components = URLComponents(string: "https://codeforces.com/api/user.info")
        components?.queryItems = [URLQueryItem(name: "handles", value: username),
                                  URLQueryItem(name: "checkHistoricHandles", value: "false")]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 64 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any], json["status"] as? String == "OK",
              let user = (json["result"] as? [[String: Any]])?.first,
              let handle = CommunityHandle.text(user["handle"]), handle.lowercased() == username.lowercased() else { return nil }
        let text = { (key: String) in CommunityHandle.text(user[key]) }
        let profileURL = "https://codeforces.com/profile/\(handle)"
        var parts = ["Codeforces account found: \(profileURL)"]
        var meta = ["platform": "codeforces", "username": handle, "profileURL": profileURL]
        let name = [text("firstName"), text("lastName")].compactMap { $0 }.joined(separator: " ")
        if !name.isEmpty, name.lowercased() != handle.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        let place = [text("city"), text("country")].compactMap { $0 }.joined(separator: ", ")
        if !place.isEmpty {
            parts.append("Location: \(place)")
            meta["location"] = place
        }
        if let organization = text("organization") {
            parts.append("Organization: \(organization)")
            meta["company"] = organization
        }
        if let rank = text("rank") { parts.append("Rank: \(rank)" + ((user["rating"] as? Int).map { " (\($0))" } ?? "")) }
        if let registered = user["registrationTimeSeconds"] as? Double, registered > 0 {
            let since = ISO8601DateFormatter.string(from: Date(timeIntervalSince1970: registered), timeZone: .gmt,
                                                    formatOptions: [.withFullDate])
            parts.append("Registered: \(since)")
            meta["since"] = since
        }
        if let avatar = text("titlePhoto") ?? text("avatar"), avatar.hasPrefix("https://") { meta["avatar"] = avatar }
        return PluginResult(source: "Codeforces", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// LeetCode profile lookup through the GraphQL API its own pages use (no key
/// required): the real name, country, company, school and job, and the
/// GitHub, Twitter, LinkedIn and other sites the profile lists.
///
/// API: POST https://leetcode.com/graphql → `{"data": {"matchedUser": {...} | null}}`
struct LeetCodePlugin: FootprintPlugin {
    let name = "LeetCode"
    let description = "LeetCode profile, with the name, company, school and accounts it lists"
    let accepts: Set<TargetShape> = [.username]

    static let query = """
    query($u: String!) { matchedUser(username: $u) { username githubUrl twitterUrl linkedinUrl \
    profile { realName aboutMe countryName company school jobTitle websites userAvatar } } }
    """

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://leetcode.com/graphql"),
              let body = try? JSONSerialization.data(withJSONObject: ["query": Self.query, "variables": ["u": username]]),
              let response = await PluginHTTP.request(
                url, method: .POST, headers: ["Content-Type": "application/json", "Referer": "https://leetcode.com/"],
                body: body, timeout: 10, bodyMode: .complete(maxBytes: 128 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let user = (json["data"] as? [String: Any])?["matchedUser"] as? [String: Any],
              let login = CommunityHandle.text(user["username"]), login.lowercased() == username.lowercased() else { return nil }
        let profile = user["profile"] as? [String: Any] ?? [:]
        let text = { (key: String) in CommunityHandle.text(profile[key]) }
        let profileURL = "https://leetcode.com/u/\(login)/"
        var parts = ["LeetCode account found: \(profileURL)"]
        var meta = ["platform": "leetcode", "username": login, "profileURL": profileURL]
        if let name = text("realName"), name.lowercased() != login.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        if let country = text("countryName") {
            parts.append("Country: \(country)")
            meta["location"] = country
        }
        let job = text("jobTitle")
        if let company = text("company") {
            parts.append("Works at: \(company)" + (job.map { " (\($0))" } ?? ""))
            meta["company"] = company
        }
        if let school = text("school") {
            parts.append("School: \(school)")
            meta["org"] = school
        }
        if let avatar = text("userAvatar"), avatar.hasPrefix("https://") { meta["avatar"] = avatar }
        let websites = (profile["websites"] as? [String] ?? []).prefix(8).map { $0 }
        let urls = ["githubUrl", "twitterUrl", "linkedinUrl"].compactMap { CommunityHandle.text(user[$0]) } + websites
        if let declared = CommunityHandle.declare(CommunityHandle.accounts(in: urls), on: "LeetCode", into: &meta) {
            parts.append("Lists: \(declared)")
        }
        if let site = websites.first(where: { IdentityLinks.account(at: $0.hasPrefix("http") ? $0 : "https://\($0)")?.0 == "web" }) {
            meta["blog"] = site
        }
        let bio = (profile["aboutMe"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bio, !bio.isEmpty { parts.append("About: \(bio.prefix(160))") }
        if let written = BioLinks.linked(in: bio, excluding: "leetcode:\(login)") { meta["bioLinked"] = written }
        return PluginResult(source: "LeetCode", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
