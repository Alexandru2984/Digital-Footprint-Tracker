import Vapor
import Foundation

/// Checks whether a Reddit account exists for a given username via the public
/// `about.json` API (no key required).
///
/// Detection validates the JSON body, not just the status code: Reddit answers
/// datacenter/VPS IPs with 403/429 or a 200 HTML "blocked" page for *any*
/// username, so a status-only check reports a hit for everyone. We require a real
/// `t2` account object whose `name` matches the queried username.
struct RedditPlugin: FootprintPlugin {
    let name = "Reddit"
    let description = "Reddit account lookup"
    /// Reddit handles only.
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: "https://www.reddit.com/user/\(username)/about.json") else { return [] }

        guard let response = await PluginHTTP.request(
            url,
            headers: ["Accept": "application/json"],
            timeout: 10,
            bodyMode: .complete(maxBytes: 128 * 1_024),
            on: app
        ) else { return [] }
        return Self.evaluate(username: username, status: response.status, body: response.data).map { [$0] } ?? []
    }

    /// Pure detection: a hit only when the body is a genuine Reddit `t2` account
    /// whose `name` matches the queried username. Rejects 403/429 blocks and any
    /// 200 that isn't a real account object. Unit-testable offline.
    static func evaluate(username: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              (json["kind"] as? String) == "t2",
              let data = json["data"] as? [String: Any],
              let name = data["name"] as? String,
              name.lowercased() == username.lowercased()
        else { return nil }

        let profile = "https://www.reddit.com/user/\(name)"
        var meta = ["platform": "reddit", "username": name, "profileURL": profile]
        let joinedDate = (data["created_utc"] as? NSNumber)
            .flatMap { TimelineIntelligence.isoDay(unixTimestamp: $0.doubleValue) }
        if let joinedDate { meta["since"] = joinedDate }
        let joinedText = joinedDate.map { " Joined: \($0)." } ?? ""
        if (data["is_suspended"] as? Bool) == true {
            return PluginResult(
                source: "Reddit", type: "account_presence", confidenceScore: 0.85,
                rawData: "Reddit account exists (suspended). Profile: \(profile).\(joinedText)", metadata: meta)
        }
        return PluginResult(
            source: "Reddit", type: "account_presence", confidenceScore: 1.0,
            rawData: "Reddit account found. Profile: \(profile).\(joinedText)", metadata: meta)
    }
}
