import Vapor
import Foundation

/// Checks Steam community vanity URLs via the public XML API.
/// No API key required — Steam exposes ?xml=1 on community profile pages.
struct SteamPlugin: FootprintPlugin {
    let name = "SteamAccountCheck"
    let description = "Steam profile search (vanity URL)"
    /// Steam vanity URLs only.
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Steam vanity URLs: alphanumeric + underscore, 2–32 chars
        guard username.range(of: "^[a-zA-Z0-9_-]{2,32}$", options: .regularExpression) != nil else { return [] }

        guard let url = URL(string: "https://steamcommunity.com/id/\(username)/?xml=1") else { return [] }
        guard let response = await PluginHTTP.request(
            url,
            timeout: 10,
            bodyMode: .complete(maxBytes: 512 * 1_024),
            on: app
        ), response.status == 200 else { return [] }
        let data = response.data
        guard let xml = String(data: data, encoding: .utf8) else { return [] }

        // If the profile doesn't exist, Steam returns an <error> tag
        guard !xml.contains("<error>") else { return [] }

        func extractTag(_ tag: String, from text: String) -> String? {
            let open = "<\(tag)>"
            let close = "</\(tag)>"
            guard let r1 = text.range(of: open),
                  let r2 = text.range(of: close, range: r1.upperBound..<text.endIndex)
            else { return nil }
            let value = String(text[r1.upperBound..<r2.lowerBound])
                .replacingOccurrences(of: "<![CDATA[", with: "")
                .replacingOccurrences(of: "]]>", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return value.isEmpty ? nil : value
        }

        guard let steamID = extractTag("steamID64", from: xml) else { return [] }

        var parts: [String] = ["Steam profile: https://steamcommunity.com/id/\(username)"]
        parts.append("SteamID64: \(steamID)")
        let memberSince = extractTag("memberSince", from: xml)
        if let persona = extractTag("steamID", from: xml)           { parts.append("Persona: \(persona)") }
        if let memberSince                                          { parts.append("Member since: \(memberSince)") }
        if let location = extractTag("location", from: xml)         { parts.append("Location: \(location)") }
        if let summary = extractTag("summary", from: xml) {
            let cleaned = summary
                .replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleaned.isEmpty {
                parts.append("Summary: \(cleaned.prefix(200))")
            }
        }

        var meta: [String: String] = [
            "platform": "steam",
            "username": username,
            "profileURL": "https://steamcommunity.com/id/\(username)",
            "steamID64": steamID
        ]
        if let location = extractTag("location", from: xml) { meta["location"] = location }
        if let memberSince { meta["since"] = memberSince }

        return [PluginResult(
            source: name,
            type: "account_presence",
            confidenceScore: 1.0,
            rawData: parts.joined(separator: " | "),
            metadata: meta
        )]
    }
}
