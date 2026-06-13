import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Checks Steam community vanity URLs via the public XML API.
/// No API key required — Steam exposes ?xml=1 on community profile pages.
struct SteamPlugin: FootprintPlugin {
    let name = "SteamAccountCheck"
    let description = "Steam profile search (vanity URL)"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Steam vanity URLs: alphanumeric + underscore, 2–32 chars
        guard username.range(of: "^[a-zA-Z0-9_-]{2,32}$", options: .regularExpression) != nil else { return [] }

        guard let url = URL(string: "https://steamcommunity.com/id/\(username)/?xml=1") else { return [] }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("Digital-Footprint-Tracker/1.0", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }
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
            if let persona = extractTag("steamID", from: xml)           { parts.append("Persona: \(persona)") }
            if let since = extractTag("memberSince", from: xml)         { parts.append("Member since: \(since)") }
            if let location = extractTag("location", from: xml)         { parts.append("Location: \(location)") }
            if let summary = extractTag("summary", from: xml) {
                let cleaned = summary
                    .replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !cleaned.isEmpty {
                    parts.append("Summary: \(cleaned.prefix(200))")
                }
            }

            return [PluginResult(
                source: name,
                type: "account_presence",
                confidenceScore: 1.0,
                rawData: parts.joined(separator: " | ")
            )]
        } catch {
            return []
        }
    }
}
