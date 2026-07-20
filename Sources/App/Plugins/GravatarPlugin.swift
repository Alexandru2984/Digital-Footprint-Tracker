import Vapor
import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Gravatar lookup by email. Beyond confirming an avatar exists, Gravatar serves
/// a public profile JSON keyed by the email's MD5 hash that often exposes the
/// person's real name, location, and — most valuably — their *verified linked
/// accounts* (Twitter, GitHub, Facebook, …). That turns one email into a cluster
/// of cross-platform identities for free, no API key required.
struct GravatarPlugin: FootprintPlugin {
    let name = "GravatarCheck"
    let description = "Gravatar profile + verified linked accounts by email"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }

        let cleanedEmail = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = Insecure.MD5.hash(data: Data(cleanedEmail.utf8))
        let hashString = digest.map { String(format: "%02hhx", $0) }.joined()
        let avatarURL = "https://en.gravatar.com/avatar/\(hashString)?d=404"

        // Prefer the rich profile JSON (its 200 also implies the avatar exists).
        if let profileURL = URL(string: "https://gravatar.com/\(hashString).json"),
           let resp = await PluginHTTP.request(profileURL, on: app), resp.status == 200,
           let results = Self.parseProfile(resp.data, email: cleanedEmail, avatarURL: avatarURL),
           !results.isEmpty {
            return results
        }

        // Fall back to a HEAD presence check (d=404 makes a missing avatar 404).
        guard let url = URL(string: avatarURL),
              let resp = await PluginHTTP.request(url, method: .HEAD, bodyMode: .prefix(maxBytes: 0), on: app), resp.status == 200 else { return [] }
        return [PluginResult(
            source: name,
            type: "avatar_presence",
            confidenceScore: 1.0,
            rawData: "Gravatar found! URL: \(avatarURL)",
            metadata: ["email": cleanedEmail, "profileURL": avatarURL]
        )]
    }

    /// Parses the Gravatar profile JSON into a profile result plus one result per
    /// verified linked account. Pure + internal so it's unit-testable offline.
    static func parseProfile(_ data: Data, email: String, avatarURL: String) -> [PluginResult]? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let entries = json["entry"] as? [[String: Any]],
              let entry = entries.first else { return nil }

        var results: [PluginResult] = []

        let displayName = (entry["displayName"] as? String) ?? ""
        let username    = (entry["preferredUsername"] as? String) ?? ""
        let profileUrl  = (entry["profileUrl"] as? String) ?? avatarURL
        let location    = (entry["currentLocation"] as? String) ?? ""

        var meta: [String: String] = ["email": email, "profileURL": profileUrl]
        if !displayName.isEmpty { meta["name"] = displayName }
        if !username.isEmpty    { meta["username"] = username }
        if !location.isEmpty    { meta["location"] = location }

        var parts = ["Gravatar profile: \(profileUrl)"]
        if !displayName.isEmpty { parts.append("Name: \(displayName)") }
        if !username.isEmpty    { parts.append("Username: \(username)") }
        if !location.isEmpty    { parts.append("Location: \(location)") }

        results.append(PluginResult(
            source: "Gravatar",
            type: "account_presence",
            confidenceScore: 1.0,
            rawData: parts.joined(separator: " | "),
            metadata: meta
        ))

        // Verified linked accounts — the cross-platform identity gold.
        if let accounts = entry["accounts"] as? [[String: Any]] {
            for acct in accounts.prefix(15) {
                let service  = (acct["shortname"] as? String) ?? (acct["domain"] as? String) ?? "link"
                let handle   = (acct["username"] as? String) ?? (acct["display"] as? String) ?? ""
                let url      = (acct["url"] as? String) ?? ""
                let verified = (acct["verified"] as? String) == "true" || (acct["verified"] as? Bool) == true
                guard !handle.isEmpty || !url.isEmpty else { continue }

                var am: [String: String] = ["platform": service]
                if !handle.isEmpty { am["username"] = handle }
                if !url.isEmpty    { am["url"] = url }

                results.append(PluginResult(
                    source: "Gravatar:\(service)",
                    type: "identity_proof",
                    confidenceScore: verified ? 0.95 : 0.7,
                    rawData: "Linked \(service) account\(verified ? " (verified)" : ""): \(handle.isEmpty ? url : handle)",
                    metadata: am
                ))
            }
        }
        return results
    }
}
