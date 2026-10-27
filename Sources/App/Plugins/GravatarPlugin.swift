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
    /// Gravatar is keyed on an email hash.
    let accepts: Set<TargetShape> = [.email]

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

        var meta: [String: String] = ["email": email, "profileURL": profileUrl, "platform": "gravatar", "avatar": avatarURL,
                                      "matchKind": "verified",
                                      "matchReason": "the Gravatar profile is registered to this address"]
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

                var am: [String: String] = [
                    "platform": service,
                    "matchKind": verified ? "verified" : "declared",
                    "matchReason": verified ? "listed on the address's Gravatar profile and verified by Gravatar"
                                            : "listed on the address's Gravatar profile",
                ]
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

/// Gravatar profile by its username (no key required): the name, location,
/// job, company and bio the owner filled in, and the accounts Gravatar
/// verified by signing in to each (OAuth), not just the ones typed in.
///
/// API: GET https://api.gravatar.com/v3/profiles/{username} → 200 | 404
struct GravatarProfilePlugin: FootprintPlugin {
    let name = "GravatarProfile"
    let description = "Gravatar profile by username, with the accounts Gravatar verified"
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let username = CommunityHandle.validated(input),
              let url = URL(string: "https://api.gravatar.com/v3/profiles/\(username)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 256 * 1_024), on: app
              ), response.status == 200 else { return [] }
        return Self.evaluate(username: username, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(username: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let profileURL = CommunityHandle.text(json["profile_url"]), profileURL.hasPrefix("https://"),
              let slug = URL(string: profileURL)?.path.split(separator: "/").first.map(String.init),
              slug.lowercased() == username.lowercased() else { return nil }
        var parts = ["Gravatar profile found: \(profileURL)"]
        var meta = ["platform": "gravatar", "username": slug, "profileURL": profileURL]
        if let name = CommunityHandle.text(json["display_name"]), name.lowercased() != slug.lowercased() {
            parts.append("Name: \(name)")
            meta["name"] = name
        }
        if let location = CommunityHandle.text(json["location"]) {
            parts.append("Location: \(location)")
            meta["location"] = location
        }
        let job = CommunityHandle.text(json["job_title"])
        if let company = CommunityHandle.text(json["company"]) {
            parts.append("Works at: \(company)" + (job.map { " (\($0))" } ?? ""))
            meta["company"] = company
        } else if let job {
            parts.append("Job: \(job)")
        }
        let bio = (json["description"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bio, !bio.isEmpty { parts.append("Bio: \(bio.prefix(160))") }
        if let avatar = CommunityHandle.text(json["avatar_url"]), avatar.hasPrefix("https://") { meta["avatar"] = avatar }
        let verified = (json["verified_accounts"] as? [[String: Any]] ?? [])
            .filter { $0["is_hidden"] as? Bool != true }.compactMap { $0["url"] as? String }
        if let linked = IdentityLinks.linked(CommunityHandle.accounts(in: verified)) {
            meta["linked"] = linked
            meta["linkKind"] = "verified"
            meta["linkReason"] = "verified by Gravatar, which had the owner sign in to each"
            parts.append("Verified accounts: \(linked.replacingOccurrences(of: ",", with: ", "))")
        }
        if let written = BioLinks.linked(in: bio, excluding: "gravatar:\(slug)") { meta["bioLinked"] = written }
        return PluginResult(source: "Gravatar", type: "account_presence", confidenceScore: 1.0,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
