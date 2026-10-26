import Vapor
import Foundation

/// Looks up a Bluesky profile through the public AppView API (no key required).
///
/// Two inputs, two meanings:
/// - a username `alice` is checked as `alice.bsky.social`, the default handle
///   namespace, so a hit is an account that may or may not be the target;
/// - a domain `example.com` is checked as a handle itself. Bluesky only shows
///   a domain as someone's handle after its owner proved control of it (a DNS
///   TXT record or a file on the site), so a hit ties the domain to a person.
///
/// A hit requires the profile's own `handle` to equal the one asked for. The
/// API resolves a handle to an account and then reports that account's current
/// handle, which is `handle.invalid` once the domain proof lapses: an account
/// that no longer proves the handle must not be reported as holding it.
///
/// API: GET https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}
/// Returns 200 + profile JSON, or 400 "Profile not found".
struct BlueskyPlugin: FootprintPlugin {
    let name = "BlueskyOSINT"
    let description = "Bluesky profile lookup (handles and verified domain handles)"
    let accepts: Set<TargetShape> = [.username, .domain]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let handle = Self.handle(for: input),
              var components = URLComponents(string: "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile")
        else { return [] }
        components.queryItems = [URLQueryItem(name: "actor", value: handle)]
        guard let url = components.url,
              let response = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                timeout: 10,
                bodyMode: .complete(maxBytes: 256 * 1_024),
                on: app
              ) else { return [] }
        return Self.evaluate(input: input, handle: handle, status: response.status, body: response.data)
            .map { [$0] } ?? []
    }

    /// The handle to look up for `input`, or nil when it cannot be one.
    /// Handle segments are letters, digits and hyphens (no underscores), each
    /// at most 63 characters, and a username becomes a `.bsky.social` handle.
    static func handle(for input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !value.isEmpty, value.count <= 253, !value.contains("@") else { return nil }
        let segment = #"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"#
        if value.range(of: "^\(segment)$", options: .regularExpression) != nil {
            // A bare number is a phone-shaped input, not a handle anyone picks.
            guard value.range(of: #"^[0-9]+$"#, options: .regularExpression) == nil else { return nil }
            return "\(value).bsky.social"
        }
        guard value.range(of: "^(\(segment)\\.)+[a-z][a-z0-9-]*[a-z0-9]$", options: .regularExpression) != nil
        else { return nil }
        return value
    }

    /// Pure detection, unit-testable offline: a result only for a 200 whose
    /// profile carries a DID and exactly the requested handle.
    static func evaluate(input: String, handle: String, status: Int, body: Data) -> PluginResult? {
        guard status == 200,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let did = json["did"] as? String, did.hasPrefix("did:"),
              let returned = (json["handle"] as? String)?.lowercased(),
              returned == handle
        else { return nil }

        let profileURL = "https://bsky.app/profile/\(returned)"
        let displayName = (json["displayName"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let bio = (json["description"] as? String ?? "")
            .replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let joined = (json["createdAt"] as? String).flatMap { TimelineIntelligence.normalizedDate($0)?.value }
        let verified = ((json["verification"] as? [String: Any])?["verifiedStatus"] as? String) == "valid"
        let domainHandle = !handle.hasSuffix(".bsky.social")

        var parts = [domainHandle
            ? "Bluesky account uses \(returned) as its verified domain handle: \(profileURL)"
            : "Bluesky account found: \(profileURL)"]
        if !displayName.isEmpty { parts.append("Display name: \(displayName)") }
        if let followers = json["followersCount"] as? Int { parts.append("Followers: \(followers)") }
        if let posts = json["postsCount"] as? Int { parts.append("Posts: \(posts)") }
        if let joined { parts.append("Joined: \(joined)") }
        if verified { parts.append("Verified by Bluesky") }
        if !bio.isEmpty { parts.append("Bio: \(bio.count > 160 ? String(bio.prefix(160)) + "…" : bio)") }

        var meta = ["platform": "bluesky", "username": returned, "profileURL": profileURL, "did": did]
        if !displayName.isEmpty { meta["name"] = displayName }
        if let joined { meta["since"] = joined }
        if let avatar = json["avatar"] as? String, !avatar.isEmpty { meta["avatar"] = avatar }
        if let linked = BioLinks.linked(in: bio, excluding: "bluesky:\(returned)") { meta["bioLinked"] = linked }
        if domainHandle {
            meta["domain"] = returned
            meta["matchKind"] = "verified"
            meta["matchReason"] = "the domain's owner proved it as this Bluesky handle"
        }

        return PluginResult(
            source: "Bluesky",
            type: "social_media",
            confidenceScore: 1.0,
            rawData: parts.joined(separator: " | "),
            metadata: meta
        )
    }
}
