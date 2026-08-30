import Vapor
import Foundation

/// Checks whether a public Telegram account or channel exists for a given username.
///
/// Method: fetches t.me/{username} and inspects the Open Graph tags.
/// A real Telegram profile returns an `og:title` that differs from the generic
/// "Telegram" fallback. We also check for the presence of `tgme_page_title`
/// in the HTML body as a secondary confirmation.
///
/// Note: Telegram returns HTTP 200 for non-existent usernames too (soft 404),
/// so status code alone is insufficient — content validation is required.
///
/// Reads only a bounded prefix through the shared outbound client.
struct TelegramPlugin: FootprintPlugin {
    let name = "TelegramOSINT"
    let description = "Telegram username / channel search"
    /// Telegram handles only.
    let accepts: Set<TargetShape> = [.username]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@"),
              input.range(of: #"^\+?[0-9]{7,15}$"#, options: .regularExpression) == nil,
              input.range(of: #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"#,
                          options: .regularExpression) == nil
        else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Telegram usernames: 5-32 chars, alphanumeric + underscore
        guard username.count >= 5, username.count <= 32,
              username.range(of: #"^[a-zA-Z0-9_]+$"#, options: .regularExpression) != nil
        else { return [] }

        guard let url = URL(string: "https://t.me/\(username)") else { return [] }

        guard let response = await PluginHTTP.request(
            url,
            headers: [
                "User-Agent": "Mozilla/5.0 (compatible; DigitalFootprintTracker/1.0)",
                "Accept": "text/html",
            ],
            timeout: 12,
            bodyMode: .prefix(maxBytes: 8_192),
            on: app
        ), response.status == 200 else { return [] }

        // Read first 8 KB — enough for OG tags in <head>
        let body = String(data: response.data, encoding: .utf8) ?? ""

        // Negative signals: Telegram's "not found" page contains these markers
        let notFoundMarkers = [
            "tgme_page_icon_image",   // shown only on 404 pages
            "If you have Telegram, you can contact",  // generic CTA on not-found
        ]
        // If the page contains a specific "user not found" pattern, bail out
        if body.contains("tgme_page_photo_image") == false &&
           notFoundMarkers.contains(where: { body.contains($0) }) {
            return []
        }

        // Extract og:title — the profile/display name
        guard let titleValue = Self.ogContent("title", from: body) else { return [] }

        // Generic fallback titles mean the user doesn't exist
        let genericTitles = ["Telegram", "Telegram: Contact @\(username.lowercased())"]
        let isGeneric = genericTitles.contains { titleValue.lowercased().contains($0.lowercased()) }
                        && !body.contains("tgme_page_title")

        if isGeneric { return [] }

        // Extract og:description for extra context
        let description = Self.ogContent("description", from: body) ?? ""

        // Determine if it's a channel/group or a personal account
        let isChannel = body.contains("tgme_page_extra") || body.contains("subscribers") || body.contains("members")
        let accountType = isChannel ? "channel/group" : "personal account"

        var parts = ["Telegram \(accountType) found: t.me/\(username)"]
        if !titleValue.isEmpty && !titleValue.contains("Telegram") {
            parts.append("Name: \(titleValue)")
        }
        if !description.isEmpty {
            let truncDesc = description.count > 120 ? String(description.prefix(120)) + "…" : description
            parts.append("Description: \(truncDesc)")
        }

        var meta: [String: String] = ["platform": "telegram", "username": username, "profileURL": "https://t.me/\(username)"]
        // A concrete profile title (not the generic "Telegram" fallback) is the
        // account's display name — feed it into identity synthesis.
        if !titleValue.isEmpty && !titleValue.contains("Telegram") { meta["name"] = titleValue }

        return [PluginResult(
            source: "Telegram",
            type: "social_media",
            confidenceScore: 0.9,
            rawData: parts.joined(separator: " | "),
            metadata: meta
        )]
    }

    /// Extracts the `content` value of an Open Graph meta tag (`og:title`,
    /// `og:description`) from an HTML string. Pure + internal so the parsing is
    /// unit-testable offline, and shared by the title/description extraction.
    static func ogContent(_ property: String, from html: String) -> String? {
        let pattern = "og:\(property)\" content=\"([^\"]+)\""
        guard let range = html.range(of: pattern, options: .regularExpression) else { return nil }
        let match = String(html[range])
        guard let contentRange = match.range(of: "content=\"([^\"]+)\"", options: .regularExpression) else { return nil }
        return String(match[contentRange])
            .replacingOccurrences(of: "content=\"", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
    }
}
