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

        do {
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

            // Extract og:title
            guard let titleRange = body.range(of: #"og:title" content="([^"]+)""#,
                                               options: .regularExpression) else { return [] }
            let titleMatch = String(body[titleRange])
            // Parse out the value between the quotes after "content="
            let titleValue: String
            if let contentRange = titleMatch.range(of: #"content="([^"]+)""#, options: .regularExpression) {
                let raw = String(titleMatch[contentRange])
                titleValue = raw.replacingOccurrences(of: "content=\"", with: "")
                                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            } else {
                return []
            }

            // Generic fallback titles mean the user doesn't exist
            let genericTitles = ["Telegram", "Telegram: Contact @\(username.lowercased())"]
            let isGeneric = genericTitles.contains { titleValue.lowercased().contains($0.lowercased()) }
                            && !body.contains("tgme_page_title")

            if isGeneric { return [] }

            // Extract og:description for extra context
            var description = ""
            if let descRange = body.range(of: #"og:description" content="([^"]+)""#, options: .regularExpression) {
                let raw = String(body[descRange])
                if let valRange = raw.range(of: #"content="([^"]+)""#, options: .regularExpression) {
                    description = String(raw[valRange])
                        .replacingOccurrences(of: "content=\"", with: "")
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                }
            }

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

            return [PluginResult(
                source: "Telegram",
                type: "social_media",
                confidenceScore: 0.9,
                rawData: parts.joined(separator: " | "),
                metadata: ["platform": "telegram", "username": username, "profileURL": "https://t.me/\(username)"]
            )]
        } catch {
            return []
        }
    }
}
