import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Searches paste sites for a given username or email address.
///
/// - For **emails**: queries HaveIBeenPwned's paste API (`/pasteaccount/{email}`)
///   using the same `HIBP_API_KEY` as HaveIBeenPwnedPlugin.
/// - For **usernames**: checks whether a public Pastebin profile exists at
///   `https://pastebin.com/u/{username}` (HTTP 200 = exists).
///
/// Uses URLSession (Foundation) — lifecycle-independent, safe from asyncShutdown races.
struct PastebinPlugin: FootprintPlugin {
    let name = "PastebinOSINT"
    let description = "Pastebin / paste-site content search"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.contains("@") {
            return await scanEmail(trimmed, app: app)
        } else {
            return await scanUsername(trimmed, app: app)
        }
    }

    // MARK: - Email branch (HIBP paste API)

    private func scanEmail(_ email: String, app: Application) async -> [PluginResult] {
        guard let apiKey = Environment.get("HIBP_API_KEY"), !apiKey.isEmpty else {
            return [PluginResult(
                source: "PastebinOSINT",
                type: "paste_exposure",
                confidenceScore: 0.3,
                rawData: "Set HIBP_API_KEY in .env to enable paste site search for email addresses."
            )]
        }

        let encoded = email.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? email
        guard let url = URL(string: "https://haveibeenpwned.com/api/v3/pasteaccount/\(encoded)") else {
            return []
        }

        var req = URLRequest(url: url, timeoutInterval: 12)
        req.setValue(apiKey, forHTTPHeaderField: "hibp-api-key")
        req.setValue("DigitalFootprintTracker/1.0 (OSINT research tool)", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { return [] }

            switch http.statusCode {
            case 200:
                guard let pastes = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                    return []
                }
                let count = pastes.count
                let sources = pastes.compactMap { $0["Source"] as? String }
                let uniqueSources = Array(Set(sources)).sorted().prefix(5).joined(separator: ", ")
                let oldest = pastes.compactMap { $0["Date"] as? String }.sorted().first ?? "unknown date"

                return [PluginResult(
                    source: "PastebinOSINT",
                    type: "paste_exposure",
                    confidenceScore: 0.95,
                    rawData: "\(email) found in \(count) paste(s). Sources: \(uniqueSources.isEmpty ? "various" : uniqueSources). Earliest: \(oldest)",
                    metadata: ["email": email, "pasteCount": String(count)]
                )]
            case 404:
                // 404 means "not found in pastes" — not an error.
                return []
            case 429:
                app.logger.warning("PastebinPlugin: HIBP rate-limited (429)")
                return []
            default:
                return []
            }
        } catch {
            return []
        }
    }

    // MARK: - Username branch (Pastebin.com profile check)

    private func scanUsername(_ username: String, app: Application) async -> [PluginResult] {
        // Pastebin usernames: alphanumeric + underscore, 3-20 chars.
        guard username.count >= 3, username.count <= 20,
              username.range(of: #"^[a-zA-Z0-9_]+$"#, options: .regularExpression) != nil
        else { return [] }

        guard let url = URL(string: "https://pastebin.com/u/\(username)") else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("DigitalFootprintTracker/1.0 (OSINT research tool)", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }

            // Confirm the page actually refers to the user (not a 404 soft-redirect).
            let body = String(data: data.prefix(4096), encoding: .utf8) ?? ""
            guard body.lowercased().contains("pastebin.com/u/\(username.lowercased())") ||
                  body.lowercased().contains("\(username.lowercased())'s pastes")
            else { return [] }

            return [PluginResult(
                source: "PastebinOSINT",
                type: "paste_exposure",
                confidenceScore: 0.85,
                rawData: "Pastebin public profile found for \"\(username)\": https://pastebin.com/u/\(username)",
                metadata: ["platform": "pastebin", "username": username, "profileURL": "https://pastebin.com/u/\(username)"]
            )]
        } catch {
            return []
        }
    }
}
