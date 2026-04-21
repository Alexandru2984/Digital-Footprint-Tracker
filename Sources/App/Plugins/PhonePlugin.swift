import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Detects phone number inputs and performs basic OSINT.
///
/// Accepts inputs that look like phone numbers:
///   - E.164 format: `+1234567890` (starts with `+`, 7–15 digits)
///   - Digit-only:   `1234567890` (7–15 digits, no letters)
///
/// If `ABSTRACT_PHONE_API_KEY` is set in the environment, validates the number
/// via AbstractAPI Phone Validation (https://app.abstractapi.com/api/phone-validation).
/// Otherwise, returns a structural-analysis result only.
///
/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
struct PhonePlugin: FootprintPlugin {
    let name = "PhoneOSINT"

    // Matches E.164 (+…) or raw digit strings, 7–15 digits total.
    private static let phoneRegex = try! NSRegularExpression(
        pattern: #"^\+?[0-9]{7,15}$"#
    )

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)

        guard PhonePlugin.phoneRegex.firstMatch(
            in: trimmed,
            range: NSRange(trimmed.startIndex..., in: trimmed)
        ) != nil else { return [] }

        // Normalise: strip non-digit characters for display.
        let digits = trimmed.filter { $0.isNumber }
        let e164 = trimmed.hasPrefix("+") ? trimmed : "+\(trimmed)"

        guard let apiKey = Environment.get("ABSTRACT_PHONE_API_KEY"), !apiKey.isEmpty else {
            // No API key: return a low-confidence structural result so the UI
            // shows the operator detected a phone number without false precision.
            return [PluginResult(
                source: "PhoneFormat",
                type: "phone_number",
                confidenceScore: 0.4,
                rawData: "Input looks like a phone number (\(digits) digits). " +
                    "Set ABSTRACT_PHONE_API_KEY in .env for carrier/country lookup."
            )]
        }

        guard let url = URL(string: "https://phonevalidation.abstractapi.com/v1/?api_key=\(apiKey)&phone=\(e164)") else {
            return []
        }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }

            let valid   = json["valid"]   as? Bool   ?? false
            let country = (json["country"] as? [String: Any])?["name"] as? String ?? "Unknown"
            let carrier = json["carrier"] as? String ?? "Unknown"
            let type    = json["type"]    as? String ?? "Unknown"
            let format  = json["format"]  as? [String: Any]
            let intl    = format?["international"] as? String ?? e164

            guard valid else {
                return [PluginResult(
                    source: "PhoneOSINT",
                    type: "phone_number",
                    confidenceScore: 0.3,
                    rawData: "Phone number \(intl) appears invalid or unassigned."
                )]
            }

            return [PluginResult(
                source: "PhoneOSINT",
                type: "phone_number",
                confidenceScore: 0.95,
                rawData: "Phone \(intl) — Country: \(country), Carrier: \(carrier), Type: \(type)"
            )]
        } catch {
            return []
        }
    }
}
