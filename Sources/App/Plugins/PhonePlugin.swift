import Vapor
import Foundation

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
/// Responses use the shared streaming client with a strict size limit.
struct PhonePlugin: FootprintPlugin {
    let name = "PhoneOSINT"
    let description = "Phone number OSINT (carrier, region)"
    let cacheTTL: TimeInterval = 86_400 // carrier/region data is very stable

    // Matches E.164 (+…) or raw digit strings, 7–15 digits total.
    private static let phoneRegex = try? NSRegularExpression(
        pattern: #"^\+?[0-9]{7,15}$"#
    )

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let phoneRegex = PhonePlugin.phoneRegex,
              phoneRegex.firstMatch(
                in: trimmed,
                range: NSRange(trimmed.startIndex..., in: trimmed)
              ) != nil else { return [] }

        // Normalise: strip non-digit characters for display.
        let digits = trimmed.filter { $0.isNumber }
        let e164 = trimmed.hasPrefix("+") ? trimmed : "+\(trimmed)"

        guard let apiKey = try RuntimeSecret.value("ABSTRACT_PHONE_API_KEY"), !apiKey.isEmpty else {
            // No API key: return a low-confidence structural result so the UI
            // shows the operator detected a phone number without false precision.
            return [PluginResult(
                source: "PhoneFormat",
                type: "phone_number",
                confidenceScore: 0.4,
                rawData: "Input looks like a phone number (\(digits) digits). " +
                    "Configure the Abstract API credential for carrier/country lookup.",
                metadata: ["phone": e164]
            )]
        }

        guard let url = URL(string: "https://phonevalidation.abstractapi.com/v1/?api_key=\(apiKey)&phone=\(e164)") else {
            return []
        }
        guard let response = await PluginHTTP.request(
            url,
            headers: ["Accept": "application/json"],
            timeout: 10,
            bodyMode: .complete(maxBytes: 256 * 1_024),
            on: app
        ), response.status == 200 else { return [] }
        let data = response.data
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
                rawData: "Phone number \(intl) appears invalid or unassigned.",
                metadata: ["phone": intl]
            )]
        }

        return [PluginResult(
            source: "PhoneOSINT",
            type: "phone_number",
            confidenceScore: 0.95,
            rawData: "Phone \(intl) — Country: \(country), Carrier: \(carrier), Type: \(type)",
            metadata: ["phone": intl, "country": country, "carrier": carrier]
        )]
    }
}
