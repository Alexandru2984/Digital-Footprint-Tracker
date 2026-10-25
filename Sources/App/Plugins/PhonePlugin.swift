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
/// Otherwise (or when that fails), answers from libphonenumber's offline data.
///
/// Responses use the shared streaming client with a strict size limit.
struct PhonePlugin: FootprintPlugin {
    let name = "PhoneOSINT"
    let description = "Phone number OSINT (carrier, region)"
    /// E.164 / bare-digit numbers only.
    let accepts: Set<TargetShape> = [.phone]
    let cacheTTL: TimeInterval = 86_400 // carrier/region data is very stable
    /// v2: phone intelligence API (line status, owner, breaches).
    /// v3: country, region and carrier offline when the API has no answer.
    let cacheVersion = 3

    // Matches E.164 (+…) or raw digit strings, 7–15 digits total.
    private static let phoneRegex = try? NSRegularExpression(
        pattern: #"^\+?[0-9]{7,15}$"#
    )

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let phoneRegex = Self.phoneRegex,
              phoneRegex.firstMatch(
                in: trimmed,
                range: NSRange(trimmed.startIndex..., in: trimmed)
              ) != nil else { return [] }

        // Normalise: strip non-digit characters for display.
        let digits = trimmed.filter { $0.isNumber }
        let e164 = trimmed.hasPrefix("+") ? trimmed : "+\(trimmed)"

        let offline = Self.offline(digits: digits, e164: e164)
        guard let apiKey = try RuntimeSecret.value("ABSTRACT_PHONE_API_KEY"), !apiKey.isEmpty else {
            return offline
        }

        // Abstract retired phonevalidation.abstractapi.com; keys are only
        // accepted by the phone intelligence API now, which also reports line
        // status, risk, breaches and sometimes the registered name.
        var components = URLComponents(string: "https://phoneintelligence.abstractapi.com/v1/")
        components?.queryItems = [URLQueryItem(name: "api_key", value: apiKey), URLQueryItem(name: "phone", value: digits)]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                timeout: 10,
                bodyMode: .complete(maxBytes: 256 * 1_024),
                on: app
              ),
              response.status == 200 else { return offline }
        let evaluated = Self.evaluate(body: response.data, fallback: e164)
        return evaluated.isEmpty ? offline : evaluated
    }

    /// What the number itself says, with no service asked: its country, the
    /// region and carrier its range was allocated to.
    static func offline(digits: String, e164: String) -> [PluginResult] {
        guard let info = PhoneLookup.lookup(digits) else {
            // `0722 123 456`: a national number, which names no country.
            let why = digits.hasPrefix("0")
                ? "it is in national format: scan it with its country code (+40 722 123 456, not 0722 123 456)"
                : "its calling code is not one in use"
            return [PluginResult(source: "PhoneFormat", type: "phone_number", confidenceScore: 0.4,
                                 rawData: "Input looks like a phone number (\(digits.count) digits), but \(why).",
                                 metadata: ["phone": digits.hasPrefix("0") ? digits : e164])]
        }
        var parts = ["Phone \(e164)", info.region.map { "\(info.country) (\($0))" } ?? info.country]
        var meta = ["phone": e164, "country": info.country, "countryCode": info.countryCode]
        if let region = info.region { meta["numberRegion"] = region }
        if let carrier = info.carrier {
            parts.append("Mobile range of \(carrier) (the original carrier; a ported number may have moved)")
            meta["carrier"] = carrier
            meta["lineType"] = "mobile"
        }
        return [PluginResult(source: "PhoneFormat", type: "phone_number", confidenceScore: 0.8,
                             rawData: parts.joined(separator: " | ") + " | offline data: libphonenumber \(PhoneData.release)",
                             metadata: meta)]
    }

    /// Pure parser for the phone intelligence response.
    static func evaluate(body: Data, fallback e164: String) -> [PluginResult] {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return [] }
        func section(_ key: String) -> [String: Any] { json[key] as? [String: Any] ?? [:] }
        func text(_ dict: [String: Any], _ key: String) -> String? {
            guard let value = (dict[key] as? String)?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { return nil }
            return value
        }
        let format = section("phone_format"), carrier = section("phone_carrier"), location = section("phone_location")
        let validation = section("phone_validation"), risk = section("phone_risk")
        let registration = section("phone_registration"), breaches = section("phone_breaches")
        let intl = text(format, "international") ?? e164

        guard validation["is_valid"] as? Bool == true else {
            return [PluginResult(source: "PhoneOSINT", type: "phone_number", confidenceScore: 0.3,
                                 rawData: "Phone number \(intl) appears invalid or unassigned.", metadata: ["phone": intl])]
        }

        let country = text(location, "country_name")
        // Where the number was allocated, not where its owner lives: kept out
        // of `location`, which identity synthesis reads as the latter.
        let region = [text(location, "city"), text(location, "region")].compactMap { $0 }.joined(separator: ", ")
        var parts = ["Phone \(intl)"]
        if let country { parts.append(region.isEmpty ? country : "\(country) (\(region))") }
        if let name = text(carrier, "name") { parts.append("Carrier: \(name)") }
        if let line = text(carrier, "line_type") { parts.append("Line: \(line)") }
        if let status = text(validation, "line_status") { parts.append("Status: \(status)") }
        if validation["is_voip"] as? Bool == true { parts.append("VoIP") }
        if risk["is_disposable"] as? Bool == true { parts.append("Disposable number") }
        if let level = text(risk, "risk_level") { parts.append("Risk: \(level)") }

        var meta = ["phone": intl]
        if let country { meta["country"] = country }
        if !region.isEmpty { meta["numberRegion"] = region }
        if let name = text(carrier, "name") { meta["carrier"] = name }
        if let line = text(carrier, "line_type") { meta["lineType"] = line }

        var results = [PluginResult(source: "PhoneOSINT", type: "phone_number", confidenceScore: 0.95,
                                    rawData: parts.joined(separator: " | "), metadata: meta)]

        // Caller-ID registration: who the line is registered to, when known.
        if let owner = text(registration, "name") {
            let kind = text(registration, "type").map { " (\($0))" } ?? ""
            results.append(PluginResult(
                source: "PhoneOSINT", type: "phone_owner", confidenceScore: 0.7,
                rawData: "\(intl) is registered to \(owner)\(kind) (caller-ID record).",
                metadata: ["phone": intl, "name": owner]))
        }

        let domains = (breaches["breached_domains"] as? [Any] ?? []).compactMap { entry -> String? in
            (entry as? String) ?? ((entry as? [String: Any])?["domain"] as? String)
        }
        let total = breaches["total_breaches"] as? Int ?? domains.count
        if total > 0 {
            var line = "\(intl) appears in \(total) known breach(es)"
            if !domains.isEmpty { line += ": \(domains.prefix(10).joined(separator: ", "))" }
            if let first = text(breaches, "date_first_breached") { line += " | First: \(first)" }
            results.append(PluginResult(
                source: "PhoneOSINT", type: "data_breach", confidenceScore: 0.9, rawData: line,
                metadata: ["phone": intl, "breaches": domains.prefix(30).joined(separator: ", ")]))
        }
        return results
    }
}
