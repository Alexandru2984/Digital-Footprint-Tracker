import Vapor
import Foundation

/// Data breaches an email address appears in, from XposedOrNot's free API
/// (no key required). Emits the same `data_breach` shape as the HIBP plugin,
/// so breach names, the data each exposed and when feed the profile, the
/// timeline and the risk score the same way.
///
/// API: GET https://api.xposedornot.com/v1/breach-analytics?email={email}
/// (an address in no breach answers 200 with `ExposedBreaches: null`).
struct XposedOrNotPlugin: FootprintPlugin {
    let name = "XposedOrNot"
    let description = "Data breaches an email appears in (XposedOrNot, free)"
    let accepts: Set<TargetShape> = [.email]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let email = EmailAddress.normalize(input) else { return [] }
        var components = URLComponents(string: "https://api.xposedornot.com/v1/breach-analytics")
        components?.queryItems = [URLQueryItem(name: "email", value: email)]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 20,
                bodyMode: .complete(maxBytes: 4 * 1_024 * 1_024), on: app
              ),
              response.status == 200 else { return [] }
        return Self.evaluate(email: email, body: response.data)
    }

    struct Breach: Equatable {
        let name: String
        let year: String?
        let records: Int?
        let exposed: [String]
        let plaintextPasswords: Bool
    }

    static func parse(_ body: Data) -> [Breach]? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
        guard let exposed = json["ExposedBreaches"] as? [String: Any],
              let details = exposed["breaches_details"] as? [[String: Any]] else {
            // `ExposedBreaches: null`: checked, and in no breach.
            return json.keys.contains("ExposedBreaches") ? [] : nil
        }
        return details.prefix(300).compactMap { item -> Breach? in
            guard let name = (item["breach"] as? String)?.trimmingCharacters(in: .whitespaces), !name.isEmpty,
                  name.count <= 100 else { return nil }
            let year = (item["xposed_date"] as? String).flatMap {
                $0.range(of: #"^(19|20)\d\d$"#, options: .regularExpression) != nil ? $0 : nil
            }
            let classes = (item["xposed_data"] as? String ?? "").split(separator: ";")
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty && $0.count <= 60 }
            let risk = (item["password_risk"] as? String ?? "").lowercased()
            return Breach(name: name, year: year, records: item["xposed_records"] as? Int,
                          exposed: classes, plaintextPasswords: risk == "plaintext" || risk == "easytocrack")
        }
    }

    static func evaluate(email: String, body: Data) -> [PluginResult] {
        guard let breaches = parse(body) else { return [] }
        guard !breaches.isEmpty else {
            return [PluginResult(source: "XposedOrNot", type: "breach_check", confidenceScore: 1.0,
                                 rawData: "No breaches found for this email address (XposedOrNot).",
                                 metadata: ["email": email])]
        }
        // Newest first: what leaked recently matters most.
        let ordered = breaches.sorted { ($0.year ?? "0", $0.name) > ($1.year ?? "0", $1.name) }
        let summary = ordered.prefix(40).map { breach -> String in
            var bits: [String] = []
            if let year = breach.year { bits.append(year) }
            if let records = breach.records { bits.append("\(records) accounts") }
            return bits.isEmpty ? breach.name : "\(breach.name) (\(bits.joined(separator: ", ")))"
        }.joined(separator: "; ")
        let classes = Set(breaches.flatMap(\.exposed)).sorted()
        var meta = ["email": email, "breachCount": String(breaches.count),
                    "breaches": ordered.prefix(30).map(\.name).joined(separator: ", ")]
        if !classes.isEmpty { meta["dataClasses"] = classes.prefix(20).joined(separator: ", ") }
        let dated = ordered.prefix(30).compactMap { breach in breach.year.map { "\(breach.name)|\($0)" } }
        if !dated.isEmpty { meta["breachDates"] = dated.joined(separator: "; ") }
        let weak = breaches.filter(\.plaintextPasswords).map(\.name)
        var raw = "Found in \(breaches.count) breach(es): \(summary)"
        if breaches.count > 40 { raw += "; and \(breaches.count - 40) more" }
        if !weak.isEmpty {
            raw += " | Passwords stored in plain text or easy to crack in: " + weak.prefix(10).joined(separator: ", ")
            meta["weakPasswordBreaches"] = weak.prefix(20).joined(separator: ", ")
        }
        return [PluginResult(source: "XposedOrNot", type: "data_breach", confidenceScore: 1.0,
                             rawData: raw, metadata: meta)]
    }
}
