import Vapor
import Foundation

/// Data breaches an email address appears in, from LeakCheck's public API (no
/// key required): a second index beside XposedOrNot, with breaches the other
/// lacks. Emits the same `data_breach` shape; the profile merges the two lists
/// by breach (`Dropbox.com` here is `Dropbox` there).
///
/// API: GET https://leakcheck.io/api/public?check={email}
/// → `{"success": true, "found": N, "fields": [...], "sources": [{"name", "date"}]}`
/// or `{"success": false, "error": "Not found"}`. `fields` is what leaked
/// across all of them; `found` counts records, not breaches.
struct LeakCheckPlugin: FootprintPlugin {
    let name = "LeakCheck"
    let description = "Data breaches an email appears in (LeakCheck, free)"
    let accepts: Set<TargetShape> = [.email]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let email = EmailAddress.normalize(input) else { return [] }
        var components = URLComponents(string: "https://leakcheck.io/api/public")
        components?.queryItems = [URLQueryItem(name: "check", value: email)]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 15,
                bodyMode: .complete(maxBytes: 2 * 1_024 * 1_024), on: app
              ),
              response.status == 200 else { return [] }
        return Self.evaluate(email: email, body: response.data)
    }

    /// LeakCheck's field names, as the data classes the other breach sources use.
    static let dataClasses: [String: String] = [
        "password": "Passwords", "ssn": "Social security numbers", "dob": "Dates of birth",
        "address": "Physical addresses", "phone": "Phone numbers", "ip": "IP addresses",
        "ip1": "IP addresses", "ip2": "IP addresses", "name": "Names", "first_name": "Names",
        "last_name": "Names", "middle_name": "Names", "profile_name": "Names", "username": "Usernames",
        "gender": "Genders", "zip": "Geographic locations", "city": "Geographic locations",
        "state": "Geographic locations", "region": "Geographic locations", "country": "Geographic locations",
        "company_name": "Employers",
    ]

    static func evaluate(email: String, body: Data) -> [PluginResult] {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return [] }
        guard json["success"] as? Bool == true else {
            // "Not found" is an answer; a rate limit or a refused query is not.
            guard (json["error"] as? String)?.lowercased() == "not found" else { return [] }
            return [PluginResult(source: "LeakCheck", type: "breach_check", confidenceScore: 1.0,
                                 rawData: "No breaches found for this email address (LeakCheck).",
                                 metadata: ["email": email])]
        }
        var seen: Set<String> = []
        let breaches = (json["sources"] as? [[String: Any]] ?? []).prefix(500).compactMap { item -> (name: String, year: String?)? in
            guard let name = (item["name"] as? String)?.trimmingCharacters(in: .whitespaces), !name.isEmpty,
                  name.count <= 100, seen.insert(name.lowercased()).inserted else { return nil }
            let year = (item["date"] as? String).map { String($0.prefix(4)) }
                .flatMap { $0.range(of: #"^(19|20)\d\d$"#, options: .regularExpression) != nil ? $0 : nil }
            return (name, year)
        }
        guard !breaches.isEmpty else { return [] }
        let ordered = breaches.sorted { ($0.year ?? "0", $0.name) > ($1.year ?? "0", $1.name) }
        let summary = ordered.prefix(40).map { breach in breach.year.map { "\(breach.name) (\($0))" } ?? breach.name }
        var classes: [String] = []
        for field in json["fields"] as? [String] ?? [] {
            if let label = dataClasses[field.lowercased()], !classes.contains(label) { classes.append(label) }
        }
        classes.insert("Email addresses", at: 0)
        var meta = ["email": email, "breachCount": String(breaches.count),
                    "breaches": ordered.prefix(30).map(\.name).joined(separator: ", "),
                    "dataClasses": classes.prefix(20).joined(separator: ", ")]
        let dated = ordered.prefix(30).compactMap { breach in breach.year.map { "\(breach.name)|\($0)" } }
        if !dated.isEmpty { meta["breachDates"] = dated.joined(separator: "; ") }
        var raw = "Found in \(breaches.count) breach(es): \(summary.joined(separator: "; "))"
        if breaches.count > 40 { raw += "; and \(breaches.count - 40) more" }
        if classes.count > 1 { raw += " | Leaked: " + classes.joined(separator: ", ") }
        return [PluginResult(source: "LeakCheck", type: "data_breach", confidenceScore: 1.0,
                             rawData: raw, metadata: meta)]
    }
}
