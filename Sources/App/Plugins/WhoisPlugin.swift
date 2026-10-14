import Foundation
import Vapor

struct WhoisPlugin: FootprintPlugin {
    let name = "WHOIS"
    let description = "RDAP / WHOIS domain registration info"
    /// WHOIS answers for registrations and for RIR IP allocations alike.
    let accepts: Set<TargetShape> = [.domain, .ipv4]
    let cacheTTL: TimeInterval = 14_400 // 4 h
    /// v2: registry found through the IANA bootstrap; IP networks typed apart.
    /// v3: the registrant, from the registry or the registrar's RDAP server.
    let cacheVersion = 3

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("."), !input.contains("@"),
              !input.hasPrefix("http") else { return [] }

        let target = input.lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? input
        let isIP = target.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil

        // rdap.org only redirects to the registry's own server, and the shared
        // client follows no redirects, so every lookup through it came back
        // empty. Ask the registry directly, found through IANA's bootstrap.
        guard let base = await RDAPBootstrap.shared.baseURL(for: target, isIP: isIP, app: app),
              let url = URL(string: base + (isIP ? "ip/" : "domain/") + target),
              let response = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/rdap+json, application/json"],
                timeout: 10,
                bodyMode: .complete(maxBytes: 2 * 1_024 * 1_024),
                on: app
              ),
              response.status == 200 else { return [] }
        var results = Self.parseResponse(response.data, domain: target).map { [$0] } ?? []
        guard !isIP else { return results }

        // Thin registries (.com, .net) keep only the registrar; the registrant
        // lives on the registrar's own RDAP server, which the registry links.
        var registrant = Self.registrant(in: response.data, domain: target)
        if registrant == nil, let related = Self.registrarLink(in: response.data),
           let answer = await PluginHTTP.request(
               related, headers: ["Accept": "application/rdap+json, application/json"], timeout: 10,
               bodyMode: .complete(maxBytes: 2 * 1_024 * 1_024), on: app
           ), answer.status == 200 {
            registrant = Self.registrant(in: answer.data, domain: target)
        }
        if let registrant { results.append(registrant) }
        return results
    }

    /// The registrar's RDAP record for the domain, as linked by the registry:
    /// https only, and only a link that says it is RDAP.
    static func registrarLink(in data: Data) -> URL? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let links = json["links"] as? [[String: Any]] else { return nil }
        return links.lazy.compactMap { link -> URL? in
            guard (link["rel"] as? String) == "related",
                  (link["type"] as? String)?.contains("rdap") ?? false,
                  let href = link["href"] as? String, href.hasPrefix("https://"),
                  let url = URL(string: href), url.host != nil else { return nil }
            return url
        }.first
    }

    /// Words registries and privacy services put where the registrant was.
    private static let redactionMarkers = [
        "redacted", "privacy", "private", "protected", "withheld", "not disclosed", "proxy", "gdpr",
        "masking", "please query", "please contact", "whoisguard", "anonymi", "hidden", "n/a", "not available",
        "data protection", "contact the registrar", "identity protect",
    ]

    static func isRedacted(_ value: String) -> Bool {
        let lower = value.lowercased()
        return lower.count < 2 || redactionMarkers.contains { lower.contains($0) }
    }

    /// Who registered the domain, when the record says so. Most gTLD records
    /// are redacted since GDPR; organisations, many ccTLDs and older
    /// registrations still name the holder.
    static func registrant(in data: Data, domain: String) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        func entities(_ object: [String: Any]) -> [[String: Any]] {
            let direct = object["entities"] as? [[String: Any]] ?? []
            return direct + direct.flatMap { entities($0) }
        }
        guard let entity = entities(json).first(where: { ($0["roles"] as? [String])?.contains("registrant") ?? false }),
              let properties = (entity["vcardArray"] as? [Any])?.dropFirst().first as? [[Any]] else { return nil }

        func text(_ field: String) -> String? {
            guard let prop = properties.first(where: { ($0.first as? String) == field }),
                  let value = prop.last as? String else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty || isRedacted(trimmed) ? nil : String(trimmed.prefix(200))
        }
        let org = text("org")
        let name = text("fn").flatMap { $0.caseInsensitiveCompare(org ?? "") == .orderedSame ? nil : $0 }
        let email = text("email").map { $0.lowercased().replacingOccurrences(of: "mailto:", with: "") }
            .flatMap { $0.range(of: #"^[^@\s]+@[^@\s]+\.[a-z]{2,}$"#, options: .regularExpression) == nil ? nil : $0 }
        // `adr` is [name, params, type, [po box, ext, street, city, region, code, country]];
        // registries also put the country in the parameter `cc`.
        var country: String?
        if let adr = properties.first(where: { ($0.first as? String) == "adr" }) {
            let parts = (adr.last as? [Any])?.compactMap { $0 as? String } ?? []
            let params = adr.count > 1 ? adr[1] as? [String: Any] : nil
            country = [parts.last, params?["cc"] as? String].compactMap { $0 }
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .first { !$0.isEmpty && !isRedacted($0) }
        }
        guard name != nil || org != nil || email != nil else { return nil }

        var parts = ["Registrant of \(domain)"]
        var meta = ["platform": "domain", "account": domain, "domain": domain, "matchKind": "verified",
                    "matchReason": "the registration record names this holder"]
        if let name { parts.append("Name: \(name)"); meta["name"] = name }
        if let org { parts.append("Organization: \(org)"); meta["org"] = org }
        if let email {
            parts.append("Email: \(email)")
            meta["email"] = email
            meta["linked"] = "email:\(email)"
            meta["linkKind"] = "declared"
            meta["linkReason"] = "the registration record gives this contact address"
        }
        if let country { parts.append("Country: \(country)"); meta["location"] = country }
        return PluginResult(source: "RDAP/WHOIS", type: "domain_registrant", confidenceScore: 0.9,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }

    /// Pure RDAP response parser. Important event dates are retained as
    /// structured metadata so timeline consumers do not need to scrape raw text.
    static func parseResponse(_ data: Data, domain: String) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }

        var info: [String] = []
        var metadata = ["domain": domain]
        var registrationDates: [String] = []
        var expirationDates: [String] = []
        var changedDates: [String] = []

        if let entities = json["entities"] as? [[String: Any]] {
            for entity in entities {
                let roles = (entity["roles"] as? [String]) ?? []
                if roles.contains("registrar"),
                   let vcardArray = entity["vcardArray"] as? [Any],
                   let vcardProps = vcardArray.dropFirst().first as? [[Any]] {
                    for prop in vcardProps {
                        if (prop.first as? String) == "fn",
                           let name = prop.last as? String {
                            info.append("Registrar: \(name)")
                        }
                    }
                }
            }
        }

        if let events = json["events"] as? [[String: Any]] {
            for event in events {
                if let action = event["eventAction"] as? String,
                   let date = event["eventDate"] as? String,
                   let normalized = TimelineIntelligence.normalizedDate(date)?.value {
                    switch action.lowercased() {
                    case "registration":
                        registrationDates.append(normalized)
                        info.append("Registered: \(normalized)")
                    case "expiration":
                        expirationDates.append(normalized)
                        info.append("Expires: \(normalized)")
                    case "last changed":
                        changedDates.append(normalized)
                        info.append("Updated: \(normalized)")
                    default: break
                    }
                }
            }
        }
        metadata["registrationDate"] = registrationDates.min()
        metadata["expirationDate"] = expirationDates.max()
        metadata["lastChangedDate"] = changedDates.max()

        // An IP network object: who holds the block, and its range.
        if (json["objectClassName"] as? String) == "ip network" {
            if let name = json["name"] as? String, !name.isEmpty { info.insert("Network: \(name)", at: 0) }
            if let start = json["startAddress"] as? String, let end = json["endAddress"] as? String {
                info.append("Range: \(start) – \(end)")
            }
        }

        if let nameservers = json["nameservers"] as? [[String: Any]] {
            let ns = nameservers.compactMap { $0["ldhName"] as? String }.prefix(4)
            if !ns.isEmpty { info.append("Nameservers: \(ns.joined(separator: ", "))") }
        }

        if let status = json["status"] as? [String], !status.isEmpty {
            info.append("Status: \(status.prefix(3).joined(separator: ", "))")
        }

        guard !info.isEmpty else { return nil }
        return PluginResult(
            source: "RDAP/WHOIS",
            type: (json["objectClassName"] as? String) == "ip network" ? "whois_record" : "domain_registration",
            confidenceScore: 0.95,
            rawData: info.joined(separator: " | "),
            metadata: metadata
        )
    }
}
