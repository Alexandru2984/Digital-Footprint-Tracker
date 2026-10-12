import Foundation
import Vapor

struct WhoisPlugin: FootprintPlugin {
    let name = "WHOIS"
    let description = "RDAP / WHOIS domain registration info"
    /// WHOIS answers for registrations and for RIR IP allocations alike.
    let accepts: Set<TargetShape> = [.domain, .ipv4]
    let cacheTTL: TimeInterval = 14_400 // 4 h

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
        return Self.parseResponse(response.data, domain: target).map { [$0] } ?? []
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
