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

        let domain = input.lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? input

        guard let url = URL(string: "https://rdap.org/domain/\(domain)") else { return [] }
        guard let response = await PluginHTTP.request(
                url,
                headers: ["Accept": "application/json"],
                timeout: 10,
                bodyMode: .complete(maxBytes: 2 * 1_024 * 1_024),
                on: app
              ),
              response.status == 200 else { return [] }
        return Self.parseResponse(response.data, domain: domain).map { [$0] } ?? []
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
            type: "domain_registration",
            confidenceScore: 0.95,
            rawData: info.joined(separator: " | "),
            metadata: metadata
        )
    }
}
