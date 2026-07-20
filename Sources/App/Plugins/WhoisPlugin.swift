import Foundation
import Vapor

struct WhoisPlugin: FootprintPlugin {
    let name = "WHOIS"
    let description = "RDAP / WHOIS domain registration info"
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
        let data = response.data
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }

        var info: [String] = []

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
                   let date = event["eventDate"] as? String {
                    let formatted = String(date.prefix(10))
                    switch action {
                    case "registration":  info.append("Registered: \(formatted)")
                    case "expiration":    info.append("Expires: \(formatted)")
                    case "last changed":  info.append("Updated: \(formatted)")
                    default: break
                    }
                }
            }
        }

        if let nameservers = json["nameservers"] as? [[String: Any]] {
            let ns = nameservers.compactMap { $0["ldhName"] as? String }.prefix(4)
            if !ns.isEmpty { info.append("Nameservers: \(ns.joined(separator: ", "))") }
        }

        if let status = json["status"] as? [String], !status.isEmpty {
            info.append("Status: \(status.prefix(3).joined(separator: ", "))")
        }

        guard !info.isEmpty else { return [] }
        return [PluginResult(
            source: "RDAP/WHOIS",
            type: "domain_registration",
            confidenceScore: 0.95,
            rawData: info.joined(separator: " | "),
            metadata: ["domain": domain]
        )]
    }
}
