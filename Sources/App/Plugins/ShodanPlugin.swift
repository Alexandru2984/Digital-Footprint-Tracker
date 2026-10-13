import Foundation
import Vapor

/// Open ports, services and known CVEs of an IPv4 address from Shodan's host
/// record.
///
/// Uses the host lookup (`/shodan/host/{ip}`), which every API plan includes.
/// It used host *search* before, which spends query credits; a free key has
/// none, so every call was refused and the plugin always said "nothing
/// exposed". Domains reach this plugin through their resolved addresses (the
/// pivot round scans the `ip` a DNS finding reports), so it takes IPs only.
struct ShodanPlugin: FootprintPlugin {
    let name = "Shodan"
    let requiredSecret: String? = "SHODAN_API_KEY"
    let description = "Exposed ports, services and CVEs of an IP (requires API key)"
    let accepts: Set<TargetShape> = [.ipv4]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let ip = IPv4Text.normalized(input),
              let apiKey = try RuntimeSecret.value("SHODAN_API_KEY"), !apiKey.isEmpty,
              let url = URL(string: "https://api.shodan.io/shodan/host/\(ip)?key=\(apiKey)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 15,
                bodyMode: .complete(maxBytes: 4 * 1_024 * 1_024), on: app
              ),
              // 404 is "Shodan has no record of this address", not a failure.
              response.status == 200 else { return [] }
        return Self.evaluate(ip: ip, body: response.data)
    }

    /// One result per exposed service (at most 10), carrying the host's CVEs
    /// and hostnames so identity synthesis can rebuild the host view.
    static func evaluate(ip: String, body: Data) -> [PluginResult] {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              (json["ip_str"] as? String) == ip else { return [] }
        let services = json["data"] as? [[String: Any]] ?? []
        let hostCVEs = (json["vulns"] as? [String]) ?? []
        let hostnames = (json["hostnames"] as? [String] ?? []).prefix(5)
        let networkOrg = (json["org"] as? String) ?? (json["isp"] as? String)
        let country = json["country_name"] as? String

        var seenPorts: Set<String> = []
        var results: [PluginResult] = []
        for service in services {
            guard let port = service["port"] as? Int, results.count < 10 else { continue }
            let transport = (service["transport"] as? String ?? "tcp").lowercased()
            guard seenPorts.insert("\(port)/\(transport)").inserted else { continue }
            let module = (service["_shodan"] as? [String: Any])?["module"] as? String
            let product = [service["product"] as? String, service["version"] as? String]
                .compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " ")
            let serviceCVEs = ((service["vulns"] as? [String: Any])?.keys).map(Array.init) ?? []
            let cves = Array(Set(hostCVEs + serviceCVEs)).sorted()

            var parts = ["\(ip):\(port)/\(transport) open"]
            if !product.isEmpty { parts.append(product) } else if let module { parts.append(module) }
            if let networkOrg { parts.append("Network: \(networkOrg)") }
            if let country { parts.append(country) }
            if !hostnames.isEmpty { parts.append("Hostnames: \(hostnames.joined(separator: ", "))") }
            if !cves.isEmpty { parts.append("CVEs: \(cves.prefix(5).joined(separator: ", "))") }

            var meta = ["ip": ip, "port": String(port), "transport": transport]
            // Not `org`: identity synthesis reads that as the person's
            // organisation, and the operator of an address is not that.
            if let networkOrg { meta["networkOrg"] = networkOrg }
            if !product.isEmpty { meta["product"] = product }
            if !cves.isEmpty { meta["cves"] = cves.prefix(20).joined(separator: ",") }
            if !hostnames.isEmpty { meta["hostnames"] = hostnames.joined(separator: ",") }
            results.append(PluginResult(source: "Shodan", type: cves.isEmpty ? "exposed_service" : "vulnerability",
                                        confidenceScore: 0.9, rawData: parts.joined(separator: " | "), metadata: meta))
        }
        return results
    }
}
