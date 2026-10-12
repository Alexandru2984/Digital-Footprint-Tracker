import Vapor
import Foundation

/// IANA's RDAP bootstrap registry (RFC 9224): which server answers for each
/// top-level domain and each IPv4 block. Fetched on first use and kept for a
/// day; the files are small (~70 KB and ~6 KB) and change rarely.
///
/// Only `https` base URLs are used, and a lookup for something the registry
/// does not cover (`.ro` and `.de` publish no RDAP service) returns nil
/// rather than guessing a server.
actor RDAPBootstrap {
    static let shared = RDAPBootstrap()
    static let maxAge: TimeInterval = 86_400

    private var dns: (services: [[String]: [String]], fetchedAt: Date)?
    private var ipv4: (services: [[String]: [String]], fetchedAt: Date)?

    func baseURL(for target: String, isIP: Bool, app: Application) async -> String? {
        guard let services = await load(isIP: isIP, app: app) else { return nil }
        return isIP ? Self.baseURL(forIPv4: target, services: services)
                    : Self.baseURL(forDomain: target, services: services)
    }

    private func load(isIP: Bool, app: Application) async -> [[String]: [String]]? {
        let cached = isIP ? ipv4 : dns
        if let cached, Date().timeIntervalSince(cached.fetchedAt) < Self.maxAge { return cached.services }
        let path = isIP ? "ipv4.json" : "dns.json"
        guard let url = URL(string: "https://data.iana.org/rdap/\(path)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 15,
                bodyMode: .complete(maxBytes: 512 * 1_024), on: app
              ),
              response.status == 200,
              let services = Self.parse(response.data)
        else { return cached?.services }   // a stale copy beats none
        if isIP { ipv4 = (services, Date()) } else { dns = (services, Date()) }
        return services
    }

    /// `services` maps each entry's keys (TLDs or CIDR blocks) to its https
    /// base URLs, each ending in `/`.
    static func parse(_ data: Data) -> [[String]: [String]]? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let entries = json["services"] as? [[Any]] else { return nil }
        var services: [[String]: [String]] = [:]
        for entry in entries where entry.count == 2 {
            guard let keys = entry[0] as? [String], let urls = entry[1] as? [String] else { continue }
            let secure = urls.filter { $0.lowercased().hasPrefix("https://") }
                .map { $0.hasSuffix("/") ? $0 : $0 + "/" }
            if !secure.isEmpty { services[keys.map { $0.lowercased() }] = secure }
        }
        return services.isEmpty ? nil : services
    }

    /// The longest matching label suffix wins (RFC 9224 §4), so a registry
    /// for a second-level zone would beat its TLD's.
    static func baseURL(forDomain domain: String, services: [[String]: [String]]) -> String? {
        let labels = domain.lowercased().split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return nil }
        for start in 1..<labels.count {
            let suffix = labels[start...].joined(separator: ".")
            if let urls = services.first(where: { $0.key.contains(suffix) })?.value { return urls.first }
        }
        return nil
    }

    /// The most specific block containing the address wins.
    static func baseURL(forIPv4 address: String, services: [[String]: [String]]) -> String? {
        guard let ip = ipv4Value(address) else { return nil }
        var best: (prefix: Int, url: String)?
        for (blocks, urls) in services {
            for block in blocks {
                let parts = block.split(separator: "/")
                guard parts.count == 2, let network = ipv4Value(String(parts[0])),
                      let prefix = Int(parts[1]), (0...32).contains(prefix) else { continue }
                let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
                if ip & mask == network & mask, prefix > (best?.prefix ?? -1), let url = urls.first {
                    best = (prefix, url)
                }
            }
        }
        return best?.url
    }

    private static func ipv4Value(_ text: String) -> UInt32? {
        let octets = text.split(separator: ".").compactMap { UInt32($0) }
        guard octets.count == 4, octets.allSatisfy({ $0 <= 255 }) else { return nil }
        return octets.reduce(0) { $0 << 8 | $1 }
    }

    /// Test seam.
    func reset() { dns = nil; ipv4 = nil }
}
