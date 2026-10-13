import Vapor
import Foundation

/// Who announces an IPv4 address on the internet: its routed prefix, origin
/// AS and the AS holder, from RIPEstat (no key required). WHOIS says who was
/// allocated a block; this says who actually routes it today, which for a
/// cloud or CDN address is the more useful answer.
///
/// API: GET https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}
struct RIPEStatPlugin: FootprintPlugin {
    let name = "RIPEstat"
    let description = "Routed prefix, origin AS and network operator of an IP"
    let accepts: Set<TargetShape> = [.ipv4]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let ip = IPv4Text.normalized(input),
              let url = URL(string: "https://stat.ripe.net/data/prefix-overview/data.json?resource=\(ip)&sourceapp=digital-footprint-tracker"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 15,
                bodyMode: .complete(maxBytes: 256 * 1_024), on: app
              ),
              response.status == 200 else { return [] }
        return Self.evaluate(ip: ip, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(ip: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let data = json["data"] as? [String: Any] else { return nil }
        let prefix = data["resource"] as? String
        let asns = (data["asns"] as? [[String: Any]] ?? []).compactMap { entry -> (Int, String)? in
            guard let asn = entry["asn"] as? Int else { return nil }
            return (asn, (entry["holder"] as? String ?? "").trimmingCharacters(in: .whitespaces))
        }
        let announced = (data["announced"] as? Bool) ?? !asns.isEmpty
        guard let prefix, !asns.isEmpty || !announced else { return nil }

        var parts: [String]
        var meta = ["ip": ip, "prefix": prefix]
        if let (asn, holder) = asns.first {
            let origin = asns.map { "AS\($0.0)" + ($0.1.isEmpty ? "" : " (\($0.1))") }.joined(separator: ", ")
            parts = ["\(ip) is routed in \(prefix) by \(origin)"]
            meta["asn"] = "AS\(asn)"
            // Not `org`: the operator of an address is not the target's employer,
            // and identity synthesis reads `org` as the latter.
            if !holder.isEmpty { meta["asnHolder"] = holder }
        } else {
            parts = ["\(ip) is in \(prefix), which no network currently announces"]
        }
        if let block = (data["block"] as? [String: Any])?["desc"] as? String, !block.isEmpty {
            parts.append(block)
        }
        return PluginResult(source: "RIPEstat", type: "ip_network", confidenceScore: 0.95,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}

/// Whether an address is seen scanning the internet, and how GreyNoise
/// classifies it (community API, no key required, rate limited per day).
///
/// A 404 is the normal "not observed" answer, not a failure. An address that
/// belongs to a known business service (GreyNoise's RIOT set, e.g. a public
/// resolver) is reported as such: that is context, not exposure.
///
/// API: GET https://api.greynoise.io/v3/community/{ip}
struct GreyNoisePlugin: FootprintPlugin {
    let name = "GreyNoise"
    let description = "Whether an IP scans the internet, and GreyNoise's classification"
    let accepts: Set<TargetShape> = [.ipv4]
    let cacheTTL: TimeInterval = 21_600

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let ip = IPv4Text.normalized(input),
              let url = URL(string: "https://api.greynoise.io/v3/community/\(ip)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/json"], timeout: 10,
                bodyMode: .complete(maxBytes: 64 * 1_024), on: app
              ),
              response.status == 200 else { return [] }
        return Self.evaluate(ip: ip, body: response.data).map { [$0] } ?? []
    }

    static func evaluate(ip: String, body: Data) -> PluginResult? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              (json["ip"] as? String) == ip else { return nil }
        let noise = json["noise"] as? Bool ?? false
        let riot = json["riot"] as? Bool ?? false
        let classification = (json["classification"] as? String ?? "unknown").lowercased()
        let actor = (json["name"] as? String ?? "").trimmingCharacters(in: .whitespaces)
        let lastSeen = (json["last_seen"] as? String).flatMap { TimelineIntelligence.normalizedDate($0)?.value }
        var meta = ["ip": ip, "classification": classification]
        if !actor.isEmpty, actor.lowercased() != "unknown" { meta["actor"] = actor }

        if noise {
            var parts = ["\(ip) is observed scanning the internet (GreyNoise: \(classification))"]
            if let named = meta["actor"] { parts.append("Actor: \(named)") }
            if let lastSeen { parts.append("Last seen: \(lastSeen)"); meta["lastSeen"] = lastSeen }
            parts.append("https://viz.greynoise.io/ip/\(ip)")
            let type = classification == "malicious" ? "ip_scanner" : "ip_scanner_benign"
            return PluginResult(source: "GreyNoise", type: type,
                                confidenceScore: classification == "malicious" ? 0.95 : 0.8,
                                rawData: parts.joined(separator: " | "), metadata: meta)
        }
        if riot {
            let service = meta["actor"].map { ": \($0)" } ?? ""
            return PluginResult(source: "GreyNoise", type: "known_service", confidenceScore: 0.9,
                                rawData: "\(ip) belongs to a known business service\(service) (GreyNoise RIOT)",
                                metadata: meta)
        }
        return nil
    }
}

/// Whether an address is a Tor exit relay right now, checked against the Tor
/// Project's published exit list. The list is downloaded and matched here, so
/// the address under investigation is never sent anywhere.
struct TorExitPlugin: FootprintPlugin {
    let name = "TorExit"
    let description = "Whether an IP is a current Tor exit relay (Tor Project list, checked locally)"
    let accepts: Set<TargetShape> = [.ipv4]
    let cacheTTL: TimeInterval = 3_600

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard let ip = IPv4Text.normalized(input),
              let exits = await TorExitList.shared.current(app: app),
              exits.contains(ip) else { return [] }
        return [PluginResult(
            source: "Tor Project", type: "tor_exit", confidenceScore: 1.0,
            rawData: "\(ip) is a Tor exit relay: traffic from it is from Tor users, not from whoever operates it.",
            metadata: ["ip": ip])]
    }
}

/// The Tor bulk exit list, refreshed at most hourly. A failed refresh keeps
/// the previous copy for up to a day rather than reporting every address as
/// "not an exit".
actor TorExitList {
    static let shared = TorExitList()
    static let refreshAfter: TimeInterval = 3_600
    static let maxStale: TimeInterval = 86_400

    private var cached: (addresses: Set<String>, fetchedAt: Date)?

    func current(app: Application) async -> Set<String>? {
        if let cached, Date().timeIntervalSince(cached.fetchedAt) < Self.refreshAfter { return cached.addresses }
        if let url = URL(string: "https://check.torproject.org/torbulkexitlist"),
           let response = await PluginHTTP.request(url, timeout: 15, bodyMode: .complete(maxBytes: 2 * 1_024 * 1_024), on: app),
           response.status == 200,
           let text = String(bytes: response.data, encoding: .utf8) {
            let addresses = Self.parse(text)
            if !addresses.isEmpty {
                cached = (addresses, Date())
                return addresses
            }
        }
        if let cached, Date().timeIntervalSince(cached.fetchedAt) < Self.maxStale { return cached.addresses }
        return nil
    }

    static func parse(_ text: String) -> Set<String> {
        Set(text.split(whereSeparator: \.isNewline).compactMap { IPv4Text.normalized(String($0)) })
    }

    /// Test seam.
    func reset() { cached = nil }
}

/// A dotted-quad IPv4 address in canonical form, or nil.
enum IPv4Text {
    static func normalized(_ text: String) -> String? {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [Int] = []
        for part in parts {
            guard (1...3).contains(part.count), part.allSatisfy(\.isASCII), let value = Int(part), (0...255).contains(value)
            else { return nil }
            octets.append(value)
        }
        return octets.map(String.init).joined(separator: ".")
    }
}
