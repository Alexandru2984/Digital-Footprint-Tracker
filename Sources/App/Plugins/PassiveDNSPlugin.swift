import Foundation
import Vapor

struct PassiveDNSPlugin: FootprintPlugin {
    let name = "PassiveDNS"
    let description = "Historical DNS and subdomain discovery"
    /// hostsearch maps a domain's names to addresses; reverseiplookup lists
    /// the names an address serves; mnemonic's passive DNS remembers when.
    let accepts: Set<TargetShape> = [.domain, .ipv4]
    /// v2: an address lists the domains it serves, not itself as a subdomain.
    /// v3: a domain's past addresses; mnemonic when hackertarget's quota is spent.
    let cacheVersion = 3

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains(".") && !input.contains("@") else { return [] }
        if Self.isIPv4(input) {
            let served = await cohosted(on: input, app: app)
            if !served.isEmpty { return served }
            let names = await Self.observations(of: input, app: app)
                .filter { $0.answer == input }.map(\.query)
            return Self.parseCohosted(names.joined(separator: "\n"), ip: input)
        }
        async let observed = Self.observations(of: input, app: app)
        var results = await hostsearch(input, app: app)
        if let history = Self.history(of: input, from: await observed) { results.append(history) }
        return results
    }

    private func hostsearch(_ input: String, app: Application) async -> [PluginResult] {
        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? input
        guard let url = URL(string: "https://api.hackertarget.com/hostsearch/?q=\(encoded)") else { return [] }

        guard let response = await PluginHTTP.request(
                url,
                timeout: 15,
                bodyMode: .complete(maxBytes: 512 * 1_024),
                on: app
              ),
              response.status == 200 else { return [] }
        let responseData = response.data
        guard let text = String(data: responseData, encoding: .utf8),
              !text.contains("error"),
              !text.contains("API count exceeded") else { return [] }

        var results: [PluginResult] = []
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines.prefix(20) {
            let lineStr = String(line)
            guard let commaIdx = lineStr.firstIndex(of: ",") else { continue }
            let hostname = String(lineStr[lineStr.startIndex..<commaIdx])
            let ip = String(lineStr[lineStr.index(after: commaIdx)...])
            guard !hostname.isEmpty, !ip.isEmpty else { continue }
            results.append(PluginResult(
                source: "PassiveDNS",
                type: "subdomain_ip",
                confidenceScore: 0.85,
                rawData: "Subdomain: \(hostname) → IP: \(ip)",
                metadata: ["subdomain": hostname, "ip": ip]
            ))
        }
        return results
    }

    /// The domains an address serves: on a dedicated server, the owner's
    /// other sites; on shared hosting, neighbours (hence never a pivot).
    private func cohosted(on ip: String, app: Application) async -> [PluginResult] {
        guard let url = URL(string: "https://api.hackertarget.com/reverseiplookup/?q=\(ip)"),
              let response = await PluginHTTP.request(url, timeout: 15, bodyMode: .complete(maxBytes: 512 * 1_024), on: app),
              response.status == 200,
              let text = String(data: response.data, encoding: .utf8) else { return [] }
        return Self.parseCohosted(text, ip: ip)
    }

    static func parseCohosted(_ text: String, ip: String) -> [PluginResult] {
        let hosts = text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { host in
                host != ip && !isIPv4(host) && host.count <= 253
                    && host.range(of: #"^[a-z0-9-]+(\.[a-z0-9-]+)+$"#, options: .regularExpression) != nil
            }
        guard !hosts.isEmpty else { return [] }
        let shown = Array(hosts.prefix(30))
        var raw = "Domains served by \(ip): " + shown.joined(separator: ", ")
        if hosts.count > shown.count { raw += " and \(hosts.count - shown.count) more" }
        return [PluginResult(source: "PassiveDNS", type: "cohosted_domain", confidenceScore: 0.8, rawData: raw,
                             metadata: ["ip": ip, "domains": shown.joined(separator: ", "), "count": String(hosts.count)])]
    }

    struct Observation: Equatable {
        let query: String
        let answer: String
        let firstSeen: Date
        let lastSeen: Date
    }

    /// A records mnemonic's sensors saw for `name` (a domain, or an address
    /// as the answer), with when. Free and keyless, at a modest daily quota.
    static func observations(of name: String, app: Application) async -> [Observation] {
        guard let url = URL(string: "https://api.mnemonic.no/pdns/v3/\(name)?limit=100"),
              let response = await PluginHTTP.request(url, headers: ["Accept": "application/json"], timeout: 15,
                                                      bodyMode: .complete(maxBytes: 1_024 * 1_024), on: app),
              response.status == 200 else { return [] }
        return parseObservations(response.data)
    }

    static func parseObservations(_ data: Data) -> [Observation] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rows = json["data"] as? [[String: Any]] else { return [] }
        return rows.compactMap { row in
            guard (row["rrtype"] as? String)?.lowercased() == "a",
                  let query = (row["query"] as? String)?.lowercased(), let answer = row["answer"] as? String,
                  isIPv4(answer), let first = row["firstSeenTimestamp"] as? Double,
                  let last = row["lastSeenTimestamp"] as? Double else { return nil }
            return Observation(query: query, answer: answer, firstSeen: Date(timeIntervalSince1970: first / 1_000),
                               lastSeen: Date(timeIntervalSince1970: last / 1_000))
        }
    }

    /// Where `domain` pointed over time, newest first. An address it left
    /// behind a CDN for may still be its origin server.
    static func history(of domain: String, from observations: [Observation]) -> PluginResult? {
        var spans: [String: (first: Date, last: Date)] = [:]
        for seen in observations where seen.query == domain.lowercased() {
            let span = spans[seen.answer]
            spans[seen.answer] = (min(span?.first ?? seen.firstSeen, seen.firstSeen), max(span?.last ?? seen.lastSeen, seen.lastSeen))
        }
        guard !spans.isEmpty else { return nil }
        let month = DateFormatter()
        month.locale = Locale(identifier: "en_US_POSIX")
        month.timeZone = TimeZone(identifier: "UTC")
        month.dateFormat = "yyyy-MM"
        let ordered = spans.sorted { $0.value.last > $1.value.last }.prefix(15)
        let lines = ordered.map { ip, span in
            "\(ip)\(SharedEdge.contains(ip) ? " (CDN)" : "") \(month.string(from: span.first))–\(month.string(from: span.last))"
        }
        let origins = ordered.map(\.key).filter { !SharedEdge.contains($0) }
        var meta = ["domain": domain, "addresses": ordered.map(\.key).joined(separator: ", ")]
        if ordered.contains(where: { SharedEdge.contains($0.key) }), !origins.isEmpty {
            meta["possibleOrigins"] = origins.joined(separator: ", ")
        }
        var raw = "Addresses \(domain) pointed to (passive DNS): " + lines.joined(separator: "; ")
        if let origins = meta["possibleOrigins"] {
            raw += " | Before or beside its CDN it pointed to \(origins): its origin server may still answer there."
        }
        return PluginResult(source: "PassiveDNS", type: "dns_history", confidenceScore: 0.8, rawData: raw, metadata: meta)
    }

    static func isIPv4(_ value: String) -> Bool {
        value.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil
    }
}
