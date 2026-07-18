import Foundation

/// DNS resolution over HTTPS (Cloudflare's JSON API). Replaces shelling out to
/// `dig`: no binary dependency, works inside minimal containers and behind
/// restrictive egress, and rides `PluginHTTP`'s retry + per-host throttle.
enum DoHResolver {

    /// DNS record type → its numeric RR type, used to filter mixed answers
    /// (a query often returns CNAMEs alongside the requested type).
    private static let typeNumbers: [String: Int] = [
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
        "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "CAA": 257
    ]

    /// Resolves `name` records of `type` (e.g. "A", "MX", "TXT", "PTR"). Returns
    /// the record `data` strings, or [] on failure.
    static func resolve(_ name: String, type: String) async -> [String] {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? name
        guard let url = URL(string: "https://cloudflare-dns.com/dns-query?name=\(encoded)&type=\(type)") else { return [] }
        guard let resp = await PluginHTTP.request(url, headers: ["Accept": "application/dns-json"]),
              resp.status == 200 else { return [] }
        return parse(resp.data, type: type)
    }

    /// Parses a Cloudflare DoH JSON body into the `data` strings for `type`.
    /// Pure + internal so it's unit-testable offline.
    static func parse(_ data: Data, type: String) -> [String] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let answers = json["Answer"] as? [[String: Any]] else { return [] }
        let want = typeNumbers[type]
        return answers.compactMap { answer -> String? in
            if let want, let t = answer["type"] as? Int, t != want { return nil }
            guard let value = answer["data"] as? String else { return nil }
            return value.trimmingCharacters(in: CharacterSet(charactersIn: "\"")).trimmingCharacters(in: .whitespaces)
        }
    }

    /// Builds the reverse-DNS name for an IPv4 address (1.2.3.4 → 4.3.2.1.in-addr.arpa).
    static func reverseIPv4Name(_ ip: String) -> String? {
        let parts = ip.split(separator: ".")
        guard parts.count == 4, parts.allSatisfy({ Int($0) != nil }) else { return nil }
        return parts.reversed().joined(separator: ".") + ".in-addr.arpa"
    }

    /// Extracts the mail host from an MX record `data` string ("10 mail.x.com.").
    static func mxHost(_ record: String) -> String {
        let host = record.split(separator: " ").last.map(String.init) ?? record
        return host.hasSuffix(".") ? String(host.dropLast()) : host
    }
}
