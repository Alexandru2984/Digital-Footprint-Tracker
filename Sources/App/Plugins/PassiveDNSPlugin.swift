import Foundation
import Vapor

struct PassiveDNSPlugin: FootprintPlugin {
    let name = "PassiveDNS"
    let description = "Historical DNS and subdomain discovery"
    /// hostsearch maps a domain's names to addresses; reverseiplookup lists
    /// the names an address serves.
    let accepts: Set<TargetShape> = [.domain, .ipv4]
    /// v2: an address lists the domains it serves, not itself as a subdomain.
    let cacheVersion = 2

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains(".") && !input.contains("@") else { return [] }
        if Self.isIPv4(input) { return await cohosted(on: input, app: app) }

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

    static func isIPv4(_ value: String) -> Bool {
        value.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil
    }
}
