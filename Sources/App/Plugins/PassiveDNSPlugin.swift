import Foundation
import Vapor

struct PassiveDNSPlugin: FootprintPlugin {
    let name = "PassiveDNS"
    let description = "Historical DNS and subdomain discovery"
    /// hostsearch answers forward and reverse lookups.
    let accepts: Set<TargetShape> = [.domain, .ipv4]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains(".") && !input.contains("@") else { return [] }

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
}
