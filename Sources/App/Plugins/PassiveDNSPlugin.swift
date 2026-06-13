import Foundation
import Vapor
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct PassiveDNSPlugin: FootprintPlugin {
    let name = "PassiveDNS"
    let description = "Historical DNS and subdomain discovery"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains(".") && !input.contains("@") else { return [] }

        let encoded = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? input
        guard let url = URL(string: "https://api.hackertarget.com/hostsearch/?q=\(encoded)") else { return [] }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15

        guard let (responseData, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let text = String(data: responseData, encoding: .utf8),
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
