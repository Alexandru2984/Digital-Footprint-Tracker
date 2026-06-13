import Vapor
import Foundation

/// Internet Archive (Wayback Machine) history for a domain: how far back it was
/// captured, when it was last seen, and how many distinct days it was archived.
/// A strong historical-presence signal — when a site first appeared and whether
/// it's still alive — via the public CDX API, no key required.
struct WaybackPlugin: FootprintPlugin {
    let name = "Wayback"
    let description = "Internet Archive history (first/last seen, snapshot count)"
    let cacheTTL: TimeInterval = 86_400 // archive history barely moves day-to-day

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("."), !input.contains("@"), !input.hasPrefix("http") else { return [] }

        let domain = input.lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? input

        let encoded = domain.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? domain
        guard let url = URL(string:
            "https://web.archive.org/cdx/search/cdx?url=\(encoded)&output=json&fl=timestamp&collapse=timestamp:8&limit=10000"
        ) else { return [] }

        guard let resp = await PluginHTTP.request(url), resp.status == 200 else { return [] }
        let (count, first, last) = Self.parseCDX(resp.data)
        guard count > 0, let first, let last else { return [] }

        let firstDate = Self.formatTimestamp(first)
        let lastDate  = Self.formatTimestamp(last)
        return [PluginResult(
            source: "Wayback",
            type: "archive_history",
            confidenceScore: 0.7,
            rawData: "Internet Archive: \(domain) captured on \(count) distinct day(s); first \(firstDate), last \(lastDate)",
            metadata: ["domain": domain, "firstSeen": firstDate, "lastSeen": lastDate, "snapshotDays": String(count)]
        )]
    }

    /// Parses a CDX JSON body (`[["timestamp"], ["2010…"], …]`) into a count and
    /// the earliest / latest timestamps. Pure + internal for tests.
    static func parseCDX(_ data: Data) -> (count: Int, first: String?, last: String?) {
        guard let rows = try? JSONSerialization.jsonObject(with: data) as? [[String]], rows.count > 1 else {
            return (0, nil, nil)
        }
        let timestamps = rows.dropFirst().compactMap { $0.first }.filter { $0.count >= 8 }.sorted()
        guard !timestamps.isEmpty else { return (0, nil, nil) }
        return (timestamps.count, timestamps.first, timestamps.last)
    }

    /// "20100315123456" → "2010-03-15".
    static func formatTimestamp(_ ts: String) -> String {
        guard ts.count >= 8 else { return ts }
        let s = Array(ts)
        return "\(String(s[0..<4]))-\(String(s[4..<6]))-\(String(s[6..<8]))"
    }
}
