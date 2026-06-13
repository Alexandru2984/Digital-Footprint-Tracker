import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Shodan-grade exposure data with no API key: open ports, known vulnerabilities
/// (CVEs), software (CPEs), hostnames and tags for an IP — via Shodan's free, open
/// InternetDB API (`https://internetdb.shodan.io/{ip}`). This is the passive answer
/// to "what's exposed on this host": no scanning, no key, just Shodan's own
/// pre-collected dataset. The keyed `ShodanPlugin` returns nothing without a key,
/// so for most scans this is where port/CVE intelligence actually comes from.
///
/// Domain inputs are resolved to their A records first (bounded, public IPv4 only);
/// an IP input is queried directly. Parsing is pure for offline unit tests.
struct InternetDBPlugin: FootprintPlugin {
    let name = "InternetDB"
    let description = "Open ports, CVEs & exposed services per IP (free, no key)"
    let cacheTTL: TimeInterval = 21_600 // 6 h

    private static let ipv4Pattern = #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let target = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Only domain / IP inputs have host infrastructure to look up.
        guard !target.contains("@"), target.contains(".") else { return [] }

        let ips = await Self.resolveIPs(target)
        guard !ips.isEmpty else { return [] }

        var results: [PluginResult] = []
        for ip in ips {
            guard let url = URL(string: "https://internetdb.shodan.io/\(ip)") else { continue }
            // 404 = host not in the dataset (i.e. nothing exposed) — a real "clean" answer.
            guard let resp = await PluginHTTP.request(url), resp.status == 200 else { continue }
            results.append(contentsOf: Self.parse(resp.data, ip: ip))
        }
        return results
    }

    /// Resolves a target to up to 3 distinct **public** IPv4 addresses. An IP input
    /// passes through (when public); a domain is resolved via DoH. Private / internal
    /// addresses are dropped — InternetDB only holds public hosts and we never want to
    /// echo internal infrastructure.
    static func resolveIPs(_ target: String) async -> [String] {
        func isPublic(_ ip: String) -> Bool {
            ip.range(of: ipv4Pattern, options: .regularExpression) != nil
                && !SSRFGuard.isInternalHostname(ip)
        }

        if target.range(of: ipv4Pattern, options: .regularExpression) != nil {
            return isPublic(target) ? [target] : []
        }

        var seen = Set<String>()
        var out: [String] = []
        for ip in await DoHResolver.resolve(target, type: "A") where isPublic(ip) && seen.insert(ip).inserted {
            out.append(ip)
            if out.count == 3 { break }
        }
        return out
    }

    /// Pure parser of an InternetDB JSON record into findings. Returns [] when the
    /// host has nothing of interest. Unit-testable without a network.
    static func parse(_ data: Data, ip: String) -> [PluginResult] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        let ports     = (json["ports"] as? [Int]) ?? []
        let vulns     = (json["vulns"] as? [String]) ?? []
        let cpes      = (json["cpes"] as? [String]) ?? []
        let hostnames = (json["hostnames"] as? [String]) ?? []
        let tags      = (json["tags"] as? [String]) ?? []

        var results: [PluginResult] = []

        // ── Open ports → exposed services (threat) ───────────────────────────────
        if !ports.isEmpty {
            let sorted = ports.sorted()
            let portList = sorted.map(String.init)
            var meta: [String: String] = ["ip": ip, "ports": portList.joined(separator: ", ")]
            if !hostnames.isEmpty { meta["hostnames"] = hostnames.prefix(5).joined(separator: ", ") }
            if !tags.isEmpty { meta["tags"] = tags.joined(separator: ", ") }
            var parts = ["IP \(ip): \(sorted.count) open port(s) — \(portList.prefix(20).joined(separator: ", "))"]
            if !tags.isEmpty { parts.append("tags: \(tags.joined(separator: ", "))") }
            if !hostnames.isEmpty { parts.append("hostnames: \(hostnames.prefix(5).joined(separator: ", "))") }
            results.append(PluginResult(
                source: "InternetDB", type: "exposed_service", confidenceScore: 0.9,
                rawData: parts.joined(separator: " | "), metadata: meta))
        }

        // ── Known CVEs → vulnerability (threat) ──────────────────────────────────
        if !vulns.isEmpty {
            let cves = vulns.sorted()
            let meta: [String: String] = [
                "ip": ip,
                "cves": cves.prefix(40).joined(separator: ", "),
                "cve_count": String(cves.count)
            ]
            let shown = cves.prefix(8).joined(separator: ", ")
            let more = cves.count > 8 ? " (+\(cves.count - 8) more)" : ""
            results.append(PluginResult(
                source: "InternetDB", type: "vulnerability", confidenceScore: 0.95,
                rawData: "IP \(ip): \(cves.count) known CVE(s) — \(shown)\(more)", metadata: meta))
        }

        // ── Software fingerprint (CPEs) → informational ──────────────────────────
        if !cpes.isEmpty {
            let meta: [String: String] = ["ip": ip, "cpes": cpes.prefix(10).joined(separator: ", ")]
            results.append(PluginResult(
                source: "InternetDB", type: "tech_stack", confidenceScore: 0.7,
                rawData: "IP \(ip) software: \(cpes.prefix(6).joined(separator: ", "))", metadata: meta))
        }

        return results
    }
}
