import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Maps the *whole footprint's* exposure, not just the apex host — the breadth that
/// is Shodan's real value. It enumerates a domain's subdomains from Certificate
/// Transparency logs, resolves them to IPs, and pulls free Shodan-grade exposure
/// (open ports + CVEs) for every host that isn't already the apex IP. The result is
/// "here is everything this organisation has on the internet, and what's open on it".
///
/// Marked `heavy` (one crt.sh call + bounded DoH + bounded InternetDB lookups) so the
/// candidate fan-out runs it on at most one target. All breadth is hard-capped:
/// `maxHosts` subdomains, `maxIPs` exposure lookups. Apex exposure is left to
/// `InternetDBPlugin` so the two don't double-report the same IP.
struct AttackSurfacePlugin: FootprintPlugin {
    let name = "AttackSurface"
    let description = "Whole-footprint exposure: subdomains → IPs → open ports & CVEs"
    let cacheTTL: TimeInterval = 21_600 // 6 h
    let heavy = true

    private static let ipv4Pattern = #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#
    static let maxHosts = 15
    static let maxIPs = 15

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let target = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // Domains only — subdomains don't apply to an email, a username, or a bare IP.
        guard !target.contains("@"), target.contains("."),
              target.range(of: Self.ipv4Pattern, options: .regularExpression) == nil,
              target.range(of: #"[a-z]"#, options: .regularExpression) != nil else { return [] }

        // 1. Footprint = apex + CT-log subdomains.
        let hosts = Self.hostList(apex: target,
                                  subdomains: await CrtShPlugin.enumerate(domain: target, limit: Self.maxHosts),
                                  limit: Self.maxHosts)

        // 2. Resolve to public IPv4s. Track the apex's own IPs so subdomains sharing
        //    them aren't re-scanned (InternetDBPlugin already covers the apex).
        var apexIPs = Set<String>()
        var ipToHost: [String: String] = [:]   // representative host per IP
        var mappings: [(host: String, ip: String)] = []
        for host in hosts {
            if Task.isCancelled { break }
            for ip in await DoHResolver.resolve(host, type: "A") where Self.isPublicIPv4(ip) {
                if host == target { apexIPs.insert(ip) }
                if ipToHost[ip] == nil { ipToHost[ip] = host }
                mappings.append((host, ip))
            }
        }

        var results: [PluginResult] = []

        // The surface map itself: subdomain → IP (recorded even with no open ports).
        var seen = Set<String>()
        for (host, ip) in mappings where host != target && seen.insert("\(host)|\(ip)").inserted {
            results.append(PluginResult(
                source: "AttackSurface", type: "subdomain_ip", confidenceScore: 0.85,
                rawData: "\(host) → \(ip)",
                metadata: ["subdomain": host, "ip": ip, "domain": target]))
        }

        // 3. Exposure for IPs unique to the subdomains (not shared with the apex).
        let exposureIPs = ipToHost.keys.filter { !apexIPs.contains($0) }.sorted().prefix(Self.maxIPs)
        for ip in exposureIPs {
            if Task.isCancelled { break }
            guard let url = URL(string: "https://internetdb.shodan.io/\(ip)"),
                  let resp = await PluginHTTP.request(url), resp.status == 200 else { continue }
            let host = ipToHost[ip]
            for finding in InternetDBPlugin.parse(resp.data, ip: ip) {
                var meta = finding.metadata ?? [:]
                if let host { meta["subdomain"] = host }
                meta["domain"] = target
                results.append(PluginResult(
                    source: "AttackSurface", type: finding.type, confidenceScore: finding.confidenceScore,
                    rawData: (host.map { "\($0): " } ?? "") + finding.rawData, metadata: meta))
            }
        }

        return results
    }

    /// Apex first, then unique subdomains, capped at `limit`. Pure / testable.
    static func hostList(apex: String, subdomains: [String], limit: Int) -> [String] {
        var hosts = [apex]
        for sub in subdomains where !hosts.contains(sub) {
            hosts.append(sub)
            if hosts.count >= limit { break }
        }
        return hosts
    }

    static func isPublicIPv4(_ ip: String) -> Bool {
        ip.range(of: ipv4Pattern, options: .regularExpression) != nil && !SSRFGuard.isInternalHostname(ip)
    }
}
