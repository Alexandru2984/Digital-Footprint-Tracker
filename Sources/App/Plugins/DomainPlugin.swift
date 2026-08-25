import Vapor
import Foundation

/// Detects domain name / IP inputs and performs DNS + WHOIS OSINT.
///
/// Activated when the input contains a dot, no `@`, and no `+`/`-` prefix
/// (i.e. looks like `example.com`, `sub.domain.org`, or `1.2.3.4`).
///
/// Uses Vapor's DNS resolver plus a bounded `whois` subprocess. The process has
/// a 15-second deadline, a 1 MB output cap, and no inherited app environment.
struct DomainPlugin: FootprintPlugin {
    let name = "DomainOSINT"
    let description = "DNS records, WHOIS, SSL info"
    let cacheTTL: TimeInterval = 14_400 // 4 h

    // Basic domain/IP regex. Intentionally loose — input has already been
    // sanitised by ScanController's character whitelist.
    private static let domainRegex = try? NSRegularExpression(
        pattern: #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#
    )

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let target = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let domainRegex = DomainPlugin.domainRegex,
              domainRegex.firstMatch(
                in: target,
                range: NSRange(target.startIndex..., in: target)
              ) != nil else { return [] }

        var results: [PluginResult] = []

        // ── A records (DNS-over-HTTPS) ───────────────────────────────────────────
        var resolvedIPs: [String] = []
        let aRecords = await DoHResolver.resolve(target, type: "A", on: app)
            .filter { $0.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil }
        if !aRecords.isEmpty {
            resolvedIPs = aRecords
            results.append(PluginResult(
                source: "DomainDNS",
                type: "dns_a_record",
                confidenceScore: 1.0,
                rawData: "A records for \(target): \(aRecords.joined(separator: ", "))",
                metadata: ["domain": target, "ip": aRecords[0]]
            ))
        }

        // ── MX records ──────────────────────────────────────────────────────────
        let mxHosts = await DoHResolver.resolve(target, type: "MX", on: app).map { DoHResolver.mxHost($0) }.filter { !$0.isEmpty }
        if !mxHosts.isEmpty {
            results.append(PluginResult(
                source: "DomainDNS",
                type: "dns_mx_record",
                confidenceScore: 0.95,
                rawData: "MX records for \(target): \(mxHosts.joined(separator: "; "))",
                metadata: ["domain": target]
            ))
        }

        // ── TXT / SPF records ───────────────────────────────────────────────────
        let spf = await DoHResolver.resolve(target, type: "TXT", on: app)
            .filter { $0.lowercased().hasPrefix("v=spf") || $0.lowercased().contains("dmarc") }
        if !spf.isEmpty {
            results.append(PluginResult(
                source: "DomainDNS",
                type: "dns_spf_record",
                confidenceScore: 0.9,
                rawData: "Email security records for \(target): \(spf.joined(separator: " | "))",
                metadata: ["domain": target]
            ))
        }

        // ── WHOIS ────────────────────────────────────────────────────────────────
        if let whoisOut = await runWhois(target: target, app: app) {
            let lines = whoisOut.components(separatedBy: .newlines)
            let interesting = lines.filter { line in
                let l = line.lowercased()
                return l.contains("registrar:") || l.contains("creation date:") ||
                       l.contains("registry expiry") || l.contains("name server:") ||
                       l.contains("registrant") || l.contains("updated date:")
            }.prefix(8).map { $0.trimmingCharacters(in: .whitespaces) }

            if !interesting.isEmpty {
                results.append(PluginResult(
                    source: "DomainWHOIS",
                    type: "whois_record",
                    confidenceScore: 0.85,
                    rawData: "WHOIS for \(target): \(interesting.joined(separator: " | "))",
                    metadata: ["domain": target]
                ))
            }
        }

        // ── Reverse DNS (PTR) for IPs ────────────────────────────────────────────
        let isIP = target.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil
        if isIP, let revName = DoHResolver.reverseIPv4Name(target),
           let ptrRaw = await DoHResolver.resolve(revName, type: "PTR", on: app).first {
            let ptr = ptrRaw.hasSuffix(".") ? String(ptrRaw.dropLast()) : ptrRaw
            if !ptr.isEmpty {
                results.append(PluginResult(
                    source: "DomainDNS",
                    type: "dns_ptr_record",
                    confidenceScore: 0.9,
                    rawData: "Reverse DNS for \(target): \(ptr)",
                    metadata: ["ip": target, "domain": ptr]
                ))
            }
        }

        // ── IP Geolocation ────────────────────────────────────────────────────────
        // Collect all IPs to geolocate: the target if it's an IP, or the resolved A records.
        let ipsToGeolocate: [String]
        if isIP {
            ipsToGeolocate = [target]
        } else {
            ipsToGeolocate = Array(resolvedIPs
                .filter { $0.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil }
                .prefix(3))
        }

        if !ipsToGeolocate.isEmpty {
            results.append(contentsOf: geolocateIPs(ipsToGeolocate, app: app))
        }

        return results
    }

    // MARK: - Offline IP geolocation

    /// Resolve scan targets locally. Sending investigated IPs to a third-party
    /// geolocation API leaks the user's research graph; the previous endpoint
    /// also used cleartext HTTP, allowing passive observation and tampering.
    private func geolocateIPs(_ ips: [String], app: Application) -> [PluginResult] {
        guard let database = app.geoIP else { return [] }

        return ips.map(database.lookup).compactMap { geo in
            guard geo.status == "success" else { return nil }
            var parts: [String] = ["IP: \(geo.query)"]
            if let country = geo.country, !country.isEmpty { parts.append("Country: \(country)") }
            if let region = geo.regionName, !region.isEmpty { parts.append("Region: \(region)") }
            if let city = geo.city, !city.isEmpty { parts.append("City: \(city)") }
            var meta: [String: String] = ["ip": geo.query]
            if let country = geo.country, !country.isEmpty { meta["country"] = country }
            if let countryCode = geo.countryCode, !countryCode.isEmpty { meta["countryCode"] = countryCode }
            return PluginResult(
                source: "DomainGeo",
                type: "ip_geolocation",
                confidenceScore: 0.95,
                rawData: parts.joined(separator: " | "),
                metadata: meta
            )
        }
    }

    // MARK: - Subprocess helpers

    private func runWhois(target: String, app: Application) async -> String? {
        // Sanitise: whois only accepts hostname chars (already guaranteed by
        // the domain regex above, but being explicit here).
        guard target.range(of: #"^[a-zA-Z0-9.\-:]+$"#, options: .regularExpression) != nil else {
            return nil
        }
        return await runProcess(path: "/usr/bin/whois", args: [target], timeout: 15)
    }

    /// Runs WHOIS without a shell, inherited secrets, unbounded output, or a
    /// cooperative-thread-blocking wait.
    private func runProcess(path: String, args: [String], timeout: Double) async -> String? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }
        guard let execution = try? await BoundedProcess.run(
            executable: path,
            arguments: args,
            environment: ["PATH": "/usr/bin:/usr/local/bin", "LANG": "C.UTF-8"],
            timeout: timeout,
            maxOutputBytes: 1 * 1_024 * 1_024
        ), execution.succeeded else { return nil }
        return String(data: execution.stdout, encoding: .utf8)
    }
}
