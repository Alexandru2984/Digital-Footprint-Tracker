import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Detects domain name / IP inputs and performs DNS + WHOIS OSINT.
///
/// Activated when the input contains a dot, no `@`, and no `+`/`-` prefix
/// (i.e. looks like `example.com`, `sub.domain.org`, or `1.2.3.4`).
///
/// Uses only `dig` and `whois` subprocesses (both available on the VPS).
/// Each subprocess is bounded by a 15-second kill timer via DispatchSemaphore,
/// matching the pattern used in BulkEmailPlugin for holehe.
struct DomainPlugin: FootprintPlugin {
    let name = "DomainOSINT"
    let description = "DNS records, WHOIS, SSL info"
    let cacheTTL: TimeInterval = 14_400 // 4 h

    // Basic domain/IP regex. Intentionally loose — input has already been
    // sanitised by ScanController's character whitelist.
    private static let domainRegex = try! NSRegularExpression(
        pattern: #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#
    )

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let target = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard DomainPlugin.domainRegex.firstMatch(
            in: target,
            range: NSRange(target.startIndex..., in: target)
        ) != nil else { return [] }

        var results: [PluginResult] = []

        // ── A records ───────────────────────────────────────────────────────────
        var resolvedIPs: [String] = []
        if let aOut = runDig(args: [target, "A", "+short", "+time=3", "+tries=1"], app: app) {
            let ips = aOut.components(separatedBy: .newlines)
                         .map { $0.trimmingCharacters(in: .whitespaces) }
                         .filter { !$0.isEmpty && !$0.hasPrefix(";") }
            resolvedIPs = ips
            if !ips.isEmpty {
                results.append(PluginResult(
                    source: "DomainDNS",
                    type: "dns_a_record",
                    confidenceScore: 1.0,
                    rawData: "A records for \(target): \(ips.joined(separator: ", "))"
                ))
            }
        }

        // ── MX records ──────────────────────────────────────────────────────────
        if let mxOut = runDig(args: [target, "MX", "+short", "+time=3", "+tries=1"], app: app) {
            let mx = mxOut.components(separatedBy: .newlines)
                          .map { $0.trimmingCharacters(in: .whitespaces) }
                          .filter { !$0.isEmpty && !$0.hasPrefix(";") }
            if !mx.isEmpty {
                results.append(PluginResult(
                    source: "DomainDNS",
                    type: "dns_mx_record",
                    confidenceScore: 0.95,
                    rawData: "MX records for \(target): \(mx.joined(separator: "; "))"
                ))
            }
        }

        // ── TXT / SPF records ───────────────────────────────────────────────────
        if let txtOut = runDig(args: [target, "TXT", "+short", "+time=3", "+tries=1"], app: app) {
            let spf = txtOut.components(separatedBy: .newlines)
                            .map { $0.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
                            .filter { $0.lowercased().hasPrefix("v=spf") || $0.lowercased().contains("dmarc") }
            if !spf.isEmpty {
                results.append(PluginResult(
                    source: "DomainDNS",
                    type: "dns_spf_record",
                    confidenceScore: 0.9,
                    rawData: "Email security records for \(target): \(spf.joined(separator: " | "))"
                ))
            }
        }

        // ── WHOIS ────────────────────────────────────────────────────────────────
        if let whoisOut = runWhois(target: target, app: app) {
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
                    rawData: "WHOIS for \(target): \(interesting.joined(separator: " | "))"
                ))
            }
        }

        // ── Reverse DNS (PTR) for IPs ────────────────────────────────────────────
        let isIP = target.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil
        if isIP, let ptrOut = runDig(args: ["-x", target, "+short", "+time=3", "+tries=1"], app: app) {
            let ptr = ptrOut.trimmingCharacters(in: .whitespacesAndNewlines)
            if !ptr.isEmpty {
                results.append(PluginResult(
                    source: "DomainDNS",
                    type: "dns_ptr_record",
                    confidenceScore: 0.9,
                    rawData: "Reverse DNS for \(target): \(ptr)"
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
            if let geoResults = await geolocateIPs(ipsToGeolocate, app: app) {
                results.append(contentsOf: geoResults)
            }
        }

        return results
    }

    // MARK: - IP Geolocation via ip-api.com (free, no key, 45 req/min limit)

    private func geolocateIPs(_ ips: [String], app: Application) async -> [PluginResult]? {
        guard let url = URL(string: "http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,isp,org,as") else { return nil }

        let body = try? JSONSerialization.data(withJSONObject: ips.map { ["query": $0] })
        guard let body = body else { return nil }

        var req = URLRequest(url: url, timeoutInterval: 8)
        req.httpMethod = "POST"
        req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        guard let (data, response) = try? await URLSession.shared.data(for: req),
              let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }

        struct GeoResult: Decodable {
            let status: String
            let query: String?
            let country: String?
            let countryCode: String?
            let regionName: String?
            let city: String?
            let isp: String?
            let org: String?
            let `as`: String?
        }

        guard let geos = try? JSONDecoder().decode([GeoResult].self, from: data) else { return nil }

        return geos.compactMap { geo in
            guard geo.status == "success", let ip = geo.query else { return nil }
            var parts: [String] = ["IP: \(ip)"]
            if let country = geo.country     { parts.append("Country: \(country)") }
            if let region = geo.regionName, !region.isEmpty { parts.append("Region: \(region)") }
            if let city = geo.city, !city.isEmpty           { parts.append("City: \(city)") }
            if let isp = geo.isp, !isp.isEmpty              { parts.append("ISP: \(isp)") }
            if let org = geo.org, !org.isEmpty, org != geo.isp { parts.append("Org: \(org)") }
            if let asn = geo.as, !asn.isEmpty               { parts.append("ASN: \(asn)") }
            return PluginResult(
                source: "DomainGeo",
                type: "ip_geolocation",
                confidenceScore: 0.95,
                rawData: parts.joined(separator: " | ")
            )
        }
    }

    // MARK: - Subprocess helpers

    private func runDig(args: [String], app: Application) -> String? {
        return runProcess(path: "/usr/bin/dig", args: args, timeout: 8, app: app)
    }

    private func runWhois(target: String, app: Application) -> String? {
        // Sanitise: whois only accepts hostname chars (already guaranteed by
        // the domain regex above, but being explicit here).
        guard target.range(of: #"^[a-zA-Z0-9.\-:]+$"#, options: .regularExpression) != nil else {
            return nil
        }
        return runProcess(path: "/usr/bin/whois", args: [target], timeout: 15, app: app)
    }

    /// Runs a subprocess synchronously, killing it after `timeout` seconds.
    /// Returns stdout as a String, or nil on failure / timeout.
    private func runProcess(path: String, args: [String], timeout: Double, app: Application) -> String? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.environment = ["PATH": "/usr/bin:/usr/local/bin", "HOME": "/tmp"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do { try process.run() } catch { return nil }

        var output: String?

        // Block on a background GCD thread so we never stall a Swift cooperative thread.
        let sema = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in sema.signal() }

        let killTimer = DispatchWorkItem {
            if process.isRunning { process.terminate() }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: killTimer)

        DispatchQueue.global(qos: .utility).sync {
            sema.wait()
            killTimer.cancel()
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        output = String(data: data, encoding: .utf8)
        return output
    }
}
