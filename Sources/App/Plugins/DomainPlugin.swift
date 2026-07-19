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

        // ── A records (DNS-over-HTTPS) ───────────────────────────────────────────
        var resolvedIPs: [String] = []
        let aRecords = await DoHResolver.resolve(target, type: "A")
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
        let mxHosts = await DoHResolver.resolve(target, type: "MX").map { DoHResolver.mxHost($0) }.filter { !$0.isEmpty }
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
        let spf = await DoHResolver.resolve(target, type: "TXT")
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
           let ptrRaw = await DoHResolver.resolve(revName, type: "PTR").first {
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
            var meta: [String: String] = ["ip": ip]
            if let country = geo.country, !country.isEmpty { meta["country"] = country }
            if let isp = geo.isp, !isp.isEmpty             { meta["org"] = isp }
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
        return await runProcess(path: "/usr/bin/whois", args: [target], timeout: 15, app: app)
    }

    /// Runs a subprocess, killing it after `timeout` seconds. Returns stdout as a
    /// String, or nil on failure / timeout.
    ///
    /// All the blocking work (process wait + pipe read) runs on a GCD utility
    /// thread and the `async` caller stays *suspended* via the continuation — it
    /// never occupies a Swift cooperative thread. The previous version wrapped the
    /// wait in `DispatchQueue.global().sync { … }`, which does NOT offload (`.sync`
    /// runs on the calling thread): a slow `whois` then pinned a cooperative
    /// thread, and enough concurrent scans starved the pool so hard that even the
    /// runner's own 120 s deadline task couldn't resume — the whole scan hung.
    private func runProcess(path: String, args: [String], timeout: Double, app: Application) async -> String? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }

        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = args
                process.environment = ["PATH": "/usr/bin:/usr/local/bin", "HOME": "/tmp"]
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice

                do { try process.run() } catch { cont.resume(returning: nil); return }

                // Hard kill after `timeout` so a hung/slow whois can't block forever.
                let killTimer = DispatchWorkItem { if process.isRunning { process.terminate() } }
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: killTimer)

                // Read to EOF first (drains the pipe so a chatty process can't block
                // on a full buffer), then reap. The kill timer bounds both.
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                killTimer.cancel()
                cont.resume(returning: String(data: data, encoding: .utf8))
            }
        }
    }
}
