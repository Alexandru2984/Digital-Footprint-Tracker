import Vapor

/// Collapses a scan's flat list of findings into a single synthesized identity —
/// the "who is this" view. Names, locations, emails, phones, the handles seen
/// (and on which platforms), confirmed accounts, breaches and exposed IPs are
/// aggregated and de-duplicated; a handle confirmed on several platforms gets a
/// confidence boost (cross-source corroboration).
///
/// Pure + DB-free so it's unit-testable. `IdentityController` builds `Input`s
/// from Fluent rows and serves the result.
enum IdentitySynthesizer {

    struct Input {
        let source: String
        let type: String
        let confidence: Double
        let metadata: [String: String]
        let rawData: String
    }

    struct HandleUse: Content {
        let handle: String
        let platforms: [String]
        let confidence: Double
    }

    struct Account: Content {
        let platform: String
        let reference: String
        let confidence: Double
    }

    /// Attack-surface of a single exposed host: the open ports and known CVEs seen
    /// on an IP (sourced from InternetDB / Shodan findings).
    struct ServiceExposure: Content {
        let ip: String
        let ports: [String]
        let cves: [String]
        let hostnames: [String]
    }

    struct IdentityProfile: Content {
        let likelyName: String?
        let names: [String]
        let locations: [String]
        let organizations: [String]
        let emails: [String]
        let phones: [String]
        let handles: [HandleUse]
        let confirmedAccounts: [Account]
        let breaches: [String]
        let exposedIPs: [String]
        let exposedServices: [ServiceExposure]
        let vulnerabilities: [String]
        let riskScore: Int
        let riskLevel: String
        let resultCount: Int
    }

    private static let accountTypes: Set<String> = [
        "account_presence", "social_media", "identity_proof", "avatar_presence", "developer_identity"
    ]

    static func synthesize(from inputs: [Input], riskScore: Int, riskLevel: String) -> IdentityProfile {
        var nameCounts: [String: Int] = [:]
        var locations = Set<String>()
        var orgs = Set<String>()
        var emails = Set<String>()
        var phones = Set<String>()
        var handlePlatforms: [String: Set<String>] = [:]
        var handleConfidence: [String: Double] = [:]
        var accountsByKey: [String: Account] = [:]
        var breaches = Set<String>()
        var ips = Set<String>()
        var svcPorts: [String: Set<String>] = [:]
        var svcCves: [String: Set<String>] = [:]
        var svcHosts: [String: Set<String>] = [:]
        var allCves = Set<String>()

        for inp in inputs {
            let m = inp.metadata
            if let n = nonEmpty(m["name"]) { nameCounts[n, default: 0] += 1 }
            if let l = nonEmpty(m["location"]) { locations.insert(l) }
            if let o = nonEmpty(m["company"]) ?? nonEmpty(m["org"]) { orgs.insert(o) }
            if let e = nonEmpty(m["email"]), e.contains("@") { emails.insert(e.lowercased()) }
            if let p = nonEmpty(m["phone"]) { phones.insert(p) }
            if let ip = nonEmpty(m["ip"]) {
                ips.insert(ip)
                for port in csv(m["ports"]) { svcPorts[ip, default: []].insert(port) }
                if let single = nonEmpty(m["port"]) { svcPorts[ip, default: []].insert(single) }
                for cve in csv(m["cves"]) { svcCves[ip, default: []].insert(cve); allCves.insert(cve) }
                for host in csv(m["hostnames"]) { svcHosts[ip, default: []].insert(host) }
            }

            if let handle = nonEmpty(m["username"]) {
                let platform = nonEmpty(m["platform"]) ?? inp.source
                handlePlatforms[handle, default: []].insert(platform)
                handleConfidence[handle] = max(handleConfidence[handle] ?? 0, inp.confidence)
            }

            if accountTypes.contains(inp.type) {
                let platform = nonEmpty(m["platform"]) ?? inp.source
                let reference = nonEmpty(m["profileURL"]) ?? nonEmpty(m["url"]) ?? nonEmpty(m["username"]) ?? String(inp.rawData.prefix(160))
                let key = "\(platform.lowercased())|\(reference.lowercased())"
                // Keep the highest-confidence sighting of each (platform, reference).
                if (accountsByKey[key]?.confidence ?? -1) < inp.confidence {
                    accountsByKey[key] = Account(platform: platform, reference: String(reference.prefix(200)), confidence: inp.confidence)
                }
            }

            if inp.type == "data_breach", let list = nonEmpty(m["breaches"]) {
                for b in list.split(separator: ",") {
                    let name = b.trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty { breaches.insert(name) }
                }
            }
        }

        let likelyName = nameCounts.max { ($0.value, $0.key) < ($1.value, $1.key) }?.key
        let handles = handlePlatforms.map { handle, platforms -> HandleUse in
            let base = handleConfidence[handle] ?? 0.5
            let boosted = min(1.0, base + 0.1 * Double(platforms.count - 1))
            return HandleUse(handle: handle, platforms: platforms.sorted(), confidence: boosted)
        }.sorted { ($0.platforms.count, $0.confidence) > ($1.platforms.count, $1.confidence) }

        // Hosts with actual exposure (open ports and/or known CVEs), ports sorted numerically.
        let serviceIPs = Set(svcPorts.keys).union(svcCves.keys)
        let exposedServices = serviceIPs.sorted().map { ip in
            ServiceExposure(
                ip: ip,
                ports: (svcPorts[ip] ?? []).sorted { (Int($0) ?? 0, $0) < (Int($1) ?? 0, $1) },
                cves: (svcCves[ip] ?? []).sorted(),
                hostnames: (svcHosts[ip] ?? []).sorted()
            )
        }

        return IdentityProfile(
            likelyName: likelyName,
            names: nameCounts.keys.sorted(),
            locations: locations.sorted(),
            organizations: orgs.sorted(),
            emails: emails.sorted(),
            phones: phones.sorted(),
            handles: handles,
            confirmedAccounts: accountsByKey.values.sorted { $0.confidence > $1.confidence },
            breaches: breaches.sorted(),
            exposedIPs: ips.sorted(),
            exposedServices: exposedServices,
            vulnerabilities: allCves.sorted(),
            riskScore: riskScore,
            riskLevel: riskLevel,
            resultCount: inputs.count
        )
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        return s
    }

    /// Splits a comma-separated metadata value ("22, 80, 443") into trimmed, non-empty parts.
    private static func csv(_ s: String?) -> [String] {
        guard let s = nonEmpty(s) else { return [] }
        return s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

extension Scan {
    /// Synthesize this scan's findings into a single identity profile. Requires
    /// `results` to be eager-loaded (`.with(\.$results)`); shared by the identity
    /// and graph-export endpoints so the mapping lives in one place.
    func synthesizedIdentity() -> IdentitySynthesizer.IdentityProfile {
        let risk = RiskScorer.compute(results: results)
        let inputs = results.map {
            IdentitySynthesizer.Input(
                source: $0.source,
                type: $0.type,
                confidence: $0.confidenceScore,
                metadata: $0.metadataObject ?? [:],
                rawData: $0.rawData
            )
        }
        return IdentitySynthesizer.synthesize(from: inputs, riskScore: risk.value, riskLevel: risk.level.rawValue)
    }
}
