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
        let exposedDataClasses: [String]
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
        var nameScore: [String: Double] = [:]        // normalized key → summed confidence (weight)
        var nameForms: [String: [String: Int]] = [:] // normalized key → seen display forms + counts
        var locations = Set<String>()
        var orgs = Set<String>()
        var emails = Set<String>()
        var phones = Set<String>()
        var handlePlatforms: [String: Set<String>] = [:]
        var handleConfidence: [String: Double] = [:]
        var accountsByKey: [String: Account] = [:]
        var breaches = Set<String>()
        var dataClasses = Set<String>()
        var ips = Set<String>()
        var svcPorts: [String: Set<String>] = [:]
        var svcCves: [String: Set<String>] = [:]
        var svcHosts: [String: Set<String>] = [:]
        var allCves = Set<String>()

        for inp in inputs {
            let m = inp.metadata
            if let rawName = nonEmpty(m["name"]) {
                let display = collapseWhitespace(rawName)
                let key = display.lowercased()
                // Weight by the finding's confidence so a name from a confirmed
                // account outranks a one-off mention from a weak source, and
                // corroboration across sources accumulates. Case/spacing variants
                // ("John Smith" / "john  smith") merge into one identity.
                nameScore[key, default: 0] += max(0.1, min(1.0, inp.confidence))
                nameForms[key, default: [:]][display, default: 0] += 1
            }
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
                let key = "\(platform.lowercased())|\(canonicalRef(reference))"
                // Keep the highest-confidence sighting of each (platform, reference).
                if (accountsByKey[key]?.confidence ?? -1) < inp.confidence {
                    accountsByKey[key] = Account(platform: platform, reference: String(reference.prefix(200)), confidence: inp.confidence)
                }
            }

            if inp.type == "data_breach" {
                for name in csv(m["breaches"]) { breaches.insert(name) }
                // Categories of data leaked (passwords, phone numbers, …) — what the
                // breaches actually exposed, not just their names.
                for dc in csv(m["dataClasses"]) { dataClasses.insert(dc) }
            }
        }

        // Pick the most-seen casing for a normalized name key.
        func displayForm(_ key: String) -> String {
            guard let forms = nameForms[key] else { return key }
            return forms.max { l, r in l.value != r.value ? l.value < r.value : l.key > r.key }?.key ?? key
        }
        // Drop "names" that just echo a handle, or are handle-shaped (contain a
        // digit/underscore, or are a single lowercase token). Plugins sometimes
        // copy the username into `name`; that's not a real identity and must not
        // become the headline. Kept: anything with a space (given + family) or an
        // uppercase letter (a proper noun) and no handle markers.
        let handleKeys = Set(handlePlatforms.keys.map { $0.lowercased() })
        func isRealName(_ key: String) -> Bool {
            if handleKeys.contains(key) { return false }
            let display = displayForm(key)
            if display.contains("_") || display.rangeOfCharacter(from: .decimalDigits) != nil { return false }
            let hasSpace = display.contains(" ")
            let hasUpper = display.rangeOfCharacter(from: .uppercaseLetters) != nil
            return hasSpace || hasUpper
        }
        let validNameKeys = nameScore.keys.filter(isRealName)
        // The highest summed-confidence name is the likely identity; ties → lexical.
        let bestNameKey = validNameKeys.max { l, r in
            let a = nameScore[l] ?? 0, b = nameScore[r] ?? 0
            return a != b ? a < b : l > r
        }
        let likelyName = bestNameKey.map(displayForm)
        let resolvedNames = validNameKeys.map(displayForm).sorted()
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
            names: resolvedNames,
            locations: locations.sorted(),
            organizations: orgs.sorted(),
            emails: emails.sorted(),
            phones: phones.sorted(),
            handles: handles,
            confirmedAccounts: accountsByKey.values.sorted { $0.confidence > $1.confidence },
            breaches: breaches.sorted(),
            exposedDataClasses: dataClasses.sorted(),
            exposedIPs: ips.sorted(),
            exposedServices: exposedServices,
            vulnerabilities: allCves.sorted(),
            riskScore: riskScore,
            riskLevel: riskLevel,
            resultCount: inputs.count
        )
    }

    /// Canonicalize an account reference (usually a profile URL) so the same
    /// account found by several plugins collapses into one: lowercase, drop the
    /// scheme, a leading `www.`, and any trailing slash. E.g. the dedicated
    /// GitHub check ("https://github.com/x") and the Sherlock sweep
    /// ("https://www.github.com/x/") become the same "github.com/x".
    private static func canonicalRef(_ ref: String) -> String {
        var s = ref.lowercased().trimmingCharacters(in: .whitespaces)
        for scheme in ["https://", "http://"] where s.hasPrefix(scheme) { s.removeFirst(scheme.count) }
        if s.hasPrefix("www.") { s.removeFirst(4) }
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    /// Trim and collapse internal runs of whitespace to a single space, so
    /// "John   Smith" and "John Smith" are the same name.
    private static func collapseWhitespace(_ s: String) -> String {
        s.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\r" })
            .joined(separator: " ")
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
