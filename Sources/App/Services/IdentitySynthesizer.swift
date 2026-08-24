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

    typealias TimelineEvent = TimelineIntelligence.Event

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
        let timeline: [TimelineEvent]
        let riskScore: Int
        let riskLevel: String
        let resultCount: Int
    }

    private static let accountTypes: Set<String> = [
        "account_presence", "social_media", "identity_proof", "avatar_presence", "developer_identity"
    ]

    static func synthesize(from inputs: [Input], riskScore: Int, riskLevel: String) -> IdentityProfile {
        var nameScore: [String: Double] = [:]            // normalized key → summed confidence (weight)
        var nameForms: [String: [String: Int]] = [:]     // normalized key → seen display forms + counts
        var locationForms: [String: [String: Int]] = [:] // same case/spacing merge for places…
        var orgForms: [String: [String: Int]] = [:]      // …and organizations
        var emails = Set<String>()
        var phoneForms: [String: [String: Int]] = [:] // canonical number → seen formats + counts
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
            if let l = nonEmpty(m["location"]) { record(collapseWhitespace(l), into: &locationForms) }
            if let o = nonEmpty(m["company"]) ?? nonEmpty(m["org"]) { record(collapseWhitespace(o), into: &orgForms) }
            if let e = nonEmpty(m["email"]), e.contains("@") { emails.insert(e.lowercased()) }
            if let p = nonEmpty(m["phone"]) {
                let display = collapseWhitespace(p)
                record(display, key: canonicalPhone(display), into: &phoneForms)
            }
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
        func displayForm(_ key: String) -> String { nameForms[key].flatMap(bestForm) ?? key }
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
            locations: resolveForms(locationForms),
            organizations: resolveForms(orgForms),
            emails: emails.sorted(),
            phones: resolveForms(phoneForms),
            handles: handles,
            confirmedAccounts: accountsByKey.values.sorted { $0.confidence > $1.confidence },
            breaches: breaches.sorted(),
            exposedDataClasses: dataClasses.sorted(),
            exposedIPs: ips.sorted(),
            exposedServices: exposedServices,
            vulnerabilities: allCves.sorted(),
            timeline: buildTimeline(from: inputs),
            riskScore: riskScore,
            riskLevel: riskLevel,
            resultCount: inputs.count
        )
    }

    /// Backward-compatible identity-profile projection of the richer timeline
    /// report. The dedicated endpoint also returns its aggregate summary.
    static func buildTimeline(from inputs: [Input]) -> [TimelineEvent] {
        TimelineIntelligence.build(from: inputs).events
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

    /// Record a display form under its case-folded key, tallying how often each
    /// casing was seen so the most common one can be surfaced later.
    private static func record(_ display: String, into forms: inout [String: [String: Int]]) {
        record(display, key: display.lowercased(), into: &forms)
    }

    /// Record a display form under an explicit normalization key — used where the
    /// merge rule isn't just case-folding (e.g. phone-number formatting).
    private static func record(_ display: String, key: String, into forms: inout [String: [String: Int]]) {
        forms[key, default: [:]][display, default: 0] += 1
    }

    /// Canonicalize a phone number for dedup: keep a leading "+", drop spaces,
    /// dashes, dots and parentheses. This merges pure formatting variants of the
    /// same number ("+40 721 234 567" / "+40721234567") while keeping genuinely
    /// different numbers apart — a national "0721…" and an international "+40721…"
    /// get distinct keys, since inferring country codes reliably is out of scope.
    private static func canonicalPhone(_ s: String) -> String {
        let plus = s.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("+") ? "+" : ""
        return plus + s.filter { $0.isNumber }
    }

    /// The most-seen display form for one normalized key; ties break to the
    /// lexically-smallest form so the result is deterministic.
    private static func bestForm(_ forms: [String: Int]) -> String? {
        forms.max { l, r in l.value != r.value ? l.value < r.value : l.key > r.key }?.key
    }

    /// Collapse case/spacing variants ("Berlin" / "berlin" / "Berlin ") into one
    /// entry each, keeping the casing seen most often, sorted for stable output.
    private static func resolveForms(_ formsByKey: [String: [String: Int]]) -> [String] {
        formsByKey.values.compactMap(bestForm).sorted()
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
    /// Maps structured result fields to the DB-free intelligence input once.
    /// Timeline callers skip raw-payload decryption because they only consume
    /// allow-listed metadata.
    func identityInputs(
        includeRawData: Bool = true,
        maximumCount: Int? = nil
    ) throws -> [IdentitySynthesizer.Input] {
        let selectedResults: ArraySlice<Result>
        if let maximumCount {
            selectedResults = results.prefix(max(0, maximumCount))
        } else {
            selectedResults = results[...]
        }
        return try selectedResults.map {
            IdentitySynthesizer.Input(
                source: $0.source,
                type: $0.type,
                confidence: $0.confidenceScore,
                metadata: try $0.metadataObject ?? [:],
                rawData: includeRawData ? (try $0.rawData) : ""
            )
        }
    }

    /// Synthesize this scan's findings into a single identity profile. Requires
    /// `results` to be eager-loaded (`.with(\.$results)`); shared by the identity
    /// and graph-export endpoints so the mapping lives in one place.
    func synthesizedIdentity() throws -> IdentitySynthesizer.IdentityProfile {
        let risk = try RiskScorer.compute(results: results)
        let inputs = try identityInputs()
        return IdentitySynthesizer.synthesize(from: inputs, riskScore: risk.value, riskLevel: risk.level.rawValue)
    }

    func timelineIntelligence() throws -> TimelineIntelligence.Report {
        TimelineIntelligence.build(from: try identityInputs(
            includeRawData: false,
            maximumCount: TimelineIntelligence.maximumInputs
        ))
    }
}
