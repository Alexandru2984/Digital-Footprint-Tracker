import Foundation

/// Computes an aggregate exposure risk score (0–100) and level for a set of scan
/// results.
///
/// Design goals (this replaced a linear "Σ confidence × typeWeight ÷ 20" model
/// that had three concrete flaws):
///
///   1. **Clean signals counted as risk.** HIBP emits `type: "breach_check"`
///      with confidence 1.0 when an address is *not* in any breach. The old
///      `type.contains("breach")` test scored that as a 3× breach hit — i.e. a
///      clean account looked riskier. Such negative/noise signals now map to a
///      zero-weight category.
///   2. **No saturation / double counting.** The same account found by two
///      plugins (e.g. GitHub via the dedicated check *and* via Sherlock), or 40
///      social profiles, scaled linearly. Each category now saturates, so the
///      first confirmed finding matters far more than the tenth, and a single
///      breach outweighs a pile of public profiles.
///   3. **Crude weighting.** Findings are bucketed into categories with
///      calibrated base weights; a breach dominates threat-intel, which
///      dominates identity links, which dominate mere account presence.
///
/// Per category the contribution is `base × (1 − e^(−evidence ⁄ k))`, where
/// `evidence` is the summed confidence of that category's findings and `k` tunes
/// how quickly it saturates. The capped sum across categories is the score.
enum RiskScorer {

    enum Level: String {
        case low      = "Low"
        case medium   = "Medium"
        case high     = "High"
        case critical = "Critical"

        /// Tailwind/custom colour class used in frontend badges.
        var colour: String {
            switch self {
            case .low:      return "green"
            case .medium:   return "yellow"
            case .high:     return "orange"
            case .critical: return "red"
            }
        }
    }

    struct Score {
        let value: Int        // 0–100
        let level: Level
    }

    /// Risk categories, ordered roughly by severity. `base` is the maximum
    /// points the category can contribute; `k` controls saturation speed (a
    /// smaller `k` saturates with less evidence).
    /// Internal rather than private so the coverage test can assert not just
    /// that a type is classified, but that it lands in the right bucket.
    enum Category: CaseIterable {
        case breach      // confirmed leak / paste exposure
        case threat      // exposed service, malicious / abusive reputation
        case identity    // cross-platform identity linkage (Keybase, dev identity)
        case contact     // phone, geolocation, exposed wallet — direct PII
        case account     // account / avatar / social presence
        case infra       // DNS, subdomains, WHOIS technical records
        case noise       // negative / clean / error signals — no exposure

        var base: Double {
            switch self {
            case .breach:   return 45
            case .threat:   return 25
            case .identity: return 18
            case .contact:  return 15
            case .account:  return 15
            case .infra:    return 5
            case .noise:    return 0
            }
        }

        var k: Double {
            switch self {
            case .breach:   return 1.0
            case .threat:   return 1.5
            case .identity: return 2.0
            case .contact:  return 1.5
            case .account:  return 3.0
            case .infra:    return 2.0
            case .noise:    return 1.0
            }
        }
    }

    static func compute(results: [Result]) throws -> Score {
        // Drop exact duplicates (same source+type+rawData) so a cache re-add or
        // a repeat finding can't inflate the score.
        var seen = Set<String>()
        var contributions: [(Category, Double)] = []
        for r in results {
            let key = "\(r.source)\u{1}\(r.type)\u{1}\(try r.rawData)"
            guard seen.insert(key).inserted else { continue }
            contributions.append((category(for: r.type), r.confidenceScore))
        }
        return score(from: contributions)
    }

    /// Overload accepting raw `(confidence, type)` tuples — used when the full
    /// `Result` model isn't loaded. No dedup (no source/rawData to key on).
    static func compute(raw: [(confidence: Double, type: String)]) -> Score {
        score(from: raw.map { (category(for: $0.type), $0.confidence) })
    }

    // MARK: - Core

    private static func score(from contributions: [(Category, Double)]) -> Score {
        guard !contributions.isEmpty else { return Score(value: 0, level: .low) }

        // Sum confidence (evidence) per category.
        var evidence: [Category: Double] = [:]
        for (category, confidence) in contributions {
            evidence[category, default: 0] += max(0.0, min(1.0, confidence))
        }

        // Saturating contribution per category, summed and capped.
        var total = 0.0
        for category in Category.allCases {
            guard let ev = evidence[category], ev > 0, category.base > 0 else { continue }
            total += category.base * (1 - exp(-ev / category.k))
        }

        let value = Int(min(100.0, total).rounded())
        return Score(value: value, level: level(for: value))
    }

    private static func level(for value: Int) -> Level {
        switch value {
        case 0..<25:  return .low
        case 25..<50: return .medium
        case 50..<75: return .high
        default:      return .critical
        }
    }

    // MARK: - Classification

    /// Every result type a shipping plugin emits, mapped to its risk category.
    ///
    /// A dictionary rather than a `switch` so the coverage is *inspectable*: a
    /// test walks the plugin sources, collects every `type:` literal, and fails
    /// if one is missing here. That matters because an unlisted type does not
    /// error — it silently falls through to the substring heuristic below and
    /// gets whatever weight its spelling happens to attract. That is precisely
    /// how `breach_check` (the "no breaches found" signal) once scored as a
    /// breach, and how `security_txt` — a domain publishing a responsible
    /// disclosure policy, which is a good sign — was counted as exposure.
    static let explicitCategories: [String: Category] = [
        // ── Negative / clean / informational signals — explicitly zero risk ──
        // `breach_check` is the "no breaches found" case; `data_breach` is the
        // real hit.
        "breach_check": .noise,
        "api_rate_limit": .noise,
        "username_validation": .noise,
        // Email-auth posture: the informational records and a locked-down
        // result are zero-risk; only an actually-spoofable domain counts as
        // exposure (see `email_spoofable`).
        "email_auth_ok": .noise,
        "email_auth_spf": .noise,
        "email_auth_dmarc": .noise,
        "email_auth_dkim": .noise,
        "email_auth_mta_sts": .noise,
        "email_auth_spf_missing": .noise,
        "email_auth_dmarc_missing": .noise,
        "dnssec_enabled": .noise,
        "dns_caa": .noise,
        // Facts about an address, not exposure of the person behind it: that a
        // provider is disposable, or that the domain has (or lacks) MX records,
        // says nothing about what leaked.
        "disposable_email": .noise,
        "email_intel": .noise,
        // Publishing security.txt is a responsible-disclosure signal. Scoring it
        // as risk penalises the sites doing the right thing.
        "security_txt": .noise,

        // ── Confirmed leak / paste exposure ──────────────────────────────────
        "data_breach": .breach,
        "paste_exposure": .breach,
        "exposed_file": .breach,

        // ── Exposed service, malicious or abusive reputation ─────────────────
        "exposed_service": .threat,
        "vulnerability": .threat,
        "ip_abuse": .threat,
        "ip_reputation": .threat,
        "domain_reputation": .threat,
        "lookalike_domain": .threat,
        "email_spoofable": .threat,
        // A host served over plain HTTP is a real weakness, not a neutral
        // infrastructure fact.
        "insecure_transport": .threat,

        // ── Cross-platform identity linkage ──────────────────────────────────
        "identity_proof": .identity,
        "developer_identity": .identity,

        // ── Direct PII ───────────────────────────────────────────────────────
        "phone_number": .contact,
        "ip_geolocation": .contact,
        "crypto_wallet": .contact,
        // An address harvested from public commit metadata. It landed here
        // anyway, but only because the word "email" happens to appear in the
        // heuristic's contact branch — the same accident that once scored
        // `breach_check` as a breach. Stated, it is a decision.
        "email": .contact,

        // ── Account / avatar / social presence ───────────────────────────────
        "account_presence": .account,
        "avatar_presence": .account,
        "social_media": .account,

        // ── Technical records and reconnaissance detail ──────────────────────
        "dns_a_record": .infra,
        "dns_mx_record": .infra,
        "dns_ptr_record": .infra,
        "dns_spf_record": .infra,
        "subdomain": .infra,
        "subdomain_ip": .infra,
        "whois_record": .infra,
        "domain_registration": .infra,
        "archive_history": .infra,
        "disallowed_path": .infra,
        "sitemap": .infra,
        "tech_stack": .infra,
        // Deliberately `infra`, not `threat`: this reports a *grade*, covering
        // both a well-configured site and a bare one, so weighting it as a
        // weakness would penalise the former. The grade itself is in metadata.
        "security_headers": .infra
    ]

    /// Maps a result `type` to a risk category: the explicit table above, then
    /// substring heuristics so a type from a plugin added after this file was
    /// last touched still lands somewhere sane rather than nowhere.
    private static func category(for type: String) -> Category {
        let normalized = type.lowercased()
        if let known = explicitCategories[normalized] { return known }
        if normalized.contains("breach") || normalized.contains("leak")
            || normalized.contains("password") || normalized.contains("credential") {
            return .breach
        }
        if normalized.contains("exposed") || normalized.contains("vuln")
            || normalized.contains("abuse") || normalized.contains("malicious") {
            return .threat
        }
        if normalized.contains("phone") || normalized.contains("location")
            || normalized.contains("geo") || normalized.contains("email") {
            return .contact
        }
        if normalized.contains("account") || normalized.contains("profile")
            || normalized.contains("presence") {
            return .account
        }
        return .infra
    }
}
