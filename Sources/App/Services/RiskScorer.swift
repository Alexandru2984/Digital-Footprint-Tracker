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
    private enum Category: CaseIterable {
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

    static func compute(results: [Result]) -> Score {
        // Drop exact duplicates (same source+type+rawData) so a cache re-add or
        // a repeat finding can't inflate the score.
        var seen = Set<String>()
        var contributions: [(Category, Double)] = []
        for r in results {
            let key = "\(r.source)\u{1}\(r.type)\u{1}\(r.rawData)"
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

    /// Maps a result `type` to a risk category. Exact matches first, then a few
    /// substring heuristics so a new plugin type still lands somewhere sane.
    private static func category(for type: String) -> Category {
        switch type.lowercased() {
        // Negative / clean / error signals — explicitly zero risk. `breach_check`
        // is the "no breaches found" case; `data_breach` is the real hit.
        case "breach_check", "api_rate_limit", "username_validation":
            return .noise
        case "data_breach", "paste_exposure":
            return .breach
        case "exposed_service", "vulnerability", "ip_abuse", "ip_reputation", "domain_reputation",
             "lookalike_domain":
            return .threat
        case "identity_proof", "developer_identity":
            return .identity
        case "phone_number", "ip_geolocation", "crypto_wallet":
            return .contact
        case "account_presence", "avatar_presence", "social_media":
            return .account
        case "dns_a_record", "dns_mx_record", "dns_ptr_record", "dns_spf_record",
             "subdomain", "subdomain_ip", "whois_record", "domain_registration":
            return .infra
        default:
            let t = type.lowercased()
            if t.contains("breach") || t.contains("leak") || t.contains("password") || t.contains("credential") {
                return .breach
            }
            if t.contains("exposed") || t.contains("vuln") || t.contains("abuse") || t.contains("malicious") {
                return .threat
            }
            if t.contains("phone") || t.contains("location") || t.contains("geo") || t.contains("email") {
                return .contact
            }
            if t.contains("account") || t.contains("profile") || t.contains("presence") {
                return .account
            }
            return .infra
        }
    }
}
