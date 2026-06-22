import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Brand-impersonation recon: generates lookalike permutations of the target
/// domain (dnstwist-style — omission, transposition, adjacent-key typos,
/// bitsquatting, homoglyphs, hyphenation, TLD swaps) and reports the ones that
/// actually *resolve*. A registered, live lookalike is candidate phishing /
/// brand-abuse infrastructure — the kind of attack surface an org rarely sees
/// until a customer is already on it.
///
/// Marked `heavy` (one bounded DoH lookup per candidate, all to the same host) so
/// the candidate fan-out runs it on at most one target. Permutation generation is
/// pure and capped at `maxCandidates`; egress is only to Cloudflare DoH with the
/// candidate carried in the `name` query param (project-controlled host → no SSRF).
struct TyposquatPlugin: FootprintPlugin {
    let name = "Typosquat"
    let description = "Lookalike / typosquatting domains that resolve (dnstwist-style)"
    let cacheTTL: TimeInterval = 21_600 // 6 h — domain registration changes slowly
    let heavy = true

    /// Hard cap on DNS lookups per run. Each candidate is one DoH request to the
    /// shared `cloudflare-dns.com` throttle (0.25 s spacing), so this bounds the
    /// plugin's slice of the 120 s scan deadline well under it.
    static let maxCandidates = 30

    private static let ipv4Pattern = #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let target = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // Domains only — typos of an email, a username, or a bare IP are meaningless.
        guard !target.contains("@"), !target.hasPrefix("http"), target.contains("."),
              target.range(of: Self.ipv4Pattern, options: .regularExpression) == nil,
              target.range(of: #"[a-z]"#, options: .regularExpression) != nil else { return [] }

        let host = CrtShPlugin.normalizeDomain(target)
        guard let base = Self.registrable(host) else { return [] }
        let candidates = Self.permutations(of: base)
        guard !candidates.isEmpty else { return [] }

        // Resolve all candidates concurrently; the per-host throttle serialises
        // the actual DoH starts, and DoHResolver/PluginHTTP honour Task cancel so
        // a deadline hit during the scan tears these down cleanly.
        return await withTaskGroup(of: PluginResult?.self) { group in
            for candidate in candidates {
                group.addTask {
                    if Task.isCancelled { return nil }
                    let ips = await DoHResolver.resolve(candidate.domain, type: "A")
                    guard let ip = ips.first(where: { Self.isIPv4($0) }) ?? ips.first else { return nil }
                    return PluginResult(
                        source: "Typosquat",
                        type: "lookalike_domain",
                        confidenceScore: 0.6, // resolves = registered & live; intent unproven
                        rawData: "Live lookalike \(candidate.domain) → \(ip) (\(candidate.technique) of \(base.full))",
                        metadata: [
                            "lookalike": candidate.domain,
                            "baseDomain": base.full,
                            "technique": candidate.technique,
                            "ip": ip
                        ])
                }
            }
            var out: [PluginResult] = []
            for await result in group { if let result { out.append(result) } }
            // Deterministic order regardless of which lookups finished first.
            return out.sorted { ($0.metadata?["lookalike"] ?? "") < ($1.metadata?["lookalike"] ?? "") }
        }
    }

    // MARK: - Registrable domain

    struct Base: Equatable {
        let sld: String   // second-level label (the bit people typo)
        let tld: String   // public suffix — taken as the final label
        var full: String { "\(sld).\(tld)" }
    }

    /// Reduces a host to its registrable `sld.tld` using the last two labels.
    /// A naive split (no Public Suffix List) — good enough for the common `.com`
    /// case; multi-part suffixes like `.co.uk` fold to `co.uk`, which simply
    /// yields fewer useful permutations rather than anything unsafe.
    static func registrable(_ host: String) -> Base? {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return nil }
        let sld = labels[labels.count - 2]
        let tld = labels[labels.count - 1]
        guard sld.count >= 2, !tld.isEmpty,
              tld.allSatisfy({ $0.isLetter }),
              sld.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else { return nil }
        return Base(sld: sld, tld: tld)
    }

    // MARK: - Permutation generation (pure / testable)

    /// Generates deduped, validated lookalike domains for `base`, capped at
    /// `maxCandidates`. Techniques are interleaved (round-robin) so the cap keeps
    /// variety instead of draining one technique first.
    static func permutations(of base: Base) -> [(domain: String, technique: String)] {
        let sld = base.sld, tld = base.tld
        func domains(_ slds: [String]) -> [String] { slds.map { "\($0).\(tld)" } }

        var buckets: [(technique: String, items: [String])] = [
            ("omission",       domains(omissions(sld))),
            ("transposition",  domains(transpositions(sld))),
            ("repetition",     domains(repetitions(sld))),
            ("replacement",    domains(replacements(sld))),
            ("insertion",      domains(insertions(sld))),
            ("homoglyph",      domains(homoglyphs(sld))),
            ("bitsquat",       domains(bitsquats(sld))),
            ("hyphenation",    domains(hyphenations(sld))),
            ("tld-swap",       tldSwaps(sld: sld, tld: tld))
        ]
        // Validate + drop the base domain itself up front so the round-robin
        // cap is spent only on genuine, well-formed lookalikes.
        for i in buckets.indices {
            buckets[i].items = buckets[i].items.filter { $0 != base.full && isValidHostname($0) }
        }

        var out: [(domain: String, technique: String)] = []
        var seen = Set<String>([base.full])
        var idx = 0
        var anyLeft = true
        while out.count < maxCandidates && anyLeft {
            anyLeft = false
            for bucket in buckets where idx < bucket.items.count {
                anyLeft = true
                let domain = bucket.items[idx]
                if seen.insert(domain).inserted {
                    out.append((domain, bucket.technique))
                    if out.count >= maxCandidates { break }
                }
            }
            idx += 1
        }
        return out
    }

    // MARK: - Techniques (operate on the SLD label)

    static func omissions(_ s: String) -> [String] {
        let c = Array(s)
        guard c.count > 2 else { return [] }
        return c.indices.map { i in String(c[..<i] + c[(i + 1)...]) }
    }

    static func transpositions(_ s: String) -> [String] {
        var c = Array(s)
        guard c.count > 1 else { return [] }
        var out: [String] = []
        for i in 0..<(c.count - 1) where c[i] != c[i + 1] {
            c.swapAt(i, i + 1)
            out.append(String(c))
            c.swapAt(i, i + 1)
        }
        return out
    }

    static func repetitions(_ s: String) -> [String] {
        let c = Array(s)
        return c.indices.map { i in String(c[...i] + c[i...]) }
    }

    static func replacements(_ s: String) -> [String] {
        let c = Array(s)
        var out: [String] = []
        for i in c.indices {
            for n in neighbors(c[i]) where n != c[i] {
                var v = c; v[i] = n; out.append(String(v))
            }
        }
        return out
    }

    static func insertions(_ s: String) -> [String] {
        let c = Array(s)
        var out: [String] = []
        for i in c.indices {
            for n in neighbors(c[i]) where n != c[i] {
                out.append(String(c[..<i]) + String(n) + String(c[i...]))
            }
        }
        return out
    }

    static func homoglyphs(_ s: String) -> [String] {
        let c = Array(s)
        var out: [String] = []
        for i in c.indices {
            for alt in homoglyphMap[c[i]] ?? "" {
                var v = c; v[i] = alt; out.append(String(v))
            }
        }
        return out
    }

    /// Single-bit flips of each ASCII byte that land on another valid hostname
    /// character — models in-flight/memory corruption ("bitsquatting").
    static func bitsquats(_ s: String) -> [String] {
        let c = Array(s)
        var out: [String] = []
        for i in c.indices {
            guard let ascii = c[i].asciiValue else { continue }
            for bit in 0..<7 {
                let flipped = ascii ^ (1 << bit)
                let scalar = Unicode.Scalar(flipped)
                let ch = Character(scalar)
                guard ch != c[i], isHostChar(ch) else { continue }
                var v = c; v[i] = ch; out.append(String(v))
            }
        }
        return out
    }

    static func hyphenations(_ s: String) -> [String] {
        let c = Array(s)
        guard c.count > 2 else { return [] }
        return (1..<c.count).map { i in String(c[..<i]) + "-" + String(c[i...]) }
    }

    static func tldSwaps(sld: String, tld: String) -> [String] {
        commonTLDs.filter { $0 != tld }.map { "\(sld).\($0)" }
    }

    // MARK: - Tables & validation

    private static let commonTLDs = [
        "com", "net", "org", "io", "co", "app", "dev", "info",
        "online", "xyz", "site", "live", "me", "biz"
    ]

    /// QWERTY horizontal neighbours per key — adjacent-key fat-finger typos.
    private static let keyboardNeighbors: [Character: String] = [
        "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
        "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
        "a": "qsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
        "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
        "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
        "n": "bhjm", "m": "njk"
    ]

    private static func neighbors(_ c: Character) -> String { keyboardNeighbors[c] ?? "" }

    /// Common visual confusables that stay within the valid hostname charset.
    private static let homoglyphMap: [Character: String] = [
        "o": "0", "0": "o", "l": "1i", "1": "li", "i": "1l",
        "e": "3", "3": "e", "a": "4", "4": "a", "s": "5", "5": "s",
        "b": "6", "6": "b", "g": "9", "9": "g", "t": "7", "7": "t", "z": "2", "2": "z"
    ]

    private static func isHostChar(_ c: Character) -> Bool {
        c.isASCII && (c.isLetter || c.isNumber || c == "-")
    }

    static func isIPv4(_ s: String) -> Bool {
        s.range(of: ipv4Pattern, options: .regularExpression) != nil
    }

    /// RFC-1123-ish hostname check: every label 1–63 chars of `[a-z0-9-]`, not
    /// starting/ending with a hyphen, total length ≤ 253.
    static func isValidHostname(_ host: String) -> Bool {
        guard host.count <= 253, host.contains(".") else { return false }
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            guard (1...63).contains(label.count),
                  label.first != "-", label.last != "-",
                  label.allSatisfy({ $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") }) else {
                return false
            }
        }
        return true
    }
}
