import Foundation

/// Cross-scan entity correlation. Finds entities (emails, usernames, IPs,
/// domains, phones, …) that appear across two or more of a user's scans —
/// the OSINT pivot that links separate targets to the same person.
///
/// Pure and DB-free so it is unit-testable. `CorrelationController` builds
/// `ScanSummary` values from Fluent rows and calls `correlate`.
///
/// Sources of entities, in order of precision:
///   1. The scan's own `input` — the strongest anchor, previously ignored.
///   2. A result's structured `metadata` (e.g. GitHub's `twitter`/`location`,
///      Shodan's `ip`) — precise, typed.
///   3. Regex over `rawData` — fallback for plugins not yet emitting metadata,
///      preserving the original behaviour.
enum Correlator {

    struct ResultEntry {
        let source: String
        let type: String
        let rawData: String
        let metadata: [String: String]?
    }

    struct ScanSummary {
        let id: UUID
        let input: String
        let results: [ResultEntry]
    }

    struct Occurrence: Equatable {
        let scanID: UUID
        let input: String
        let source: String
        let resultType: String
    }

    struct Entity {
        let value: String
        let type: String
        let occurrences: [Occurrence]
    }

    /// Minimum length for an entity value to be considered (filters noise like
    /// short numeric fragments).
    private static let minEntityLength = 4

    static func correlate(_ scans: [ScanSummary]) -> [Entity] {
        guard scans.count >= 2 else { return [] }

        // entity value → (type, scanID → first occurrence in that scan)
        var types: [String: String] = [:]
        var occurrences: [String: [UUID: Occurrence]] = [:]

        for scan in scans {
            for extracted in entities(in: scan) where extracted.value.count >= minEntityLength {
                let key = extracted.value
                if types[key] == nil { types[key] = extracted.type }
                // One occurrence per (entity, scan): first source wins.
                if occurrences[key]?[scan.id] == nil {
                    occurrences[key, default: [:]][scan.id] = Occurrence(
                        scanID: scan.id,
                        input: scan.input,
                        source: extracted.source,
                        resultType: extracted.type
                    )
                }
            }
        }

        var result: [Entity] = []
        for (value, perScan) in occurrences where perScan.count >= 2 {
            let occ = perScan.values.sorted { $0.scanID.uuidString < $1.scanID.uuidString }
            result.append(Entity(value: value, type: types[value] ?? "unknown", occurrences: occ))
        }
        result.sort { $0.occurrences.count > $1.occurrences.count }
        return Array(result.prefix(100))
    }

    // MARK: - Entity extraction

    private struct Extracted { let type: String; let value: String; let source: String }

    private static func entities(in scan: ScanSummary) -> [Extracted] {
        var out: [Extracted] = []

        // 1. The scan input is itself an entity (strongest anchor).
        out.append(Extracted(type: classifyInput(scan.input), value: normalize(scan.input), source: "scan_input"))

        // 2. Per result: structured metadata if present, else regex fallback.
        for r in scan.results {
            if let meta = r.metadata, !meta.isEmpty {
                out.append(contentsOf: structuredEntities(meta, source: r.source))
            } else {
                out.append(contentsOf: regexEntities(r.rawData, source: r.source))
            }
        }
        return out
    }

    /// Maps known metadata keys to correlation entity types. Platform-handle
    /// keys (e.g. Keybase identity proofs, a GitHub-linked twitter) all collapse
    /// to `username` so the same handle on different platforms correlates.
    private static let keyToType: [String: String] = [
        "email": "email",
        "username": "username",
        "twitter": "username",
        "github": "username",
        "reddit": "username",
        "hackernews": "username",
        "mastodon": "username",
        "gitlab": "username",
        "steam": "username",
        "telegram": "username",
        "facebook": "username",
        "instagram": "username",
        "phone": "phone",
        "phonenumber": "phone",
        "ip": "ip",
        "domain": "domain",
        "subdomain": "domain",
        "location": "location",
        "company": "org",
        "org": "org",
        "blog": "url",
        "profileurl": "url",
        "url": "url",
        "website": "url",
        "wallet": "wallet",
        "cryptowallet": "wallet"
    ]

    private static func structuredEntities(_ meta: [String: String], source: String) -> [Extracted] {
        meta.compactMap { key, value in
            guard let type = keyToType[key.lowercased()] else { return nil }
            let v = normalize(value)
            guard !v.isEmpty else { return nil }
            return Extracted(type: type, value: v, source: source)
        }
    }

    private static let patterns: [(type: String, pattern: String)] = [
        ("email",  #"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"#),
        ("ip",     #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#),
        ("domain", #"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|co|uk|de|fr|ru|info|xyz|app|dev)\b"#),
        ("phone",  #"(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}"#),
        ("hash",   #"\b[a-fA-F0-9]{32,64}\b"#)
    ]

    private static func regexEntities(_ text: String, source: String) -> [Extracted] {
        var out: [Extracted] = []
        for (entityType, pattern) in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { continue }
            let range = NSRange(text.startIndex..., in: text)
            for match in regex.matches(in: text, range: range) {
                guard let r = Range(match.range, in: text) else { continue }
                let value = String(text[r]).lowercased()
                if value.count < 5 { continue }
                if entityType == "hash" && value.allSatisfy({ $0.isNumber }) { continue }
                out.append(Extracted(type: entityType, value: value, source: source))
            }
        }
        return out
    }

    // MARK: - Helpers

    private static func normalize(_ s: String) -> String {
        var v = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if v.hasPrefix("@") { v.removeFirst() }
        return v
    }

    private static func classifyInput(_ input: String) -> String {
        let v = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if v.contains("@") { return "email" }
        if v.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil { return "ip" }
        if v.contains(".") { return "domain" }
        if v.hasPrefix("+") || v.allSatisfy({ $0.isNumber }) { return "phone" }
        return "username"
    }
}
