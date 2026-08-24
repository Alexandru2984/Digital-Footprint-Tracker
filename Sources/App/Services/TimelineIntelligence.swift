import Foundation
import Vapor

/// Builds a privacy-bounded, deterministic chronology from structured finding
/// metadata. Raw finding payloads and arbitrary metadata are never copied into
/// the report.
enum TimelineIntelligence {
    static let maximumEvents = 500
    private static let maximumObservations = 5_000
    static let maximumInputs = 10_000
    private static let maximumBreachDatesPerInput = 250
    private static let maximumBreachMetadataCharacters = 64_000
    private static let maximumSourcesPerEvent = 12
    private static let maximumConflictDates = 8

    struct Event: Content, Equatable {
        let date: String
        let label: String
        let category: String
        let precision: String
        let sources: [String]
        let confidence: Double
        let evidenceCount: Int
        let conflicting: Bool
        let conflictDates: [String]

        init(
            date: String,
            label: String,
            category: String,
            precision: String? = nil,
            sources: [String] = [],
            confidence: Double = 0,
            evidenceCount: Int = 1,
            conflicting: Bool = false,
            conflictDates: [String] = []
        ) {
            self.date = date
            self.label = label
            self.category = category
            self.precision = precision ?? (date.count == 4 ? "year" : "day")
            self.sources = sources
            self.confidence = confidence
            self.evidenceCount = evidenceCount
            self.conflicting = conflicting
            self.conflictDates = conflictDates
        }
    }

    struct Summary: Content, Equatable {
        let eventCount: Int
        let totalEventCount: Int
        let truncated: Bool
        let earliestDate: String?
        let latestDate: String?
        let categoryCounts: [String: Int]
        let sourceCount: Int
        let corroboratedEvents: Int
        let conflictGroups: Int
        let breachEventCount: Int
        let breachRecurrenceCount: Int
        let breachYears: [Int]
    }

    struct Report: Content, Equatable {
        let schemaVersion: Int
        let events: [Event]
        let summary: Summary
    }

    struct NormalizedDate: Equatable {
        let value: String
        let precision: String
    }

    private struct Candidate {
        let logicalKey: String
        let date: NormalizedDate
        let label: String
        let category: String
        let source: String
        let confidence: Double
    }

    private struct GroupKey: Hashable {
        let logicalKey: String
        let date: String
    }

    /// Extracts account, breach, domain-registration, certificate and archive
    /// events. Processing and output limits protect this read endpoint from
    /// pathological legacy metadata while retaining a stable oldest-first view.
    static func build(from inputs: [IdentitySynthesizer.Input]) -> Report {
        var candidates: [Candidate] = []
        for input in inputs.prefix(maximumInputs) where candidates.count < maximumObservations {
            appendAccountCandidate(from: input, to: &candidates)
            appendBreachCandidates(from: input, to: &candidates)
            appendDomainCandidates(from: input, to: &candidates)
            appendArchiveCandidates(from: input, to: &candidates)
            appendCertificateCandidate(from: input, to: &candidates)
        }
        return makeReport(candidates)
    }

    private static func appendAccountCandidate(from input: IdentitySynthesizer.Input, to candidates: inout [Candidate]) {
        let metadata = input.metadata
        guard let since = nonEmpty(metadata["since"]) else { return }
        let platform = boundedText(nonEmpty(metadata["platform"]) ?? input.source, limit: 40)
            ?? "Unknown"
        let accountReference = boundedText(
            nonEmpty(metadata["username"]) ?? nonEmpty(metadata["profileURL"]) ?? platform,
            limit: 200
        ) ?? platform
        appendCandidate(
            rawDate: since,
            label: "\(prettyPlatform(platform)) account created",
            category: "account",
            logicalKey: "account|\(platform)|\(accountReference)",
            input: input,
            to: &candidates
        )
    }

    private static func appendBreachCandidates(from input: IdentitySynthesizer.Input, to candidates: inout [Candidate]) {
        guard input.type == "data_breach",
              let dates = nonEmpty(
                input.metadata["breachDates"],
                maximumCharacters: maximumBreachMetadataCharacters
              ) else { return }
        for entry in dates.split(separator: ";", omittingEmptySubsequences: true)
            .prefix(maximumBreachDatesPerInput) {
            guard let separator = entry.lastIndex(of: "|") else { continue }
            let name = String(entry[..<separator]).trimmingCharacters(in: .whitespacesAndNewlines)
            let rawDate = String(entry[entry.index(after: separator)...])
            guard let cleanName = boundedText(name, limit: 120) else { continue }
            appendCandidate(
                rawDate: rawDate,
                label: "Breach: \(cleanName)",
                category: "breach",
                logicalKey: "breach|\(cleanName)",
                input: input,
                to: &candidates
            )
        }
    }

    private static func appendDomainCandidates(from input: IdentitySynthesizer.Input, to candidates: inout [Candidate]) {
        guard input.type == "domain_registration" else { return }
        let domain = boundedText(nonEmpty(input.metadata["domain"]) ?? "domain", limit: 120) ?? "domain"
        let events = [
            ("registrationDate", "\(domain) registered", "registration"),
            ("lastChangedDate", "\(domain) registration updated", "updated"),
            ("expirationDate", "\(domain) registration expires", "expiration"),
        ]
        for (field, label, kind) in events {
            guard let rawDate = nonEmpty(input.metadata[field]) else { continue }
            appendCandidate(
                rawDate: rawDate,
                label: label,
                category: "domain",
                logicalKey: "domain|\(domain)|\(kind)",
                input: input,
                to: &candidates
            )
        }
    }

    private static func appendArchiveCandidates(from input: IdentitySynthesizer.Input, to candidates: inout [Candidate]) {
        guard input.type == "archive_history" else { return }
        let domain = boundedText(nonEmpty(input.metadata["domain"]) ?? "domain", limit: 120) ?? "domain"
        let events = [
            ("firstSeen", "\(domain) first archived", "first"),
            ("lastSeen", "\(domain) last archived", "last"),
        ]
        for (field, label, kind) in events {
            guard let rawDate = nonEmpty(input.metadata[field]) else { continue }
            appendCandidate(
                rawDate: rawDate,
                label: label,
                category: "archive",
                logicalKey: "archive|\(domain)|\(kind)",
                input: input,
                to: &candidates
            )
        }
    }

    private static func appendCertificateCandidate(from input: IdentitySynthesizer.Input, to candidates: inout [Candidate]) {
        guard let firstSeen = nonEmpty(input.metadata["certificateNotBefore"]) else { return }
        let hostname = nonEmpty(input.metadata["subdomain"])
            ?? nonEmpty(input.metadata["domain"])
            ?? "hostname"
        let cleanHostname = boundedText(hostname, limit: 120) ?? "hostname"
        appendCandidate(
            rawDate: firstSeen,
            label: "Certificate first seen: \(cleanHostname)",
            category: "certificate",
            logicalKey: "certificate|\(cleanHostname)",
            input: input,
            to: &candidates
        )
    }

    private static func appendCandidate(
        rawDate: String,
        label: String,
        category: String,
        logicalKey: String,
        input: IdentitySynthesizer.Input,
        to candidates: inout [Candidate]
    ) {
        guard candidates.count < maximumObservations,
              let date = normalizedDate(rawDate),
              let cleanLabel = boundedText(label, limit: 160),
              let cleanSource = boundedText(input.source, limit: 80)
        else { return }
        let confidence = input.confidence.isFinite ? min(1, max(0, input.confidence)) : 0
        candidates.append(Candidate(
            logicalKey: logicalKey.lowercased(),
            date: date,
            label: cleanLabel,
            category: category,
            source: cleanSource,
            confidence: confidence
        ))
    }

    private static func makeReport(_ candidates: [Candidate]) -> Report {
        let datesByLogicalKey = Dictionary(grouping: candidates, by: \Candidate.logicalKey)
            .mapValues { Set($0.map(\.date.value)).sorted() }
        let grouped = Dictionary(grouping: candidates) {
            GroupKey(logicalKey: $0.logicalKey, date: $0.date.value)
        }

        let allEvents = grouped.values.compactMap { observations -> Event? in
            guard let first = observations.first else { return nil }
            let sources = Array(Set(observations.map(\.source)).sorted().prefix(maximumSourcesPerEvent))
            let sourceBoost = min(0.15, Double(max(0, sources.count - 1)) * 0.05)
            let confidence = min(1, (observations.map(\.confidence).max() ?? 0) + sourceBoost)
            let conflictDates = datesByLogicalKey[first.logicalKey] ?? []
            return Event(
                date: first.date.value,
                label: observations.map(\.label).min() ?? first.label,
                category: first.category,
                precision: first.date.precision,
                sources: sources,
                confidence: confidence,
                evidenceCount: observations.count,
                conflicting: conflictDates.count > 1,
                conflictDates: conflictDates.count > 1
                    ? Array(conflictDates.prefix(maximumConflictDates))
                    : []
            )
        }.sorted {
            if $0.date != $1.date { return $0.date < $1.date }
            if $0.category != $1.category { return $0.category < $1.category }
            return $0.label < $1.label
        }

        let events = Array(allEvents.prefix(maximumEvents))
        var categoryCounts: [String: Int] = [:]
        for event in allEvents { categoryCounts[event.category, default: 0] += 1 }
        let breachKeys = Set(candidates.filter { $0.category == "breach" }.map(\.logicalKey))
        let breachYears = Set(allEvents.filter { $0.category == "breach" }
            .compactMap { Int($0.date.prefix(4)) }).sorted()

        return Report(
            schemaVersion: 1,
            events: events,
            summary: Summary(
                eventCount: events.count,
                totalEventCount: allEvents.count,
                truncated: allEvents.count > events.count,
                earliestDate: allEvents.first?.date,
                latestDate: allEvents.last?.date,
                categoryCounts: categoryCounts,
                sourceCount: Set(allEvents.flatMap(\.sources)).count,
                corroboratedEvents: allEvents.filter { $0.sources.count > 1 }.count,
                conflictGroups: datesByLogicalKey.values.filter { $0.count > 1 }.count,
                breachEventCount: breachKeys.count,
                breachRecurrenceCount: max(0, breachKeys.count - 1),
                breachYears: breachYears
            )
        )
    }

    /// Accepts a strict year, a valid ISO day/RFC3339 date, or the English date
    /// emitted by Steam. All output is normalized to a year or UTC-style ISO day.
    static func normalizedDate(_ raw: String) -> NormalizedDate? {
        let bounded = raw.prefix(65)
        guard bounded.count <= 64 else { return nil }
        let value = bounded.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.count <= 64 else { return nil }

        if value.range(of: "^[0-9]{4}$", options: .regularExpression) != nil,
           let year = Int(value), (1970...2100).contains(year) {
            return NormalizedDate(value: value, precision: "year")
        }

        if value.count == 10, let normalized = normalizedISODay(value) { return normalized }
        if let normalized = normalizedISOTimestamp(value) { return normalized }

        let collapsed = value.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        return normalizedEnglishDay(collapsed)
    }

    private static func normalizedISOTimestamp(_ value: String) -> NormalizedDate? {
        let pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}"
            + "(?:\\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?$"
        guard value.range(of: pattern, options: .regularExpression) != nil,
              let localDay = normalizedISODay(String(value.prefix(10))) else { return nil }
        let timeStart = value.index(value.startIndex, offsetBy: 11)
        let time = value[timeStart...].prefix(8).split(separator: ":").compactMap { Int($0) }
        guard time.count == 3, (0...23).contains(time[0]), (0...59).contains(time[1]),
              (0...59).contains(time[2]) else { return nil }

        var offsetSeconds = 0
        if let zoneRange = value.range(of: "[+-][0-9]{2}:?[0-9]{2}$", options: .regularExpression) {
            let rawZone = String(value[zoneRange])
            let zone = String(rawZone.dropFirst()).replacingOccurrences(of: ":", with: "")
            guard zone.count == 4,
                  let hour = Int(zone.prefix(2)), let minute = Int(zone.suffix(2)),
                  (0...14).contains(hour), (0...59).contains(minute),
                  hour < 14 || minute == 0 else { return nil }
            let sign = rawZone.first == "-" ? -1 : 1
            offsetSeconds = sign * ((hour * 60 + minute) * 60)
        }

        let fields = localDay.value.split(separator: "-").compactMap { Int($0) }
        guard fields.count == 3, let zone = TimeZone(secondsFromGMT: offsetSeconds) else { return nil }
        var localCalendar = Calendar(identifier: .gregorian)
        localCalendar.timeZone = zone
        var components = DateComponents()
        components.calendar = localCalendar
        components.timeZone = zone
        components.year = fields[0]
        components.month = fields[1]
        components.day = fields[2]
        components.hour = time[0]
        components.minute = time[1]
        components.second = time[2]
        guard let instant = localCalendar.date(from: components) else { return nil }

        guard let utcZone = TimeZone(secondsFromGMT: 0) else { return nil }
        var utcCalendar = Calendar(identifier: .gregorian)
        utcCalendar.timeZone = utcZone
        let utc = utcCalendar.dateComponents([.year, .month, .day], from: instant)
        guard let year = utc.year, let month = utc.month, let day = utc.day else { return nil }
        return normalizedISODay(String(format: "%04d-%02d-%02d", year, month, day))
    }

    private static func normalizedEnglishDay(_ value: String) -> NormalizedDate? {
        let parts = value.split(separator: " ")
        guard parts.count == 3, parts[1].hasSuffix(","),
              let day = Int(parts[1].dropLast()), let year = Int(parts[2]) else { return nil }
        let months = [
            "january": 1, "jan": 1, "february": 2, "feb": 2,
            "march": 3, "mar": 3, "april": 4, "apr": 4,
            "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
            "august": 8, "aug": 8, "september": 9, "sep": 9,
            "october": 10, "oct": 10, "november": 11, "nov": 11,
            "december": 12, "dec": 12,
        ]
        guard let month = months[parts[0].lowercased()] else { return nil }
        let isoDay = String(format: "%04d-%02d-%02d", year, month, day)
        return normalizedISODay(isoDay)
    }

    /// UTC day for provider timestamps such as Reddit/Hacker News `created_utc`.
    static func isoDay(unixTimestamp: Double) -> String? {
        guard unixTimestamp.isFinite, unixTimestamp >= 0 else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = calendar.dateComponents(
            [.year, .month, .day],
            from: Date(timeIntervalSince1970: unixTimestamp)
        )
        guard let year = components.year, let month = components.month, let day = components.day,
              (1970...2100).contains(year) else { return nil }
        return String(format: "%04d-%02d-%02d", year, month, day)
    }

    private static func normalizedISODay(_ value: String) -> NormalizedDate? {
        guard value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}$", options: .regularExpression) != nil else {
            return nil
        }
        let fields = value.split(separator: "-").compactMap { Int($0) }
        guard fields.count == 3, (1970...2100).contains(fields[0]) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        var components = DateComponents()
        components.calendar = calendar
        components.timeZone = calendar.timeZone
        components.year = fields[0]
        components.month = fields[1]
        components.day = fields[2]
        guard let date = calendar.date(from: components) else { return nil }
        let checked = calendar.dateComponents([.year, .month, .day], from: date)
        guard checked.year == fields[0], checked.month == fields[1], checked.day == fields[2] else { return nil }
        return NormalizedDate(value: value, precision: "day")
    }

    private static func prettyPlatform(_ raw: String) -> String {
        let platform = boundedText(raw, limit: 40) ?? "Unknown"
        let known = [
            "github": "GitHub",
            "gitlab": "GitLab",
            "hackernews": "Hacker News",
            "mastodon": "Mastodon",
            "reddit": "Reddit",
            "steam": "Steam",
        ]
        let key = platform.lowercased()
        return known[key] ?? platform.prefix(1).uppercased() + platform.dropFirst()
    }

    private static func boundedText(_ raw: String, limit: Int) -> String? {
        guard limit > 0 else { return nil }
        let sample = String(raw.prefix(max(256, limit * 4)))
        let withoutControls = sample.components(separatedBy: .controlCharacters).joined(separator: " ")
        let collapsed = withoutControls.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        guard !collapsed.isEmpty else { return nil }
        return String(collapsed.prefix(limit))
    }

    private static func nonEmpty(_ raw: String?, maximumCharacters: Int = 512) -> String? {
        guard let raw else { return nil }
        let bounded = raw.prefix(maximumCharacters + 1)
        guard bounded.count <= maximumCharacters else { return nil }
        let trimmed = bounded.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
