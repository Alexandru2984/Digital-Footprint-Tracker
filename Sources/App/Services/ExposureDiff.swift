import Vapor

/// Computes the security-relevant change between two scans of the same target:
/// newly opened / closed ports, new / resolved CVEs, new / removed subdomains and
/// web-posture grade shifts. This turns the scanner from a snapshot into change
/// detection — the monitoring an attack-surface tool needs ("port 3389 just opened
/// on 1.2.3.4", not "12 findings changed").
///
/// Pure and DB-free (operates on `IdentitySynthesizer.Input`s), so it unit-tests
/// offline and is shared by the diff endpoint and the scheduled monitor.
enum ExposureDiff {

    struct HostPorts: Content { let ip: String; let ports: [String] }
    struct GradeChange: Content { let domain: String; let from: String?; let to: String }

    struct Delta: Content {
        let newPorts: [HostPorts]
        let closedPorts: [HostPorts]
        let newCVEs: [String]
        let resolvedCVEs: [String]
        let newSubdomains: [String]
        let removedSubdomains: [String]
        let gradeChanges: [GradeChange]

        static let empty = Delta(newPorts: [], closedPorts: [], newCVEs: [], resolvedCVEs: [],
                                 newSubdomains: [], removedSubdomains: [], gradeChanges: [])

        /// Did anything get *worse* (new attack surface)? Drives whether to alert.
        var hasExposureChange: Bool {
            !newPorts.isEmpty || !newCVEs.isEmpty || !newSubdomains.isEmpty || worsenedGrades
        }
        var isEmpty: Bool {
            newPorts.isEmpty && closedPorts.isEmpty && newCVEs.isEmpty && resolvedCVEs.isEmpty
                && newSubdomains.isEmpty && removedSubdomains.isEmpty && gradeChanges.isEmpty
        }
        var worsenedGrades: Bool { gradeChanges.contains { isWorse(from: $0.from, to: $0.to) } }

        /// One short, alert-friendly line of the additions (what got worse).
        var headline: String {
            var parts: [String] = []
            let portCount = newPorts.reduce(0) { $0 + $1.ports.count }
            if let h = newPorts.first, portCount > 0 {
                let example = "\(h.ip): \(h.ports.prefix(4).joined(separator: ","))"
                parts.append("+\(portCount) port\(portCount == 1 ? "" : "s") (\(example))")
            }
            if !newCVEs.isEmpty {
                parts.append("+\(newCVEs.count) CVE\(newCVEs.count == 1 ? "" : "s") (\(newCVEs.prefix(2).joined(separator: ", ")))")
            }
            if !newSubdomains.isEmpty {
                parts.append("+\(newSubdomains.count) subdomain\(newSubdomains.count == 1 ? "" : "s") (\(newSubdomains.prefix(2).joined(separator: ", ")))")
            }
            for gc in gradeChanges where isWorse(from: gc.from, to: gc.to) {
                parts.append("\(gc.domain) posture \(gc.from ?? "?")→\(gc.to)")
            }
            return parts.joined(separator: " · ")
        }
    }

    /// The exposure facts pulled out of a scan's findings.
    struct Snapshot {
        var portsByIP: [String: Set<String>] = [:]
        var cvesByIP: [String: Set<String>] = [:]
        var subdomains: Set<String> = []
        var gradeByDomain: [String: String] = [:]
    }

    static func between(previous: [IdentitySynthesizer.Input], current: [IdentitySynthesizer.Input]) -> Delta {
        diff(previous: snapshot(from: previous), current: snapshot(from: current))
    }

    static func snapshot(from inputs: [IdentitySynthesizer.Input]) -> Snapshot {
        var snap = Snapshot()
        for inp in inputs {
            let m = inp.metadata
            if let ip = nonEmpty(m["ip"]) {
                for port in csv(m["ports"]) { snap.portsByIP[ip, default: []].insert(port) }
                if let single = nonEmpty(m["port"]) { snap.portsByIP[ip, default: []].insert(single) }
                for cve in csv(m["cves"]) { snap.cvesByIP[ip, default: []].insert(cve) }
            }
            if inp.type == "subdomain" || inp.type == "subdomain_ip" {
                if let sub = nonEmpty(m["subdomain"]) { snap.subdomains.insert(sub.lowercased()) }
            }
            if inp.type == "security_headers", let dom = nonEmpty(m["domain"]), let grade = nonEmpty(m["grade"]) {
                snap.gradeByDomain[dom.lowercased()] = grade
            }
        }
        return snap
    }

    static func diff(previous prev: Snapshot, current cur: Snapshot) -> Delta {
        var newPorts: [HostPorts] = []
        var closedPorts: [HostPorts] = []
        for ip in Set(prev.portsByIP.keys).union(cur.portsByIP.keys).sorted() {
            let added = (cur.portsByIP[ip] ?? []).subtracting(prev.portsByIP[ip] ?? [])
            let removed = (prev.portsByIP[ip] ?? []).subtracting(cur.portsByIP[ip] ?? [])
            if !added.isEmpty { newPorts.append(HostPorts(ip: ip, ports: sortPorts(added))) }
            if !removed.isEmpty { closedPorts.append(HostPorts(ip: ip, ports: sortPorts(removed))) }
        }

        var newCVEs: [String] = []
        var resolvedCVEs: [String] = []
        for ip in Set(prev.cvesByIP.keys).union(cur.cvesByIP.keys).sorted() {
            for cve in (cur.cvesByIP[ip] ?? []).subtracting(prev.cvesByIP[ip] ?? []).sorted() {
                newCVEs.append("\(cve) (\(ip))")
            }
            for cve in (prev.cvesByIP[ip] ?? []).subtracting(cur.cvesByIP[ip] ?? []).sorted() {
                resolvedCVEs.append("\(cve) (\(ip))")
            }
        }

        var gradeChanges: [GradeChange] = []
        for dom in Set(prev.gradeByDomain.keys).union(cur.gradeByDomain.keys).sorted() {
            let from = prev.gradeByDomain[dom]
            guard let to = cur.gradeByDomain[dom], to != from else { continue }
            gradeChanges.append(GradeChange(domain: dom, from: from, to: to))
        }

        return Delta(
            newPorts: newPorts, closedPorts: closedPorts,
            newCVEs: newCVEs, resolvedCVEs: resolvedCVEs,
            newSubdomains: cur.subdomains.subtracting(prev.subdomains).sorted(),
            removedSubdomains: prev.subdomains.subtracting(cur.subdomains).sorted(),
            gradeChanges: gradeChanges)
    }

    // MARK: - Helpers

    /// True if the grade got worse (A is best; a later letter is worse). A brand-new
    /// grade (no prior) is not itself "worse" — there's no baseline to regress from.
    static func isWorse(from: String?, to: String) -> Bool {
        guard let from else { return false }
        return to > from
    }

    private static func sortPorts(_ ports: Set<String>) -> [String] {
        ports.sorted { (Int($0) ?? 0, $0) < (Int($1) ?? 0, $1) }
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        return s
    }

    private static func csv(_ s: String?) -> [String] {
        guard let s = nonEmpty(s) else { return [] }
        return s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}
