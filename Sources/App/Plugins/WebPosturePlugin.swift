import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Grades a host's HTTP/TLS security posture — the recon a scanner does that Shodan
/// only hints at: which hardening headers are set (HSTS, CSP, X-Frame-Options, …),
/// whether the site even serves HTTPS, and what server/framework it leaks. Pure
/// `WebPosture.analyze` keeps the grading logic unit-testable; the plugin only does
/// the (SSRF-guarded) fetch.
///
/// The destination host is user-controlled, so fetches go through `SafeHTTP` (pre-flight
/// DNS check + redirect re-validation), never the project-host `PluginHTTP`.

/// Pure security-header grader.
enum WebPosture {
    /// Recommended hardening headers: lowercased key → display name → grade weight
    /// (HSTS and CSP matter most, so they carry the heaviest weight).
    static let recommended: [(key: String, name: String, weight: Double)] = [
        ("strict-transport-security", "HSTS", 2.0),
        ("content-security-policy", "CSP", 2.0),
        ("x-frame-options", "X-Frame-Options", 1.0),
        ("x-content-type-options", "X-Content-Type-Options", 1.0),
        ("referrer-policy", "Referrer-Policy", 0.5),
        ("permissions-policy", "Permissions-Policy", 0.5)
    ]

    struct Assessment {
        let grade: String
        let present: [String]
        let missing: [String]
        let server: String?
    }

    static func analyze(headers: [String: String]) -> Assessment {
        var present: [String] = []
        var missing: [String] = []
        var score = 0.0
        let maxScore = recommended.reduce(0.0) { $0 + $1.weight }
        for h in recommended {
            if let value = headers[h.key], !value.trimmingCharacters(in: .whitespaces).isEmpty {
                present.append(h.name)
                score += h.weight
            } else {
                missing.append(h.name)
            }
        }
        return Assessment(grade: grade(for: score / maxScore),
                          present: present, missing: missing,
                          server: fingerprint(headers))
    }

    static func grade(for ratio: Double) -> String {
        switch ratio {
        case 0.9...:      return "A"
        case 0.75..<0.9:  return "B"
        case 0.55..<0.75: return "C"
        case 0.35..<0.55: return "D"
        case 0.15..<0.35: return "E"
        default:          return "F"
        }
    }

    /// Server / framework fingerprint from the `Server` and `X-Powered-By` headers.
    static func fingerprint(_ headers: [String: String]) -> String? {
        var parts: [String] = []
        if let s = nonEmpty(headers["server"]) { parts.append(s) }
        if let p = nonEmpty(headers["x-powered-by"]) { parts.append(p) }
        return parts.isEmpty ? nil : parts.joined(separator: " / ")
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s = s?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return nil }
        return s
    }
}

struct WebPosturePlugin: FootprintPlugin {
    let name = "WebPosture"
    let description = "TLS/HTTP security-header grade & server fingerprint"
    let cacheTTL: TimeInterval = 14_400 // 4 h

    private static let ipv4Pattern = #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let domain = CrtShPlugin.normalizeDomain(input)
        // Hostnames only (the fetch needs a real web host); skip emails, bare IPs.
        guard !domain.contains("@"), domain.contains("."),
              domain.range(of: Self.ipv4Pattern, options: .regularExpression) == nil,
              domain.range(of: #"^[a-z0-9.\-]+$"#, options: .regularExpression) != nil,
              domain.range(of: #"[a-z]"#, options: .regularExpression) != nil else { return [] }

        // Prefer HTTPS; if it won't connect, fall back to HTTP and flag the missing TLS.
        if let resp = await probe("https://\(domain)/") {
            return Self.findings(domain: domain, resp: resp, httpsServed: true)
        }
        if let resp = await probe("http://\(domain)/") {
            return Self.findings(domain: domain, resp: resp, httpsServed: resp.finalURL?.scheme == "https")
        }
        return []
    }

    private func probe(_ urlString: String) async -> SafeHTTP.Response? {
        guard let url = URL(string: urlString) else { return nil }
        return try? await SafeHTTP.shared.get(url: url)
    }

    static func findings(domain: String, resp: SafeHTTP.Response, httpsServed: Bool) -> [PluginResult] {
        let a = WebPosture.analyze(headers: resp.headers)
        var results: [PluginResult] = []

        var raw = "Security headers for \(domain): grade \(a.grade)"
        if !a.missing.isEmpty { raw += " | missing: \(a.missing.joined(separator: ", "))" }
        if !a.present.isEmpty { raw += " | present: \(a.present.joined(separator: ", "))" }
        results.append(PluginResult(
            source: "WebPosture", type: "security_headers", confidenceScore: 0.8, rawData: raw,
            metadata: [
                "domain": domain, "grade": a.grade,
                "present": a.present.joined(separator: ", "),
                "missing": a.missing.joined(separator: ", "),
                "https": httpsServed ? "yes" : "no"
            ]))

        if !httpsServed {
            results.append(PluginResult(
                source: "WebPosture", type: "insecure_transport", confidenceScore: 0.85,
                rawData: "\(domain) does not serve HTTPS (HTTP only)",
                metadata: ["domain": domain]))
        }

        if let server = a.server {
            results.append(PluginResult(
                source: "WebPosture", type: "tech_stack", confidenceScore: 0.7,
                rawData: "\(domain) web server: \(server)",
                metadata: ["domain": domain, "server": server]))
        }
        return results
    }
}
