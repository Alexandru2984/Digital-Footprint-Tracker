import Foundation

/// SSRF guard utilities — used to reject targets and outbound URLs that resolve
/// to private, loopback, or link-local hosts (including cloud metadata endpoints).
///
/// Used by the scan endpoint (`ScanController.scan`, `BulkScanController.bulkScan`)
/// and by outbound webhook / notification dispatchers to prevent the server from
/// being weaponised to probe internal infrastructure.
enum SSRFGuard {

    /// Returns true if the raw input looks like a private/loopback/link-local host.
    /// Strips the email local-part if present before checking.
    static func isInternalTarget(_ input: String) -> Bool {
        let host: String
        if let atIdx = input.firstIndex(of: "@") {
            host = String(input[input.index(after: atIdx)...])
        } else {
            host = input
        }
        return isInternalHostname(host)
    }

    /// Returns true if a URL points to a private/loopback/link-local host.
    static func isInternalURL(_ url: URL) -> Bool {
        guard let host = url.host else { return true }
        return isInternalHostname(host)
    }

    private static func isInternalHostname(_ host: String) -> Bool {
        let lower = host.lowercased()

        // Loopback / localhost
        if lower == "localhost" || lower == "ip6-localhost" || lower == "::1" { return true }
        if lower.hasSuffix(".localhost") { return true }

        // Loopback IPv4
        if lower.hasPrefix("127.") { return true }

        // Private class A: 10.0.0.0/8
        if lower.hasPrefix("10.") { return true }

        // Private class B: 172.16.0.0/12
        if lower.hasPrefix("172.") {
            let parts = lower.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]), second >= 16 && second <= 31 { return true }
        }

        // Private class C: 192.168.0.0/16
        if lower.hasPrefix("192.168.") { return true }

        // Link-local: 169.254.0.0/16 (AWS/GCP metadata)
        if lower.hasPrefix("169.254.") { return true }

        // IPv6 private / link-local
        if lower.hasPrefix("fc") || lower.hasPrefix("fd") || lower.hasPrefix("fe80") { return true }

        return false
    }
}
