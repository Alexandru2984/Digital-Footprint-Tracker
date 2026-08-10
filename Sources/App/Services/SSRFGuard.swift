import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// SSRF guard utilities — used to reject targets and outbound URLs that resolve
/// to private, loopback, or link-local hosts (including cloud metadata endpoints).
///
/// Used by the scan endpoint (`ScanController.scan`, `BulkScanController.bulkScan`)
/// and by outbound webhook / notification dispatchers to prevent the server from
/// being weaponised to probe internal infrastructure.
///
/// Three layers, from cheap to thorough:
///   1. `isInternalHostname` — structural, no DNS. Strict dotted-quad IPv4 and
///      IPv6 literals (incl. IPv4-mapped) plus well-known internal hostnames.
///      Safe to run on arbitrary scan input: a bare numeric *username* like
///      "12345" is NOT misread as an IP (inet_pton requires full dotted-quad).
///   2. `isInternalURL` — adds the greedy numeric IPv4 forms (decimal
///      `2130706433`, hex `0x7f000001`, short `127.1`). A numeric URL *host* is
///      unambiguously an address, so greedy parsing here can't false-positive.
///   3. `resolvesToInternal` — resolves the host via DNS and rejects if ANY
///      answer is internal (fail-closed on resolution failure). This is the
///      DNS-rebinding mitigation and MUST gate every user-controlled outbound
///      request (see `SafeHTTP`). Blocking call — keep it off hot paths.
enum SSRFGuard {

    /// Returns true if the raw input looks like a private/loopback/link-local host.
    /// Strips the email local-part if present before checking. Structural only.
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
    /// Includes greedy numeric-IPv4 detection (decimal/hex/octal/short forms).
    static func isInternalURL(_ url: URL) -> Bool {
        guard let host = url.host, !host.isEmpty else { return true }
        if isInternalHostname(host) { return true }
        if let greedy = parseGreedyIPv4(host) { return isPrivateIPv4(greedy) }
        return false
    }

    /// Structural, DNS-free check. Recognises:
    ///   • localhost / *.localhost / ip6-localhost
    ///   • strict dotted-quad IPv4 literals (RFC1918, loopback, link-local,
    ///     0.0.0.0/8, CGNAT 100.64/10, multicast/reserved)
    ///   • IPv6 literals: ::1, ::, fc00::/7, fe80::/10, and IPv4-mapped
    static func isInternalHostname(_ host: String) -> Bool {
        var lower = host.lowercased()
        // Strip brackets around IPv6 literals, e.g. "[::1]".
        if lower.hasPrefix("[") && lower.hasSuffix("]") {
            lower = String(lower.dropFirst().dropLast())
        }
        // Strip a zone identifier, e.g. "fe80::1%eth0".
        if let pct = lower.firstIndex(of: "%") { lower = String(lower[..<pct]) }

        guard !lower.isEmpty else { return true }

        // Hostname forms.
        if lower == "localhost" || lower.hasSuffix(".localhost") { return true }
        if lower == "ip6-localhost" || lower == "ip6-loopback" { return true }

        // Strict dotted-quad IPv4 (inet_pton rejects "12345" and "2130706433",
        // so a numeric username is left for the scan layer to treat as text).
        if let v4 = parseStrictIPv4(lower) { return isPrivateIPv4(v4) }

        // IPv6 literal.
        if let v6 = parseIPv6(lower) { return isInternalIPv6(v6) }

        // Unknown / public hostname. DNS resolution is handled separately.
        return false
    }

    /// Resolves `host` via DNS and returns true if it (or any of its A/AAAA
    /// answers) is internal. Fail-closed: a resolution failure returns true so
    /// an unresolvable / poisoned name is never dialled. Blocking — call off the
    /// request hot path (used by `SafeHTTP` for outbound webhooks/notifications).
    static func resolvesToInternal(_ host: String) -> Bool {
        guard !host.isEmpty else { return true }
        if isInternalHostname(host) { return true }
        // Greedy numeric forms resolve locally without touching DNS.
        if let greedy = parseGreedyIPv4(host) { return isPrivateIPv4(greedy) }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        var res: UnsafeMutablePointer<addrinfo>?
        let status = host.withCString { getaddrinfo($0, nil, &hints, &res) }
        guard status == 0, let head = res else { return true } // fail closed
        defer { freeaddrinfo(head) }

        var node: UnsafeMutablePointer<addrinfo>? = head
        while let cur = node {
            if let sa = cur.pointee.ai_addr {
                switch cur.pointee.ai_family {
                case AF_INET:
                    let v4 = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                        UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
                    }
                    if isPrivateIPv4(v4) { return true }
                case AF_INET6:
                    let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p -> [UInt8] in
                        var a6 = p.pointee.sin6_addr
                        return withUnsafeBytes(of: &a6) { Array($0) }
                    }
                    if isInternalIPv6(bytes) { return true }
                default:
                    break
                }
            }
            node = cur.pointee.ai_next
        }
        return false
    }

    /// Resolve `host` and return the concrete public IP the caller must dial to
    /// defeat DNS rebinding: the connection is pinned to *this* address instead
    /// of re-resolving the hostname (which an attacker's low-TTL DNS could rebind
    /// to an internal address between the check and the connect). Returns nil if
    /// the host is internal, unresolvable, or resolves to *any* internal address
    /// (fail-closed). Blocking — call off the request hot path.
    static func resolveValidatedIP(_ host: String) -> String? {
        guard !host.isEmpty, !isInternalHostname(host) else { return nil }
        // Numeric literal forms are deterministic (no DNS) — return as-is once public.
        if let greedy = parseGreedyIPv4(host) { return isPrivateIPv4(greedy) ? nil : host }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        var res: UnsafeMutablePointer<addrinfo>?
        let status = host.withCString { getaddrinfo($0, nil, &hints, &res) }
        guard status == 0, let head = res else { return nil } // fail closed
        defer { freeaddrinfo(head) }

        var chosen: String?
        var node: UnsafeMutablePointer<addrinfo>? = head
        while let cur = node {
            if let sa = cur.pointee.ai_addr {
                switch cur.pointee.ai_family {
                case AF_INET:
                    let v4 = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                        UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
                    }
                    if isPrivateIPv4(v4) { return nil } // any internal answer → block
                    if chosen == nil {
                        chosen = "\((v4 >> 24) & 0xff).\((v4 >> 16) & 0xff).\((v4 >> 8) & 0xff).\(v4 & 0xff)"
                    }
                case AF_INET6:
                    let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p -> [UInt8] in
                        var a6 = p.pointee.sin6_addr
                        return withUnsafeBytes(of: &a6) { Array($0) }
                    }
                    if isInternalIPv6(bytes) { return nil }
                    if chosen == nil { chosen = ipv6String(bytes) }
                default:
                    break
                }
            }
            node = cur.pointee.ai_next
        }
        return chosen
    }

    /// True if `host` is an IP literal (dotted-quad, greedy-numeric, or IPv6),
    /// meaning no DNS lookup is involved and rebinding cannot apply.
    static func isIPLiteral(_ host: String) -> Bool {
        var h = host.lowercased()
        if h.hasPrefix("[") && h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        if let pct = h.firstIndex(of: "%") { h = String(h[..<pct]) }
        return parseGreedyIPv4(h) != nil || parseIPv6(h) != nil
    }

    private static func ipv6String(_ b: [UInt8]) -> String {
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { raw in
            for i in 0..<min(16, b.count) { raw[i] = b[i] }
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
        return String(cString: buf)
    }

    // MARK: - IPv4

    private static func parseStrictIPv4(_ s: String) -> UInt32? {
        var addr = in_addr()
        guard s.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return nil }
        return UInt32(bigEndian: addr.s_addr)
    }

    /// Lenient parse via inet_aton: accepts decimal (`2130706433`), hex
    /// (`0x7f000001`), octal, and short forms (`127.1`).
    private static func parseGreedyIPv4(_ s: String) -> UInt32? {
        var addr = in_addr()
        guard s.withCString({ inet_aton($0, &addr) }) != 0 else { return nil }
        return UInt32(bigEndian: addr.s_addr)
    }

    private static func isPrivateIPv4(_ a: UInt32) -> Bool {
        let b0 = (a >> 24) & 0xff
        let b1 = (a >> 16) & 0xff
        if b0 == 0 { return true }                              // 0.0.0.0/8 ("this host")
        if b0 == 127 { return true }                            // loopback
        if b0 == 10 { return true }                             // RFC1918 class A
        if b0 == 172 && (16...31).contains(b1) { return true }  // RFC1918 class B
        if b0 == 192 && b1 == 168 { return true }               // RFC1918 class C
        if b0 == 169 && b1 == 254 { return true }               // link-local + cloud metadata
        if b0 == 100 && (64...127).contains(b1) { return true } // CGNAT 100.64.0.0/10
        if b0 >= 224 { return true }                            // multicast / reserved
        return false
    }

    // MARK: - IPv6

    private static func parseIPv6(_ s: String) -> [UInt8]? {
        var addr = in6_addr()
        guard s.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    private static func isInternalIPv6(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return true }
        // :: unspecified
        if b.allSatisfy({ $0 == 0 }) { return true }
        // ::1 loopback
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return true }
        // fc00::/7 unique-local
        if (b[0] & 0xfe) == 0xfc { return true }
        // fe80::/10 link-local
        if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return true }
        // IPv4-mapped ::ffff:a.b.c.d → re-check the embedded v4
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {
            let v4 = (UInt32(b[12]) << 24) | (UInt32(b[13]) << 16) | (UInt32(b[14]) << 8) | UInt32(b[15])
            return isPrivateIPv4(v4)
        }
        return false
    }
}
