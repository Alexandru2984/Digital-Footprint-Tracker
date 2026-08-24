import Vapor
import NIOCore

extension Request {
    /// Best-effort real-client IP behind the deployment's reverse-proxy chain.
    ///
    /// Trust order, but only when the socket peer is loopback:
    ///   1. `X-Real-IP` — set by *our* nginx to `$remote_addr`, which the
    ///      `ngx_http_realip_module` (see `conf.d/cloudflare-realip.conf`)
    ///      derives from `CF-Connecting-IP` ONLY when the TCP peer is a
    ///      Cloudflare edge or the local `cloudflared` tunnel. A client hitting
    ///      the origin directly cannot forge it — nginx overwrites whatever
    ///      they send.
    ///   2. `CF-Connecting-IP` — also rewritten to the validated `$remote_addr`
    ///      by nginx, kept as a redundant source.
    ///   3. raw socket peer.
    ///
    /// A direct request to Vapor can carry arbitrary forwarding headers. Such
    /// headers are ignored unless the TCP peer is the local reverse proxy. The
    /// nginx real_ip trust list independently validates Cloudflare peers before
    /// nginx overwrites X-Real-IP. **Never** trust raw `X-Forwarded-For` — clients
    /// can prepend arbitrary entries.
    ///
    /// Used by `AuditLogger`, `ScanRateLimiter`, `AuthRateLimiter`, and
    /// `ScanController.scan` so the same source of truth applies to rate
    /// limiting, audit attribution, and abuse correlation.
    var clientIP: String {
        let peerIP = remoteAddress?.ipAddress
        // In-memory Vapor tests have no socket peer. They still exercise the
        // proxy path using explicit headers; real non-test requests must prove
        // that they arrived from a loopback peer.
        let fromTrustedProxy = peerIP.map(ClientIPResolver.isLoopback)
            ?? (application.environment == .testing)

        if fromTrustedProxy {
            if let realIP = ClientIPResolver.normalizedIPAddress(
                headers.first(name: "X-Real-IP")
            ) {
                return realIP
            }
            if let cf = ClientIPResolver.normalizedIPAddress(
                headers.first(name: "CF-Connecting-IP")
            ) {
                return cf
            }
        }
        return peerIP ?? "unknown"
    }
}

enum ClientIPResolver {
    /// The supported deployment has nginx and Vapor on the same host. Keeping
    /// this trust boundary to loopback avoids silently trusting every RFC1918
    /// host if the Vapor listener is ever exposed to a private network.
    static func isLoopback(_ ip: String) -> Bool {
        let value = ip.lowercased()
        return value == "::1"
            || value.hasPrefix("127.")
            || value.hasPrefix("::ffff:127.")
    }

    /// Accept only a single numeric IP address. Besides preventing malformed
    /// audit data, this rejects forwarding chains, hostnames, and control text.
    static func normalizedIPAddress(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let value = raw.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty, value.utf8.count <= 64, !value.contains("%"),
              let address = try? SocketAddress(ipAddress: value, port: 0) else {
            return nil
        }
        return address.ipAddress
    }
}

/// IP anonymisation for anything persisted (audit log, exports).
///
/// Privacy-first: we keep enough of the address to correlate abuse from the same
/// network (an IPv4 /24, an IPv6 /48) but drop the host-precise bits that would
/// pin the record to one machine/person. The full IP is still used transiently
/// for rate limiting — only the *stored* value is coarsened.
enum IPPrivacy {
    static func anonymize(_ ip: String) -> String {
        let trimmed = ip.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed != "unknown" else { return trimmed }
        // IPv4 → zero the final octet (/24).
        if !trimmed.contains(":") {
            let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
            if parts.count == 4 { return "\(parts[0]).\(parts[1]).\(parts[2]).0" }
            return trimmed
        }
        // IPv6 → keep the first three hextets (/48), drop the rest.
        let groups = trimmed.split(separator: ":", omittingEmptySubsequences: false)
        let kept = groups.prefix(3).filter { !$0.isEmpty }
        guard !kept.isEmpty else { return "::" }
        return kept.joined(separator: ":") + "::"
    }
}
