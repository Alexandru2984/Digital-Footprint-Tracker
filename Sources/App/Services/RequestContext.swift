import Vapor

extension Request {
    /// Best-effort real-client IP behind the deployment's reverse-proxy chain.
    ///
    /// Trust order:
    ///   1. `X-Real-IP` — set by *our* nginx to `$remote_addr`, which the
    ///      `ngx_http_realip_module` (see `snippets/cloudflare-realip.conf`)
    ///      derives from `CF-Connecting-IP` ONLY when the TCP peer is a
    ///      Cloudflare edge. A client hitting the origin directly cannot forge
    ///      it — nginx overwrites whatever they send.
    ///   2. `CF-Connecting-IP` — also rewritten to the validated `$remote_addr`
    ///      by nginx, kept as a redundant source.
    ///   3. raw socket peer.
    ///
    /// The origin's port 443 is reachable directly (not only via Cloudflare), so
    /// a naive "trust CF-Connecting-IP first" is spoofable: a direct request can
    /// carry an arbitrary `CF-Connecting-IP` and bypass per-IP rate limiting and
    /// forge audit attribution. The nginx real_ip trust list closes that; this
    /// order makes the app rely on the header nginx controls. **Never** trust raw
    /// `X-Forwarded-For` — clients can prepend arbitrary entries.
    ///
    /// Used by `AuditLogger`, `ScanRateLimiter`, `AuthRateLimiter`, and
    /// `ScanController.scan` so the same source of truth applies to rate
    /// limiting, audit attribution, and abuse correlation.
    var clientIP: String {
        if let realIP = headers.first(name: "X-Real-IP")?
            .trimmingCharacters(in: .whitespaces), !realIP.isEmpty {
            return realIP
        }
        if let cf = headers.first(name: "CF-Connecting-IP")?
            .trimmingCharacters(in: .whitespaces), !cf.isEmpty {
            return cf
        }
        return remoteAddress?.ipAddress ?? "unknown"
    }
}
