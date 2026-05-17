import Vapor

extension Request {
    /// Best-effort real-client IP behind the deployment's reverse-proxy chain.
    ///
    /// Trusts `CF-Connecting-IP` (set by Cloudflare) then `X-Real-IP` (set by
    /// nginx). Both are stripped from inbound requests by the proxies, so a
    /// client cannot inject them. **Never** trust raw `X-Forwarded-For` —
    /// clients can prepend arbitrary entries before nginx appends the real
    /// peer address.
    ///
    /// Used by `AuditLogger`, `ScanRateLimiter`, `AuthRateLimiter`, and
    /// `ScanController.scan` so the same source of truth applies to rate
    /// limiting, audit attribution, and abuse correlation.
    var clientIP: String {
        if let cf = headers.first(name: "CF-Connecting-IP")?
            .trimmingCharacters(in: .whitespaces), !cf.isEmpty {
            return cf
        }
        if let realIP = headers.first(name: "X-Real-IP")?
            .trimmingCharacters(in: .whitespaces), !realIP.isEmpty {
            return realIP
        }
        return remoteAddress?.ipAddress ?? "unknown"
    }
}
