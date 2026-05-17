import Vapor
import NIOConcurrencyHelpers

// Per-IP / per-user token-bucket-ish limiter: caps how many /scan requests a single
// client can trigger within a rolling window. Authenticated users get a higher quota.
// Prevents one user from fanning out thousands of outbound HTTP requests via bulk plugins.
final class ScanRateLimiter: AsyncMiddleware {
    private struct Entry {
        var count: Int
        var windowStart: Date
    }

    private let anonMax: Int
    private let authedMax: Int
    private let windowSeconds: TimeInterval
    private let lock = NIOLock()
    private var entries: [String: Entry] = [:]

    init(anonMax: Int = 3, authedMax: Int = 10, windowSeconds: TimeInterval = 60) {
        self.anonMax = anonMax
        self.authedMax = authedMax
        self.windowSeconds = windowSeconds
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Trust Cloudflare's real-client header first, then nginx's X-Real-IP,
        // then fall back to the socket address. Never take the first X-Forwarded-For
        // entry directly — it is trivially spoofable by clients.
        let ipKey: String
        if let cf = request.headers.first(name: "CF-Connecting-IP")?
            .trimmingCharacters(in: .whitespaces), !cf.isEmpty {
            ipKey = cf
        } else if let realIP = request.headers.first(name: "X-Real-IP")?
            .trimmingCharacters(in: .whitespaces), !realIP.isEmpty {
            ipKey = realIP
        } else {
            ipKey = request.remoteAddress?.ipAddress ?? "unknown"
        }

        let userID = request.authenticatedUserID
        let isAuthed = userID != nil
        let key = isAuthed ? "user:\(userID!.uuidString)" : "ip:\(ipKey)"
        let maxForKey = isAuthed ? authedMax : anonMax

        let now = Date()
        let allowed: Bool = lock.withLock {
            var entry = entries[key] ?? Entry(count: 0, windowStart: now)
            if now.timeIntervalSince(entry.windowStart) >= windowSeconds {
                entry = Entry(count: 0, windowStart: now)
            }
            entry.count += 1
            entries[key] = entry

            // Lazily prune expired entries to prevent unbounded growth.
            if entries.count > 500 {
                entries = entries.filter {
                    now.timeIntervalSince($0.value.windowStart) < windowSeconds
                }
            }

            return entry.count <= maxForKey
        }

        guard allowed else {
            var headers = HTTPHeaders()
            headers.add(name: "Retry-After", value: "\(Int(windowSeconds))")
            throw Abort(.tooManyRequests, headers: headers, reason: "Rate limit exceeded; try again later.")
        }
        return try await next.respond(to: request)
    }
}
