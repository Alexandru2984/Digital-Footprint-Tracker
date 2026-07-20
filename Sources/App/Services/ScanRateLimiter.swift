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
    private let maxTrackedKeys: Int
    private let lock = NIOLock()
    private var entries: [String: Entry] = [:]

    init(anonMax: Int = 3, authedMax: Int = 10,
         windowSeconds: TimeInterval = 60, maxTrackedKeys: Int = 10_000) {
        precondition(maxTrackedKeys > 0)
        self.anonMax = anonMax
        self.authedMax = authedMax
        self.windowSeconds = windowSeconds
        self.maxTrackedKeys = maxTrackedKeys
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Real client IP resolved via the same Request.clientIP helper used by
        // AuditLogger and the auth limiter — never trust raw X-Forwarded-For.
        let ipKey = request.clientIP
        let userID = request.authenticatedUserID
        let isAuthed = userID != nil
        let key = isAuthed ? "user:\(userID!.uuidString)" : "ip:\(ipKey)"
        let maxForKey = isAuthed ? authedMax : anonMax

        let now = Date()
        let allowed: Bool = lock.withLock {
            if entries[key] == nil, entries.count >= maxTrackedKeys {
                entries = entries.filter {
                    now.timeIntervalSince($0.value.windowStart) < windowSeconds
                }
                // During a distributed-source flood, fail closed for new keys
                // instead of letting the limiter dictionary grow without bound.
                guard entries.count < maxTrackedKeys else { return false }
            }
            var entry = entries[key] ?? Entry(count: 0, windowStart: now)
            if now.timeIntervalSince(entry.windowStart) >= windowSeconds {
                entry = Entry(count: 0, windowStart: now)
            }
            entry.count += 1
            entries[key] = entry

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
