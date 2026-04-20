import Vapor
import NIOConcurrencyHelpers

// Per-IP token-bucket-ish limiter: caps how many /scan requests a single client
// can trigger within a rolling window. Prevents one user from fanning out
// thousands of outbound HTTP requests via the bulk plugins.
final class ScanRateLimiter: AsyncMiddleware {
    private struct Entry {
        var count: Int
        var windowStart: Date
    }

    private let maxRequests: Int
    private let windowSeconds: TimeInterval
    private let lock = NIOLock()
    private var entries: [String: Entry] = [:]

    init(maxRequests: Int = 5, windowSeconds: TimeInterval = 60) {
        self.maxRequests = maxRequests
        self.windowSeconds = windowSeconds
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let key = request.headers.first(name: "X-Forwarded-For")?
            .split(separator: ",").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces)
            ?? request.remoteAddress?.ipAddress
            ?? "unknown"

        let now = Date()
        let allowed: Bool = lock.withLock {
            var entry = entries[key] ?? Entry(count: 0, windowStart: now)
            if now.timeIntervalSince(entry.windowStart) >= windowSeconds {
                entry = Entry(count: 0, windowStart: now)
            }
            entry.count += 1
            entries[key] = entry
            return entry.count <= maxRequests
        }

        guard allowed else {
            throw Abort(.tooManyRequests, reason: "Rate limit exceeded; try again later.")
        }
        return try await next.respond(to: request)
    }
}
