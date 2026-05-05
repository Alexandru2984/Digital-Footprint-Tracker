import Vapor
import NIOConcurrencyHelpers

/// Strict per-IP rate limiter for authentication endpoints.
/// Allows up to `maxAttempts` requests per `windowSeconds` per IP.
/// On violation returns 429 with a Retry-After header.
final class AuthRateLimiter: AsyncMiddleware {
    private struct Entry {
        var count: Int
        var windowStart: Date
    }

    private let maxAttempts: Int
    private let windowSeconds: TimeInterval
    private let lock = NIOLock()
    private var entries: [String: Entry] = [:]

    /// - Parameters:
    ///   - maxAttempts: Maximum number of requests per window (default: 10).
    ///   - windowSeconds: Rolling window length in seconds (default: 300 = 5 min).
    init(maxAttempts: Int = 10, windowSeconds: TimeInterval = 300) {
        self.maxAttempts = maxAttempts
        self.windowSeconds = windowSeconds
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let ip: String
        if let cf = request.headers.first(name: "CF-Connecting-IP")?
            .trimmingCharacters(in: .whitespaces), !cf.isEmpty {
            ip = cf
        } else if let realIP = request.headers.first(name: "X-Real-IP")?
            .trimmingCharacters(in: .whitespaces), !realIP.isEmpty {
            ip = realIP
        } else {
            ip = request.remoteAddress?.ipAddress ?? "unknown"
        }

        let now = Date()
        let allowed: Bool = lock.withLock {
            var entry = entries[ip] ?? Entry(count: 0, windowStart: now)
            if now.timeIntervalSince(entry.windowStart) >= windowSeconds {
                entry = Entry(count: 0, windowStart: now)
            }
            entry.count += 1
            entries[ip] = entry

            if entries.count > 1000 {
                entries = entries.filter {
                    now.timeIntervalSince($0.value.windowStart) < windowSeconds
                }
            }

            return entry.count <= maxAttempts
        }

        guard allowed else {
            var headers = HTTPHeaders()
            headers.add(name: "Retry-After", value: "\(Int(windowSeconds))")
            throw Abort(.tooManyRequests, headers: headers, reason: "Too many attempts. Please wait before trying again.")
        }
        return try await next.respond(to: request)
    }
}
