import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Shared outbound HTTP client for OSINT plugins that call fixed, project-known
/// public APIs (GitHub, HIBP, Shodan, VirusTotal, AbuseIPDB, Gravatar, …).
///
/// What it centralises that 24 hand-rolled `URLSession.shared` call sites did not:
///   • One pooled session with a bounded per-host connection count.
///   • A single consistent User-Agent.
///   • Retry with exponential backoff + jitter on 429 / 5xx, honouring the
///     `Retry-After` header (capped). Transient rate limits no longer drop a
///     finding on the floor — the previous code returned `[]` on the first 429.
///
/// Scope note: callers here target hosts the project controls, with user input
/// only in the path/query, so SSRF redirect risk is nil. Plugins where the
/// *host* is user-influenced (BulkUsername, Domain) keep their own
/// `SSRFGuard.isInternalURL` checks and do NOT route through here.
enum PluginHTTP {
    static let userAgent = "Digital-Footprint-Tracker/1.0 (+https://swift.micutu.com)"

    struct Response: Sendable {
        let status: Int
        let data: Data
        let finalURL: URL?
    }

    private static let session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 15
        cfg.timeoutIntervalForResource = 30
        cfg.httpMaximumConnectionsPerHost = 6
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg)
    }()

    /// Perform a request, retrying on 429/5xx. Returns nil only on a transport
    /// failure that persists across all attempts. A 4xx other than 429 (e.g. a
    /// 404 "not found") is returned as-is — it is a real answer, not an error.
    static func request(
        _ url: URL,
        method: String = "GET",
        headers: [String: String] = [:],
        timeout: TimeInterval = 15,
        maxRetries: Int = 2
    ) async -> Response? {
        // Politeness: space out requests to the same host so the candidate
        // fan-out (which may hit one API several times per scan) doesn't burst.
        if let host = url.host {
            let wait = await HostThrottle.shared.reserve(host)
            if wait > 0 { await sleep(seconds: wait) }
        }

        var attempt = 0
        while true {
            if Task.isCancelled { return nil }

            var req = URLRequest(url: url, timeoutInterval: timeout)
            req.httpMethod = method
            req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
            for (key, value) in headers { req.setValue(value, forHTTPHeaderField: key) }

            do {
                let (data, resp) = try await session.data(for: req)
                guard let http = resp as? HTTPURLResponse else { return nil }
                if (http.statusCode == 429 || (500...599).contains(http.statusCode)), attempt < maxRetries {
                    await sleep(seconds: retryDelay(http: http, attempt: attempt))
                    attempt += 1
                    continue
                }
                return Response(status: http.statusCode, data: data, finalURL: http.url)
            } catch {
                guard attempt < maxRetries, !Task.isCancelled else { return nil }
                await sleep(seconds: backoff(attempt))
                attempt += 1
            }
        }
    }

    // MARK: - Backoff

    /// Exponential backoff with jitter: ~0.5s, ~1s, ~2s … plus up to 0.3s noise.
    private static func backoff(_ attempt: Int) -> Double {
        pow(2.0, Double(attempt)) * 0.5 + Double.random(in: 0...0.3)
    }

    /// Prefer the server's `Retry-After` (integer seconds), capped at 30s so a
    /// hostile or huge value can't stall a scan (the 120s scan deadline would
    /// cancel it anyway). Falls back to exponential backoff.
    private static func retryDelay(http: HTTPURLResponse, attempt: Int) -> Double {
        if let raw = http.value(forHTTPHeaderField: "Retry-After"), let secs = Double(raw) {
            return min(max(secs, 0), 30)
        }
        return min(backoff(attempt), 30)
    }

    private static func sleep(seconds: Double) async {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }
}

/// Spaces outbound requests to the same host so the candidate fan-out (which can
/// hit one API several times for a single scan) stays polite and avoids tripping
/// upstream rate limits or IP blocks. Distinct hosts never wait on each other.
private actor HostThrottle {
    static let shared = HostThrottle()
    private var nextAllowed: [String: Date] = [:]
    private let minInterval: TimeInterval = 0.25

    /// Reserves the next slot for `host` and returns how long the caller should
    /// wait before issuing the request.
    func reserve(_ host: String) -> TimeInterval {
        let now = Date()
        let slot = max(now, nextAllowed[host] ?? now)
        nextAllowed[host] = slot.addingTimeInterval(minInterval)
        if nextAllowed.count > 512 {
            nextAllowed = nextAllowed.filter { $0.value > now }
        }
        return slot.timeIntervalSince(now)
    }
}
