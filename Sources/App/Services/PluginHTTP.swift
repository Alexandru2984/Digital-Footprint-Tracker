import Foundation
import Vapor

/// Shared bounded client for plugins that call fixed, project-known public APIs.
/// Responses are streamed with a hard byte ceiling and redirects are disabled so
/// API credentials cannot be forwarded to a destination chosen by an upstream.
enum PluginHTTP {
    static let userAgent = "Digital-Footprint-Tracker/1.0 (+https://swift.micutu.com)"

    struct Response: Sendable {
        let status: Int
        let data: Data
        let finalURL: URL?
    }

    static func request(
        _ url: URL,
        method: HTTPMethod = .GET,
        headers: [String: String] = [:],
        body: Data? = nil,
        timeout: TimeInterval = 15,
        maxRetries: Int = 2,
        bodyMode: OutboundHTTP.BodyMode = .complete(maxBytes: 2 * 1_024 * 1_024),
        on app: Application
    ) async -> Response? {
        if let host = url.host {
            let wait = await HostThrottle.shared.reserve(host)
            if wait > 0 { await sleep(seconds: wait) }
        }

        var attempt = 0
        while true {
            if Task.isCancelled { return nil }

            var requestHeaders = headers
            if requestHeaders.keys.first(where: { $0.lowercased() == "user-agent" }) == nil {
                requestHeaders["User-Agent"] = userAgent
            }

            do {
                let response = try await OutboundHTTP.request(
                    url,
                    method: method,
                    headers: requestHeaders,
                    body: body,
                    timeout: timeout,
                    bodyMode: bodyMode,
                    maxRedirects: 0,
                    on: app
                )
                if (response.status == 429 || (500...599).contains(response.status)), attempt < maxRetries {
                    await sleep(seconds: retryDelay(headers: response.headers, attempt: attempt))
                    attempt += 1
                    continue
                }
                return Response(status: response.status, data: response.data, finalURL: response.finalURL)
            } catch is OutboundHTTP.RequestError {
                // URL-policy failures are deterministic; retrying only repeats a
                // blocked request and can amplify DNS work.
                return nil
            } catch {
                guard attempt < maxRetries, !Task.isCancelled else { return nil }
                await sleep(seconds: backoff(attempt))
                attempt += 1
            }
        }
    }

    private static func backoff(_ attempt: Int) -> Double {
        pow(2.0, Double(attempt)) * 0.5 + Double.random(in: 0...0.3)
    }

    private static func retryDelay(headers: [String: String], attempt: Int) -> Double {
        if let raw = headers["retry-after"], let seconds = Double(raw) {
            return min(max(seconds, 0), 30)
        }
        return min(backoff(attempt), 30)
    }

    private static func sleep(seconds: Double) async {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }
}

private actor HostThrottle {
    static let shared = HostThrottle()
    private var nextAllowed: [String: Date] = [:]
    private let minInterval: TimeInterval = 0.25

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
