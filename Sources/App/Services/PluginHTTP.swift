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
        // A host that has failed repeatedly is skipped outright rather than
        // being retried into the ground. Without this, one dead provider costs
        // every scan the full retry ladder (timeout + backoff + timeout +
        // backoff + timeout ≈ 47s at the defaults) — and because a round only
        // ends once every plugin reports, that latency is paid by the whole
        // scan, on every scan, for as long as the provider stays down.
        let host = url.host
        if let host {
            guard await HostCircuitBreaker.shared.allows(host) else {
                app.logger.debug("PluginHTTP: skipping \(host); its circuit is open after repeated failures.")
                return nil
            }
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
                if let host {
                    // 4xx is the upstream answering, not failing: a 404 means
                    // "no such account", which is a perfectly good result. Only
                    // exhausted rate limiting and server errors count against
                    // the host.
                    if response.status == 429 || (500...599).contains(response.status) {
                        await HostCircuitBreaker.shared.recordFailure(host)
                    } else {
                        await HostCircuitBreaker.shared.recordSuccess(host)
                    }
                }
                return Response(status: response.status, data: response.data, finalURL: response.finalURL)
            } catch is OutboundHTTP.RequestError {
                // URL-policy failures are deterministic; retrying only repeats a
                // blocked request and can amplify DNS work. They say nothing
                // about the host's health, so they must not trip its breaker.
                return nil
            } catch {
                guard attempt < maxRetries, !Task.isCancelled else {
                    // Cancellation is our own doing, not the host's fault.
                    if let host, !Task.isCancelled { await HostCircuitBreaker.shared.recordFailure(host) }
                    return nil
                }
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

/// Per-host circuit breaker for the shared plugin client.
///
/// The plugin layer cannot see upstream health on its own: nearly every plugin
/// is written as `guard let response = await PluginHTTP.request(…) else { return [] }`,
/// so a provider that is completely down is indistinguishable from one that
/// legitimately found nothing — the scan runner counts it a success and the next
/// scan pays the same dead-host cost again. The information exists only here, at
/// the transport, which is where the decision belongs.
///
/// Deliberately simple and process-local, matching `HostThrottle` above: closed
/// until `failureThreshold` consecutive failures, then open for a cooldown that
/// doubles per consecutive trip up to `maxCooldown`. There is no explicit
/// half-open state — the first request after the cooldown elapses *is* the
/// probe, and its outcome either resets the host or re-opens it for longer.
///
/// A tripped breaker degrades a scan (that provider contributes nothing) rather
/// than failing it, which is the same contract as any plugin returning `[]`.
actor HostCircuitBreaker {
    static let shared = HostCircuitBreaker()

    /// Consecutive failures before a host is skipped. Set above the retry count
    /// so a single flaky request — already retried twice inside `request` —
    /// cannot trip it.
    private let failureThreshold = 3
    private let baseCooldown: TimeInterval = 60
    private let maxCooldown: TimeInterval = 900
    private let maxTrackedHosts = 512

    private struct State {
        var consecutiveFailures = 0
        /// Consecutive trips, used to grow the cooldown. Reset by any success.
        var trips = 0
        var openUntil: Date?
    }
    private var hosts: [String: State] = [:]

    /// Counters for `/metrics`; process-lifetime, like every other counter.
    private(set) var tripsTotal: UInt64 = 0

    /// False while the host is in its cooldown window.
    func allows(_ host: String) -> Bool {
        guard let openUntil = hosts[host]?.openUntil else { return true }
        guard Date() >= openUntil else { return false }
        // Cooldown elapsed: let this request through as the probe.
        hosts[host]?.openUntil = nil
        return true
    }

    func recordSuccess(_ host: String) {
        guard hosts[host] != nil else { return }
        hosts.removeValue(forKey: host)
    }

    func recordFailure(_ host: String) {
        var state = hosts[host] ?? State()
        state.consecutiveFailures += 1
        if state.consecutiveFailures >= failureThreshold {
            state.trips += 1
            state.consecutiveFailures = 0
            let cooldown = min(baseCooldown * pow(2, Double(state.trips - 1)), maxCooldown)
            state.openUntil = Date().addingTimeInterval(cooldown)
            tripsTotal &+= 1
        }
        hosts[host] = state
        pruneIfNeeded()
    }

    /// Hosts currently in a cooldown window. Reported as a single gauge rather
    /// than a per-host label so a scan of many domains cannot inflate metric
    /// cardinality; the host names go to the log when a breaker trips.
    func openCircuitCount() -> Int {
        let now = Date()
        return hosts.values.filter { ($0.openUntil ?? now) > now }.count
    }

    /// Bounded like `HostThrottle`: drop healthy, non-open entries first so a
    /// long-running process cannot accumulate a map of every host ever probed.
    private func pruneIfNeeded() {
        guard hosts.count > maxTrackedHosts else { return }
        let now = Date()
        hosts = hosts.filter { ($0.value.openUntil ?? .distantPast) > now }
    }

    /// Test seam: drop all state so one test's failures cannot leak into another.
    func reset() {
        hosts.removeAll()
        tripsTotal = 0
    }
}
