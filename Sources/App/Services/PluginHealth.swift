import Foundation
import Logging
import Vapor

/// Per-plugin health, built from what each live run actually did upstream.
///
/// A plugin cannot report its own breakage: nearly every one is written as
/// `guard let response = await PluginHTTP.request(…) else { return [] }` and
/// rejects a block page or an error body as "not found", so a source that has
/// changed its API, started blocking the VPS, or lost its key looks exactly
/// like a target with no account there. Counting thrown errors alone would
/// show every source as healthy forever.
///
/// The signal lives in `PluginHTTP`: `ScanPluginRunner` binds a `RunProbe` as a
/// task-local around each live `scan`, every request made under it records its
/// outcome, and a run whose requests *all* failed is `unreachable`. A run with
/// at least one real upstream answer is `ok` — a username sweep where some
/// sites refuse the VPS is still working.
///
/// A plugin whose last `failingStreak` runs failed stops making live runs:
/// `ScanPluginRunner` asks `admit` before each uncached scan, and a failing
/// plugin gets one probe run per window (5 minutes, doubling to an hour)
/// until a probe succeeds. Cached results are still served meanwhile.
///
/// Process-local and reset on restart, like every other counter in
/// `MetricsRegistry`. Cache hits are not runs: they say nothing about the
/// upstream today.
actor PluginHealth {
    static let shared = PluginHealth()

    /// The probe of the live plugin run the current task belongs to, if any.
    @TaskLocal static var probe: RunProbe?

    enum Outcome: String, Sendable, CaseIterable, Codable {
        case ok, unreachable, error, timeout
    }

    /// How one upstream request ended, from the plugin's point of view.
    enum Call: Sendable, Equatable {
        /// The upstream answered. A 404 is a real answer ("no such account").
        case answered
        /// It answered with a refusal: 401/403 (blocked or bad key) or 429
        /// after the retries ran out.
        case refused(status: Int)
        /// 5xx after the retries ran out.
        case upstreamError(status: Int)
        /// No response at all: connection, TLS, timeout, or an open circuit.
        case unreachable

        init(status: Int) {
            switch status {
            case 401, 403, 429: self = .refused(status: status)
            case 500...599: self = .upstreamError(status: status)
            default: self = .answered
            }
        }
    }

    /// Collects the calls of one live run. A class behind a lock rather than an
    /// actor so `PluginHTTP` can record without an extra hop, and so the runner
    /// can read a timed-out run's partial tally while the abandoned task may
    /// still be writing to it.
    final class RunProbe: @unchecked Sendable {
        private let lock = NSLock()
        private var answered = 0
        private var failed = 0
        private var lastFailure: String?
        private var live = false

        /// Called before each uncached `scan`; a run served wholly from the
        /// cache never calls it and is not recorded.
        func markLive() {
            lock.lock(); defer { lock.unlock() }
            live = true
        }

        func record(_ call: Call) {
            lock.lock(); defer { lock.unlock() }
            switch call {
            case .answered:
                answered += 1
            case .refused(let status), .upstreamError(let status):
                failed += 1
                lastFailure = "HTTP \(status)"
            case .unreachable:
                failed += 1
                lastFailure = "no response"
            }
        }

        struct Tally: Sendable {
            let live: Bool
            let answered: Int
            let failed: Int
            let lastFailure: String?
        }

        var tally: Tally {
            lock.lock(); defer { lock.unlock() }
            return Tally(live: live, answered: answered, failed: failed, lastFailure: lastFailure)
        }
    }

    /// Classifies a finished run. Only an all-failed run is `unreachable`; a
    /// plugin that made no HTTP calls (DNS, WHOIS, local analysis) is judged
    /// by whether it threw.
    static func outcome(threw: Bool, timedOut: Bool, answered: Int, failed: Int) -> Outcome {
        if timedOut { return .timeout }
        if threw { return .error }
        if failed > 0 && answered == 0 { return .unreachable }
        return .ok
    }

    enum Status: String, Sendable, Codable, Hashable {
        /// No live run since the process started.
        case idle
        case healthy
        /// More than a quarter of recent runs failed.
        case degraded
        /// The last `failingStreak` runs all failed.
        case failing
    }

    struct Run: Sendable {
        let at: Date
        let outcome: Outcome
        let duration: TimeInterval
        let results: Int
        let detail: String?
    }

    struct Report: Content, Equatable {
        let plugin: String
        let status: Status
        let runs: Int
        let failures: Int
        let averageMilliseconds: Int?
        let lastRunAt: Date?
        let lastSuccessAt: Date?
        let lastFailureAt: Date?
        let lastFailure: String?
        /// Live runs skipped since the restart because the plugin was failing.
        let skipped: Int
        /// When a failing plugin may next make one live probe run.
        let nextProbeAt: Date?
    }

    static let window = 20
    static let failingStreak = 3
    static let firstProbeDelay: TimeInterval = 300
    static let maxProbeDelay: TimeInterval = 3_600

    private var history: [String: [Run]] = [:]
    private var lastSuccess: [String: Date] = [:]
    private var lastFailure: [String: (at: Date, detail: String)] = [:]
    private var totals: [String: [Outcome: UInt64]] = [:]
    /// Consecutive failed runs, reset by any success.
    private var streak: [String: Int] = [:]
    private var nextProbe: [String: Date] = [:]
    private var skips: [String: UInt64] = [:]

    /// Whether `plugin` may make a live run now. A failing plugin is let
    /// through once per probe window, so concurrent scans cannot all probe a
    /// dead source at once; every other call is refused and counted. The probe
    /// window doubles with each failed probe, from `firstProbeDelay` up to
    /// `maxProbeDelay`, and a successful run lifts it entirely.
    ///
    /// Only live runs are gated: cached results stay valid and keep being
    /// served while the source is down.
    func admit(_ plugin: String, now: Date = Date()) -> Bool {
        guard Self.status(of: history[plugin] ?? []) == .failing else { return true }
        if let next = nextProbe[plugin], now < next {
            skips[plugin, default: 0] &+= 1
            return false
        }
        nextProbe[plugin] = now.addingTimeInterval(Self.probeDelay(afterStreak: streak[plugin] ?? Self.failingStreak))
        return true
    }

    static func probeDelay(afterStreak streak: Int) -> TimeInterval {
        let doublings = Double(min(max(0, streak - failingStreak), 16))
        return min(firstProbeDelay * pow(2, doublings), maxProbeDelay)
    }

    /// Records one live run and logs when the plugin's status crosses into or
    /// out of `failing`, so a broken source reaches the journal at warning
    /// priority once instead of on every scan.
    func record(plugin: String, run: Run, logger: Logger? = nil) {
        let before = Self.status(of: history[plugin] ?? [])
        var runs = history[plugin] ?? []
        runs.append(run)
        if runs.count > Self.window { runs.removeFirst(runs.count - Self.window) }
        history[plugin] = runs
        totals[plugin, default: [:]][run.outcome, default: 0] &+= 1

        let detail = run.detail.map { "\(run.outcome.rawValue), \($0)" } ?? run.outcome.rawValue
        if run.outcome == .ok {
            lastSuccess[plugin] = run.at
            streak[plugin] = nil
            nextProbe[plugin] = nil
        } else {
            lastFailure[plugin] = (run.at, detail)
            streak[plugin, default: 0] += 1
        }

        let after = Self.status(of: runs)
        if after == .failing {
            let delay = Self.probeDelay(afterStreak: streak[plugin] ?? Self.failingStreak)
            nextProbe[plugin] = run.at.addingTimeInterval(delay)
            if before != .failing {
                let message = "Plugin \(plugin) is failing: its last \(Self.failingStreak) live runs failed "
                    + "(latest: \(detail)); skipping live runs, next probe in \(Int(delay / 60)) min."
                logger?.warning("\(message)")
            }
        } else if before == .failing {
            logger?.notice("Plugin \(plugin) recovered.")
        }
    }

    static func status(of runs: [Run]) -> Status {
        guard !runs.isEmpty else { return .idle }
        if runs.count >= failingStreak && runs.suffix(failingStreak).allSatisfy({ $0.outcome != .ok }) {
            return .failing
        }
        let failures = runs.filter { $0.outcome != .ok }.count
        return failures * 4 > runs.count ? .degraded : .healthy
    }

    /// One report per name in `plugins`, in that order, so a plugin that has
    /// not run since the restart still shows up (as `idle`).
    func reports(for plugins: [String]) -> [Report] {
        plugins.map { name in
            let runs = history[name] ?? []
            let average = runs.isEmpty ? nil
                : Int((runs.map(\.duration).reduce(0, +) / Double(runs.count) * 1_000).rounded())
            return Report(
                plugin: name,
                status: Self.status(of: runs),
                runs: runs.count,
                failures: runs.filter { $0.outcome != .ok }.count,
                averageMilliseconds: average,
                lastRunAt: runs.last?.at,
                lastSuccessAt: lastSuccess[name],
                lastFailureAt: lastFailure[name]?.at,
                lastFailure: lastFailure[name]?.detail,
                skipped: Int(clamping: skips[name] ?? 0),
                nextProbeAt: nextProbe[name]
            )
        }
    }

    /// Process-lifetime run counts for `/metrics`.
    func runTotals() -> [String: [Outcome: UInt64]] { totals }

    /// Process-lifetime skipped-run counts for `/metrics`.
    func skipTotals() -> [String: UInt64] { skips }

    /// Test seam.
    func reset() {
        history.removeAll()
        lastSuccess.removeAll()
        lastFailure.removeAll()
        totals.removeAll()
        streak.removeAll()
        nextProbe.removeAll()
        skips.removeAll()
    }
}
