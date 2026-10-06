import Vapor

/// Failed-attempt budgets per account, across every client address.
///
/// `AuthRateLimiter` counts per IP. That bounds one client, not an attack
/// spread over many: each new address brings a fresh budget against the same
/// account. This counts failures per account instead and refuses further
/// attempts on it once the budget is spent, until the window has passed.
///
/// Password attempts are keyed on the submitted username whether or not an
/// account exists, so the throttle's state never reveals which names are real.
///
/// In memory, like `AuthRateLimiter`: a restart forgives, which is acceptable
/// for one instance. Memory is bounded so random usernames cannot grow it
/// without limit. The cost of that bound: someone who fills it can evict a
/// victim's counter — but every one of those attempts is also throttled per IP,
/// so it costs about as much as attacking the account directly.
actor AccountThrottle {
    static let passwords = AccountThrottle(maxFailures: 10, window: 15 * 60)
    static let secondFactor = AccountThrottle(maxFailures: 10, window: 15 * 60)
    /// One pending 2FA login: a few wrong codes and it is over, so another run
    /// of guesses costs the password step again.
    static let pendingSecondFactor = AccountThrottle(
        maxFailures: TwoFactorController.maxCodesPerPendingLogin, window: 300
    )

    private let maxFailures: Int
    private let window: TimeInterval
    private let maxKeys: Int
    private var failures: [String: [Date]] = [:]

    init(maxFailures: Int, window: TimeInterval, maxKeys: Int = 50_000) {
        self.maxFailures = maxFailures
        self.window = window
        self.maxKeys = maxKeys
    }

    /// Seconds until the account may be tried again, or nil when it may be now.
    func retryAfter(_ key: String, now: Date = Date()) -> Int? {
        let recent = live(key, now: now)
        guard recent.count >= maxFailures, let oldest = recent.first else { return nil }
        return max(1, Int((window - now.timeIntervalSince(oldest)).rounded(.up)))
    }

    func recordFailure(_ key: String, now: Date = Date()) {
        if failures[key] == nil, failures.count >= maxKeys { evict(now: now) }
        var recent = live(key, now: now)
        recent.append(now)
        failures[key] = Array(recent.suffix(maxFailures))
    }

    func recordSuccess(_ key: String) {
        failures[key] = nil
    }

    /// The key's failures still inside the window, dropping it when none are.
    private func live(_ key: String, now: Date) -> [Date] {
        let recent = (failures[key] ?? []).filter { now.timeIntervalSince($0) < window }
        failures[key] = recent.isEmpty ? nil : recent
        return recent
    }

    private func evict(now: Date) {
        failures = failures.filter { _, dates in dates.contains { now.timeIntervalSince($0) < window } }
        guard failures.count >= maxKeys else { return }
        let excess = failures.count - maxKeys + 1
        let stalest = failures
            .sorted { ($0.value.last ?? .distantPast) < ($1.value.last ?? .distantPast) }
            .prefix(excess)
        for (key, _) in stalest { failures[key] = nil }
    }

    /// For tests: the number of accounts currently being tracked.
    func trackedKeyCount() -> Int { failures.count }

    static func usernameKey(_ username: String) -> String {
        username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func tooManyAttempts(retryAfter seconds: Int) -> Abort {
        Abort(
            .tooManyRequests,
            headers: ["Retry-After": String(seconds)],
            reason: "Too many failed attempts for this account. Try again later."
        )
    }
}
