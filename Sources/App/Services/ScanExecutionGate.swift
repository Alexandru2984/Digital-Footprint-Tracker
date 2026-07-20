import Foundation
import Vapor

/// Process-wide admission gate for full scan executions. One scan can fan out
/// into dozens of plugins (and some plugins issue their own bounded fan-out), so
/// request-count limiting alone does not protect CPU, sockets, memory, or third-
/// party quotas.
///
/// Active work is capped and the waiting queue is bounded. When the queue is
/// full the scan is marked failed instead of remaining `pending` forever.
actor ScanExecutionGate {
    static let shared = ScanExecutionGate()

    private let maxConcurrent: Int
    private let maxQueued: Int
    private var active = 0
    private var waiters: [CheckedContinuation<Bool, Never>] = []

    init(maxConcurrent: Int? = nil, maxQueued: Int? = nil) {
        let configuredConcurrent = Int(Environment.get("SCAN_MAX_CONCURRENT") ?? "") ?? 3
        let configuredQueued = Int(Environment.get("SCAN_MAX_QUEUED") ?? "") ?? 32
        self.maxConcurrent = min(16, max(1, maxConcurrent ?? configuredConcurrent))
        self.maxQueued = min(256, max(0, maxQueued ?? configuredQueued))
    }

    func acquire() async -> Bool {
        if active < maxConcurrent {
            active += 1
            return true
        }
        guard waiters.count < maxQueued else { return false }
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        if !waiters.isEmpty {
            let next = waiters.removeFirst()
            next.resume(returning: true) // transfer the active permit
        } else {
            active = max(0, active - 1)
        }
    }

    func snapshot() -> (active: Int, queued: Int) {
        (active, waiters.count)
    }
}
