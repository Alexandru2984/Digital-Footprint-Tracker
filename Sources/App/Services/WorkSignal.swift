import Foundation

/// Lets a polling worker start on new work right away instead of on its next
/// tick, so the tick itself can be slow.
///
/// The notification and export workers polled the database every two seconds
/// to keep pickup latency low — some 86,000 queries a day against tables that
/// were almost always empty. Enqueuers now raise a flag in memory; the worker
/// checks it in short, database-free steps and keeps a slow poll for work that
/// becomes due any other way: a retry's backoff expiring, another process.
///
/// Deliberately not continuation-based. A continuation that never resumes on
/// cancellation would hang the worker's shutdown, and checking a flag every
/// 200 ms costs nothing measurable.
actor WorkSignal {
    static let notificationDelivery = WorkSignal()
    static let exportJobs = WorkSignal()

    private var flagged = false

    func signal() {
        flagged = true
    }

    /// Sleeps up to `seconds`, returning early once signalled or cancelled.
    func wait(upTo seconds: Int) async {
        let deadline = ContinuousClock.now + .seconds(seconds)
        while ContinuousClock.now < deadline, !Task.isCancelled {
            if flagged {
                flagged = false
                return
            }
            try? await Task.sleep(for: .milliseconds(200))
        }
    }
}
