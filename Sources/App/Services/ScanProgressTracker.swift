import Foundation

/// Thread-safe in-memory store for per-scan plugin progress.
/// Keyed by scan UUID. Lost on restart — only used for live SSE display.
actor ScanProgressTracker {
    static let shared = ScanProgressTracker()
    private init() {}

    private struct Progress {
        var done: Int
        var total: Int
        var lastName: String
    }
    private var store: [UUID: Progress] = [:]

    func start(scanID: UUID, total: Int) {
        store[scanID] = Progress(done: 0, total: total, lastName: "")
    }

    func complete(scanID: UUID, pluginName: String) {
        if var p = store[scanID] {
            p.done += 1
            p.lastName = pluginName
            store[scanID] = p
        }
    }

    func get(for scanID: UUID) -> (done: Int, total: Int, lastName: String)? {
        guard let p = store[scanID] else { return nil }
        return (p.done, p.total, p.lastName)
    }

    func remove(for scanID: UUID) {
        store.removeValue(forKey: scanID)
    }
}
