import Vapor
import Foundation

/// Which of the sweep's sites still find an account known to exist there
/// (each site's own `username_claimed`). One that does not is broken: a
/// changed page, a block, a dead domain. Its silence says nothing, so the
/// sweep leaves it out until it finds its account again, and the admin page
/// lists it. The negative check (`SherlockReliability`) catches sites that
/// find anyone; this catches the ones that find no one.
actor SherlockAudit {
    static let shared = SherlockAudit()
    /// A verdict older than this is no longer applied.
    static let validity: TimeInterval = 2 * 86_400

    struct Summary: Content, Equatable {
        let checkedAt: Date
        let audited: Int
        let broken: [String]
    }

    private(set) var latest: Summary?

    func record(_ summary: Summary) { latest = summary }

    func broken(now: Date = Date()) -> Set<String> {
        guard let latest, now.timeIntervalSince(latest.checkedAt) < Self.validity else { return [] }
        return Set(latest.broken)
    }

    /// Test seam.
    func reset() { latest = nil }

    /// The sites that missed their account twice, or nil when so many missed
    /// that the fault is on this side (the network, a block on this server).
    static func verdict(audited: Int, missedTwice: Set<String>) -> [String]? {
        guard audited > 0, Double(missedTwice.count) / Double(audited) <= 0.5 else { return nil }
        return missedTwice.sorted()
    }

    /// The admin page's line for the sweep.
    static func note(_ summary: Summary?) -> String? {
        guard let summary else { return nil }
        guard !summary.broken.isEmpty else {
            return "Site audit: all \(summary.audited) sites found their known account"
        }
        let names = summary.broken.prefix(30).joined(separator: ", ") + (summary.broken.count > 30 ? ", …" : "")
        return "Site audit: \(summary.broken.count) of \(summary.audited) sites cannot find their known account,"
            + " left out of the sweep: \(names)"
    }
}

/// Audits the sweep's sites a quarter of an hour after boot, then daily.
struct SherlockAuditRunner: LifecycleHandler {
    static let firstDelay: Double = 900
    static let interval: Double = 86_400

    func didBoot(_ application: Application) throws {
        guard application.environment != .testing else { return }
        let app = application
        Task {
            try? await Task.sleep(for: .seconds(Self.firstDelay))
            while !Task.isCancelled {
                if let sweep = ScanController.defaultPlugins.lazy.compactMap({ $0 as? BulkUsernamePlugin }).first {
                    await sweep.audit(app: app)
                }
                try? await Task.sleep(for: .seconds(Self.interval))
            }
        }
    }
}
