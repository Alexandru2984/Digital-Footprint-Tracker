import Vapor
import Fluent

struct AuditLogger {
    /// Persist an audit-log entry in a fire-and-forget background Task. Errors
    /// no longer disappear silently — they go to the request logger so a
    /// broken audit pipeline is visible in ops logs.
    static func log(req: Request, action: String, target: String) {
        // Resolve and capture everything we need from the request *now*, then
        // hand off to a detached Task. `req` may be invalidated by the time
        // the task runs; locals are safe.
        let userID = req.authenticatedUserID
        // Store an anonymised IP (/24 or /48) — enough for abuse correlation,
        // not enough to pin the record to one host. The full IP is only used
        // transiently for rate limiting, never persisted.
        let clientIP = IPPrivacy.anonymize(req.clientIP)
        let db = req.db
        let logger = req.logger
        Task {
            let entry = AuditLog(
                userID: userID,
                action: action,
                target: String(target.prefix(200)),
                ip: String(clientIP.prefix(45))
            )
            do {
                try await entry.save(on: db)
            } catch {
                logger.error("AuditLogger: failed to persist entry (action=\(action)): \(error)")
            }
        }
    }
}
