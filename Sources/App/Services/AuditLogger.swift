import Vapor
import Fluent

struct AuditLogger {
    /// Persist an audit entry before the caller advances to its next mutation.
    /// This ordering is essential for account deletion and other multi-step
    /// operations: a detached write could otherwise recreate identifiers after
    /// they had already been pseudonymised or deleted.
    static func log(req: Request, userID explicitUserID: UUID? = nil,
                    action: String, target: String) async {
        // Registration is logged just before its authenticated session is
        // established, so that caller supplies the newly-created ID explicitly.
        let userID = explicitUserID ?? req.authenticatedUserID
        // Store an anonymised IP (/24 or /48) — enough for abuse correlation,
        // not enough to pin the record to one host. The full IP is only used
        // transiently for rate limiting, never persisted.
        let clientIP = IPPrivacy.anonymize(req.clientIP)
        let entry = AuditLog(
            userID: userID,
            action: action,
            target: String(target.prefix(200)),
            ip: String(clientIP.prefix(45))
        )
        do {
            try await entry.save(on: req.db)
        } catch {
            req.logger.error("AuditLogger: failed to persist entry (action=\(action)).")
        }
    }
}
