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
        let storedTarget = String(target.prefix(200))
        let storedIP = String(clientIP.prefix(45))
        let entry = AuditLog(
            userID: userID,
            action: action,
            target: storedTarget,
            ip: storedIP
        )
        do {
            if let configuration = req.application.auditIntegrityConfiguration {
                try await AuditIntegrityLedger.persist(
                    entry,
                    plaintextTarget: storedTarget,
                    plaintextIP: storedIP,
                    on: req.db,
                    configuration: configuration
                )
            } else {
                // Development may deliberately omit the signing key. Production
                // configuration rejects that state before migrations or routes.
                try await entry.save(on: req.db)
            }
        } catch {
            await MetricsRegistry.shared.incAuditLogWriteFailure()
            req.logger.error("AuditLogger: failed to persist entry (action=\(action)).")
        }
    }
}
