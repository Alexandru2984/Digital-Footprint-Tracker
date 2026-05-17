import Vapor
import Fluent

struct AuditLogger {
    /// Fire-and-forget audit log. Never throws — errors are swallowed.
    static func log(req: Request, action: String, target: String) {
        let userID = req.authenticatedUserID
        let ip = req.headers[.xForwardedFor].first
            ?? req.peerAddress?.description
            ?? "unknown"
        let cleanIP = ip.split(separator: ",").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ip
        let db = req.db
        Task {
            let entry = AuditLog(userID: userID, action: action, target: String(target.prefix(200)), ip: String(cleanIP.prefix(45)))
            try? await entry.save(on: db)
        }
    }
}
