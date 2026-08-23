import Vapor
import Fluent

/// Self-service GDPR endpoints:
///
///   GET    /account/export — JSON dump of every row tied to the caller.
///   DELETE /account        — confirmation-gated hard delete of the same.
///
/// Both endpoints sit behind the same per-IP rate limiter as login to slow
/// down credential-stuffing-then-delete attacks against compromised accounts.
struct AccountController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        let account = routes.grouped("account")
            .grouped(AuthRateLimiter(maxAttempts: 5, windowSeconds: 600)) // 5/10 min
        account.get("export", use: exportAll)
        account.delete(use: deleteAccount)
    }

    // MARK: - Export ----------------------------------------------------------

    @Sendable
    func exportAll(req: Request) async throws -> Response {
        let user = try await req.requireRecentSessionUser()
        guard let userID = user.id else { throw Abort(.internalServerError) }
        await AuditLogger.log(req: req, action: "account_export", target: user.username)

        // Profile — never include the password hash or the encrypted Telegram
        // token. Both are at-rest secrets that should never leave the box.
        let webhookURL = try user.webhookURL
        let discordWebhookURL = try user.discordWebhookURL
        let telegramBotToken = try user.telegramBotToken
        let slackWebhookURL = try user.slackWebhookURL
        let telegramChatID = try user.telegramChatID
        let profile: [String: Any] = [
            "id":               userID.uuidString,
            "username":         user.username,
            "email":            user.email,
            "isAdmin":          user.isAdmin,
            "createdAt":        user.createdAt.map { $0.timeIntervalSince1970 } as Any,
            "retentionDays":    user.retentionDays as Any,
            "verboseAlerts":    user.verboseAlerts,
            "webhookURL":       webhookURL as Any,
            "discordConfigured":  discordWebhookURL != nil,
            "telegramConfigured": telegramBotToken != nil,
            "slackConfigured":    slackWebhookURL != nil,
            "telegramChatID":   telegramChatID as Any
        ]

        // Scans + nested results.
        let scans = try await Scan.query(on: req.db)
            .filter(\.$user.$id == userID)
            .with(\.$results)
            .sort(\.$createdAt, .descending)
            .all()
        let scansPayload: [[String: Any]] = try scans.map { s in
            let risk = try RiskScorer.compute(results: s.results)
            return [
                "id":            s.id?.uuidString ?? "",
                "input":         try s.input,
                "status":        s.status.rawValue,
                "riskScore":     risk.value,
                "riskLevel":     risk.level.rawValue,
                "scannedAt":     s.createdAt.map { $0.timeIntervalSince1970 } as Any,
                "completedAt":   s.completedAt.map { $0.timeIntervalSince1970 } as Any,
                "results":       try s.results.map { r -> [String: Any] in
                    var row: [String: Any] = [
                        "source":          r.source,
                        "type":            r.type,
                        "confidenceScore": r.confidenceScore,
                        "rawData":         try r.rawData
                    ]
                    if let meta = try r.metadataObject { row["metadata"] = meta }
                    return row
                }
            ]
        }

        let scheduled = try await ScheduledScan.query(on: req.db)
            .filter(\.$user.$id == userID)
            .all()
        let scheduledPayload: [[String: Any]] = try scheduled.map { s in [
            "id":         s.id?.uuidString ?? "",
            "input":      try s.input,
            "interval":   s.interval.rawValue,
            "isActive":   s.isActive,
            "lastRunAt":  s.lastRunAt.map { $0.timeIntervalSince1970 } as Any,
            "nextRunAt":  s.nextRunAt.timeIntervalSince1970
        ] }

        let tags = try await Tag.query(on: req.db).filter(\.$user.$id == userID).all()
        let tagsPayload: [[String: Any]] = try tags.map { t in [
            "id":     t.id?.uuidString ?? "",
            "name":   try t.name,
            "colour": t.colour
        ] }

        let notifications = try await ScanNotification.query(on: req.db)
            .filter(\.$user.$id == userID)
            .sort(\.$createdAt, .descending)
            .all()
        let notificationsPayload: [[String: Any]] = try notifications.map { n in [
            "id":              n.id?.uuidString ?? "",
            "scanID":          n.scanID.uuidString,
            "message":         try n.message,
            "newResultsCount": n.newResultsCount,
            "isRead":          n.isRead,
            "createdAt":       n.createdAt.map { $0.timeIntervalSince1970 } as Any
        ] }

        let boards = try await Investigation.query(on: req.db)
            .filter(\.$user.$id == userID)
            .sort(\.$createdAt, .descending)
            .all()
        let boardsPayload: [[String: Any]] = try boards.map { board in
            var row: [String: Any] = [
                "id": board.id?.uuidString ?? "",
                "name": try board.name,
                "watched": board.watched,
                "watchInterval": board.watchInterval as Any,
                "nextCheckAt": board.nextCheckAt.map { $0.timeIntervalSince1970 } as Any,
                "lastCheckedAt": board.lastCheckedAt.map { $0.timeIntervalSince1970 } as Any,
                "createdAt": board.createdAt.map { $0.timeIntervalSince1970 } as Any,
                "updatedAt": board.updatedAt.map { $0.timeIntervalSince1970 } as Any,
            ]
            if let data = try board.data.data(using: .utf8),
               let graph = try? JSONSerialization.jsonObject(with: data) {
                row["data"] = graph
            }
            return row
        }

        let darkWebJobs = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$user.$id == userID)
            .sort(\.$createdAt, .descending)
            .all()
        let darkWebPayload: [[String: Any]] = try darkWebJobs.map { job in
            var row: [String: Any] = [
                "id": job.id?.uuidString ?? "",
                "target": try job.target,
                "targetKind": job.targetKind.rawValue,
                "status": job.status.rawValue,
                "resultCount": job.resultCount,
                "failureCode": job.failureCode as Any,
                "cancelRequested": job.cancelRequested,
                "createdAt": job.createdAt.map { $0.timeIntervalSince1970 } as Any,
                "startedAt": job.startedAt.map { $0.timeIntervalSince1970 } as Any,
                "completedAt": job.completedAt.map { $0.timeIntervalSince1970 } as Any,
                "expiresAt": job.expiresAt.timeIntervalSince1970,
            ]
            if let result = try job.resultJSON?.data(using: .utf8),
               let normalized = try? JSONSerialization.jsonObject(with: result) {
                row["result"] = normalized
            }
            return row
        }

        // API keys — metadata only. Never include the hashed key column; an
        // attacker with the hash can still brute-force short keys offline.
        let apiKeys = try await APIKey.query(on: req.db).filter(\.$user.$id == userID).all()
        let apiKeysPayload: [[String: Any]] = apiKeys.map { k in [
            "id":         k.id?.uuidString ?? "",
            "label":      k.label,
            "createdAt":  k.createdAt.map { $0.timeIntervalSince1970 } as Any,
            "lastUsedAt": k.lastUsedAt.map { $0.timeIntervalSince1970 } as Any
        ] }

        // Audit log entries for this user — surface their own action history.
        let auditLogs = try await AuditLog.query(on: req.db)
            .filter(\.$userID == userID)
            .sort(\.$createdAt, .descending)
            .limit(1000)
            .all()
        let auditPayload: [[String: Any]] = try auditLogs.map { l in [
            "action":    l.action,
            "target":    try l.target,
            "ip":        try l.ip,
            "createdAt": l.createdAt.map { $0.timeIntervalSince1970 } as Any
        ] }

        let bundle: [String: Any] = [
            "exportedAt":    Date().timeIntervalSince1970,
            "formatVersion": 2,
            "profile":       profile,
            "scans":         scansPayload,
            "scheduled":     scheduledPayload,
            "tags":          tagsPayload,
            "notifications": notificationsPayload,
            "investigationBoards": boardsPayload,
            "darkWebInvestigations": darkWebPayload,
            "apiKeys":       apiKeysPayload,
            "auditLog":      auditPayload
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: bundle, options: [.prettyPrinted, .sortedKeys])

        let safeName = user.username
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/json; charset=utf-8")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"account-export-\(safeName)-\(stamp).json\"")
        return Response(status: .ok, headers: headers, body: .init(data: jsonData))
    }

    // MARK: - Delete ----------------------------------------------------------

    /// Two-step confirmation: the caller must echo their own username back so
    /// a stolen session cookie alone isn't enough to nuke the account. The
    /// match is case-insensitive.
    struct DeleteBody: Content {
        let confirmUsername: String
        let password: String
    }

    @Sendable
    func deleteAccount(req: Request) async throws -> HTTPStatus {
        let user = try await req.requireRecentSessionUser()
        guard let userID = user.id else { throw Abort(.internalServerError) }
        let body = try req.content.decode(DeleteBody.self)
        guard body.confirmUsername.caseInsensitiveCompare(user.username) == .orderedSame else {
            throw Abort(.badRequest, reason: "confirmUsername does not match the current account.")
        }
        guard try await req.password.async.verify(body.password, created: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Invalid credentials.")
        }

        // Belt-and-braces: the admin seeded from ADMIN_USERNAME/ADMIN_PASSWORD
        // would lock the operator out of their own box if it were deletable
        // via this endpoint. Refuse — the operator can recreate or rename via
        // shell access if they genuinely want to.
        if user.isAdmin {
            throw Abort(.forbidden, reason: "Admin accounts cannot be self-deleted. Contact another administrator.")
        }

        // Log BEFORE the row vanishes so the operator's audit trail still
        // captures who initiated the deletion, from where, and when.
        await AuditLogger.log(req: req, action: "account_deleted", target: user.username)

        let redactedTarget = FieldCrypto.encrypt("[deleted-account]")
        let redactedIP = FieldCrypto.encrypt("[deleted]")
        try await req.db.transaction { database in
            // FK cascade summary:
            //   scheduled_scans, notifications, tags, API keys,
            //   investigations, dark_web_investigations         → CASCADE
            //   scans.user_id                                    → SET NULL
            // For erasure we delete scans before the user, otherwise their
            // encrypted targets would survive as anonymous history.
            let userScans = try await Scan.query(on: database)
                .filter(\.$user.$id == userID)
                .all()
            let scanIDs = userScans.compactMap { $0.id }

            if !scanIDs.isEmpty {
                // Defense for databases that predate the cascading shared-report
                // migration. On updated schemas this is harmlessly redundant.
                try await SharedReport.query(on: database)
                    .filter(\.$scanID ~~ scanIDs)
                    .delete()
                // Results, tag links, and current share links cascade with scans.
                try await Scan.query(on: database)
                    .filter(\.$id ~~ scanIDs)
                    .delete()
            }

            // Retain only non-identifying action/timestamp evidence. Detaching
            // user_id alone was insufficient because target and IP still named
            // the deleted person/account.
            try await AuditLog.query(on: database)
                .filter(\.$userID == userID)
                .set(\.$userID, to: nil)
                .set(\.$targetCipher, to: redactedTarget)
                .set(\.$ipCipher, to: redactedIP)
                .update()

            try await user.delete(on: database)
        }

        req.session.destroy()
        return .noContent
    }
}
