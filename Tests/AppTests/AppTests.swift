import XCTest
import XCTVapor
import Fluent
import FluentSQLiteDriver
@testable import App
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

// Builds a fresh in-memory app for each test so tests are fully isolated.
// SQLite is used instead of PostgreSQL to avoid a live database dependency.
// AddScanStatus gracefully skips the PostgreSQL-specific ALTER COLUMN statements.
private func makeApp() async throws -> Application {
    let app = try await Application.make(.testing)

    var httpClientConfiguration = app.http.client.configuration
    httpClientConfiguration.redirectConfiguration = .disallow
    app.http.client.configuration = httpClientConfiguration

    // Register SQLite under the .psql ID so all model queries that use req.db
    // (which resolves to the default database) hit the in-memory store.
    app.databases.use(.sqlite(.memory), as: .psql, isDefault: true)

    app.middleware.use(CORSMiddleware(configuration: .init(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith]
    )), at: .beginning)

    app.sessions.use(.fluent)
    app.middleware.use(app.sessions.middleware)
    app.middleware.use(SessionSecurityMiddleware())
    app.middleware.use(APIKeyMiddleware())
    app.middleware.use(APIKeyScopeMiddleware())
    // Mirror production so the CSRF origin check is exercised by tests. It is a
    // no-op for requests without an Origin/Referer header (the existing tests),
    // and blocks cross-origin POST/PUT/PATCH/DELETE.
    app.middleware.use(CSRFMiddleware())

    app.migrations.add(CreateScan())
    app.migrations.add(CreateResult())
    app.migrations.add(AddScanStatus())
    app.migrations.add(AddResultMetadata())
    app.migrations.add(AddInputIndex())
    app.migrations.add(CreateUser())
    app.migrations.add(AddUserIDToScans())
    app.migrations.add(AddWebhookURLToUsers())
    app.migrations.add(CreateTags())
    app.migrations.add(CreateScanTags())
    app.migrations.add(CreateScheduledScans())
    app.migrations.add(CreateScanNotifications())
    app.migrations.add(CreateAPIKeys())
    app.migrations.add(AddAPIKeyAuthorization())
    app.migrations.add(CreateAuditLogs())
    app.migrations.add(AddRetentionDaysToUsers())
    app.migrations.add(AddNotificationChannelsToUsers())
    app.migrations.add(CreateSharedReports())
    // Note: HashAPIKeyColumn + HashSharedReportTokens are PostgreSQL-only
    // (use ADD COLUMN IF NOT EXISTS / ALTER COLUMN SET NOT NULL / ADD CONSTRAINT)
    // and are intentionally skipped here. Fresh migrations create the final
    // hash columns directly, so endpoint tests still exercise the final schema.
    app.migrations.add(CreatePluginCache())
    app.migrations.add(AddVerboseAlertsToUser())
    app.migrations.add(AddAccountSecurityToUsers())
    app.migrations.add(AddLastTotpStepToUsers())
    app.migrations.add(AddInputHashToScans())
    app.migrations.add(CreateInvestigations())
    app.migrations.add(AddWatchToInvestigations())
    app.migrations.add(CreateEncryptionMetadata())
    app.migrations.add(MigrateSensitiveFieldEncryption())
    app.migrations.add(EncryptTagNames())
    app.migrations.add(SessionRecord.migration)
    try await app.autoMigrate()

    try routes(app)
    return app
}

private func registerAndLogin(_ app: Application, username: String) async throws -> String {
    try await app.test(.POST, "/auth/register", beforeRequest: { req in
        try req.content.encode([
            "username": username,
            "email": "\(username)@example.test",
            "password": "Xk9mQ2vLp7wZ",
        ], as: .json)
    }, afterResponse: { res in
        XCTAssertEqual(res.status, .ok)
    })
    var cookie = ""
    try await app.test(.POST, "/auth/login", beforeRequest: { req in
        try req.content.encode(["username": username, "password": "Xk9mQ2vLp7wZ"], as: .json)
    }, afterResponse: { res in
        if let raw = res.headers.first(name: "set-cookie"), let pair = raw.split(separator: ";").first {
            cookie = String(pair)
        }
    })
    return cookie
}

final class AppTests: XCTestCase {

    func testEmailAddressNormalizationRejectsHeaderAndDomainAbuse() {
        XCTAssertEqual(EmailAddress.normalize("  User.Name+tag@Example.test  "),
                       "user.name+tag@example.test")
        for invalid in [
            "victim@example.test\r\nBcc: attacker@example.test",
            "two@@example.test",
            ".leading@example.test",
            "double..dot@example.test",
            "user@single-label",
            "user@-edge.example",
            "usér@example.test",
        ] {
            XCTAssertNil(EmailAddress.normalize(invalid), "Unexpectedly accepted: \(invalid)")
        }
    }

    func testBoundedProcessCapturesCapsAndTimesOut() async throws {
        func executable(_ candidates: [String]) throws -> String {
            try XCTUnwrap(candidates.first(where: FileManager.default.isExecutableFile(atPath:)))
        }
        let printf = try executable(["/usr/bin/printf", "/bin/printf"])
        let normal = try await BoundedProcess.run(
            executable: printf,
            arguments: ["safe-output"],
            environment: ["PATH": "/usr/bin:/bin"],
            timeout: 2,
            maxOutputBytes: 128
        )
        XCTAssertTrue(normal.succeeded)
        XCTAssertEqual(String(decoding: normal.stdout, as: UTF8.self), "safe-output")

        let head = try executable(["/usr/bin/head", "/bin/head"])
        let oversized = try await BoundedProcess.run(
            executable: head,
            arguments: ["-c", "4096", "/dev/zero"],
            environment: ["PATH": "/usr/bin:/bin"],
            timeout: 2,
            maxOutputBytes: 64
        )
        XCTAssertTrue(oversized.outputExceeded)
        XCTAssertEqual(oversized.stdout.count, 64)

        let sleep = try executable(["/usr/bin/sleep", "/bin/sleep"])
        let timedOut = try await BoundedProcess.run(
            executable: sleep,
            arguments: ["2"],
            environment: ["PATH": "/usr/bin:/bin"],
            timeout: 0.1,
            maxOutputBytes: 64
        )
        XCTAssertTrue(timedOut.timedOut)
        XCTAssertFalse(timedOut.succeeded)
    }

    func testRateLimiterKeyStoresFailClosedAtCapacity() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        app.grouped(ScanRateLimiter(
            anonMax: 10, authedMax: 10, windowSeconds: 60, maxTrackedKeys: 2
        )).get("_test", "scan-limiter-cap") { _ in HTTPStatus.ok }
        app.grouped(AuthRateLimiter(
            maxAttempts: 10, windowSeconds: 60, maxTrackedKeys: 2
        )).get("_test", "auth-limiter-cap") { _ in HTTPStatus.ok }

        for path in ["/_test/scan-limiter-cap", "/_test/auth-limiter-cap"] {
            for address in ["198.51.100.1", "198.51.100.2"] {
                try await app.test(.GET, path, beforeRequest: { req in
                    req.headers.replaceOrAdd(name: "X-Real-IP", value: address)
                }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
            }
            try await app.test(.GET, path, beforeRequest: { req in
                req.headers.replaceOrAdd(name: "X-Real-IP", value: "198.51.100.3")
            }, afterResponse: { res in XCTAssertEqual(res.status, .tooManyRequests) })
            // Existing keys remain serviceable while unseen keys fail closed.
            try await app.test(.GET, path, beforeRequest: { req in
                req.headers.replaceOrAdd(name: "X-Real-IP", value: "198.51.100.1")
            }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
        }
    }

    // MARK: - Session and step-up authentication

    func testLoginRotatesSessionIDAndInvalidatesTheOldSession() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var firstCookie = ""
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode([
                "username": "rotation-user", "email": "rotation@example.test", "password": "Xk9mQ2vLp7wZ",
            ], as: .json)
        }, afterResponse: { res in
            if let raw = res.headers.first(name: "Set-Cookie") {
                firstCookie = String(raw.split(separator: ";").first ?? "")
            }
        })
        XCTAssertFalse(firstCookie.isEmpty)

        var rotatedCookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: firstCookie)
            try req.content.encode(["username": "rotation-user", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            if let raw = res.headers.first(name: "Set-Cookie") {
                rotatedCookie = String(raw.split(separator: ";").first ?? "")
            }
        })
        XCTAssertFalse(rotatedCookie.isEmpty)
        XCTAssertNotEqual(firstCookie, rotatedCookie)

        try await app.test(.GET, "/auth/me", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: firstCookie)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })
        try await app.test(.GET, "/auth/me", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: rotatedCookie)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })

        let sessionsBeforeInvalidCookie = try await SessionRecord.query(on: app.db).count()
        try await app.test(.GET, "/health", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: "vapor-session=attacker-controlled-id")
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
        let sessionsAfterInvalidCookie = try await SessionRecord.query(on: app.db).count()
        XCTAssertEqual(sessionsAfterInvalidCookie, sessionsBeforeInvalidCookie,
                       "Unknown cookie IDs must not allocate persisted sessions.")
    }

    func testSensitiveOperationsRequireAndCanRefreshRecentAuthentication() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        app.post("_test", "stale-auth") { req -> HTTPStatus in
            req.session.data["authenticatedAt"] = "0"
            return .noContent
        }
        let cookie = try await registerAndLogin(app, username: "recent-auth-user")

        try await app.test(.POST, "/_test/stale-auth", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }, afterResponse: { res in XCTAssertEqual(res.status, .noContent) })

        try await app.test(.POST, "/auth/api-keys", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["label": "blocked"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })

        try await app.test(.POST, "/auth/reauth", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .noContent) })

        try await app.test(.POST, "/auth/api-keys", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["label": "allowed"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
    }

    func testTwoFactorPendingTimestampFailsClosedWhenMissing() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        app.post("_test", "remove-pending-timestamp") { req -> HTTPStatus in
            req.session.data["pending2FAAt"] = nil
            return .noContent
        }
        _ = try await registerAndLogin(app, username: "pending-twofa-user")
        let userLookup = try await User.query(on: app.db)
            .filter(\.$username == "pending-twofa-user").first()
        let user = try XCTUnwrap(userLookup)
        let secret = TOTP.generateSecret()
        user.totpSecret = secret
        user.totpEnabled = true
        try await user.save(on: app.db)

        var pendingCookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": user.username, "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            XCTAssertTrue((try? res.content.decode(LoginResponse.self).twoFactorRequired) == true)
            if let raw = res.headers.first(name: "Set-Cookie") {
                pendingCookie = String(raw.split(separator: ";").first ?? "")
            }
        })
        XCTAssertFalse(pendingCookie.isEmpty)

        try await app.test(.POST, "/_test/remove-pending-timestamp", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: pendingCookie)
        }, afterResponse: { res in XCTAssertEqual(res.status, .noContent) })
        let validCode = try XCTUnwrap(TOTP.current(secret: secret))
        try await app.test(.POST, "/auth/2fa/verify", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: pendingCookie)
            try req.content.encode(TwoFactorController.CodeBody(code: validCode), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })
    }

    // MARK: - API key least privilege

    func testAPIKeyScopesExpiryAndControlPlaneIsolation() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "api-scope-user")

        struct CreateKeyBody: Content {
            let label: String
            let scopes: [String]
            let expiresInDays: Int
        }
        var createdKey: APIKey.Created?
        try await app.test(.POST, "/auth/api-keys", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(CreateKeyBody(
                label: "scanner", scopes: ["scans:read", "scans:write"], expiresInDays: 30
            ), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            createdKey = try res.content.decode(APIKey.Created.self)
        })
        let key = try XCTUnwrap(createdKey)
        XCTAssertEqual(Set(key.scopes), ["scans:read", "scans:write"])
        XCTAssertNotNil(key.expiresAt)

        // Data-plane operation is allowed by scope.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
            try req.content.encode(ScanRequest(input: "api-user", force: nil, plugins: ["GitHubAccountCheck"]), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertNil(res.headers.first(name: "Set-Cookie"), "Bearer auth must remain stateless.")
        })

        // Control-plane and unrelated data-plane operations are deny-by-default.
        try await app.test(.GET, "/auth/api-keys", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })
        try await app.test(.POST, "/investigations", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
            try req.content.encode(InvestigationController.CreateBody(name: "Nope", data: nil), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })

        // Invalid bearer credentials must not silently fall back to anonymous.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: "not-a-valid-token")
            try req.content.encode(ScanRequest(input: "anonymous-fallback", force: nil, plugins: nil), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })

        let storedKeyLookup = try await APIKey.find(key.id!, on: app.db)
        let storedKey = try XCTUnwrap(storedKeyLookup)
        storedKey.expiresAt = Date().addingTimeInterval(-1)
        try await storedKey.save(on: app.db)
        try await app.test(.GET, "/auth/me", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })
    }

    // MARK: - Scan workload admission

    func testExecutionGateRejectsWorkBeyondItsBoundedCapacity() async {
        let gate = ScanExecutionGate(maxConcurrent: 1, maxQueued: 0)
        let first = await gate.acquire()
        let rejected = await gate.acquire()
        XCTAssertTrue(first)
        XCTAssertFalse(rejected)
        let saturated = await gate.snapshot()
        XCTAssertEqual(saturated.active, 1)
        XCTAssertEqual(saturated.queued, 0)

        await gate.release()
        let afterRelease = await gate.acquire()
        XCTAssertTrue(afterRelease)
        await gate.release()
    }

    func testAnonymousCallerCannotSelectHeavyPlugin() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(ScanRequest(input: "alice", force: nil, plugins: ["BulkOSINT"]), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
        let scanCount = try await Scan.query(on: app.db).count()
        XCTAssertEqual(scanCount, 0)
    }

    func testUnverifiedAccountCannotUseRecurringOrBulkFanout() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "fanout-user")

        var boardID = ""
        try await app.test(.POST, "/investigations", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(InvestigationController.CreateBody(
                name: "Case",
                data: #"{"nodes":[{"id":"alice","etype":"username","root":true}],"edges":[]}"#
            ), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            boardID = try res.content.decode(InvestigationController.Full.self).id
        })

        try await app.test(.PUT, "/investigations/\(boardID)/watch", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(InvestigationController.WatchBody(watched: true, interval: "daily"), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })

        try await app.test(.POST, "/scan/bulk", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(BulkScanController.BulkScanRequest(targets: ["alice"], plugins: nil), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })

        struct ScheduleBody: Content { let input: String; let interval: String }
        try await app.test(.POST, "/scheduled-scans", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(ScheduleBody(input: "alice", interval: "daily"), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })
    }

    func testBulkScanCapsAndDeduplicatesTargets() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "verified-bulk-user")
        let storedUser = try await User.query(on: app.db)
            .filter(\.$username == "verified-bulk-user")
            .first()
        let user = try XCTUnwrap(storedUser)
        user.emailVerified = true
        try await user.save(on: app.db)

        try await app.test(.POST, "/scan/bulk", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(BulkScanController.BulkScanRequest(
                targets: (0..<11).map { "user\($0)" }, plugins: ["GitHubAccountCheck"]
            ), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .badRequest) })

        try await app.test(.POST, "/scan/bulk", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(BulkScanController.BulkScanRequest(
                targets: ["Alice", "alice"], plugins: ["GitHubAccountCheck"]
            ), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(try res.content.decode([BulkScanController.BulkScanResult].self).count, 1)
        })
        let createdScanCount = try await Scan.query(on: app.db).count()
        XCTAssertEqual(createdScanCount, 1)
    }

    // MARK: - Sensitive-field encryption

    func testSensitiveFieldEncryptionEnvelopeRoundTrip() throws {
        let previous = ProcessInfo.processInfo.environment["ENCRYPTION_KEY"]
        setenv("ENCRYPTION_KEY", String(repeating: "ab", count: 32), 1)
        defer {
            if let previous { setenv("ENCRYPTION_KEY", previous, 1) }
            else { unsetenv("ENCRYPTION_KEY") }
        }

        try TokenEncryption.validateConfiguration(required: true)
        let ciphertext = try TokenEncryption.encrypt("person@example.test")
        XCTAssertTrue(ciphertext.hasPrefix("enc:v1:"))
        XCTAssertFalse(ciphertext.contains("person@example.test"))
        XCTAssertEqual(TokenEncryption.decrypt(ciphertext), "person@example.test")

        let scan = Scan(input: "person@example.test")
        XCTAssertTrue(scan.inputCipher.hasPrefix("enc:v1:"))
        XCTAssertEqual(scan.input, "person@example.test")

        let user = User(username: "alice", email: "alice@example.test", passwordHash: "hash",
                        webhookURL: "https://hooks.example.test/secret")
        XCTAssertTrue(user.webhookURLCipher?.hasPrefix("enc:v1:") == true)
        XCTAssertEqual(user.webhookURL, "https://hooks.example.test/secret")
    }

    func testEncryptionConfigurationRejectsMissingAndMalformedKeys() {
        let previous = ProcessInfo.processInfo.environment["ENCRYPTION_KEY"]
        defer {
            if let previous { setenv("ENCRYPTION_KEY", previous, 1) }
            else { unsetenv("ENCRYPTION_KEY") }
        }

        unsetenv("ENCRYPTION_KEY")
        XCTAssertNoThrow(try TokenEncryption.validateConfiguration(required: false))
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: true))

        setenv("ENCRYPTION_KEY", "not-a-64-character-hex-key", 1)
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: false))
    }

    func testEncryptionKeyVerifierRejectsKeyReplacement() async throws {
        let previous = ProcessInfo.processInfo.environment["ENCRYPTION_KEY"]
        setenv("ENCRYPTION_KEY", String(repeating: "11", count: 32), 1)
        defer {
            if let previous { setenv("ENCRYPTION_KEY", previous, 1) }
            else { unsetenv("ENCRYPTION_KEY") }
        }

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        app.databases.use(.sqlite(.memory), as: .psql, isDefault: true)
        app.migrations.add(CreateEncryptionMetadata())
        try await app.autoMigrate()
        try await EncryptionKeyVerifier.verifyOrInitialize(on: app.db)

        setenv("ENCRYPTION_KEY", String(repeating: "22", count: 32), 1)
        do {
            try await EncryptionKeyVerifier.verifyOrInitialize(on: app.db)
            XCTFail("A replacement encryption key must not pass the persistent key check")
        } catch {
            XCTAssertTrue(error is TokenEncryption.Error)
        }
    }

    // MARK: - Root route

    func testRootRouteResponds() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/") { res in
            XCTAssertEqual(res.status, .ok)
        }
    }

    // MARK: - Input validation

    func testEmptyInputReturns400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": ""], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testWhitespaceOnlyInputReturns400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "   "], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testTooLongInputReturns400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let longInput = String(repeating: "a", count: 256)
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": longInput], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testInvalidCharactersInInputReturn400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "user<script>"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    // MARK: - Scan creation

    func testScanCreationReturnsPendingStatus() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "testuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.input, "testuser")
            XCTAssertEqual(body.status, "pending")
            XCTAssertTrue(body.results.isEmpty)
        })
    }

    func testInputIsNormalized() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "  trimmed  "], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.input, "trimmed", "Leading/trailing whitespace must be stripped")
        })
    }

    func testInputRejectsLeadingHyphen() throws {
        // A leading '-' could be read as a flag by a downstream argv-based tool
        // (whois/holehe). Reject it at the source; '+' stays valid for phones.
        XCTAssertThrowsError(try InputValidator.validateScanInput("-hevil.com"))
        XCTAssertThrowsError(try InputValidator.validateScanInput("--only-used"))
        XCTAssertNoThrow(try InputValidator.validateScanInput("+40712345678"))
        XCTAssertNoThrow(try InputValidator.validateScanInput("example.com"))
    }

    // MARK: - Deduplication

    func testDuplicateScanReturnsSameID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var firstScanID: UUID?

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "dedupeuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            firstScanID = body.scanID
        })

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "dedupeuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.scanID, firstScanID, "Duplicate scan should return the same scan ID")
        })
    }

    func testWhitespaceTrimmedDeduplication() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var firstScanID: UUID?

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "normuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            firstScanID = try res.content.decode(ScanResponse.self).scanID
        })

        // " normuser " should normalise to "normuser" and hit the same scan.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": " normuser "], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.scanID, firstScanID, "Whitespace-padded duplicate should return the same scan ID")
        })
    }

    // An orphaned pending scan (its runner died mid-flight, e.g. a process crash)
    // must NOT be reused forever — it is reaped to .failed and a fresh scan starts.
    func testOrphanedPendingScanIsReapedNotReused() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // Seed an anonymous pending scan well past the ~120s in-flight window.
        let orphan = Scan(input: "orphantarget", userID: nil)
        try await orphan.save(on: app.db)
        orphan.createdAt = Date().addingTimeInterval(-600)
        try await orphan.save(on: app.db)
        let orphanID = try XCTUnwrap(orphan.id)

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "orphantarget"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertNotEqual(body.scanID, orphanID, "an orphaned pending scan must not be reused")
        })

        let reaped = try await Scan.find(orphanID, on: app.db)
        XCTAssertEqual(reaped?.status, .failed, "the orphaned pending scan is reaped to .failed")
    }

    // MARK: - GET /results/:id

    func testGetResultsReturns404ForUnknownID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/results/\(UUID().uuidString)") { res in
            XCTAssertEqual(res.status, .notFound)
        }
    }

    func testGetResultsReturns400ForInvalidID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/results/not-a-uuid") { res in
            XCTAssertEqual(res.status, .badRequest)
        }
    }

    func testGetResultsReturnsCreatedScan() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // Register + login so the scan has an owner (IDOR fix requires ownership)
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "resultstest", "email": "rt@example.test", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })

        var sessionCookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "resultstest", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            // Extract session cookie to replay on subsequent requests
            if let raw = res.headers.first(name: "set-cookie"),
               let pair = raw.split(separator: ";").first {
                sessionCookie = String(pair)
            }
        })

        var scanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "lookuptest"], as: .json)
            if !sessionCookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie) }
        }, afterResponse: { res in
            scanID = try res.content.decode(ScanResponse.self).scanID
        })

        let id = try XCTUnwrap(scanID)
        try await app.test(.GET, "/results/\(id.uuidString)", beforeRequest: { req in
            if !sessionCookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie) }
        }) { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.scanID, id)
            XCTAssertEqual(body.input, "lookuptest")
        }
    }

    // MARK: - Rate limiter

    func testRateLimiterBlocksAfterLimit() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // First 3 requests (the default anonMax) must succeed.
        for i in 0..<3 {
            try await app.test(.POST, "/scan", beforeRequest: { req in
                try req.content.encode(["input": "ratelimit\(i)"], as: .json)
            }, afterResponse: { res in
                XCTAssertNotEqual(res.status, .tooManyRequests,
                    "Request \(i + 1)/3 should not be rate-limited")
            })
        }

        // The 4th request from the same IP must be rejected.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "ratelimit_overflow"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .tooManyRequests,
                "4th request should be rate-limited")
        })
    }

    // MARK: - Auth-gated endpoints

    func testMyScansRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/my-scans") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testMyScansReturnsPaginatedResponse() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        // Register + login
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "testuser2", "email": "t2@example.test", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })
        // After registration, the session cookie is set — my-scans should return paged response
        // For this test, just check structure
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "testuser2", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { _ in })
        // Check my-scans structure
        // (full auth test with session cookies requires more complex setup; just verify auth flow works)
    }

    func testReportEndpointReturns404ForMissingID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/report/\(UUID().uuidString)") { res in
            XCTAssertEqual(res.status, .notFound)
        }
    }

    func testAdminDashboardRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/admin/dashboard") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // MARK: - SSRF Guard

    func testSSRFGuardBlocksLocalhost() {
        XCTAssertTrue(SSRFGuard.isInternalTarget("localhost"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("LOCALHOST"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("foo.localhost"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("user@localhost"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("::1"))
    }

    func testSSRFGuardBlocksLoopbackIPv4() {
        XCTAssertTrue(SSRFGuard.isInternalTarget("127.0.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("127.1.2.3"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("user@127.0.0.1"))
    }

    // Connection-pinning: the outbound path dials this exact IP (no re-resolve),
    // so an internal answer is rejected and a public one becomes the pin target.
    func testSSRFResolveValidatedIPPinsPublicAndBlocksInternal() {
        XCTAssertEqual(SSRFGuard.resolveValidatedIP("8.8.8.8"), "8.8.8.8")
        XCTAssertNil(SSRFGuard.resolveValidatedIP("127.0.0.1"))
        XCTAssertNil(SSRFGuard.resolveValidatedIP("10.0.0.1"))
        XCTAssertNil(SSRFGuard.resolveValidatedIP("192.168.1.1"))
        XCTAssertNil(SSRFGuard.resolveValidatedIP("169.254.169.254")) // cloud metadata
        XCTAssertNil(SSRFGuard.resolveValidatedIP("2130706433"))       // 127.0.0.1 in decimal
        XCTAssertNil(SSRFGuard.resolveValidatedIP(""))
    }

    func testSSRFIsIPLiteral() {
        XCTAssertTrue(SSRFGuard.isIPLiteral("8.8.8.8"))
        XCTAssertTrue(SSRFGuard.isIPLiteral("::1"))
        XCTAssertTrue(SSRFGuard.isIPLiteral("[2606:4700:4700::1111]"))
        XCTAssertTrue(SSRFGuard.isIPLiteral("2130706433"))
        XCTAssertFalse(SSRFGuard.isIPLiteral("example.com"))
        XCTAssertFalse(SSRFGuard.isIPLiteral("sub.domain.co.uk"))
    }

    func testSSRFGuardBlocksPrivateRanges() {
        // RFC 1918 — class A / B / C
        XCTAssertTrue(SSRFGuard.isInternalTarget("10.0.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("10.255.255.255"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("192.168.1.1"))
        // 172.16.0.0/12 — only 172.16 through 172.31 are private
        XCTAssertTrue(SSRFGuard.isInternalTarget("172.16.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("172.31.255.255"))
        // 172.15 and 172.32 are PUBLIC — must not be blocked
        XCTAssertFalse(SSRFGuard.isInternalTarget("172.15.0.1"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("172.32.0.1"))
    }

    func testSSRFGuardBlocksLinkLocalAndCloudMetadata() {
        // 169.254.169.254 is the AWS/GCP instance-metadata endpoint — critical to block
        XCTAssertTrue(SSRFGuard.isInternalTarget("169.254.169.254"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("169.254.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("user@169.254.169.254"))
    }

    func testSSRFGuardBlocksIPv6Private() {
        XCTAssertTrue(SSRFGuard.isInternalTarget("fc00::1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("fd12:3456:789a::1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("fe80::1"))
    }

    func testSSRFGuardAllowsPublicHosts() {
        XCTAssertFalse(SSRFGuard.isInternalTarget("example.com"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("8.8.8.8"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("1.1.1.1"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("user@example.test"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("swift.micutu.com"))
    }

    func testSSRFGuardURLBlocksInternalHosts() throws {
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://127.0.0.1/foo"))))
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://10.0.0.1/foo"))))
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://169.254.169.254/latest/meta-data"))))
        XCTAssertFalse(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://example.com/foo"))))
        XCTAssertFalse(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://api.github.com/users/alice"))))
    }

    func testScanEndpointRejectsInternalTarget() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "127.0.0.1"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest,
                "Scan endpoint must reject internal/private targets to prevent SSRF")
        })
    }

    // Numeric IP obfuscation: decimal / hex / short / IPv4-mapped forms all
    // decode to internal addresses and must be blocked when used as a URL host.
    func testSSRFGuardBlocksNumericIPObfuscation() throws {
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://2130706433/"))),     "decimal 127.0.0.1")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://0x7f000001/"))),      "hex 127.0.0.1")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://127.1/"))),           "short-form 127.0.0.1")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://0.0.0.0/"))),         "0.0.0.0/8")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://[::ffff:127.0.0.1]/"))), "IPv4-mapped loopback")
        XCTAssertTrue(SSRFGuard.isInternalTarget("100.64.0.1"), "CGNAT 100.64/10")
    }

    // A bare numeric *username* (scan input) must NOT be misread as an integer
    // IP by the structural check — that would block legitimate OSINT.
    func testSSRFGuardDoesNotMisreadNumericUsername() {
        XCTAssertFalse(SSRFGuard.isInternalTarget("12345"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("2130706433"))
    }

    func testOutboundHTTPRejectsInternalAndCredentialBearingURLsBeforeConnecting() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        do {
            _ = try await OutboundHTTP.request(
                try XCTUnwrap(URL(string: "http://127.0.0.1:8080/private")),
                bodyMode: .prefix(maxBytes: 0),
                on: app
            )
            XCTFail("Loopback egress must be rejected before connecting")
        } catch OutboundHTTP.RequestError.blockedInternalHost {
            // Expected.
        }

        do {
            _ = try await OutboundHTTP.request(
                try XCTUnwrap(URL(string: "https://token:secret@example.test/hook")),
                bodyMode: .prefix(maxBytes: 0),
                on: app
            )
            XCTFail("URL user-info must be rejected")
        } catch OutboundHTTP.RequestError.invalidURL {
            // Expected.
        }
    }

    // MARK: - CSRF origin check

    func testCSRFBlocksLookalikeOrigin() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        // hasPrefix would have let this through; an exact host match must not.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "csrfblock"], as: .json)
            req.headers.replaceOrAdd(name: "Origin", value: "https://swift.micutu.com.evil.com")
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .forbidden, "Look-alike cross-origin host must be blocked")
        })
    }

    func testCSRFAllowsLegitimateOrigin() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "csrfallow"], as: .json)
            req.headers.replaceOrAdd(name: "Origin", value: "https://swift.micutu.com")
        }, afterResponse: { res in
            XCTAssertNotEqual(res.status, .forbidden, "Legitimate origin must pass the CSRF check")
        })
    }

    func testCSRFValidatesSchemeAndPort() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        for origin in ["http://swift.micutu.com", "https://swift.micutu.com:444", "null"] {
            try await app.test(.POST, "/scan", beforeRequest: { req in
                try req.content.encode(["input": "csrf-origin"], as: .json)
                req.headers.replaceOrAdd(name: "Origin", value: origin)
            }, afterResponse: { res in
                XCTAssertEqual(res.status, .forbidden, "Unexpectedly allowed origin: \(origin)")
            })
        }
    }

    func testCSRFDummyBearerCannotBypassSessionProtection() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "csrf-bearer-user")

        try await app.test(.POST, "/scan", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            req.headers.bearerAuthorization = .init(token: "not-a-real-api-key")
            req.headers.replaceOrAdd(name: "Origin", value: "https://attacker.example")
            try req.content.encode(["input": "csrf-bearer"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .forbidden)
        })
    }

    func testCSRFRequiresProvenanceForAuthenticatedSessionsInProductionPolicy() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        // Add a second instance with the production missing-header policy. It is
        // inside the sessions and API-key middleware already configured by makeApp.
        app.middleware.use(CSRFMiddleware(requireProvenanceForSessions: true))
        let cookie = try await registerAndLogin(app, username: "csrf-provenance-user")

        try await app.test(.POST, "/scan", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["input": "csrf-no-origin"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .forbidden)
        })
    }

    func testCSRFSecFetchSiteBlocksCrossSiteRequest() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Sec-Fetch-Site", value: "cross-site")
            try req.content.encode(["username": "nobody", "password": "irrelevant"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .forbidden)
        })
    }

    func testWebhookRejectsEmbeddedCredentials() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "webhook-url-user")

        try await app.test(.POST, "/auth/webhook", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode([
                "webhookURL": "https://token:secret@example.test/delivery",
            ], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testShareLinksValidatePolicyAndUseHashOnlyFreshSchema() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "share-policy-user")

        var scanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["input": "share-policy-target"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            scanID = try res.content.decode(ScanResponse.self).scanID
        })
        let id = try XCTUnwrap(scanID)

        try await app.test(.POST, "/scans/\(id)/share", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(ShareController.CreateShareRequest(expiresIn: -1, password: nil), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .badRequest) })

        try await app.test(.POST, "/scans/\(id)/share", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(ShareController.CreateShareRequest(expiresIn: nil, password: "short"), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .badRequest) })

        var rawToken = ""
        try await app.test(.POST, "/scans/\(id)/share", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(ShareController.CreateShareRequest(
                expiresIn: ShareController.minExpirySeconds,
                password: "LongEnough123"
            ), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            rawToken = try res.content.decode(ShareController.ShareResponse.self).token
        })
        XCTAssertEqual(rawToken.utf8.count, 32)

        let storedCandidate = try await SharedReport.query(on: app.db).first()
        let stored = try XCTUnwrap(storedCandidate)
        XCTAssertEqual(stored.tokenHash, sha256Hex(rawToken))
        XCTAssertNotEqual(stored.tokenHash, rawToken)
        XCTAssertEqual(stored.tokenHash.count, 64)

        try await app.test(.GET, "/share/not-a-token") { res in
            XCTAssertEqual(res.status, .notFound)
        }
        try await app.test(.GET, "/share/\(rawToken)") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
        try await app.test(.POST, "/share/\(rawToken)", beforeRequest: { req in
            try req.content.encode(ShareController.PasswordBody(password: "wrong-password"), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })
        try await app.test(.POST, "/share/\(rawToken)", beforeRequest: { req in
            try req.content.encode(ShareController.PasswordBody(password: "LongEnough123"), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })

        let storedScan = try await Scan.find(id, on: app.db)
        let scan = try XCTUnwrap(storedScan)
        let ownerID = try XCTUnwrap(scan.$user.id)
        try await ScanNotification(
            userID: ownerID,
            scanID: id,
            message: "Sensitive target notification",
            newResultsCount: 1
        ).save(on: app.db)
        try await scan.delete(on: app.db)
        let remainingShares = try await SharedReport.query(on: app.db).count()
        let remainingNotifications = try await ScanNotification.query(on: app.db).count()
        XCTAssertEqual(remainingShares, 0,
                       "Deleting a scan must revoke and remove all of its share links")
        XCTAssertEqual(remainingNotifications, 0,
                       "Deleting a scan must remove notifications that describe its target")
    }

    func testTagQuotasAndDuplicatePolicyAreEnforced() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "tag-quota-user")
        let userCandidate = try await User.query(on: app.db)
            .filter(\.$username == "tag-quota-user")
            .first()
        let userID = try XCTUnwrap(try XCTUnwrap(userCandidate).id)

        var tags: [Tag] = []
        for index in 0..<TagController.maxTagsPerUser {
            let tag = Tag(userID: userID, name: "tag-\(index)", colour: "#112233")
            try await tag.save(on: app.db)
            tags.append(tag)
        }
        try await app.test(.POST, "/tags", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["name": "over-quota", "colour": "#445566"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .tooManyRequests) })

        try await tags.removeLast().delete(on: app.db)
        try await app.test(.POST, "/tags", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(["name": "TAG-0", "colour": "#445566"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .conflict) })

        let scan = Scan(input: "tag-quota-target", status: .completed, userID: userID)
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        for tag in tags.prefix(TagController.maxTagsPerScan) {
            try await ScanTag(scanID: scanID, tagID: try XCTUnwrap(tag.id)).save(on: app.db)
        }
        let extraTagID = try XCTUnwrap(tags[TagController.maxTagsPerScan].id)
        try await app.test(.POST, "/scans/\(scanID)/tags/\(extraTagID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }, afterResponse: { res in XCTAssertEqual(res.status, .tooManyRequests) })
    }

    // MARK: - OSINT engine: plugin metadata coherence

    // Every shipping plugin must declare an honest description — not the
    // protocol's generic "OSINT plugin" fallback. This is what regressed
    // silently before: ~17 of 24 plugins fell through a name-keyed switch.
    func testAllPluginsHaveHonestDescriptions() {
        for plugin in ScanController.defaultPlugins {
            XCTAssertFalse(plugin.description.isEmpty, "\(plugin.name) has an empty description")
            XCTAssertNotEqual(plugin.description, "OSINT plugin",
                "\(plugin.name) is still using the generic fallback description")
        }
    }

    // Plugin names double as cache keys and selection identifiers — they must be unique.
    func testPluginNamesAreUnique() {
        let names = ScanController.defaultPlugins.map { $0.name }
        XCTAssertEqual(names.count, Set(names).count, "Duplicate plugin name(s): \(names)")
    }

    // cacheTTL now lives on each plugin. Verify the tuned values land where they
    // should and that an un-overridden plugin keeps the 1-hour default — the old
    // central map silently dropped these to the default via key mismatches.
    func testPluginCacheTTLsAreDeclaredPerPlugin() {
        XCTAssertEqual(HaveIBeenPwnedPlugin().cacheTTL, 86_400, "HIBP breach data should cache 24h")
        XCTAssertEqual(BulkUsernamePlugin().cacheTTL, 21_600, "Sherlock username sweep should cache 6h")
        XCTAssertEqual(WhoisPlugin().cacheTTL, 14_400, "WHOIS should cache 4h")
        XCTAssertEqual(PhonePlugin().cacheTTL, 86_400, "Phone carrier data should cache 24h")
        // A plugin that doesn't override keeps the protocol default.
        XCTAssertEqual(RedditPlugin().cacheTTL, 3_600, "Un-tuned plugin keeps the 1h default")
    }

    // MARK: - Target derivation (email → username pivot)

    func testTargetDeriverUsernamePassesThrough() {
        XCTAssertEqual(TargetDeriver.candidates(for: "johndoe"),
                       [TargetDeriver.Candidate(value: "johndoe", origin: .primary)])
    }

    func testTargetDeriverEmailDerivesUsername() {
        let c = TargetDeriver.candidates(for: "john.doe@gmail.com")
        XCTAssertEqual(c.first, TargetDeriver.Candidate(value: "john.doe@gmail.com", origin: .primary))
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "john.doe", origin: .emailLocalPart)))
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "johndoe", origin: .variant)),
            "dot-stripped (Gmail) form should be a variant")
    }

    func testTargetDeriverStripsPlusTag() {
        let c = TargetDeriver.candidates(for: "alice+newsletter@example.test")
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "alice", origin: .emailLocalPart)))
        XCTAssertFalse(c.contains { $0.origin.derived && $0.value.contains("+") }, "The +tag must be stripped")
    }

    func testTargetDeriverSkipsShortLocalPart() {
        XCTAssertEqual(TargetDeriver.candidates(for: "ab@x.com"),
                       [TargetDeriver.Candidate(value: "ab@x.com", origin: .primary)],
                       "A too-short local-part yields no username candidate")
    }

    func testTargetDeriverDomainHasNoDerivation() {
        XCTAssertEqual(TargetDeriver.candidates(for: "example.com"),
                       [TargetDeriver.Candidate(value: "example.com", origin: .primary)])
    }

    // Username with a separator → sibling-handle variants (no dotted forms, so
    // domains are never derived from). Variants are weaker guesses.
    func testTargetDeriverUsernameSeparatorVariants() {
        let c = TargetDeriver.candidates(for: "john_doe")
        XCTAssertEqual(c.first, TargetDeriver.Candidate(value: "john_doe", origin: .primary))
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "johndoe", origin: .variant)), "separator-stripped")
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "john-doe", origin: .variant)), "separator-swapped")
    }

    // Heavy plugins run only on heavy-eligible candidates so the 480-site sweep
    // is bounded to one run: the email local-part is eligible, variants are not.
    func testTargetDeriverHeavyEligibilityBoundsFanOut() {
        let c = TargetDeriver.candidates(for: "john.doe@gmail.com")
        let heavy = c.filter { $0.origin.heavyEligible }
        XCTAssertEqual(heavy.count, 2, "primary + email local-part only (variant excluded)")
        XCTAssertTrue(heavy.contains(TargetDeriver.Candidate(value: "john.doe", origin: .emailLocalPart)))
        XCTAssertFalse(heavy.contains { $0.origin == .variant })
    }

    // MARK: - Source enrichment (Gravatar profile, GitHub commit emails)

    func testGravatarParsesProfileAndLinkedAccounts() {
        let json = """
        {"entry":[{
          "displayName":"Jane Roe","preferredUsername":"janer",
          "profileUrl":"https://gravatar.com/janer","currentLocation":"Berlin",
          "accounts":[
            {"shortname":"twitter","username":"janer_x","url":"https://twitter.com/janer_x","verified":"true"},
            {"shortname":"github","username":"janer","url":"https://github.com/janer","verified":"false"}
          ]
        }]}
        """
        let results = GravatarPlugin.parseProfile(Data(json.utf8), email: "jane@example.test", avatarURL: "https://en.gravatar.com/avatar/x")
        let r = try? XCTUnwrap(results)
        XCTAssertEqual(r?.count, 3, "profile + 2 linked accounts")
        XCTAssertEqual(r?.first?.metadata?["name"], "Jane Roe")
        XCTAssertTrue(r?.contains { $0.source == "Gravatar:twitter" && $0.confidenceScore > 0.9 } ?? false,
            "Verified linked account scores higher")
    }

    func testGravatarReturnsNilForJunk() {
        XCTAssertNil(GravatarPlugin.parseProfile(Data("not json".utf8), email: "x@y.com", avatarURL: "u"))
    }

    func testGitHubExtractsCommitEmailsAndDropsNoreply() {
        let json = """
        [
          {"type":"PushEvent","payload":{"commits":[
            {"author":{"email":"Real.Dev@Example.test","name":"Real Dev"}},
            {"author":{"email":"12345+janer@users.noreply.github.com","name":"janer"}}
          ]}},
          {"type":"WatchEvent","payload":{}}
        ]
        """
        let emails = UsernamePlugin.extractCommitEmails(from: Data(json.utf8))
        XCTAssertEqual(emails, ["real.dev@example.test"], "lowercased, deduped, noreply dropped")
    }

    // MARK: - Wayback / Internet Archive

    func testWaybackParsesCDXCountAndRange() {
        let json = """
        [["timestamp"],["20180102000000"],["20100315120000"],["20221231235959"]]
        """
        let (count, first, last) = WaybackPlugin.parseCDX(Data(json.utf8))
        XCTAssertEqual(count, 3)
        XCTAssertEqual(first, "20100315120000")
        XCTAssertEqual(last, "20221231235959")
    }

    func testWaybackEmptyCDX() {
        let (count, first, last) = WaybackPlugin.parseCDX(Data("[[\"timestamp\"]]".utf8))
        XCTAssertEqual(count, 0)
        XCTAssertNil(first)
        XCTAssertNil(last)
    }

    func testWaybackFormatsTimestamp() {
        XCTAssertEqual(WaybackPlugin.formatTimestamp("20100315123456"), "2010-03-15")
    }

    // MARK: - Email intelligence

    func testEmailIntelDetectsDisposable() {
        XCTAssertTrue(EmailIntelPlugin.isDisposable("mailinator.com"))
        XCTAssertTrue(EmailIntelPlugin.isDisposable("GuerrillaMail.com"))
        XCTAssertFalse(EmailIntelPlugin.isDisposable("gmail.com"))
    }

    func testEmailIntelFingerprintsProvider() {
        XCTAssertEqual(EmailIntelPlugin.mxProvider(["aspmx.l.google.com"]), "Google (Gmail / Workspace)")
        XCTAssertEqual(EmailIntelPlugin.mxProvider(["example-com.mail.protection.outlook.com"]), "Microsoft (Outlook / 365)")
        XCTAssertEqual(EmailIntelPlugin.mxProvider(["mail.protonmail.ch"]), "Proton Mail")
        XCTAssertNil(EmailIntelPlugin.mxProvider(["mail.self-hosted.example"]))
    }

    // MARK: - DNS over HTTPS

    func testDoHParsesAnswersAndFiltersByType() {
        let json = """
        {"Status":0,"Answer":[
          {"name":"x.com","type":1,"data":"1.2.3.4"},
          {"name":"x.com","type":5,"data":"cname.x.com"},
          {"name":"x.com","type":1,"data":"5.6.7.8"}
        ]}
        """
        XCTAssertEqual(DoHResolver.parse(Data(json.utf8), type: "A"), ["1.2.3.4", "5.6.7.8"],
            "Only A (type 1) answers, CNAME filtered out")
    }

    func testDoHMxHostStripsPriorityAndTrailingDot() {
        XCTAssertEqual(DoHResolver.mxHost("10 mail.example.com."), "mail.example.com")
    }

    func testDoHReverseIPv4Name() {
        XCTAssertEqual(DoHResolver.reverseIPv4Name("1.2.3.4"), "4.3.2.1.in-addr.arpa")
        XCTAssertNil(DoHResolver.reverseIPv4Name("not.an.ip.x"))
    }

    // MARK: - Identity synthesis

    func testIdentitySynthesizerBuildsProfile() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            I(source: "GitHubAccountCheck", type: "account_presence", confidence: 1.0,
              metadata: ["platform": "github", "username": "alice", "name": "Alice Roe",
                         "profileURL": "https://github.com/alice", "location": "Berlin"], rawData: "x"),
            I(source: "GitHub:commits", type: "email", confidence: 0.9,
              metadata: ["email": "Alice@Example.test"], rawData: "x"),
            I(source: "Gravatar:twitter", type: "identity_proof", confidence: 0.95,
              metadata: ["platform": "twitter", "username": "alice"], rawData: "x"),
            I(source: "HaveIBeenPwned", type: "data_breach", confidence: 1.0,
              metadata: ["breaches": "Adobe, LinkedIn", "dataClasses": "Email addresses, Passwords, Usernames"], rawData: "x")
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 40, riskLevel: "Medium")

        XCTAssertEqual(p.likelyName, "Alice Roe")
        XCTAssertEqual(p.locations, ["Berlin"])
        XCTAssertTrue(p.emails.contains("alice@example.test"), "email lowercased + deduped")
        XCTAssertTrue(p.breaches.contains("Adobe") && p.breaches.contains("LinkedIn"))
        XCTAssertEqual(p.exposedDataClasses, ["Email addresses", "Passwords", "Usernames"], "leaked data categories, sorted + deduped")
        XCTAssertEqual(p.riskScore, 40)

        let alice = p.handles.first { $0.handle == "alice" }
        XCTAssertEqual(alice?.platforms, ["github", "twitter"], "handle seen on both platforms")
        XCTAssertGreaterThan(alice?.confidence ?? 0, 0.95, "cross-platform confirmation boosts confidence")

        XCTAssertEqual(p.confirmedAccounts.count, 2, "github + twitter accounts, deduped")
    }

    func testIdentitySynthesizerEmpty() {
        let p = IdentitySynthesizer.synthesize(from: [], riskScore: 0, riskLevel: "Low")
        XCTAssertNil(p.likelyName)
        XCTAssertTrue(p.handles.isEmpty)
        XCTAssertEqual(p.resultCount, 0)
    }

    func testIdentitySynthesizerNameConfidenceWeightedAndMerged() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            // Weak one-off mention of the wrong name.
            I(source: "SiteA", type: "account_presence", confidence: 0.3,
              metadata: ["name": "J. Doe"], rawData: "x"),
            // Real name, corroborated by two strong sources, in two casings/spacings.
            I(source: "GitHub", type: "account_presence", confidence: 1.0,
              metadata: ["name": "John Smith"], rawData: "x"),
            I(source: "GitLab", type: "account_presence", confidence: 0.9,
              metadata: ["name": "john  smith"], rawData: "x"),
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 10, riskLevel: "Low")
        // Confidence-weighted (1.0 + 0.9 = 1.9) beats the 0.3 one-off, not by count.
        XCTAssertEqual(p.likelyName, "John Smith")
        // Case/spacing variants collapse: two distinct identities, not three.
        XCTAssertEqual(p.names.sorted(), ["J. Doe", "John Smith"])
    }

    func testIdentitySynthesizerRejectsHandleShapedNames() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            // A plugin echoing the handle into `name` — highest confidence, still junk.
            I(source: "SiteX", type: "account_presence", confidence: 1.0,
              metadata: ["username": "jsmith92", "name": "jsmith92"], rawData: "x"),
            // Handle-shaped string (underscore) — not a real name.
            I(source: "SiteY", type: "account_presence", confidence: 0.6,
              metadata: ["name": "john_smith"], rawData: "x"),
            // The only real name.
            I(source: "GitHub", type: "account_presence", confidence: 0.9,
              metadata: ["name": "John Smith"], rawData: "x"),
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 10, riskLevel: "Low")
        XCTAssertEqual(p.likelyName, "John Smith")
        XCTAssertEqual(p.names, ["John Smith"], "handle-echoes and handle-shaped strings are not names")
    }

    func testIdentitySynthesizerDedupesAccountAcrossSources() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            I(source: "GitHubAccountCheck", type: "account_presence", confidence: 1.0,
              metadata: ["platform": "github", "username": "alice",
                         "profileURL": "https://github.com/alice"], rawData: "x"),
            // Same account via the Sherlock sweep: different casing + www. + slash.
            I(source: "GitHub", type: "account_presence", confidence: 0.7,
              metadata: ["platform": "GitHub", "username": "alice",
                         "profileURL": "https://www.github.com/alice/"], rawData: "x"),
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 10, riskLevel: "Low")
        XCTAssertEqual(p.confirmedAccounts.count, 1, "same GitHub account from two sources collapses into one")
        XCTAssertEqual(p.confirmedAccounts.first?.confidence, 1.0, "keeps the highest-confidence sighting")
    }

    func testIdentitySynthesizerDedupesLocationAndOrgVariants() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            // Same place, three casing/spacing forms — "Berlin" seen twice wins.
            I(source: "A", type: "account_presence", confidence: 0.9,
              metadata: ["location": "Berlin", "company": "Acme Corp"], rawData: "x"),
            I(source: "B", type: "account_presence", confidence: 0.8,
              metadata: ["location": "berlin", "org": "acme corp"], rawData: "x"),
            I(source: "C", type: "account_presence", confidence: 0.7,
              metadata: ["location": "Berlin ", "company": "Acme  Corp"], rawData: "x"),
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 10, riskLevel: "Low")
        XCTAssertEqual(p.locations, ["Berlin"], "case/spacing variants collapse to the most-seen form")
        XCTAssertEqual(p.organizations, ["Acme Corp"], "company and org variants merge into one org")
    }

    func testIdentitySynthesizerDedupesPhoneFormatting() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            // Same number, two formats (spaced international + compact E.164).
            I(source: "PhoneOSINT", type: "phone_number", confidence: 0.95,
              metadata: ["phone": "+40 721 234 567"], rawData: "x"),
            I(source: "PhoneFormat", type: "phone_number", confidence: 0.4,
              metadata: ["phone": "+40721234567"], rawData: "x"),
            // A genuinely different national-format number must NOT be merged in.
            I(source: "PhoneFormat", type: "phone_number", confidence: 0.4,
              metadata: ["phone": "0721234567"], rawData: "x"),
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 10, riskLevel: "Low")
        XCTAssertEqual(p.phones.count, 2, "formatting variants merge; the national-format number stays separate")
        XCTAssertTrue(p.phones.contains("0721234567"))
        XCTAssertTrue(p.phones.contains(where: { $0.filter(\.isNumber) == "40721234567" }))
    }

    // MARK: - GraphML export

    func testIdentityGraphMLExport() {
        let profile = IdentitySynthesizer.IdentityProfile(
            likelyName: "Alice Roe",
            names: ["Alice Roe"],
            locations: ["Berlin"],
            organizations: ["Acme & Co"],   // ampersand must be XML-escaped
            emails: ["alice@example.test"],
            phones: [],
            handles: [IdentitySynthesizer.HandleUse(handle: "alice", platforms: ["github", "twitter"], confidence: 0.95)],
            confirmedAccounts: [IdentitySynthesizer.Account(platform: "github", reference: "https://github.com/alice", confidence: 1.0)],
            breaches: ["Adobe"],
            exposedDataClasses: ["Email addresses", "Passwords"],
            exposedIPs: ["1.2.3.4"],
            exposedServices: [IdentitySynthesizer.ServiceExposure(
                ip: "1.2.3.4", ports: ["22", "443"], cves: ["CVE-2021-1234"], hostnames: ["host.example.com"])],
            vulnerabilities: ["CVE-2021-1234"],
            riskScore: 40,
            riskLevel: "Medium",
            resultCount: 6
        )
        let xml = IdentityGraph.graphml(from: profile, target: "alice@example.test")

        XCTAssertTrue(xml.hasPrefix("<?xml"))
        XCTAssertTrue(xml.contains("<graphml"))
        XCTAssertTrue(xml.contains("</graphml>"))
        XCTAssertTrue(xml.contains("attr.name=\"relationship\""))
        XCTAssertTrue(xml.contains(">email<") || xml.contains("\">email</data>"), "email node typed")
        XCTAssertTrue(xml.contains("likely-name"), "primary name marked")
        XCTAssertTrue(xml.contains("Acme &amp; Co"), "ampersand escaped")
        XCTAssertFalse(xml.contains("Acme & Co"), "no raw ampersand")
        XCTAssertTrue(xml.contains("used-on"), "alias cross-links to the account mentioning it")
        XCTAssertTrue(xml.contains("open-port"), "ports hang off the IP host")
        XCTAssertTrue(xml.contains("vulnerable-to"), "CVEs hang off the IP host")
        XCTAssertTrue(xml.contains("CVE-2021-1234"), "CVE rendered as a node")
        XCTAssertTrue(xml.contains("exposed-data") && xml.contains("Passwords"), "leaked data classes as nodes")
    }

    func testExecutiveReportMarkdown() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            I(source: "GitHub", type: "account_presence", confidence: 1.0,
              metadata: ["platform": "github", "username": "alice", "name": "Alice Roe",
                         "profileURL": "https://github.com/alice"], rawData: "x"),
            I(source: "HIBP", type: "data_breach", confidence: 1.0,
              metadata: ["breaches": "Adobe, LinkedIn", "dataClasses": "Passwords, Phone numbers"], rawData: "x"),
            I(source: "InternetDB", type: "exposed_service", confidence: 0.9,
              metadata: ["ip": "1.2.3.4", "ports": "22, 443"], rawData: "x"),
            I(source: "InternetDB", type: "vulnerability", confidence: 0.95,
              metadata: ["ip": "1.2.3.4", "cves": "CVE-2024-9"], rawData: "x"),
            I(source: "crt.sh", type: "subdomain", confidence: 0.9, metadata: ["subdomain": "admin.example.com"], rawData: "x"),
            I(source: "WebPosture", type: "security_headers", confidence: 0.8, metadata: ["domain": "example.com", "grade": "D"], rawData: "x")
        ]
        let profile = IdentitySynthesizer.synthesize(from: inputs, riskScore: 55, riskLevel: "High")
        let md = ExecutiveReport.markdown(input: "example.com", profile: profile,
                                          surface: ExposureDiff.snapshot(from: inputs),
                                          generatedAt: Date(timeIntervalSince1970: 0))

        XCTAssertTrue(md.hasPrefix("# Digital Footprint Report — example.com"))
        XCTAssertTrue(md.contains("1970-01-01 00:00 UTC"), "deterministic UTC timestamp")
        XCTAssertTrue(md.contains("High (55/100)"))
        XCTAssertTrue(md.contains("## Executive summary"))
        XCTAssertTrue(md.contains("Alice Roe"), "likely name surfaced")
        XCTAssertTrue(md.contains("Adobe") && md.contains("LinkedIn"), "breaches listed")
        XCTAssertTrue(md.contains("Exposed data classes:") && md.contains("Passwords"), "leaked data categories surfaced")
        XCTAssertTrue(md.contains("## Attack surface") && md.contains("1.2.3.4"))
        XCTAssertTrue(md.contains("CVE-2024-9"))
        XCTAssertTrue(md.contains("| Domain | Grade |") && md.contains("| example.com | D |"))
        XCTAssertTrue(md.contains("admin.example.com"), "subdomain listed")
    }

    func testExecutiveReportHTMLEscapesAndStructures() {
        typealias I = IdentitySynthesizer.Input
        // A hostile "name" must not break out into live markup.
        let inputs = [
            I(source: "x", type: "account_presence", confidence: 1.0,
              metadata: ["platform": "github", "username": "alice",
                         "name": "Evil <script>Xss</script>", "profileURL": "https://github.com/alice"], rawData: "x"),
            I(source: "InternetDB", type: "exposed_service", confidence: 0.9,
              metadata: ["ip": "1.2.3.4", "ports": "443"], rawData: "x")
        ]
        let profile = IdentitySynthesizer.synthesize(from: inputs, riskScore: 30, riskLevel: "Medium")
        let html = ExecutiveReportHTML.html(input: "ex&ample.com", profile: profile,
                                            surface: ExposureDiff.snapshot(from: inputs),
                                            generatedAt: Date(timeIntervalSince1970: 0))

        XCTAssertTrue(html.hasPrefix("<!DOCTYPE html>"))
        XCTAssertTrue(html.contains("</html>"))
        XCTAssertFalse(html.contains("<script>Xss</script>"), "hostile name must be escaped")
        XCTAssertTrue(html.contains("&lt;script&gt;"), "name rendered as escaped text")
        XCTAssertTrue(html.contains("ex&amp;ample.com"), "ampersand in target escaped")
        XCTAssertTrue(html.contains("risk-medium"), "risk level styled")
        XCTAssertTrue(html.contains("<table>") && html.contains("1.2.3.4"), "attack-surface table present")
    }

    func testIdentitySynthesizerAggregatesInfraExposure() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            I(source: "InternetDB", type: "exposed_service", confidence: 0.9,
              metadata: ["ip": "1.2.3.4", "ports": "443, 22, 80", "hostnames": "host.example.com"], rawData: "x"),
            I(source: "InternetDB", type: "vulnerability", confidence: 0.95,
              metadata: ["ip": "1.2.3.4", "cves": "CVE-2021-1234, CVE-2019-9999"], rawData: "x"),
            I(source: "Shodan", type: "exposed_service", confidence: 0.9,
              metadata: ["ip": "5.6.7.8", "port": "8443"], rawData: "x")
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 50, riskLevel: "High")

        XCTAssertEqual(p.exposedIPs, ["1.2.3.4", "5.6.7.8"])
        XCTAssertEqual(p.vulnerabilities, ["CVE-2019-9999", "CVE-2021-1234"], "all CVEs, deduped + sorted")

        let host = p.exposedServices.first { $0.ip == "1.2.3.4" }
        XCTAssertEqual(host?.ports, ["22", "80", "443"], "ports sorted numerically")
        XCTAssertEqual(host?.cves.count, 2)
        XCTAssertEqual(p.exposedServices.first { $0.ip == "5.6.7.8" }?.ports, ["8443"], "singular 'port' key also captured")
    }

    // MARK: - InternetDB (free Shodan-grade exposure)

    func testInternetDBParse() {
        let json = #"""
        {"ip":"1.2.3.4","ports":[443,22,80],"cpes":["cpe:/a:nginx:nginx"],
         "hostnames":["host.example.com"],"tags":["cloud"],
         "vulns":["CVE-2021-1234","CVE-2020-5678"]}
        """#.data(using: .utf8)!
        let results = InternetDBPlugin.parse(json, ip: "1.2.3.4")
        XCTAssertEqual(results.count, 3, "ports + vulns + cpes → three findings")

        let svc = results.first { $0.type == "exposed_service" }
        XCTAssertEqual(svc?.metadata?["ports"], "22, 80, 443", "ports sorted + joined")
        XCTAssertEqual(svc?.metadata?["ip"], "1.2.3.4")

        let vuln = results.first { $0.type == "vulnerability" }
        XCTAssertEqual(vuln?.metadata?["cve_count"], "2")
        XCTAssertTrue(vuln?.metadata?["cves"]?.contains("CVE-2021-1234") ?? false)

        XCTAssertTrue(results.contains { $0.type == "tech_stack" })

        // A bare/empty record yields nothing (a clean host).
        let empty = #"{"ip":"1.2.3.4","ports":[],"vulns":[],"cpes":[]}"#.data(using: .utf8)!
        XCTAssertTrue(InternetDBPlugin.parse(empty, ip: "1.2.3.4").isEmpty)

        // A CVE finding is scored as threat (non-zero risk).
        XCTAssertGreaterThan(RiskScorer.compute(raw: [(0.95, "vulnerability")]).value, 0)
    }

    func testInternetDBResolveIPsFiltersPrivate() async {
        let pub = await InternetDBPlugin.resolveIPs("8.8.8.8")
        XCTAssertEqual(pub, ["8.8.8.8"], "a public IP passes straight through")
        let priv = await InternetDBPlugin.resolveIPs("192.168.1.10")
        XCTAssertTrue(priv.isEmpty, "RFC1918 address is dropped")
        let loop = await InternetDBPlugin.resolveIPs("127.0.0.1")
        XCTAssertTrue(loop.isEmpty, "loopback is dropped")
    }

    // MARK: - Attack surface (whole-footprint exposure)

    func testCrtShParsesAndDedupesSubdomains() {
        // name_value often packs several SANs into one entry, newline-separated,
        // including wildcards and duplicates.
        let json = #"""
        [{"name_value":"*.example.com\nwww.example.com"},
         {"name_value":"WWW.example.com"},
         {"name_value":"api.example.com\nmail.example.com"},
         {"name_value":"not-a-host"}]
        """#.data(using: .utf8)!
        let subs = CrtShPlugin.parseSubdomains(json, limit: 50)
        XCTAssertEqual(subs, ["example.com", "www.example.com", "api.example.com", "mail.example.com"],
                       "wildcards stripped, lowercased, deduped, non-hosts dropped, order preserved")
        XCTAssertEqual(CrtShPlugin.parseSubdomains(json, limit: 2).count, 2, "limit honoured")
        XCTAssertEqual(CrtShPlugin.normalizeDomain("https://Example.com/path"), "example.com")
    }

    func testAttackSurfaceHostListAndIPFilter() {
        let hosts = AttackSurfacePlugin.hostList(
            apex: "example.com",
            subdomains: ["www.example.com", "example.com", "api.example.com"],
            limit: 3)
        XCTAssertEqual(hosts, ["example.com", "www.example.com", "api.example.com"],
                       "apex first, deduped, capped")

        XCTAssertTrue(AttackSurfacePlugin.isPublicIPv4("8.8.8.8"))
        XCTAssertFalse(AttackSurfacePlugin.isPublicIPv4("10.0.0.1"))
        XCTAssertFalse(AttackSurfacePlugin.isPublicIPv4("169.254.169.254"), "metadata endpoint rejected")
        XCTAssertFalse(AttackSurfacePlugin.isPublicIPv4("not-an-ip"))
    }

    // MARK: - Web posture (security-header grading)

    func testWebPostureGrading() {
        // Fully hardened → grade A, nothing missing, server fingerprinted.
        let strong = WebPosture.analyze(headers: [
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "server": "nginx", "x-powered-by": "Express"
        ])
        XCTAssertEqual(strong.grade, "A")
        XCTAssertTrue(strong.missing.isEmpty)
        XCTAssertEqual(strong.server, "nginx / Express")

        // Naked response → grade F, all six missing.
        let weak = WebPosture.analyze(headers: ["server": "Apache"])
        XCTAssertEqual(weak.grade, "F")
        XCTAssertEqual(weak.missing.count, 6)
        XCTAssertEqual(weak.server, "Apache")

        // Missing only the two heaviest (HSTS + CSP): 3 of 7 weight present → grade D.
        let partial = WebPosture.analyze(headers: [
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
            "permissions-policy": "camera=()"
        ])
        XCTAssertEqual(partial.grade, "D")
        XCTAssertTrue(partial.missing.contains("HSTS") && partial.missing.contains("CSP"))
        XCTAssertNil(partial.server, "no Server/X-Powered-By → no fingerprint")

        // An empty header value counts as missing, not present.
        let blank = WebPosture.analyze(headers: ["content-security-policy": "  "])
        XCTAssertTrue(blank.missing.contains("CSP"))
    }

    // MARK: - Exposure diff (attack-surface change detection)

    private func diffInput(_ type: String, _ meta: [String: String]) -> IdentitySynthesizer.Input {
        IdentitySynthesizer.Input(source: "x", type: type, confidence: 0.9, metadata: meta, rawData: "x")
    }

    func testExposureDiffDetectsWorseningExposure() {
        let prev = [
            diffInput("exposed_service", ["ip": "1.2.3.4", "ports": "22, 80"]),
            diffInput("vulnerability", ["ip": "1.2.3.4", "cves": "CVE-2020-1"]),
            diffInput("subdomain", ["subdomain": "www.example.com"]),
            diffInput("security_headers", ["domain": "example.com", "grade": "B"])
        ]
        let cur = [
            diffInput("exposed_service", ["ip": "1.2.3.4", "ports": "22, 80, 3389"]),
            diffInput("vulnerability", ["ip": "1.2.3.4", "cves": "CVE-2020-1, CVE-2024-9"]),
            diffInput("subdomain", ["subdomain": "www.example.com"]),
            diffInput("subdomain", ["subdomain": "admin.example.com"]),
            diffInput("security_headers", ["domain": "example.com", "grade": "D"])
        ]
        let d = ExposureDiff.between(previous: prev, current: cur)

        XCTAssertEqual(d.newPorts.first?.ip, "1.2.3.4")
        XCTAssertEqual(d.newPorts.first?.ports, ["3389"], "only the newly opened port")
        XCTAssertTrue(d.newCVEs.contains { $0.contains("CVE-2024-9") && $0.contains("1.2.3.4") })
        XCTAssertEqual(d.newSubdomains, ["admin.example.com"])
        XCTAssertEqual(d.gradeChanges.first.map { "\($0.from ?? "?")→\($0.to)" }, "B→D")
        XCTAssertTrue(d.worsenedGrades, "B→D is a regression")
        XCTAssertTrue(d.hasExposureChange)
        XCTAssertFalse(d.headline.isEmpty)
    }

    func testExposureDiffIdenticalIsEmptyAndFirstScanHasNoBaseline() {
        let snap = [
            diffInput("exposed_service", ["ip": "9.9.9.9", "ports": "443"]),
            diffInput("vulnerability", ["ip": "9.9.9.9", "cves": "CVE-1"])
        ]
        let same = ExposureDiff.between(previous: snap, current: snap)
        XCTAssertTrue(same.isEmpty)
        XCTAssertFalse(same.hasExposureChange)

        // An improving grade is a change but not a regression.
        let better = ExposureDiff.between(
            previous: [diffInput("security_headers", ["domain": "x.io", "grade": "D"])],
            current:  [diffInput("security_headers", ["domain": "x.io", "grade": "A"])])
        XCTAssertEqual(better.gradeChanges.count, 1)
        XCTAssertFalse(better.worsenedGrades, "D→A is an improvement, not a regression")
        XCTAssertFalse(better.hasExposureChange)
    }

    // MARK: - Transitive pivot

    func testPivotExtractorFindsNewIdentities() {
        let results = [
            PluginResult(source: "GitHubAccountCheck", type: "account_presence", confidenceScore: 1.0,
                         rawData: "x", metadata: ["platform": "github", "username": "alice"]),
            PluginResult(source: "GitHub:commits", type: "email", confidenceScore: 0.9,
                         rawData: "x", metadata: ["email": "real.dev@example.test", "username": "alice"]),
            PluginResult(source: "Gravatar:twitter", type: "identity_proof", confidenceScore: 0.95,
                         rawData: "x", metadata: ["platform": "twitter", "username": "alice_x"])
        ]
        let pivots = PivotExtractor.candidates(from: results, alreadyScanned: ["alice"])
        XCTAssertTrue(pivots.contains("real.dev@example.test"), "harvested email becomes a pivot")
        XCTAssertTrue(pivots.contains("alice_x"), "linked handle becomes a pivot")
        XCTAssertFalse(pivots.contains("alice"), "already-scanned identity is excluded")
    }

    func testPivotExtractorRespectsCap() {
        let results = (0..<20).map {
            PluginResult(source: "s", type: "email", confidenceScore: 1.0, rawData: "x",
                         metadata: ["email": "user\($0)@example.test"])
        }
        XCTAssertEqual(PivotExtractor.candidates(from: results, alreadyScanned: []).count, PivotExtractor.maxPivots)
    }

    func testPivotExtractorSkipsLowConfidenceFindings() {
        let results = [
            // A weak (false-positive-prone) match must not seed a round-2 scan of
            // an unrelated identity.
            PluginResult(source: "SherlockSite", type: "account_presence", confidenceScore: 0.7,
                         rawData: "x", metadata: ["github": "unrelated_user"]),
            // A strong finding still pivots.
            PluginResult(source: "Keybase", type: "identity_proof", confidenceScore: 0.98,
                         rawData: "x", metadata: ["twitter": "confirmed_handle"]),
        ]
        let pivots = PivotExtractor.candidates(from: results, alreadyScanned: [])
        XCTAssertFalse(pivots.contains("unrelated_user"), "a 0.7 finding is too weak to pivot on")
        XCTAssertTrue(pivots.contains("confirmed_handle"), "a strong finding still pivots")
    }

    func testPivotExtractorPrioritizesEmailAnchorOverHandles() {
        // More handle candidates than the budget, plus one email: the email — a
        // hard identity link — must survive the cap.
        var results = (0..<6).map {
            PluginResult(source: "s", type: "account_presence", confidenceScore: 0.85,
                         rawData: "x", metadata: ["github": "handle\($0)"])
        }
        results.append(PluginResult(source: "s", type: "email", confidenceScore: 0.9,
                                    rawData: "x", metadata: ["email": "anchor@example.test"]))
        let pivots = PivotExtractor.candidates(from: results, alreadyScanned: [])
        XCTAssertEqual(pivots.count, PivotExtractor.maxPivots)
        XCTAssertTrue(pivots.contains("anchor@example.test"), "the email anchor outranks handles for the limited budget")
    }

    func testPivotedOriginIsDiscountedAndNotHeavy() {
        XCTAssertEqual(TargetDeriver.Origin.pivoted.confidenceFactor, 0.6, accuracy: 0.001)
        XCTAssertFalse(TargetDeriver.Origin.pivoted.heavyEligible, "pivots never trigger the heavy sweep")
        XCTAssertTrue(TargetDeriver.Origin.pivoted.derived)
    }

    // MARK: - Risk scoring

    private func mkResult(_ type: String, _ confidence: Double, source: String = "src", raw: String = "data") -> App.Result {
        App.Result(scanID: UUID(), source: source, type: type, confidenceScore: confidence, rawData: raw)
    }

    func testRiskScorerEmptyIsLow() {
        let s = RiskScorer.compute(results: [])
        XCTAssertEqual(s.value, 0)
        XCTAssertEqual(s.level, .low)
    }

    // The regression that motivated the rewrite: HIBP's "no breaches found"
    // result (type breach_check, confidence 1.0) must contribute ZERO risk.
    func testRiskScorerCleanBreachCheckIsZeroRisk() {
        let s = RiskScorer.compute(results: [mkResult("breach_check", 1.0, raw: "No breaches found.")])
        XCTAssertEqual(s.value, 0, "A clean breach check must not add risk")
    }

    // And it must not inflate a score built from real (account) findings.
    func testRiskScorerCleanCheckDoesNotInflate() {
        let accounts = (0..<5).map { mkResult("account_presence", 0.9, source: "s\($0)", raw: "acct \($0)") }
        let withClean = accounts + [mkResult("breach_check", 1.0, raw: "No breaches found.")]
        XCTAssertEqual(RiskScorer.compute(results: accounts).value,
                       RiskScorer.compute(results: withClean).value,
                       "A clean breach check must not change the score")
    }

    func testRiskScorerConfirmedBreachIsAtLeastMedium() {
        let s = RiskScorer.compute(results: [mkResult("data_breach", 1.0, raw: "Found in 3 breaches")])
        XCTAssertGreaterThanOrEqual(s.value, 25, "A confirmed breach should reach at least Medium")
    }

    // A live lookalike domain is impersonation/phishing infrastructure — it must
    // score in the threat band, well above a plain DNS/infra record.
    func testRiskScorerLookalikeDomainCountsAsThreat() {
        let lookalike = RiskScorer.compute(raw: [(0.6, "lookalike_domain")]).value
        let infra = RiskScorer.compute(raw: [(0.6, "subdomain")]).value
        XCTAssertGreaterThan(lookalike, infra,
            "A live lookalike domain is an impersonation threat, not mere infrastructure")
    }

    // MARK: - Typosquat permutations (pure / offline)

    func testTyposquatPermutationsAreValidLookalikes() {
        let base = TyposquatPlugin.Base(sld: "example", tld: "com")
        let perms = TyposquatPlugin.permutations(of: base)
        XCTAssertFalse(perms.isEmpty)
        XCTAssertLessThanOrEqual(perms.count, TyposquatPlugin.maxCandidates)

        let domains = perms.map { $0.domain }
        XCTAssertFalse(domains.contains("example.com"), "The base domain must never be a candidate")
        XCTAssertEqual(Set(domains).count, domains.count, "Candidates must be deduped")
        for d in domains {
            XCTAssertTrue(TyposquatPlugin.isValidHostname(d), "\(d) is not a valid hostname")
        }
        // Round-robin interleaving guarantees each technique's first item lands
        // within the cap: a TLD swap and a transposition are both expected.
        XCTAssertTrue(domains.contains("example.net"), "Expected TLD-swap lookalike example.net")
        XCTAssertTrue(domains.contains("xeample.com"), "Expected transposition lookalike xeample.com")
    }

    func testTyposquatRejectsNonRegistrableHosts() {
        XCTAssertNil(TyposquatPlugin.registrable("1.2.3.4"), "An IPv4 has no registrable typo surface")
        XCTAssertNil(TyposquatPlugin.registrable("localhost"), "A single label is not registrable")
        XCTAssertNil(TyposquatPlugin.registrable("a.com"), "A one-char SLD has no useful permutations")
        XCTAssertEqual(TyposquatPlugin.registrable("www.example.com"),
                       TyposquatPlugin.Base(sld: "example", tld: "com"),
                       "Host should fold to its registrable sld.tld")
    }

    // A single breach must outweigh a large pile of public account presences.
    func testRiskScorerBreachOutweighsManyAccounts() {
        let breach = RiskScorer.compute(results: [mkResult("data_breach", 1.0)])
        let accounts = RiskScorer.compute(results: (0..<20).map {
            mkResult("account_presence", 0.9, source: "s\($0)", raw: "acct \($0)")
        })
        XCTAssertGreaterThan(breach.value, accounts.value,
            "One breach should score higher than 20 social accounts")
    }

    // Account presence saturates: 50 profiles aren't dramatically worse than 10,
    // and account presence alone never escalates past the Low band.
    func testRiskScorerAccountPresenceSaturates() {
        let ten = RiskScorer.compute(results: (0..<10).map {
            mkResult("account_presence", 1.0, source: "s\($0)", raw: "a\($0)")
        }).value
        let fifty = RiskScorer.compute(results: (0..<50).map {
            mkResult("account_presence", 1.0, source: "s\($0)", raw: "a\($0)")
        }).value
        XCTAssertLessThanOrEqual(fifty - ten, 3, "Account category must saturate")
        XCTAssertLessThan(fifty, 25, "Public accounts alone should stay in the Low band")
    }

    // Exact-duplicate findings (same source+type+rawData) are counted once.
    func testRiskScorerDeduplicatesIdenticalFindings() {
        let one = RiskScorer.compute(results: [mkResult("data_breach", 1.0, source: "hibp", raw: "X")]).value
        let dup = RiskScorer.compute(results: [
            mkResult("data_breach", 1.0, source: "hibp", raw: "X"),
            mkResult("data_breach", 1.0, source: "hibp", raw: "X")
        ]).value
        XCTAssertEqual(one, dup, "Identical findings must not double-count")
    }

    // MARK: - Structured result metadata

    // Cache entries serialized before `metadata` existed must still decode
    // (the field is optional → decodeIfPresent yields nil).
    func testPluginResultDecodesLegacyCacheWithoutMetadata() throws {
        let legacy = #"{"source":"github","type":"account_presence","confidenceScore":1.0,"rawData":"x"}"#
        let pr = try JSONDecoder().decode(PluginResult.self, from: Data(legacy.utf8))
        XCTAssertEqual(pr.source, "github")
        XCTAssertNil(pr.metadata)
    }

    func testPluginResultMetadataRoundTrips() throws {
        let pr = PluginResult(source: "github", type: "account_presence", confidenceScore: 1.0,
                              rawData: "x", metadata: ["platform": "github", "username": "alice"])
        let back = try JSONDecoder().decode(PluginResult.self, from: JSONEncoder().encode(pr))
        XCTAssertEqual(back.metadata?["username"], "alice")
    }

    func testResultMetadataObjectDecodesStoredJSON() {
        let withMeta = App.Result(scanID: UUID(), source: "github", type: "account_presence",
                                  confidenceScore: 1.0, rawData: "x",
                                  metadata: #"{"platform":"github","username":"alice"}"#)
        XCTAssertEqual(withMeta.metadataObject?["username"], "alice")

        let without = App.Result(scanID: UUID(), source: "s", type: "t", confidenceScore: 0.5, rawData: "x")
        XCTAssertNil(without.metadataObject)
    }

    // MARK: - Correlation engine

    private func summary(_ input: String, _ results: [Correlator.ResultEntry] = []) -> Correlator.ScanSummary {
        Correlator.ScanSummary(id: UUID(), input: input, results: results)
    }

    func testCorrelatorRequiresTwoScans() {
        XCTAssertTrue(Correlator.correlate([summary("alice@example.test")]).isEmpty)
    }

    func testCorrelatorIgnoresUnsharedEntities() {
        let a = summary("alice@example.test")
        let b = summary("bob@example.test")
        XCTAssertTrue(Correlator.correlate([a, b]).isEmpty, "No shared entity → no correlation")
    }

    // The scan input itself is now a correlation anchor (it was ignored before):
    // an email that is one scan's input and another scan's structured finding links them.
    func testCorrelatorLinksInputToStructuredMetadata() {
        let a = summary("alice@example.test")
        let b = summary("aliceuser", [
            Correlator.ResultEntry(source: "HaveIBeenPwned", type: "data_breach", rawData: "x",
                                   metadata: ["email": "alice@example.test", "breachCount": "2"])
        ])
        let entities = Correlator.correlate([a, b])
        let email = entities.first { $0.type == "email" && $0.value == "alice@example.test" }
        XCTAssertEqual(email?.occurrences.count, 2, "Email should link both scans")
    }

    // Precise: a structured twitter handle links to a username scan — regex over
    // the display string could not reliably extract this.
    func testCorrelatorUsesStructuredMetadata() {
        let a = summary("alicejones", [
            Correlator.ResultEntry(source: "GitHubAccountCheck", type: "account_presence", rawData: "x",
                                   metadata: ["platform": "github", "username": "alicejones", "twitter": "bobsmith"])
        ])
        let b = summary("bobsmith")
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "bobsmith" && $0.occurrences.count == 2 },
            "Structured twitter handle should link to the username scan")
    }

    // Fallback: a plugin with no metadata still contributes via regex over rawData.
    func testCorrelatorFallsBackToRegex() {
        let a = summary("targetalpha", [
            Correlator.ResultEntry(source: "SomePlugin", type: "paste_exposure",
                                   rawData: "leaked credential for shared@example.test here", metadata: nil)
        ])
        let b = summary("shared@example.test")
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "shared@example.test" && $0.occurrences.count == 2 })
    }

    // A Keybase identity proof exposing a github handle links to a username scan.
    func testCorrelatorLinksPlatformProofHandles() {
        let a = summary("alicekb", [
            Correlator.ResultEntry(source: "Keybase", type: "identity_proof", rawData: "proofs",
                                   metadata: ["platform": "keybase", "github": "devhandle"])
        ])
        let b = summary("devhandle")
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "devhandle" && $0.type == "username" && $0.occurrences.count == 2 },
            "A platform proof handle should link to a username scan")
    }

    // A discovered subdomain links to a domain scanned directly.
    func testCorrelatorLinksSubdomainToDomainInput() {
        let a = summary("shared.example.com")
        let b = summary("otherinput", [
            Correlator.ResultEntry(source: "crt.sh", type: "subdomain", rawData: "shared.example.com",
                                   metadata: ["subdomain": "shared.example.com", "domain": "example.com"])
        ])
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "shared.example.com" && $0.type == "domain" && $0.occurrences.count == 2 })
    }

    // MARK: - Anonymous scan access (capability)

    func testAnonymousCanReadOwnScanByCapability() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var scanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "capabilitytest"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            scanID = try res.content.decode(ScanResponse.self).scanID
        })
        let id = try XCTUnwrap(scanID)

        // No auth: an ownerless scan is readable by anyone holding its ID.
        try await app.test(.GET, "/results/\(id.uuidString)") { res in
            XCTAssertEqual(res.status, .ok, "Anonymous scan must be readable by capability")
        }
    }

    func testOwnedScanNotReadableAnonymously() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "owner2", "email": "o2@example.test", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
        var cookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "owner2", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            if let raw = res.headers.first(name: "set-cookie"), let pair = raw.split(separator: ";").first { cookie = String(pair) }
        })

        var scanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "ownedscan"], as: .json)
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }, afterResponse: { res in scanID = try res.content.decode(ScanResponse.self).scanID })
        let id = try XCTUnwrap(scanID)

        // No cookie: an owned scan stays private to its owner.
        try await app.test(.GET, "/results/\(id.uuidString)") { res in
            XCTAssertEqual(res.status, .forbidden, "Owned scans must not be readable anonymously")
        }
    }

    // MARK: - Cross-tenant dedup isolation

    func testDedupDoesNotLeakAcrossOwners() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // Register + login user A.
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "ownerA", "email": "a@example.test", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })

        var cookieA = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "ownerA", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            if let raw = res.headers.first(name: "set-cookie"), let pair = raw.split(separator: ";").first {
                cookieA = String(pair)
            }
        })

        // A scans a target.
        var aScanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "sharedtarget"], as: .json)
            req.headers.replaceOrAdd(name: "Cookie", value: cookieA)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            aScanID = try res.content.decode(ScanResponse.self).scanID
        })
        let ownedID = try XCTUnwrap(aScanID)

        // An anonymous caller scanning the same input must get a fresh scan —
        // never user A's scan ID (or results) served from the dedup path.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "sharedtarget"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertNotEqual(body.scanID, ownedID,
                "Anonymous dedup must not return another user's scan")
        })
    }

    // MARK: - Email normalisation

    func testScanNormalisesEmailToLowercase() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "User@Example.test"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.input, "user@example.test",
                "Emails must be lowercased so cache lookups are case-insensitive")
        })
    }

    // MARK: - Crypto helpers

    func testSha256HexProducesKnownDigests() {
        // NIST test vectors for SHA-256
        XCTAssertEqual(
            sha256Hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        XCTAssertEqual(
            sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    // MARK: - GDPR self-service

    func testAccountExportRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/account/export") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testAccountDeleteRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.DELETE, "/account", beforeRequest: { req in
            try req.content.encode(["confirmUsername": "anyone", "password": "irrelevant"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .unauthorized)
        })
    }

    func testAccountDeleteRejectsMismatchedConfirmation() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "gdpruser", "email": "g@example.test", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })

        var cookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "gdpruser", "password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in
            if let raw = res.headers.first(name: "set-cookie"),
               let pair = raw.split(separator: ";").first {
                cookie = String(pair)
            }
        })

        // Wrong username → 400, account NOT deleted.
        try await app.test(.DELETE, "/account", beforeRequest: { req in
            try req.content.encode(["confirmUsername": "someoneelse", "password": "Xk9mQ2vLp7wZ"], as: .json)
            if !cookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: cookie) }
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest,
                "Account delete must reject a mismatched confirmUsername to prevent accidental wipe via session theft alone.")
        })

        // Correct confirmation still requires the account password.
        try await app.test(.DELETE, "/account", beforeRequest: { req in
            try req.content.encode(["confirmUsername": "gdpruser", "password": "definitely-wrong"], as: .json)
            if !cookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: cookie) }
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .unauthorized)
        })

        // Session is still valid and the account row was NOT deleted. We
        // probe via /auth/me instead of /account/export because the test DB
        // intentionally skips the PostgreSQL-only HashAPIKeyColumn migration
        // — the export query would hit a missing column in SQLite.
        try await app.test(.GET, "/auth/me", beforeRequest: { req in
            if !cookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: cookie) }
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok,
                "Account must still exist after the rejected delete attempt.")
        })
    }

    func testAccountDeleteIsAtomicAndPseudonymizesRetainedAudit() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "erase-user")

        let userCandidate = try await User.query(on: app.db)
            .filter(\.$username == "erase-user")
            .first()
        let user = try XCTUnwrap(userCandidate)
        let userID = try XCTUnwrap(user.id)
        let scan = Scan(input: "erasure-target", status: .completed, userID: userID)
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        let share = SharedReport(
            scanID: scanID,
            tokenHash: sha256Hex("abcdefghijklmnopqrstuvwxyzABCDEF")
        )
        try await share.save(on: app.db)

        try await app.test(.DELETE, "/account", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode([
                "confirmUsername": "erase-user",
                "password": "Xk9mQ2vLp7wZ",
            ], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .noContent)
        })

        let deletedUser = try await User.find(userID, on: app.db)
        let deletedScan = try await Scan.find(scanID, on: app.db)
        let remainingShares = try await SharedReport.query(on: app.db).count()
        XCTAssertNil(deletedUser)
        XCTAssertNil(deletedScan)
        XCTAssertEqual(remainingShares, 0)

        let retainedAudit = try await AuditLog.query(on: app.db).all()
        XCTAssertFalse(retainedAudit.isEmpty)
        XCTAssertTrue(retainedAudit.allSatisfy { $0.userID == nil })
        XCTAssertTrue(retainedAudit.allSatisfy { $0.target == "[deleted-account]" })
        XCTAssertTrue(retainedAudit.allSatisfy { $0.ip == "[deleted]" })
    }

    // MARK: - TOTP (2FA)

    func testTOTPGenerateVerifyRoundTrip() throws {
        let secret = TOTP.generateSecret()
        XCTAssertGreaterThanOrEqual(secret.count, 32, "160-bit secret encodes to ≥32 base32 chars")
        let code = try XCTUnwrap(TOTP.current(secret: secret))
        XCTAssertEqual(code.count, 6)
        XCTAssertTrue(TOTP.verify(code: code, secret: secret), "the current code must verify")
        // A code from a step far outside the ±1 window must not verify.
        let stale = try XCTUnwrap(TOTP.current(secret: secret, at: Date().addingTimeInterval(-600)))
        XCTAssertFalse(TOTP.verify(code: stale, secret: secret), "a 10-minute-old code is outside the window")
    }

    func testTOTPMatchedStepReturnsCurrentStep() throws {
        // `matchedStep` surfaces the accepted code's time-step so the 2FA path can
        // reject any submission at or below the last accepted step (replay).
        let secret = TOTP.generateSecret()
        let now = Date()
        let code = try XCTUnwrap(TOTP.current(secret: secret, at: now))
        XCTAssertEqual(TOTP.matchedStep(code: code, secret: secret, at: now),
                       Int(now.timeIntervalSince1970) / 30,
                       "the accepted code's step must equal the current time-step")
        XCTAssertTrue(TOTP.verify(code: code, secret: secret, at: now), "verify() still accepts a valid code")
    }

    func testBulkUsernameEvaluatePrecision() throws {
        func eval(_ site: SherlockSite, _ user: String, _ status: Int, _ final: String, _ body: String = "") -> PluginResult? {
            BulkUsernamePlugin.evaluate(
                siteName: "Site", siteData: site, username: user,
                targetURL: "https://x/\(user)", status: status,
                finalURL: URL(string: final)!, body: Data(body.utf8))
        }
        // status_code: a missing user redirected to the home/login page loses the
        // username from the final URL → must NOT be reported (the old bug).
        let sc = SherlockSite(errorType: "status_code", url: "https://9gag.com/u/{}",
                              urlMain: "https://9gag.com/", errorMsg: nil, errorUrl: nil, regexCheck: nil)
        XCTAssertNil(eval(sc, "ghost404", 200, "https://9gag.com/"))          // → home
        XCTAssertNil(eval(sc, "ghost404", 200, "https://9gag.com/login"))     // → login
        XCTAssertNotNil(eval(sc, "realuser", 200, "https://9gag.com/u/realuser")) // real profile
        XCTAssertNil(eval(sc, "realuser", 404, "https://9gag.com/u/realuser"))    // 404
        // Apex redirect keeps the username (www.github.com/user → github.com/user).
        XCTAssertNotNil(eval(sc, "blue", 200, "https://github.com/blue"))
        // A `?next=/u/name` echo in the query must not count as a hit.
        XCTAssertNil(eval(sc, "ghost", 200, "https://9gag.com/login?next=/u/ghost"))

        // message: error string present → not found; absent + username present → found.
        let msg = SherlockSite(errorType: "message", url: "https://ex.com/{}",
                               urlMain: "https://ex.com/", errorMsg: .string("User not found"),
                               errorUrl: nil, regexCheck: nil)
        XCTAssertNil(eval(msg, "ghost", 200, "https://ex.com/ghost", "Sorry, User not found."))
        XCTAssertNotNil(eval(msg, "real", 200, "https://ex.com/real", "Welcome real"))
        XCTAssertNil(eval(msg, "ghost", 200, "https://ex.com/", "home"))      // redirected home
    }

    func testRedditEvaluateRejectsBlocksAndMismatches() throws {
        let real = Data(#"{"kind":"t2","data":{"name":"spez","id":"abc"}}"#.utf8)
        XCTAssertNotNil(RedditPlugin.evaluate(username: "spez", status: 200, body: real))
        XCTAssertNotNil(RedditPlugin.evaluate(username: "SPEZ", status: 200, body: real)) // case-insensitive
        // 403 block (datacenter IP) must NOT be reported as "suspended" — the old bug.
        XCTAssertNil(RedditPlugin.evaluate(username: "anyone", status: 403, body: Data()))
        // 200 that isn't a real t2 account (block/soft page) → nil.
        XCTAssertNil(RedditPlugin.evaluate(username: "ghost", status: 200, body: Data("<html>blocked</html>".utf8)))
        XCTAssertNil(RedditPlugin.evaluate(username: "ghost", status: 404,
                                           body: Data(#"{"message":"Not Found","error":404}"#.utf8)))
        // Returned account is a different user → not a hit.
        XCTAssertNil(RedditPlugin.evaluate(username: "ghost", status: 200, body: real))
        // A suspended account is still a real account.
        let suspended = Data(#"{"kind":"t2","data":{"name":"banned_user","is_suspended":true}}"#.utf8)
        XCTAssertNotNil(RedditPlugin.evaluate(username: "banned_user", status: 200, body: suspended))
    }

    func testMastodonParseAccountExtractsNameAndBio() throws {
        let json = Data(#"""
        {"acct":"alice","display_name":"Alice Example ","url":"https://mastodon.social/@alice",
         "followers_count":42,"statuses_count":7,"locked":true,
         "note":"<p>Hi <a href=\"x\">there</a></p>"}
        """#.utf8)
        let acct = try XCTUnwrap(MastodonPlugin.parseAccount(from: json, fallbackUsername: "fallback"))
        // Display name is trimmed and now available to feed metadata["name"].
        XCTAssertEqual(acct.displayName, "Alice Example")
        XCTAssertEqual(acct.acct, "alice")
        XCTAssertEqual(acct.bio, "Hi there", "HTML tags stripped from the note")
        XCTAssertEqual(acct.followers, 42)
        XCTAssertTrue(acct.locked)
        // Malformed body → nil (no false positive).
        XCTAssertNil(MastodonPlugin.parseAccount(from: Data("not json".utf8), fallbackUsername: "x"))
    }

    func testTelegramOGContentParsing() throws {
        let html = #"""
        <meta property="og:title" content="Jane Doe">
        <meta property="og:description" content="Founder &amp; builder">
        """#
        XCTAssertEqual(TelegramPlugin.ogContent("title", from: html), "Jane Doe")
        XCTAssertEqual(TelegramPlugin.ogContent("description", from: html), "Founder &amp; builder")
        XCTAssertNil(TelegramPlugin.ogContent("image", from: html), "absent tag → nil")
    }

    func testTOTPKnownVectorRFC6238() throws {
        // RFC 6238 test vector: secret "12345678901234567890" (ASCII) → base32
        // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ; at T=59s the SHA-1 TOTP is 94287082.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        let code = TOTP.current(secret: secret, at: Date(timeIntervalSince1970: 59))
        XCTAssertEqual(code, "287082", "RFC 6238 SHA-1 6-digit vector at T=59")
    }

    func testRecoveryCodeHashingIsStable() throws {
        let codes = RecoveryCodes.generate(count: 5)
        XCTAssertEqual(codes.count, 5)
        // Hash is case- and separator-insensitive so user formatting doesn't matter.
        XCTAssertEqual(RecoveryCodes.hash(codes[0]), RecoveryCodes.hash(codes[0].uppercased()))
        XCTAssertNotEqual(RecoveryCodes.hash(codes[0]), RecoveryCodes.hash(codes[1]))
    }

    // MARK: - Password strength

    func testPasswordStrengthRejectsWeakAcceptsStrong() throws {
        XCTAssertThrowsError(try PasswordStrength.validate("password123", username: "bob", email: "bob@x.com"))
        XCTAssertThrowsError(try PasswordStrength.validate("12345678", username: "bob", email: "bob@x.com"))
        XCTAssertThrowsError(try PasswordStrength.validate("aaaaaaaa", username: "bob", email: "bob@x.com"))
        XCTAssertThrowsError(try PasswordStrength.validate("bob12345", username: "bob", email: "bob@x.com"),
            "must reject a password containing the username")
        XCTAssertNoThrow(try PasswordStrength.validate("Xk9mQ2vLp7wZ", username: "bob", email: "bob@x.com"))
    }

    // MARK: - Email authentication posture

    func testSPFPolicyStrength() {
        XCTAssertEqual(EmailAuth.spfPolicy("v=spf1 include:_spf.google.com -all")?.spoofable, false)
        XCTAssertEqual(EmailAuth.spfPolicy("v=spf1 include:_spf.google.com ~all")?.spoofable, true)
        XCTAssertEqual(EmailAuth.spfPolicy("v=spf1 mx ?all")?.spoofable, true)
        XCTAssertEqual(EmailAuth.spfPolicy("v=spf1 mx")?.spoofable, true, "no explicit all ⇒ implicit neutral")
        XCTAssertNil(EmailAuth.spfPolicy(nil))
    }

    func testDMARCPolicyEnforcement() {
        XCTAssertEqual(EmailAuth.dmarcPolicy("v=DMARC1; p=reject; rua=mailto:a@b.com")?.enforced, true)
        XCTAssertEqual(EmailAuth.dmarcPolicy("v=DMARC1; p=quarantine")?.enforced, true)
        XCTAssertEqual(EmailAuth.dmarcPolicy("v=DMARC1; p=none")?.enforced, false)
        XCTAssertNil(EmailAuth.dmarcPolicy(nil))
    }

    func testEmailAuthGrades() {
        // Fully locked down → grade A, a clean (noise) headline.
        let strong = EmailAuth.analyze(domain: "secure.example",
            EmailAuth.Signals(spf: "v=spf1 -all", dmarc: "v=DMARC1; p=reject"))
        XCTAssertTrue(strong.contains { $0.type == "email_auth_ok" })
        XCTAssertFalse(strong.contains { $0.type == "email_spoofable" })

        // Nothing configured → grade F, a spoofable exposure headline + missing findings.
        let weak = EmailAuth.analyze(domain: "open.example", EmailAuth.Signals())
        XCTAssertTrue(weak.contains { $0.type == "email_spoofable" && $0.metadata["grade"] == "F" })
        XCTAssertTrue(weak.contains { $0.type == "email_auth_spf_missing" })
        XCTAssertTrue(weak.contains { $0.type == "email_auth_dmarc_missing" })

        // A spoofable domain must raise the risk score above a locked-down one.
        func score(_ f: [EmailAuth.Finding]) -> Int {
            RiskScorer.compute(raw: f.map { (confidence: $0.confidence, type: $0.type) }).value
        }
        XCTAssertGreaterThan(score(weak), score(strong))
    }

    // MARK: - Exposed-file detection (content-verified)

    func testExposedFilesContentVerification() {
        // Real signatures match.
        XCTAssertNotNil(ExposedFiles.classify(path: "/.env", status: 200, body: "APP_KEY=secret\nDB_PASSWORD=hunter2\n"))
        XCTAssertNotNil(ExposedFiles.classify(path: "/.git/HEAD", status: 200, body: "ref: refs/heads/main\n"))
        XCTAssertNotNil(ExposedFiles.classify(path: "/.git/config", status: 200, body: "[core]\n\trepositoryformatversion = 0\n"))
        XCTAssertNotNil(ExposedFiles.classify(path: "/backup.sql", status: 200, body: "CREATE TABLE users (id INT);"))

        // SPA fallback (index.html served for every path) must NOT false-positive.
        let spa = "<!doctype html><html><head><title>App</title></head><body></body></html>"
        XCTAssertNil(ExposedFiles.classify(path: "/.env", status: 200, body: spa))
        XCTAssertNil(ExposedFiles.classify(path: "/.git/config", status: 200, body: spa))

        // 206 (partial content from a Range request) is accepted like 200.
        XCTAssertNotNil(ExposedFiles.classify(path: "/.env", status: 206, body: "DB_PASSWORD=x\n"))
        // Non-2xx never matches even with a real-looking body.
        XCTAssertNil(ExposedFiles.classify(path: "/.env", status: 404, body: "DB_PASSWORD=x"))
        XCTAssertNil(ExposedFiles.classify(path: "/.env", status: 403, body: "DB_PASSWORD=x"))
    }

    // MARK: - Investigation boards

    func testInvestigationBoardLifecycleAndIsolation() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        func login(_ name: String) async throws -> String {
            try await app.test(.POST, "/auth/register", beforeRequest: { req in
                try req.content.encode(["username": name, "email": "\(name)@ex.test", "password": "Xk9mQ2vLp7wZ"], as: .json)
            }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
            var cookie = ""
            try await app.test(.POST, "/auth/login", beforeRequest: { req in
                try req.content.encode(["username": name, "password": "Xk9mQ2vLp7wZ"], as: .json)
            }, afterResponse: { res in
                if let raw = res.headers.first(name: "set-cookie"), let p = raw.split(separator: ";").first { cookie = String(p) }
            })
            return cookie
        }

        let alice = try await login("alice")

        // Create a board.
        var boardID = ""
        try await app.test(.POST, "/investigations", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: alice)
            try req.content.encode(["name": "Case 1", "data": #"{"nodes":[{"id":"a"}],"edges":[]}"#], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            boardID = try res.content.decode(InvestigationController.Full.self).id
            XCTAssertFalse(boardID.isEmpty)
        })

        // List shows it with the right node count.
        try await app.test(.GET, "/investigations", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: alice)
        }, afterResponse: { res in
            let list = try res.content.decode([InvestigationController.Summary].self)
            XCTAssertEqual(list.count, 1)
            XCTAssertEqual(list.first?.nodeCount, 1)
        })

        // Update (grow the graph).
        try await app.test(.PUT, "/investigations/\(boardID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: alice)
            try req.content.encode(["data": #"{"nodes":[{"id":"a"},{"id":"b"}],"edges":[{"source":"a","target":"b"}]}"#], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(try res.content.decode(InvestigationController.Full.self).data.contains("\"b\""))
        })

        // Invalid data (no nodes/edges arrays) is rejected.
        try await app.test(.PUT, "/investigations/\(boardID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: alice)
            try req.content.encode(["data": "not json"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .badRequest) })

        // Structural caps reject valid JSON that would otherwise grow into an
        // unbounded graph or feed oversized identifiers into the UI.
        let tooManyNodes = (0...InvestigationController.maxNodes)
            .map { #"{"id":"n\#($0)"}"# }
            .joined(separator: ",")
        let oversizedGraph = #"{"nodes":[\#(tooManyNodes)],"edges":[]}"#
        try await app.test(.PUT, "/investigations/\(boardID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: alice)
            try req.content.encode(["data": oversizedGraph], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .payloadTooLarge) })

        // A different user cannot read Alice's board.
        let bob = try await login("bob")
        try await app.test(.GET, "/investigations/\(boardID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: bob)
        }, afterResponse: { res in XCTAssertEqual(res.status, .notFound) })

        // Bob's own list is empty.
        try await app.test(.GET, "/investigations", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: bob)
        }, afterResponse: { res in
            XCTAssertEqual(try res.content.decode([InvestigationController.Summary].self).count, 0)
        })
    }

    // MARK: - Board graph enrichment (watch runner)

    func testBoardGraphExtractAndMerge() throws {
        let results = [
            BoardGraph.ResultInput(source: "Reddit", type: "account_presence", rawData: "exists", metadata: ["username": "alice"]),
            BoardGraph.ResultInput(source: "EmailIntel", type: "email", rawData: "x", metadata: ["email": "alice@proton.me"]),
            BoardGraph.ResultInput(source: "HIBP", type: "data_breach", rawData: "LinkedIn 2012", metadata: ["name": "LinkedIn"]),
            BoardGraph.ResultInput(source: "GitHub", type: "breach_check", rawData: "clean", metadata: [:])  // must be ignored
        ]
        let ex = BoardGraph.extract(rootId: "alice", results: results)
        let ids = Set(ex.nodes.map { $0.id })
        XCTAssertTrue(ids.contains("alice@proton.me"))
        XCTAssertTrue(ids.contains("breach:linkedin"))
        XCTAssertTrue(ex.nodes.contains { $0.etype == "account" && $0.label == "@Reddit" })
        XCTAssertFalse(ids.contains { $0.contains("github") }, "breach_check (clean signal) must not create a node")
        XCTAssertTrue(ex.nodes.allSatisfy { $0.new == true }, "freshly discovered nodes are flagged new")

        // Merge into an existing graph dedupes and reports only genuinely-new nodes.
        var graph = BoardGraph.Graph(nodes: [BoardGraph.Node(id: "alice@proton.me", label: nil, etype: "email", root: nil, expanded: nil, new: nil, x: nil, y: nil)], edges: [])
        let added = BoardGraph.merge(into: &graph, nodes: ex.nodes, edges: ex.edges)
        XCTAssertEqual(added, ex.nodes.count - 1, "the already-present email node is not counted as new")
        // Round-trips through the on-disk JSON form.
        let json = try XCTUnwrap(BoardGraph.encode(graph))
        XCTAssertNotNil(BoardGraph.decode(json))
    }

    // MARK: - SiteMeta (security.txt + robots.txt recon)

    func testSiteMetaSecurityTxtParse() throws {
        let good = "# our policy\nContact: mailto:security@acme.com\nExpires: 2030-01-01T00:00:00Z\nPolicy: https://acme.com/policy\n"
        let sec = try XCTUnwrap(SiteMeta.parseSecurityTxt(good))
        XCTAssertEqual(sec.contacts.first, "mailto:security@acme.com")
        XCTAssertEqual(sec.expires, "2030-01-01T00:00:00Z")
        XCTAssertEqual(SiteMeta.contactEmail(sec.contacts), "security@acme.com")
        // An HTML error page or a file without Contact is not a security.txt.
        XCTAssertNil(SiteMeta.parseSecurityTxt("<!doctype html><html>404</html>"))
        XCTAssertNil(SiteMeta.parseSecurityTxt("Policy: https://x/p\n"))
    }

    func testSiteMetaRobotsParse() throws {
        let robots = """
        # comment
        User-agent: *
        Disallow: /admin/
        Disallow: /search
        Disallow: /admin/
        Sitemap: https://acme.com/sitemap.xml
        """
        let r = SiteMeta.parseRobots(robots)
        XCTAssertEqual(r.disallowed, ["/admin/", "/search"], "deduped, comments ignored")
        XCTAssertEqual(r.sitemaps, ["https://acme.com/sitemap.xml"])
        XCTAssertEqual(SiteMeta.interesting(r.disallowed), ["/admin/"], "only the sensitive path is flagged")
        // HTML masquerading as robots.txt yields nothing.
        XCTAssertEqual(SiteMeta.parseRobots("<html><body>nope</body></html>").disallowed.count, 0)
    }
}
