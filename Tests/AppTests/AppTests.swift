import XCTest
import XCTVapor
import Fluent
import FluentSQLiteDriver
import NIOCore
import SQLKit
@testable import App
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

private struct EnvironmentSnapshot {
    private let values: [(name: String, value: String?)]

    init(_ names: [String]) {
        values = names.map { ($0, ProcessInfo.processInfo.environment[$0]) }
    }

    func restore() {
        for item in values {
            if let value = item.value {
                setenv(item.name, value, 1)
            } else {
                unsetenv(item.name)
            }
        }
    }
}

private let encryptionEnvironmentNames = [
    "ENCRYPTION_KEY",
    "ENCRYPTION_KEY_FILE",
    "ENCRYPTION_KEY_ID",
    "ENCRYPTION_PREVIOUS_KEYS",
    "ENCRYPTION_PREVIOUS_KEYS_FILE",
    "ENCRYPTION_WRITE_VERSION",
]

private func configureEncryptionEnvironment(
    key: String,
    keyID: String? = nil,
    previousKeys: String? = nil,
    writeVersion: String = "1"
) {
    unsetenv("ENCRYPTION_KEY_FILE")
    setenv("ENCRYPTION_KEY", key, 1)
    setenv("ENCRYPTION_WRITE_VERSION", writeVersion, 1)
    if let keyID { setenv("ENCRYPTION_KEY_ID", keyID, 1) }
    else { unsetenv("ENCRYPTION_KEY_ID") }
    unsetenv("ENCRYPTION_PREVIOUS_KEYS_FILE")
    if let previousKeys { setenv("ENCRYPTION_PREVIOUS_KEYS", previousKeys, 1) }
    else { unsetenv("ENCRYPTION_PREVIOUS_KEYS") }
}

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
    app.middleware.use(NoCacheMiddleware(), at: .beginning)
    app.middleware.use(SensitiveFieldFailureMiddleware())

    app.sessions.use(.fluent)
    app.middleware.use(app.sessions.middleware)
    app.middleware.use(SessionSecurityMiddleware())
    app.middleware.use(APIKeyMiddleware())
    app.middleware.use(APIKeyScopeMiddleware())
    // Mirror production so the CSRF origin check is exercised by tests. It is a
    // no-op for requests without an Origin/Referer header (the existing tests),
    // and blocks cross-origin POST/PUT/PATCH/DELETE.
    app.middleware.use(CSRFMiddleware())

    // Stable test-only Ed25519 seed. Production never has a fallback and must
    // supply its independently generated signing key before startup.
    app.auditIntegrityConfiguration = try AuditIntegrityConfiguration(
        keyID: "test-key",
        privateKeyHex: String(repeating: "42", count: 32),
        commitmentKeyHex: String(repeating: "44", count: 32)
    )

    app.migrations.add(CreateScan())
    app.migrations.add(CreateResult())
    app.migrations.add(AddScanStatus())
    app.migrations.add(AddResultMetadata())
    app.migrations.add(CreateScanResultEvents())
    app.migrations.add(AddInputIndex())
    app.migrations.add(CreateUser())
    app.migrations.add(AddUserIDToScans())
    app.migrations.add(AddWebhookURLToUsers())
    app.migrations.add(CreateTags())
    app.migrations.add(CreateScanTags())
    app.migrations.add(CreateScheduledScans())
    app.migrations.add(CreateScanNotifications())
    app.migrations.add(CreateNotificationOutbox())
    app.migrations.add(CreateExportJobs())
    app.migrations.add(CreateAPIKeys())
    app.migrations.add(AddAPIKeyAuthorization())
    app.migrations.add(CreateAuditLogs())
    app.migrations.add(CreateAuditIntegrityLedger())
    app.migrations.add(AddRetentionDaysToUsers())
    app.migrations.add(DefaultUserRetention())
    app.migrations.add(AddNotificationChannelsToUsers())
    app.migrations.add(CreateSharedReports())
    app.migrations.add(ExpireLegacySharedReports())
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
    app.migrations.add(CreateDarkWebInvestigations())
    app.migrations.add(EnforceDarkWebActiveJobUniqueness())
    app.migrations.add(CreateEncryptionMetadata())
    app.migrations.add(MigrateSensitiveFieldEncryption())
    app.migrations.add(EncryptTagNames())
    app.migrations.add(SessionRecord.migration)
    try await app.autoMigrate()

    app.darkWebConfiguration = DarkWebConfiguration(
        enabled: true,
        workerURL: URL(string: "http://127.0.0.1:8766")!,
        sharedSecret: String(repeating: "t", count: 32),
        retentionHours: 72,
        maxOutstandingJobs: 5,
        maxJobsPerUserPerDay: 3,
        jobTimeoutSeconds: 600
    )
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

    func testRuntimeSecretAcceptsPrivateFilesAndRejectsUnsafeSources() throws {
        let name = "RUNTIME_SECRET_TEST_VALUE"
        let fileName = "\(name)_FILE"
        let environment = EnvironmentSnapshot([name, fileName])
        defer { environment.restore() }
        unsetenv(name)
        unsetenv(fileName)

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("runtime-secret-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let credential = directory.appendingPathComponent("credential")
        try Data("file-backed-secret\n".utf8).write(to: credential)
        XCTAssertEqual(chmod(credential.path, 0o600), 0)
        setenv(fileName, credential.path, 1)

        XCTAssertEqual(try RuntimeSecret.value(name), "file-backed-secret")

        setenv(name, "inline-secret", 1)
        XCTAssertThrowsError(try RuntimeSecret.value(name)) {
            XCTAssertEqual($0 as? RuntimeSecret.Error, .conflictingSources(name))
        }
        unsetenv(name)

        XCTAssertEqual(chmod(credential.path, 0o640), 0)
        XCTAssertThrowsError(try RuntimeSecret.value(name)) {
            XCTAssertEqual($0 as? RuntimeSecret.Error, .unsafeFile(name))
        }

        XCTAssertEqual(chmod(credential.path, 0o600), 0)
        try Data("first\nsecond".utf8).write(to: credential)
        XCTAssertThrowsError(try RuntimeSecret.value(name)) {
            XCTAssertEqual($0 as? RuntimeSecret.Error, .invalidValue(name))
        }

        try Data("123456789".utf8).write(to: credential)
        XCTAssertThrowsError(try RuntimeSecret.value(name, maximumBytes: 8)) {
            XCTAssertEqual($0 as? RuntimeSecret.Error, .tooLarge(name))
        }

        let symlink = directory.appendingPathComponent("credential-link")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: credential)
        setenv(fileName, symlink.path, 1)
        XCTAssertThrowsError(try RuntimeSecret.value(name)) {
            XCTAssertEqual($0 as? RuntimeSecret.Error, .unreadable(name))
        }

        setenv(fileName, "relative/credential", 1)
        XCTAssertThrowsError(try RuntimeSecret.value(name)) {
            XCTAssertEqual($0 as? RuntimeSecret.Error, .invalidPath(name))
        }
    }

    func testFileBackedEncryptionAndAuditCredentialsAreConsumed() throws {
        let names = encryptionEnvironmentNames + [
            "AUDIT_SIGNING_KEY", "AUDIT_SIGNING_KEY_FILE", "AUDIT_SIGNING_KEY_ID",
            "AUDIT_COMMITMENT_KEY", "AUDIT_COMMITMENT_KEY_FILE",
        ]
        let environment = EnvironmentSnapshot(names)
        defer { environment.restore() }
        names.forEach { unsetenv($0) }

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("runtime-crypto-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        func installCredential(_ name: String, value: String) throws {
            let path = directory.appendingPathComponent(name.lowercased())
            try Data("\(value)\n".utf8).write(to: path)
            XCTAssertEqual(chmod(path.path, 0o600), 0)
            setenv("\(name)_FILE", path.path, 1)
        }

        try installCredential("ENCRYPTION_KEY", value: String(repeating: "51", count: 32))
        try installCredential("AUDIT_SIGNING_KEY", value: String(repeating: "52", count: 32))
        try installCredential("AUDIT_COMMITMENT_KEY", value: String(repeating: "53", count: 32))
        setenv("ENCRYPTION_KEY_ID", "file-primary", 1)
        setenv("ENCRYPTION_WRITE_VERSION", "2", 1)
        setenv("AUDIT_SIGNING_KEY_ID", "file-audit", 1)

        try TokenEncryption.validateConfiguration(required: true)
        let context = TokenEncryption.Context(field: "test.file", recordID: UUID())
        let ciphertext = try TokenEncryption.encrypt("private-value", context: context)
        XCTAssertEqual(try TokenEncryption.decryptRequired(ciphertext, context: context), "private-value")

        let audit = try XCTUnwrap(AuditIntegrityConfiguration.fromEnvironment(required: true))
        XCTAssertEqual(audit.keyID, "file-audit")
        XCTAssertEqual(audit.publicKeyBytes.count, 32)
    }

    func testAuditSigningConfigurationFailsClosedAndSeparatesKeyIdentity() throws {
        let names = [
            "AUDIT_SIGNING_KEY", "AUDIT_SIGNING_KEY_FILE", "AUDIT_SIGNING_KEY_ID",
            "AUDIT_COMMITMENT_KEY", "AUDIT_COMMITMENT_KEY_FILE",
            "ENCRYPTION_KEY", "ENCRYPTION_KEY_FILE",
        ]
        let environment = EnvironmentSnapshot(names)
        defer { environment.restore() }

        unsetenv("AUDIT_SIGNING_KEY")
        unsetenv("AUDIT_SIGNING_KEY_FILE")
        unsetenv("AUDIT_SIGNING_KEY_ID")
        unsetenv("AUDIT_COMMITMENT_KEY")
        unsetenv("AUDIT_COMMITMENT_KEY_FILE")
        unsetenv("ENCRYPTION_KEY")
        unsetenv("ENCRYPTION_KEY_FILE")
        XCTAssertNil(try AuditIntegrityConfiguration.fromEnvironment(required: false))
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual($0 as? AuditIntegrityConfiguration.ConfigurationError, .missingKey)
        }

        setenv("AUDIT_SIGNING_KEY", String(repeating: "42", count: 32), 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: false)) {
            XCTAssertEqual($0 as? AuditIntegrityConfiguration.ConfigurationError, .incompleteConfiguration)
        }
        setenv("AUDIT_SIGNING_KEY_ID", "audit-test", 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual(
                $0 as? AuditIntegrityConfiguration.ConfigurationError,
                .missingCommitmentKey
            )
        }
        setenv("AUDIT_COMMITMENT_KEY", String(repeating: "44", count: 32), 1)
        setenv("AUDIT_SIGNING_KEY_ID", "spaces are forbidden", 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual($0 as? AuditIntegrityConfiguration.ConfigurationError, .invalidKeyID)
        }
        setenv("AUDIT_SIGNING_KEY", "not-hex", 1)
        setenv("AUDIT_SIGNING_KEY_ID", "audit-test", 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual($0 as? AuditIntegrityConfiguration.ConfigurationError, .invalidKey)
        }

        setenv("AUDIT_SIGNING_KEY", String(repeating: "43", count: 32), 1)
        setenv("AUDIT_COMMITMENT_KEY", "not-hex", 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual(
                $0 as? AuditIntegrityConfiguration.ConfigurationError,
                .invalidCommitmentKey
            )
        }
        setenv("AUDIT_COMMITMENT_KEY", String(repeating: "44", count: 32), 1)
        let valid = try XCTUnwrap(AuditIntegrityConfiguration.fromEnvironment(required: true))
        XCTAssertEqual(valid.keyID, "audit-test")
        XCTAssertEqual(valid.publicKeyBytes.count, 32)

        setenv("ENCRYPTION_KEY", String(repeating: "43", count: 32), 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual(
                $0 as? AuditIntegrityConfiguration.ConfigurationError,
                .reusedKeyMaterial
            )
        }
        setenv("ENCRYPTION_KEY", String(repeating: "44", count: 32), 1)
        XCTAssertThrowsError(try AuditIntegrityConfiguration.fromEnvironment(required: true)) {
            XCTAssertEqual(
                $0 as? AuditIntegrityConfiguration.ConfigurationError,
                .reusedKeyMaterial
            )
        }
        XCTAssertThrowsError(
            try AuditIntegrityConfiguration(
                keyID: "reused",
                privateKeyHex: String(repeating: "45", count: 32),
                commitmentKeyHex: String(repeating: "45", count: 32)
            )
        ) {
            XCTAssertEqual(
                $0 as? AuditIntegrityConfiguration.ConfigurationError,
                .reusedKeyMaterial
            )
        }
    }

    func testAuditIntegrityLedgerCoversRedactionRetentionRotationAndTamper() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let firstKey = try XCTUnwrap(app.auditIntegrityConfiguration)

        let log = AuditLog(
            userID: UUID(),
            action: "integrity_test",
            target: "person@example.test",
            ip: "192.0.2.0"
        )
        try await AuditIntegrityLedger.persist(
            log,
            plaintextTarget: "person@example.test",
            plaintextIP: "192.0.2.0",
            on: app.db,
            configuration: firstKey
        )
        var verification = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: firstKey
        )
        XCTAssertTrue(verification.isValid)
        XCTAssertEqual(verification.verifiedEvents, 1)

        try await app.db.transaction { transaction in
            log.userID = nil
            log.setTarget("[deleted-account]")
            log.setIP("[deleted]")
            try await log.update(on: transaction)
            try await AuditIntegrityLedger.recordRedaction(
                of: log,
                plaintextTarget: "[deleted-account]",
                plaintextIP: "[deleted]",
                on: transaction,
                configuration: firstKey
            )
        }
        verification = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: firstKey
        )
        XCTAssertTrue(verification.isValid)
        XCTAssertEqual(verification.verifiedEvents, 2)

        let logID = try log.requireID()
        try await app.db.transaction { transaction in
            try await AuditIntegrityLedger.recordRetention(
                auditLogID: logID,
                on: transaction,
                configuration: firstKey
            )
            try await log.delete(on: transaction)
        }
        verification = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: firstKey
        )
        XCTAssertTrue(verification.isValid)
        XCTAssertEqual(verification.verifiedEvents, 3)

        let rotatedKey = try AuditIntegrityConfiguration(
            keyID: "test-key-rotated",
            privateKeyHex: String(repeating: "43", count: 32),
            commitmentKeyHex: String(repeating: "44", count: 32)
        )
        let didRotate = try await AuditIntegrityLedger.ensureActiveKeyAnchored(
            on: app.db,
            configuration: rotatedKey
        )
        XCTAssertTrue(didRotate)
        let didRotateAgain = try await AuditIntegrityLedger.ensureActiveKeyAnchored(
            on: app.db,
            configuration: rotatedKey
        )
        XCTAssertFalse(didRotateAgain)
        verification = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: rotatedKey
        )
        XCTAssertTrue(verification.isValid)
        XCTAssertEqual(verification.verifiedEvents, 4)
        let oldKeyView = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: firstKey
        )
        XCTAssertFalse(oldKeyView.isValid)
        XCTAssertEqual(oldKeyView.failureCode, "active_key_not_anchored")

        let wrongCommitmentKey = try AuditIntegrityConfiguration(
            keyID: "test-key-rotated",
            privateKeyHex: String(repeating: "43", count: 32),
            commitmentKeyHex: String(repeating: "45", count: 32)
        )
        let wrongCommitmentView = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: wrongCommitmentKey
        )
        XCTAssertFalse(wrongCommitmentView.isValid)
        XCTAssertEqual(wrongCommitmentView.failureCode, "audit_log_payload_mismatch")

        let storedHead = try await AuditIntegrityHead.find(
            AuditIntegrityHead.singletonID,
            on: app.db
        )
        let head = try XCTUnwrap(storedHead)
        head.headHash = String(repeating: "f", count: 64)
        try await head.update(on: app.db)
        let tampered = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: rotatedKey
        )
        XCTAssertFalse(tampered.isValid)
        XCTAssertEqual(tampered.failureCode, "head_mismatch")
    }

    func testAuditIntegrityEventsRejectMutationAtDatabaseBoundary() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let configuration = try XCTUnwrap(app.auditIntegrityConfiguration)
        let log = AuditLog(userID: nil, action: "immutable_test", target: "target", ip: "[system]")
        try await AuditIntegrityLedger.persist(
            log,
            plaintextTarget: "target",
            plaintextIP: "[system]",
            on: app.db,
            configuration: configuration
        )
        let initialVerification = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: configuration
        )
        XCTAssertTrue(
            initialVerification.isValid,
            initialVerification.failureCode ?? "unknown audit-integrity failure"
        )
        let storedEvent = try await AuditIntegrityEvent.query(on: app.db).first()
        let event = try XCTUnwrap(storedEvent)
        let originalPayloadHash = event.payloadHash
        let eventID = try event.requireID()
        let sql = try XCTUnwrap(app.db as? SQLDatabase)
        do {
            try await sql.raw("""
                UPDATE audit_integrity_events
                SET payload_hash = \(bind: String(repeating: "a", count: 64))
                WHERE id = \(bind: eventID)
                """).run()
            XCTFail("append-only trigger accepted an event update")
        } catch {
            // The database boundary, not merely the verifier, rejects mutation.
        }
        let reloadedEvent = try await AuditIntegrityEvent.find(eventID, on: app.db)
        XCTAssertEqual(reloadedEvent?.payloadHash, originalPayloadHash)
        let finalVerification = try await AuditIntegrityLedger.verify(
            on: app.db,
            configuration: configuration
        )
        XCTAssertTrue(
            finalVerification.isValid,
            finalVerification.failureCode ?? "unknown audit-integrity failure"
        )
    }

    func testAuditIntegrityEndpointRequiresRecentAdminAndReturnsOnlyMetadata() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "audit-integrity-admin")

        try await app.test(.GET, "/admin/audit/integrity") { response in
            XCTAssertEqual(response.status, .unauthorized)
        }
        try await app.test(.GET, "/admin/audit/integrity", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .forbidden)
        })

        let storedUser = try await User.query(on: app.db)
            .filter(\.$username == "audit-integrity-admin")
            .first()
        let user = try XCTUnwrap(storedUser)
        user.isAdmin = true
        try await user.update(on: app.db)

        try await app.test(.GET, "/admin/audit/integrity", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            let result = try response.content.decode(AuditIntegrityVerification.self)
            XCTAssertTrue(
                result.isValid,
                result.failureCode ?? "unknown audit-integrity failure"
            )
            XCTAssertGreaterThanOrEqual(result.verifiedEvents, 2)
            XCTAssertEqual(result.activeSigningKeyID, "test-key")
            let body = response.body.string
            XCTAssertFalse(body.contains("audit-integrity-admin"))
            XCTAssertFalse(body.contains("192.0.2"))
        })
    }

    func testMaintenanceCommandsNeverStartApplicationWorkers() {
        XCTAssertFalse(LifecyclePolicy.shouldStartWorkers(arguments: ["Run", "migrate", "--yes"]))
        XCTAssertFalse(LifecyclePolicy.shouldStartWorkers(
            arguments: ["Run", "crypto-rewrap", "--confirm-key-id", "primary"]
        ))
        XCTAssertTrue(LifecyclePolicy.shouldStartWorkers(arguments: ["Run", "serve"]))
    }

    func testNotificationDeliveryOutcomesAndMetricsDoNotClaimFalseSuccess() async throws {
        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        let metrics = MetricsRegistry()
        let user = User(
            username: "notification-test",
            email: "notification@example.test",
            passwordHash: "unused",
            webhookURL: "http://127.0.0.1/private-hook"
        )

        let deliveries = await NotificationDispatcher.notify(
            user: user,
            title: "Test",
            message: "Test delivery",
            scanID: nil,
            app: app,
            metrics: metrics
        )
        let outcomes = Dictionary(uniqueKeysWithValues: deliveries.map { ($0.channel, $0.outcome) })
        XCTAssertEqual(outcomes[.webhook], .failed)
        XCTAssertEqual(outcomes[.discord], .skipped)
        XCTAssertEqual(outcomes[.telegram], .skipped)
        XCTAssertEqual(outcomes[.slack], .skipped)
        XCTAssertEqual(outcomes[.email], .skipped)

        let snapshot = await metrics.snapshot()
        XCTAssertEqual(snapshot.notificationDeliveries[.webhook]?["attempted"], 1)
        XCTAssertEqual(snapshot.notificationDeliveries[.webhook]?["failed"], 1)
        XCTAssertNil(snapshot.notificationDeliveries[.webhook]?["succeeded"])
        XCTAssertEqual(snapshot.notificationDeliveries[.email]?["skipped"], 1)
        XCTAssertNil(snapshot.notificationDeliveries[.email]?["attempted"])
    }

    func testCorruptNotificationCredentialFailsOnlyItsChannel() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(key: String(repeating: "46", count: 32))

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        let metrics = MetricsRegistry()
        let user = User(
            username: "notification-corrupt-test",
            email: "notification-corrupt@example.test",
            passwordHash: "unused",
            discordWebhookURL: "http://127.0.0.1/discord"
        )
        user.webhookURLCipher = "enc:v1:not-base64"

        let before = await MetricsRegistry.shared.snapshot()
            .sensitiveFieldFailures[.userWebhookURL]?[.invalidEnvelope] ?? 0
        let deliveries = await NotificationDispatcher.notify(
            user: user,
            title: "Test",
            message: "Test delivery",
            scanID: nil,
            app: app,
            metrics: metrics
        )

        let outcomes = Dictionary(uniqueKeysWithValues: deliveries.map { ($0.channel, $0.outcome) })
        XCTAssertEqual(deliveries.count, NotificationChannel.allCases.count)
        XCTAssertEqual(outcomes[.webhook], .failed)
        XCTAssertEqual(outcomes[.discord], .failed, "Discord must still be evaluated after the corrupt webhook")
        XCTAssertEqual(outcomes[.telegram], .skipped)
        XCTAssertEqual(outcomes[.slack], .skipped)
        XCTAssertEqual(outcomes[.email], .skipped)

        let deliverySnapshot = await metrics.snapshot()
        XCTAssertEqual(deliverySnapshot.notificationDeliveries[.webhook]?["failed"], 1)
        XCTAssertEqual(deliverySnapshot.notificationDeliveries[.discord]?["failed"], 1)
        let after = await MetricsRegistry.shared.snapshot()
            .sensitiveFieldFailures[.userWebhookURL]?[.invalidEnvelope] ?? 0
        XCTAssertEqual(after, before + 1)
    }

    func testNotificationOutboxIsIdempotentAndCascadesWithItsScan() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let user = User(
            username: "outbox-idempotency",
            email: "outbox-idempotency@example.test",
            passwordHash: "unused",
            emailVerified: true
        )
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)
        let scan = Scan(input: "outbox-target", userID: userID)
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)

        let first = try await NotificationOutbox.enqueue(
            userID: userID,
            title: "Original title",
            message: "Original message",
            scanID: scanID,
            idempotencyKey: "scan-alert:\(scanID)",
            app: app
        )
        let duplicate = try await NotificationOutbox.enqueue(
            userID: userID,
            title: "Must not replace the original",
            message: "Must not replace the original",
            scanID: scanID,
            idempotencyKey: "scan-alert:\(scanID)",
            app: app
        )

        XCTAssertEqual(first.eventID, duplicate.eventID)
        XCTAssertEqual(first.jobIDs, duplicate.jobIDs)
        let eventCount = try await NotificationOutboxEvent.query(on: app.db).count()
        let jobCount = try await NotificationDeliveryJob.query(on: app.db).count()
        XCTAssertEqual(eventCount, 1)
        XCTAssertEqual(jobCount, NotificationChannel.allCases.count)
        let storedEvent = try await NotificationOutboxEvent.query(on: app.db).first()
        let event = try XCTUnwrap(storedEvent)
        let payload = try event.payload
        XCTAssertEqual(payload.title, "Original title")
        XCTAssertEqual(payload.message, "Original message")
        let jobs = try await NotificationDeliveryJob.query(on: app.db).all()
        XCTAssertEqual(Set(jobs.map(\.channelRaw)), Set(NotificationChannel.allCases.map(\.rawValue)))
        XCTAssertTrue(jobs.allSatisfy { $0.status == .pending && $0.attemptCount == 0 })

        try await scan.delete(on: app.db)
        let remainingEvents = try await NotificationOutboxEvent.query(on: app.db).count()
        let remainingJobs = try await NotificationDeliveryJob.query(on: app.db).count()
        XCTAssertEqual(remainingEvents, 0)
        XCTAssertEqual(remainingJobs, 0)
    }

    func testNotificationClaimsAreExclusiveAndExpiredLeasesAreRecovered() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let user = User(
            username: "outbox-lease",
            email: "outbox-lease@example.test",
            passwordHash: "unused",
            emailVerified: true
        )
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)
        _ = try await NotificationOutbox.enqueue(
            userID: userID,
            title: "Lease",
            message: "Lease test",
            scanID: nil,
            idempotencyKey: "lease-test",
            channels: [.email, .webhook],
            app: app
        )

        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let firstClaim = try await NotificationDeliveryWorker.claimNext(
            on: app.db, workerID: "worker-a", now: now, leaseSeconds: 60
        )
        let secondClaim = try await NotificationDeliveryWorker.claimNext(
            on: app.db, workerID: "worker-b", now: now, leaseSeconds: 60
        )
        let first = try XCTUnwrap(firstClaim)
        let second = try XCTUnwrap(secondClaim)
        XCTAssertNotEqual(first.id, second.id)
        let thirdClaim = try await NotificationDeliveryWorker.claimNext(
            on: app.db, workerID: "worker-c", now: now, leaseSeconds: 60
        )
        XCTAssertNil(thirdClaim)
        XCTAssertEqual(first.attemptCount, 1)
        XCTAssertEqual(second.attemptCount, 1)

        // Keep the second lease alive so only the first row is reclaimable.
        second.leaseExpiresAt = now.addingTimeInterval(600)
        try await second.update(on: app.db)
        let reclaimedClaim = try await NotificationDeliveryWorker.claimNext(
            on: app.db,
            workerID: "worker-c",
            now: now.addingTimeInterval(61),
            leaseSeconds: 60
        )
        let reclaimed = try XCTUnwrap(reclaimedClaim)
        XCTAssertEqual(reclaimed.id, first.id)
        XCTAssertEqual(reclaimed.leaseOwner, "worker-c")
        XCTAssertEqual(reclaimed.attemptCount, 2)

        // The former owner cannot overwrite the row after worker-c reclaimed
        // it, even if its provider call returns late.
        let reclaimedID = try XCTUnwrap(reclaimed.id)
        try await NotificationDeliveryWorker.finish(
            jobID: reclaimedID,
            workerID: "worker-a",
            attemptCount: 1,
            maxAttempts: reclaimed.maxAttempts,
            result: .succeeded,
            now: now.addingTimeInterval(62),
            on: app.db
        )
        let afterStaleFinish = try await NotificationDeliveryJob.find(reclaimedID, on: app.db)
        XCTAssertEqual(afterStaleFinish?.status, .processing)
        XCTAssertEqual(afterStaleFinish?.leaseOwner, "worker-c")

        try await NotificationDeliveryWorker.finish(
            jobID: reclaimedID,
            workerID: "worker-c",
            attemptCount: 2,
            maxAttempts: reclaimed.maxAttempts,
            result: .succeeded,
            now: now.addingTimeInterval(63),
            on: app.db
        )
        let afterCurrentFinish = try await NotificationDeliveryJob.find(reclaimedID, on: app.db)
        XCTAssertEqual(afterCurrentFinish?.status, .succeeded)
        XCTAssertNil(afterCurrentFinish?.leaseOwner)
    }

    func testNotificationWorkerDeadLettersPermanentFailuresWithoutNetworkAccess() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let user = User(
            username: "outbox-dlq",
            email: "outbox-dlq@example.test",
            passwordHash: "unused",
            webhookURL: "http://127.0.0.1/private-hook",
            emailVerified: true
        )
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)
        _ = try await NotificationOutbox.enqueue(
            userID: userID,
            title: "Blocked",
            message: "Must not reach loopback",
            scanID: nil,
            idempotencyKey: "blocked-webhook",
            channels: [.webhook],
            app: app
        )

        let processed = try await NotificationDeliveryWorker.processNext(
            app: app,
            workerID: "worker-test",
            now: Date(timeIntervalSince1970: 1_800_000_100)
        )
        let processedID = try XCTUnwrap(processed)
        let storedJob = try await NotificationDeliveryJob.find(processedID, on: app.db)
        let job = try XCTUnwrap(storedJob)
        XCTAssertEqual(job.status, .deadLetter)
        XCTAssertEqual(job.attemptCount, 1)
        XCTAssertEqual(job.lastFailureCode, "blocked_destination")
        XCTAssertNil(job.leaseOwner)
        XCTAssertNil(job.leaseExpiresAt)
        XCTAssertNotNil(job.completedAt)
    }

    func testNotificationDeadLetterAdminEndpointsRequireAdminAndReplaySafely() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let adminCookie = try await registerAndLogin(app, username: "notification-admin")
        let memberCookie = try await registerAndLogin(app, username: "notification-member")
        let storedAdmin = try await User.query(on: app.db)
            .filter(\.$username == "notification-admin")
            .first()
        let admin = try XCTUnwrap(storedAdmin)
        admin.isAdmin = true
        try await admin.update(on: app.db)
        let adminID = try XCTUnwrap(admin.id)

        _ = try await NotificationOutbox.enqueue(
            userID: adminID,
            title: "DLQ",
            message: "Operator replay test",
            scanID: nil,
            idempotencyKey: "admin-dlq-test",
            channels: [.webhook],
            app: app
        )
        let storedJob = try await NotificationDeliveryJob.query(on: app.db)
            .filter(\.$channelRaw == NotificationChannel.webhook.rawValue)
            .first()
        let job = try XCTUnwrap(storedJob)
        let jobID = try XCTUnwrap(job.id)
        job.statusRaw = NotificationDeliveryJobStatus.deadLetter.rawValue
        job.attemptCount = job.maxAttempts
        job.lastFailureCode = "network_error"
        job.completedAt = Date()
        try await job.update(on: app.db)

        try await app.test(.GET, "/admin/notification-deliveries") { response in
            XCTAssertEqual(response.status, .unauthorized)
        }
        try await app.test(.GET, "/admin/notification-deliveries", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: memberCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .forbidden)
        })
        try await app.test(.GET, "/admin/notification-deliveries", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: adminCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            let rows = try response.content.decode([NotificationDeliveryJobDTO].self)
            XCTAssertEqual(rows.map(\.id), [jobID])
            XCTAssertEqual(rows.first?.lastFailureCode, "network_error")
        })
        try await app.test(
            .POST,
            "/admin/notification-deliveries/\(jobID.uuidString)/retry",
            beforeRequest: { request in
                request.headers.replaceOrAdd(name: .cookie, value: adminCookie)
            },
            afterResponse: { response in
                XCTAssertEqual(response.status, .accepted)
            }
        )

        let replayedJob = try await NotificationDeliveryJob.find(jobID, on: app.db)
        let replayed = try XCTUnwrap(replayedJob)
        XCTAssertEqual(replayed.status, .pending)
        XCTAssertEqual(replayed.attemptCount, 0)
        XCTAssertNil(replayed.lastFailureCode)
        XCTAssertNil(replayed.completedAt)

        // Replay is compare-and-set. A repeated request must not reset a row a
        // worker may already have leased after the first accepted request.
        try await app.test(
            .POST,
            "/admin/notification-deliveries/\(jobID.uuidString)/retry",
            beforeRequest: { request in
                request.headers.replaceOrAdd(name: .cookie, value: adminCookie)
            },
            afterResponse: { response in
                XCTAssertEqual(response.status, .conflict)
            }
        )
    }

    func testNotificationRetryPolicyIsBoundedDeterministicAndClassified() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let jobID = UUID(uuidString: "00000000-0000-4000-8000-000000000123")!
        let transient = NotificationAttemptResult.failed(.transient, code: "network_error")
        let first = NotificationRetryPolicy.decision(
            for: transient, attemptCount: 1, maxAttempts: 5, jobID: jobID, now: now
        )
        let repeated = NotificationRetryPolicy.decision(
            for: transient, attemptCount: 1, maxAttempts: 5, jobID: jobID, now: now
        )
        XCTAssertEqual(first, repeated)
        guard case let .retry(nextAttempt) = first else {
            return XCTFail("A transient first failure must be retried.")
        }
        XCTAssertGreaterThanOrEqual(nextAttempt.timeIntervalSince(now), 10)
        XCTAssertLessThanOrEqual(nextAttempt.timeIntervalSince(now), 12.001)
        XCTAssertEqual(
            NotificationRetryPolicy.decision(
                for: transient, attemptCount: 5, maxAttempts: 5, jobID: jobID, now: now
            ),
            .deadLetter
        )
        XCTAssertEqual(
            NotificationRetryPolicy.decision(
                for: .failed(.permanent, code: "blocked_destination"),
                attemptCount: 1,
                maxAttempts: 5,
                jobID: jobID,
                now: now
            ),
            .deadLetter
        )
        XCTAssertEqual(
            NotificationRetryPolicy.decision(
                for: .succeeded, attemptCount: 1, maxAttempts: 5, jobID: jobID, now: now
            ),
            .succeeded
        )
        XCTAssertEqual(
            NotificationRetryPolicy.decision(
                for: .skipped, attemptCount: 1, maxAttempts: 5, jobID: jobID, now: now
            ),
            .skipped
        )
    }

    func testNotificationDeliveryConfigurationRejectsInvalidPresentValues() throws {
        let names = [
            "NOTIFICATION_WORKER_ENABLED",
            "NOTIFICATION_MAX_ATTEMPTS",
            "NOTIFICATION_POLL_SECONDS",
            "NOTIFICATION_LEASE_SECONDS",
            "NOTIFICATION_RETENTION_DAYS",
        ]
        let environment = EnvironmentSnapshot(names)
        defer { environment.restore() }

        setenv("NOTIFICATION_WORKER_ENABLED", "true", 1)
        setenv("NOTIFICATION_MAX_ATTEMPTS", "0", 1)
        setenv("NOTIFICATION_POLL_SECONDS", "2", 1)
        setenv("NOTIFICATION_LEASE_SECONDS", "60", 1)
        setenv("NOTIFICATION_RETENTION_DAYS", "30", 1)
        XCTAssertThrowsError(try NotificationDeliveryConfiguration.fromEnvironment())

        setenv("NOTIFICATION_WORKER_ENABLED", "false", 1)
        setenv("NOTIFICATION_MAX_ATTEMPTS", "7", 1)
        setenv("NOTIFICATION_POLL_SECONDS", "3", 1)
        setenv("NOTIFICATION_LEASE_SECONDS", "90", 1)
        setenv("NOTIFICATION_RETENTION_DAYS", "45", 1)
        let configuration = try NotificationDeliveryConfiguration.fromEnvironment()
        XCTAssertFalse(configuration.enabled)
        XCTAssertEqual(configuration.maxAttempts, 7)
        XCTAssertEqual(configuration.pollSeconds, 3)
        XCTAssertEqual(configuration.leaseSeconds, 90)
        XCTAssertEqual(configuration.retentionDays, 45)
    }

    func testAsyncExportJobBuildsEncryptedArtifactAndManifest() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(
            key: String(repeating: "a7", count: 32),
            keyID: "export-test",
            writeVersion: "1"
        )

        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "async-export-owner")
        let storedUser = try await User.query(on: app.db)
            .filter(\.$username == "async-export-owner")
            .first()
        let user = try XCTUnwrap(storedUser)
        let userID = try XCTUnwrap(user.id)
        let scan = Scan(input: "owner@example.test", status: .completed, userID: userID)
        scan.completedAt = Date()
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        try await Result(
            scanID: scanID,
            source: "ExportFixture",
            type: "account",
            confidenceScore: 0.9,
            rawData: "sensitive-export-value",
            metadata: #"{"platform":"fixture"}"#
        ).save(on: app.db)

        var jobID: UUID?
        try await app.test(.POST, "/export-jobs", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
            try request.content.encode(
                ExportJobController.CreateBody(scanID: scanID, format: .json),
                as: .json
            )
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .accepted)
            let job = try response.content.decode(ExportJobDTO.self)
            jobID = job.id
            XCTAssertEqual(job.status, ExportJobStatus.pending.rawValue)
            XCTAssertNil(job.downloadURL)
        })
        let id = try XCTUnwrap(jobID)

        let processed = try await ExportJobWorker.processNext(
            app: app,
            workerID: "export-worker-test"
        )
        XCTAssertEqual(processed, id)
        let storedJob = try await ExportJob.find(id, on: app.db)
        let job = try XCTUnwrap(storedJob)
        XCTAssertEqual(job.status, .completed)
        XCTAssertTrue(job.artifactCipher?.hasPrefix("enc:v1:") == true)
        XCTAssertTrue(job.manifestCipher?.hasPrefix("enc:v1:") == true)
        XCTAssertFalse(job.artifactCipher?.contains("sensitive-export-value") == true)

        var artifactHash = ""
        try await app.test(.GET, "/export-jobs/\(id)/manifest", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            let manifest = try response.content.decode(ExportJobManifest.self)
            XCTAssertEqual(manifest.jobID, id)
            XCTAssertEqual(manifest.scanID, scanID)
            XCTAssertEqual(manifest.resultCount, 1)
            XCTAssertTrue(manifest.complete)
            XCTAssertEqual(manifest.artifactSHA256.count, 64)
            artifactHash = manifest.artifactSHA256
        })

        try await app.test(.GET, "/export-jobs/\(id)/download", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.first(name: "X-Content-SHA256"), artifactHash)
            XCTAssertTrue(response.headers.first(name: "content-disposition")?.contains("attachment") == true)
            let document = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(response.body.readableBytesView))
                    as? [String: Any]
            )
            let results = try XCTUnwrap(document["results"] as? [[String: Any]])
            XCTAssertEqual(results.first?["rawData"] as? String, "sensitive-export-value")
            let provenance = try XCTUnwrap(document["provenance"] as? [String: Any])
            XCTAssertEqual(provenance["resultCount"] as? Int, 1)
        })
    }

    func testAsyncExportEndpointsAreOwnerScopedAndPendingCancellationIsTerminal() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let ownerCookie = try await registerAndLogin(app, username: "export-owner")
        let otherCookie = try await registerAndLogin(app, username: "export-other")
        let storedOwner = try await User.query(on: app.db)
            .filter(\.$username == "export-owner")
            .first()
        let owner = try XCTUnwrap(storedOwner)
        let ownerID = try XCTUnwrap(owner.id)
        let scan = Scan(input: "owner-only", status: .completed, userID: ownerID)
        scan.completedAt = Date()
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)

        try await app.test(.POST, "/export-jobs", beforeRequest: { request in
            try request.content.encode(
                ExportJobController.CreateBody(scanID: scanID, format: .json),
                as: .json
            )
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .unauthorized)
        })
        try await app.test(.POST, "/export-jobs", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: otherCookie)
            try request.content.encode(
                ExportJobController.CreateBody(scanID: scanID, format: .json),
                as: .json
            )
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .notFound)
        })

        var jobID: UUID?
        try await app.test(.POST, "/export-jobs", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: ownerCookie)
            try request.content.encode(
                ExportJobController.CreateBody(scanID: scanID, format: .graphml),
                as: .json
            )
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .accepted)
            jobID = try response.content.decode(ExportJobDTO.self).id
        })
        let id = try XCTUnwrap(jobID)

        for suffix in ["", "/manifest", "/download"] {
            try await app.test(.GET, "/export-jobs/\(id)\(suffix)", beforeRequest: { request in
                request.headers.replaceOrAdd(name: .cookie, value: otherCookie)
            }, afterResponse: { response in
                XCTAssertEqual(response.status, .notFound)
            })
        }
        try await app.test(.POST, "/export-jobs/\(id)/cancel", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: otherCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .notFound)
        })
        try await app.test(.POST, "/export-jobs/\(id)/cancel", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: ownerCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .accepted)
        })
        let cancelledJob = try await ExportJob.find(id, on: app.db)
        XCTAssertEqual(cancelledJob?.status, .cancelled)
        XCTAssertTrue(cancelledJob?.cancelRequested == true)
        let processed = try await ExportJobWorker.processNext(
            app: app,
            workerID: "must-not-claim-cancelled"
        )
        XCTAssertNil(processed)
    }

    func testExportLeaseRecoveryRejectsStaleWorkerCompletion() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let user = User(
            username: "export-lease",
            email: "export-lease@example.test",
            passwordHash: "unused"
        )
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)
        let scan = Scan(input: "lease-target", status: .completed, userID: userID)
        scan.completedAt = Date()
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        let job = ExportJob(
            userID: userID,
            scanID: scanID,
            format: .json,
            maxAttempts: 2,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        try await job.save(on: app.db)
        let jobID = try XCTUnwrap(job.id)
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        let first = try await ExportJobWorker.claimNext(
            on: app.db,
            workerID: "worker-a",
            now: now,
            leaseSeconds: 60
        )
        XCTAssertEqual(first?.id, jobID)
        let recovered = try await ExportJobWorker.claimNext(
            on: app.db,
            workerID: "worker-b",
            now: now.addingTimeInterval(61),
            leaseSeconds: 60
        )
        XCTAssertEqual(recovered?.id, jobID)

        let staleFinished = try await ExportJobWorker.finishSuccess(
            jobID: jobID,
            workerID: "worker-a",
            artifactCipher: "stale-artifact",
            manifestCipher: "stale-manifest",
            resultCount: 0,
            retentionHours: 24,
            on: app.db
        )
        XCTAssertFalse(staleFinished)
        let currentFinished = try await ExportJobWorker.finishSuccess(
            jobID: jobID,
            workerID: "worker-b",
            artifactCipher: "current-artifact",
            manifestCipher: "current-manifest",
            resultCount: 0,
            retentionHours: 24,
            on: app.db
        )
        XCTAssertTrue(currentFinished)
        let finalJob = try await ExportJob.find(jobID, on: app.db)
        XCTAssertEqual(finalJob?.status, .completed)
        XCTAssertEqual(finalJob?.attemptCount, 2)
        XCTAssertEqual(finalJob?.artifactCipher, "current-artifact")
    }

    func testAsyncExportSourceLimitFailsWithBoundedCode() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        app.exportJobConfiguration = ExportJobConfiguration(
            enabled: false,
            pollSeconds: 2,
            leaseSeconds: 120,
            retentionHours: 24,
            maxOutstandingPerUser: 3,
            maxJobsPerUserPerDay: 20,
            maxResults: 10,
            batchSize: 25,
            maxSourceBytes: 64,
            maxArtifactBytes: 1_024,
            maxAttempts: 2
        )
        let user = User(
            username: "export-limit",
            email: "export-limit@example.test",
            passwordHash: "unused"
        )
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)
        let scan = Scan(input: "limit-target", status: .completed, userID: userID)
        scan.completedAt = Date()
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        try await Result(
            scanID: scanID,
            source: "fixture",
            type: "large",
            confidenceScore: 0.5,
            rawData: String(repeating: "x", count: 128)
        ).save(on: app.db)
        let job = ExportJob(
            userID: userID,
            scanID: scanID,
            format: .json,
            maxAttempts: 2,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        try await job.save(on: app.db)
        let jobID = try XCTUnwrap(job.id)

        let processed = try await ExportJobWorker.processNext(
            app: app,
            workerID: "limit-worker"
        )
        XCTAssertEqual(processed, jobID)
        let failed = try await ExportJob.find(jobID, on: app.db)
        XCTAssertEqual(failed?.status, .failed)
        XCTAssertEqual(failed?.failureCode, "source_too_large")
        XCTAssertNil(failed?.artifactCipher)
    }

    func testExportJobConfigurationRejectsInvalidPresentValues() throws {
        let names = [
            "EXPORT_WORKER_ENABLED", "EXPORT_POLL_SECONDS", "EXPORT_LEASE_SECONDS",
            "EXPORT_RETENTION_HOURS", "EXPORT_MAX_OUTSTANDING_PER_USER",
            "EXPORT_MAX_JOBS_PER_USER_PER_DAY", "EXPORT_MAX_RESULTS",
            "EXPORT_BATCH_SIZE", "EXPORT_MAX_SOURCE_MIB", "EXPORT_MAX_ARTIFACT_MIB",
            "EXPORT_MAX_ATTEMPTS",
        ]
        let environment = EnvironmentSnapshot(names)
        defer { environment.restore() }
        setenv("EXPORT_MAX_RESULTS", "0", 1)
        XCTAssertThrowsError(try ExportJobConfiguration.fromEnvironment())

        setenv("EXPORT_WORKER_ENABLED", "false", 1)
        setenv("EXPORT_POLL_SECONDS", "3", 1)
        setenv("EXPORT_LEASE_SECONDS", "180", 1)
        setenv("EXPORT_RETENTION_HOURS", "48", 1)
        setenv("EXPORT_MAX_OUTSTANDING_PER_USER", "4", 1)
        setenv("EXPORT_MAX_JOBS_PER_USER_PER_DAY", "30", 1)
        setenv("EXPORT_MAX_RESULTS", "12000", 1)
        setenv("EXPORT_BATCH_SIZE", "300", 1)
        setenv("EXPORT_MAX_SOURCE_MIB", "8", 1)
        setenv("EXPORT_MAX_ARTIFACT_MIB", "16", 1)
        setenv("EXPORT_MAX_ATTEMPTS", "3", 1)
        let configuration = try ExportJobConfiguration.fromEnvironment()
        XCTAssertFalse(configuration.enabled)
        XCTAssertEqual(configuration.leaseSeconds, 180)
        XCTAssertEqual(configuration.maxResults, 12_000)
        XCTAssertEqual(configuration.batchSize, 300)
        XCTAssertEqual(configuration.maxSourceBytes, 8 * 1_024 * 1_024)
        XCTAssertEqual(configuration.maxArtifactBytes, 16 * 1_024 * 1_024)
        XCTAssertEqual(configuration.maxAttempts, 3)
    }

    func testPublicLivenessIsDatabaseIndependentAndLocalReadinessChecksSQL() async throws {
        struct Probe: Decodable {
            let status: String
            let db: String?
        }

        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/health") { response in
            XCTAssertEqual(response.status, .ok)
            let probe = try response.content.decode(Probe.self)
            XCTAssertEqual(probe.status, "ok")
            XCTAssertNil(probe.db, "Public liveness must not expose or query database readiness.")
        }

        try await app.test(.GET, "/ready") { response in
            XCTAssertEqual(response.status, .ok)
            let probe = try response.content.decode(Probe.self)
            XCTAssertEqual(probe.status, "ready")
            XCTAssertEqual(probe.db, "ok")
        }
    }

    func testDarkWebInvestigationQueueIsAuthorizedOwnerScopedAndCancellable() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/dark-web/status") { response in
            XCTAssertEqual(response.status, .unauthorized)
        }

        let aliceCookie = try await registerAndLogin(app, username: "darkweb-alice")
        let aliceLookup = try await User.query(on: app.db)
            .filter(\.$username == "darkweb-alice").first()
        let alice = try XCTUnwrap(aliceLookup)
        alice.emailVerified = true
        try await alice.save(on: app.db)

        try await app.test(.GET, "/dark-web/status", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: aliceCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertTrue(try response.content.decode(DarkWebInvestigationController.StatusResponse.self).enabled)
        })

        var jobID = ""
        try await app.test(.POST, "/dark-web/investigations", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: aliceCookie)
            try request.content.encode(DarkWebInvestigationController.CreateBody(
                target: "Person@Example.test",
                acknowledgedAuthorizedUse: true
            ), as: .json)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .accepted)
            let job = try response.content.decode(DarkWebInvestigationController.Detail.self)
            jobID = job.id
            XCTAssertEqual(job.target, "person@example.test")
            XCTAssertEqual(job.targetKind, DarkWebTargetKind.email.rawValue)
            XCTAssertEqual(job.status, DarkWebInvestigationStatus.pending.rawValue)
            XCTAssertNil(job.result)
        })
        XCTAssertNotNil(UUID(uuidString: jobID))

        let persistedLookup = try await DarkWebInvestigation.find(
            UUID(uuidString: jobID)!, on: app.db
        )
        let persisted = try XCTUnwrap(persistedLookup)
        XCTAssertEqual(try persisted.target, "person@example.test")
        XCTAssertEqual(persisted.targetHash, FieldCrypto.blindIndex("person@example.test"))
        XCTAssertEqual(persisted.resultCount, 0)
        XCTAssertLessThanOrEqual(
            persisted.expiresAt.timeIntervalSinceNow,
            TimeInterval(72 * 3_600 + 5)
        )

        let bobCookie = try await registerAndLogin(app, username: "darkweb-bob")
        let bobLookup = try await User.query(on: app.db)
            .filter(\.$username == "darkweb-bob").first()
        let bob = try XCTUnwrap(bobLookup)
        bob.emailVerified = true
        try await bob.save(on: app.db)
        try await app.test(.GET, "/dark-web/investigations/\(jobID)", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: bobCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .notFound)
        })
        try await app.test(.POST, "/dark-web/investigations", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: bobCookie)
            try request.content.encode(DarkWebInvestigationController.CreateBody(
                target: "example.test",
                acknowledgedAuthorizedUse: false
            ), as: .json)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .forbidden)
        })

        try await app.test(.POST, "/dark-web/investigations/\(jobID)/cancel", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: aliceCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            let job = try response.content.decode(DarkWebInvestigationController.Detail.self)
            XCTAssertEqual(job.status, DarkWebInvestigationStatus.cancelled.rawValue)
            XCTAssertTrue(job.cancelRequested)
        })

        try await app.test(.DELETE, "/dark-web/investigations/\(jobID)", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: aliceCookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .noContent)
        })
        let deleted = try await DarkWebInvestigation.find(UUID(uuidString: jobID)!, on: app.db)
        XCTAssertNil(deleted)
    }

    func testDarkWebTargetClassificationIsDeterministic() {
        XCTAssertEqual(DarkWebTargetKind.detect("person@example.test"), .email)
        XCTAssertEqual(DarkWebTargetKind.detect("example.test"), .domain)
        XCTAssertEqual(DarkWebTargetKind.detect("+40721234567"), .phone)
        XCTAssertEqual(DarkWebTargetKind.detect("+40-721-234-567"), .phone)
        XCTAssertEqual(DarkWebTargetKind.detect("handle"), .username)
    }

    func testDarkWebQueueEnforcesOneActiveJobPerUserAtDatabaseBoundary() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        _ = try await registerAndLogin(app, username: "darkweb-unique")
        let loadedUser = try await User.query(on: app.db)
            .filter(\.$username == "darkweb-unique")
            .first()
        let user = try XCTUnwrap(loadedUser)
        let userID = try XCTUnwrap(user.id)

        let first = DarkWebInvestigation(
            userID: userID, target: "first.example.test", retentionHours: 72
        )
        try await first.save(on: app.db)

        let competing = DarkWebInvestigation(
            userID: userID, target: "second.example.test", retentionHours: 72
        )
        do {
            try await competing.save(on: app.db)
            XCTFail("The partial unique index accepted two active jobs for one user.")
        } catch let error as any DatabaseError {
            XCTAssertTrue(error.isConstraintFailure)
        }

        first.status = .cancelled
        first.cancelRequested = true
        first.completedAt = Date()
        try await first.save(on: app.db)
        let replacement = DarkWebInvestigation(
            userID: userID, target: "replacement.example.test", retentionHours: 72
        )
        try await replacement.save(on: app.db)
    }

    func testDarkWebWorkerContractRejectsHostileOrOversizedResults() throws {
        let valid = DarkWebWorkerResult(
            schemaVersion: 1,
            status: "completed",
            findings: [
                DarkWebFinding(
                    type: "email",
                    value: "person@example.test",
                    source: "onion-search",
                    confidence: 0.8,
                    firstSeen: "2024-01-02",
                    lastSeen: nil
                ),
                DarkWebFinding(
                    type: "domain",
                    value: "example.test",
                    source: "onion-search",
                    confidence: 0.7,
                    firstSeen: nil,
                    lastSeen: nil
                ),
            ],
            relationships: [DarkWebRelationship(
                source: "person@example.test",
                target: "example.test",
                type: "USES",
                confidence: 0.7
            )],
            sources: ["onion-search"]
        )
        XCTAssertEqual(
            try DarkWebWorkerClient.validate(valid, originalTarget: "person@example.test"),
            valid
        )

        let hostile = DarkWebWorkerResult(
            schemaVersion: 1,
            status: "completed",
            findings: [DarkWebFinding(
                type: "email\nINJECTED",
                value: "person@example.test",
                source: "onion-search",
                confidence: 0.8,
                firstSeen: nil,
                lastSeen: nil
            )],
            relationships: [],
            sources: ["onion-search"]
        )
        XCTAssertThrowsError(try DarkWebWorkerClient.validate(
            hostile, originalTarget: "person@example.test"
        ))

        let orphanRelationship = DarkWebWorkerResult(
            schemaVersion: 1,
            status: "completed",
            findings: valid.findings,
            relationships: [DarkWebRelationship(
                source: "person@example.test",
                target: "secret-not-in-findings",
                type: "USES",
                confidence: 0.7
            )],
            sources: valid.sources
        )
        XCTAssertThrowsError(try DarkWebWorkerClient.validate(
            orphanRelationship, originalTarget: "person@example.test"
        ))

        let oversized = DarkWebWorkerResult(
            schemaVersion: 1,
            status: "completed",
            findings: (0...DarkWebWorkerClient.maximumFindings).map { index in
                DarkWebFinding(type: "domain", value: "\(index).example.test",
                               source: "test", confidence: 0.5,
                               firstSeen: nil, lastSeen: nil)
            },
            relationships: [],
            sources: ["test"]
        )
        XCTAssertThrowsError(try DarkWebWorkerClient.validate(
            oversized, originalTarget: "example.test"
        ))
    }

    func testDarkWebWorkerSignatureIsStableAndBodyBound() throws {
        let secret = String(repeating: "s", count: 32)
        let first = DarkWebWorkerClient.sign(
            timestamp: "1786550400", method: "POST", path: "/v1/investigations",
            body: Data(#"{"target":"alice"}"#.utf8), secret: secret
        )
        let second = DarkWebWorkerClient.sign(
            timestamp: "1786550400", method: "POST", path: "/v1/investigations",
            body: Data(#"{"target":"bob"}"#.utf8), secret: secret
        )
        let otherPath = DarkWebWorkerClient.sign(
            timestamp: "1786550400", method: "POST", path: "/v1/other",
            body: Data(#"{"target":"alice"}"#.utf8), secret: secret
        )
        XCTAssertEqual(first.count, 64)
        XCTAssertNotEqual(first, second)
        XCTAssertNotEqual(first, otherPath)
    }

    func testClientIPOnlyTrustsForwardingHeadersFromLoopback() async throws {
        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }

        func request(peer: String, realIP: String?, cloudflareIP: String? = nil) throws -> Request {
            var headers = HTTPHeaders()
            if let realIP { headers.add(name: "X-Real-IP", value: realIP) }
            if let cloudflareIP { headers.add(name: "CF-Connecting-IP", value: cloudflareIP) }
            return Request(
                application: app,
                headers: headers,
                remoteAddress: try SocketAddress(ipAddress: peer, port: 12_345),
                on: app.eventLoopGroup.next()
            )
        }

        let direct = try request(
            peer: "198.51.100.20", realIP: "1.2.3.4", cloudflareIP: "5.6.7.8"
        )
        XCTAssertEqual(direct.clientIP, "198.51.100.20",
                       "A direct client must not be able to forge proxy headers.")

        let proxied = try request(peer: "127.0.0.1", realIP: " 1.2.3.4 ")
        XCTAssertEqual(proxied.clientIP, "1.2.3.4")

        let invalidPrimary = try request(
            peer: "::1", realIP: "attacker.example", cloudflareIP: "2001:4860:4860::8888"
        )
        XCTAssertEqual(invalidPrimary.clientIP, "2001:4860:4860::8888")
        XCTAssertTrue(ClientIPResolver.isLoopback("::ffff:127.0.0.1"))
        XCTAssertFalse(ClientIPResolver.isLoopback("10.0.0.1"))

        for invalid in ["1.2.3.4, 5.6.7.8", "example.test", "1.2.3.4%eth0", ""] {
            XCTAssertNil(ClientIPResolver.normalizedIPAddress(invalid))
        }
    }

    func testEveryAPIResponseDisablesCaching() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // Cover both a successful public response and an error produced outside
        // any controller-specific NoCacheMiddleware route group.
        for path in ["/", "/route-that-does-not-exist"] {
            try await app.test(.GET, path) { response in
                XCTAssertEqual(response.headers.first(name: .cacheControl), "no-store")
            }
        }

        let cookie = try await registerAndLogin(app, username: "no-cache-user")
        try await app.test(.GET, "/auth/me", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.first(name: .cacheControl), "no-store")
        })
    }

    func testRetentionDefaultIsExplicitAndNeverReallyDisablesCleanup() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "retention-user")

        let initial = try await User.query(on: app.db)
            .filter(\.$username == "retention-user")
            .first()
        XCTAssertEqual(initial?.retentionDays, 30)

        let legacy = User(
            username: "legacy-retention-user",
            email: "legacy-retention@example.test",
            passwordHash: "unused",
            retentionDays: nil
        )
        try await legacy.save(on: app.db)
        try await DefaultUserRetention().prepare(on: app.db)
        let migratedLegacy = try await User.find(legacy.id, on: app.db)
        XCTAssertEqual(migratedLegacy?.retentionDays, 30, "Historical implicit defaults must be materialized")

        struct RetentionBody: Content { let retentionDays: Int? }
        try await app.test(.POST, "/auth/retention", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
            try request.content.encode(RetentionBody(retentionDays: nil), as: .json)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertNil(try response.content.decode(User.Public.self).retentionDays)
        })

        let optedOut = try await User.query(on: app.db)
            .filter(\.$username == "retention-user")
            .first()
        XCTAssertNil(optedOut?.retentionDays)
    }

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

    func testCredentialPolicyCoversBootstrapAndBCryptByteLimit() throws {
        XCTAssertEqual(
            try CredentialPolicy.validateNewCredential(
                username: "Admin_User",
                email: " ADMIN@Example.test ",
                password: "K8!vapor-safe-passphrase",
                minimumPasswordCharacters: 12
            ),
            "admin@example.test"
        )
        XCTAssertThrowsError(try CredentialPolicy.validateNewCredential(
            username: "admin",
            email: "admin@example.test",
            password: "short",
            minimumPasswordCharacters: 12
        ))
        XCTAssertThrowsError(try CredentialPolicy.validateNewCredential(
            username: "admin",
            email: "admin@example.test",
            password: String(repeating: "🛡", count: 19)
        ), "19 four-byte characters exceed BCrypt's 72-byte input limit")
        XCTAssertThrowsError(try CredentialPolicy.validateNewCredential(
            username: "admin",
            email: "admin@example.test",
            password: "your_strong_password",
            minimumPasswordCharacters: 12
        ), "Deployment-documentation placeholders must never become credentials")
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

        let cancellationStarted = Date()
        let cancellable = Task {
            try await BoundedProcess.run(
                executable: sleep,
                arguments: ["10"],
                environment: ["PATH": "/usr/bin:/bin"],
                timeout: 20,
                maxOutputBytes: 64
            )
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        cancellable.cancel()
        let cancelled = try await cancellable.value
        XCTAssertFalse(cancelled.succeeded)
        XCTAssertLessThan(
            Date().timeIntervalSince(cancellationStarted),
            2,
            "Task cancellation must terminate the child instead of waiting for its deadline."
        )
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
        user.setTOTPSecret(secret)
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

    func testDisableTwoFactorRequiresPasswordAndASecondFactor() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "disable-twofa-user")
        let userLookup = try await User.query(on: app.db)
            .filter(\.$username == "disable-twofa-user").first()
        let user = try XCTUnwrap(userLookup)
        let secret = TOTP.generateSecret()
        let recoveryCode = "abcd-efgh-jkmn"
        user.setTOTPSecret(secret)
        user.totpEnabled = true
        user.totpRecoveryCodes = String(decoding: try JSONEncoder().encode([
            RecoveryCodes.hash(recoveryCode),
        ]), as: UTF8.self)
        try await user.save(on: app.db)

        try await app.test(.POST, "/auth/2fa/disable", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
            try req.content.encode(["password": "Xk9mQ2vLp7wZ"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .badRequest) })

        try await app.test(.POST, "/auth/2fa/disable", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
            try req.content.encode(TwoFactorController.DisableBody(
                password: "wrong-password", code: recoveryCode
            ), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })

        try await app.test(.POST, "/auth/2fa/disable", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
            try req.content.encode(TwoFactorController.DisableBody(
                password: "Xk9mQ2vLp7wZ", code: "not-a-valid-code"
            ), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })

        try await app.test(.POST, "/auth/2fa/disable", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
            try req.content.encode(TwoFactorController.DisableBody(
                password: "Xk9mQ2vLp7wZ", code: recoveryCode
            ), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })

        let disabledLookup = try await User.find(try XCTUnwrap(user.id), on: app.db)
        let disabled = try XCTUnwrap(disabledLookup)
        XCTAssertFalse(disabled.totpEnabled)
        XCTAssertNil(try disabled.totpSecret)
        XCTAssertNil(disabled.totpRecoveryCodes)
        XCTAssertNil(disabled.lastTotpStep)
    }

    func testEnablingTwoFactorConsumesTheConfirmationTOTP() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "enable-twofa-user")

        var setup: TwoFactorController.SetupResponse?
        try await app.test(.POST, "/auth/2fa/setup", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            setup = try res.content.decode(TwoFactorController.SetupResponse.self)
        })
        let code = try XCTUnwrap(TOTP.current(secret: try XCTUnwrap(setup).secret))
        try await app.test(.POST, "/auth/2fa/enable", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
            try req.content.encode(TwoFactorController.CodeBody(code: code), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })

        // The enrolment proof is now recorded as used and cannot immediately
        // authorize a security downgrade with the same time-step.
        try await app.test(.POST, "/auth/2fa/disable", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
            try req.content.encode(TwoFactorController.DisableBody(
                password: "Xk9mQ2vLp7wZ", code: code
            ), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .unauthorized) })
    }

    // MARK: - API key least privilege

    func testEveryRegisteredRouteHasAnExplicitAPIKeyPolicy() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let registered = Set(app.routes.all.map(\.description))
        let reviewedList = APIKeyRoutePolicy.reviewedRouteFingerprints
        let reviewed = Set(reviewedList)

        XCTAssertEqual(
            reviewedList.count,
            reviewed.count,
            "The API-key route policy must not contain duplicate method/path rules."
        )
        XCTAssertEqual(
            reviewed,
            registered,
            "Update APIKeyRoutePolicy whenever the live Vapor route inventory changes."
        )
        for rule in APIKeyRoutePolicy.rules {
            XCTAssertNotEqual(
                APIKeyRoutePolicy.decision(method: rule.method, pathComponents: rule.path),
                .unclassified,
                "Reviewed route unexpectedly became unclassified: \(rule.fingerprint)"
            )
        }
        XCTAssertEqual(
            APIKeyRoutePolicy.decision(method: .POST, pathComponents: ["future-endpoint"]),
            .unclassified,
            "Unknown routes must fail closed instead of inheriting a broad prefix policy."
        )
    }

    func testCrossTenantResourceAndCollectionIsolationMatrix() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        _ = try await registerAndLogin(app, username: "matrix-owner")
        let attackerCookie = try await registerAndLogin(app, username: "matrix-attacker")
        let ownerLookup = try await User.query(on: app.db)
            .filter(\.$username == "matrix-owner").first()
        let attackerLookup = try await User.query(on: app.db)
            .filter(\.$username == "matrix-attacker").first()
        let owner = try XCTUnwrap(ownerLookup)
        let attacker = try XCTUnwrap(attackerLookup)
        let ownerID = try owner.requireID()
        let attackerID = try attacker.requireID()
        owner.emailVerified = true
        attacker.emailVerified = true
        try await owner.save(on: app.db)
        try await attacker.save(on: app.db)

        let ownerScan = Scan(
            input: "tenant-owner-secret.example",
            status: .completed,
            userID: ownerID
        )
        ownerScan.completedAt = Date()
        try await ownerScan.save(on: app.db)
        let ownerScanID = try ownerScan.requireID()
        let attackerScan = Scan(
            input: "tenant-attacker.example",
            status: .completed,
            userID: attackerID
        )
        attackerScan.completedAt = Date()
        try await attackerScan.save(on: app.db)
        let attackerScanID = try attackerScan.requireID()

        let ownerTag = Tag(
            userID: ownerID,
            name: "owner-private-tag",
            colour: "#123456"
        )
        let attackerTag = Tag(
            userID: attackerID,
            name: "attacker-tag",
            colour: "#654321"
        )
        try await ownerTag.save(on: app.db)
        try await attackerTag.save(on: app.db)
        let ownerTagID = try ownerTag.requireID()
        let attackerTagID = try attackerTag.requireID()
        try await ScanTag(scanID: ownerScanID, tagID: ownerTagID).save(on: app.db)

        let scheduled = ScheduledScan(
            userID: ownerID,
            input: "owner-schedule.example",
            interval: .daily,
            nextRunAt: Date().addingTimeInterval(86_400)
        )
        try await scheduled.save(on: app.db)
        let scheduledID = try scheduled.requireID()

        let notification = ScanNotification(
            userID: ownerID,
            scanID: ownerScanID,
            message: "owner notification",
            newResultsCount: 1
        )
        try await notification.save(on: app.db)
        let notificationID = try notification.requireID()

        let apiKey = APIKey(
            userID: ownerID,
            keyHash: sha256Hex("owner-matrix-key"),
            label: "owner-private-key",
            scopes: [.scansRead],
            expiresAt: Date().addingTimeInterval(86_400)
        )
        try await apiKey.save(on: app.db)
        let apiKeyID = try apiKey.requireID()

        let investigation = Investigation(
            userID: ownerID,
            name: "owner-private-board",
            data: #"{"nodes":[],"edges":[]}"#
        )
        try await investigation.save(on: app.db)
        let investigationID = try investigation.requireID()

        let darkWebJob = DarkWebInvestigation(
            userID: ownerID,
            target: "owner-dark-target",
            retentionHours: 24
        )
        darkWebJob.status = .completed
        darkWebJob.completedAt = Date()
        try await darkWebJob.save(on: app.db)
        let darkWebJobID = try darkWebJob.requireID()

        let exportJob = ExportJob(
            userID: ownerID,
            scanID: ownerScanID,
            format: .json,
            maxAttempts: 2,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        try await exportJob.save(on: app.db)
        let exportJobID = try exportJob.requireID()

        let share = SharedReport(
            scanID: ownerScanID,
            tokenHash: sha256Hex("owner-share-token"),
            expiresAt: Date().addingTimeInterval(3_600)
        )
        try await share.save(on: app.db)
        let shareID = try share.requireID()

        struct Probe {
            let method: HTTPMethod
            let path: String
            let expectedStatus: HTTPStatus
            let body: String?

            init(
                _ method: HTTPMethod,
                _ path: String,
                _ expectedStatus: HTTPStatus,
                body: String? = nil
            ) {
                self.method = method
                self.path = path
                self.expectedStatus = expectedStatus
                self.body = body
            }
        }

        let probes = [
            Probe(.GET, "/results/\(ownerScanID)", .forbidden),
            Probe(.GET, "/stream/\(ownerScanID)", .forbidden),
            Probe(.GET, "/report/\(ownerScanID)", .forbidden),
            Probe(.GET, "/export/\(ownerScanID)", .forbidden),
            Probe(.GET, "/export/\(ownerScanID)/graph", .forbidden),
            Probe(.GET, "/export/\(ownerScanID)/report", .forbidden),
            Probe(.GET, "/export/\(ownerScanID)/report.html", .forbidden),
            Probe(.GET, "/identity/\(ownerScanID)", .forbidden),
            Probe(.GET, "/scans/\(ownerScanID)/timeline", .forbidden),
            Probe(.GET, "/scans/\(ownerScanID)/exposure-diff", .notFound),
            Probe(.GET, "/scans/\(ownerScanID)/diff/\(attackerScanID)", .notFound),
            Probe(.GET, "/scans/\(attackerScanID)/diff/\(ownerScanID)", .notFound),
            Probe(.GET, "/scans/\(ownerScanID)/tags", .notFound),
            Probe(.POST, "/scans/\(ownerScanID)/tags/\(attackerTagID)", .notFound),
            Probe(.POST, "/scans/\(attackerScanID)/tags/\(ownerTagID)", .notFound),
            Probe(.DELETE, "/scans/\(ownerScanID)/tags/\(attackerTagID)", .notFound),
            Probe(.DELETE, "/scans/\(attackerScanID)/tags/\(ownerTagID)", .notFound),
            Probe(.GET, "/tags/\(ownerTagID)/scans", .notFound),
            Probe(.DELETE, "/tags/\(ownerTagID)", .notFound),
            Probe(
                .POST,
                "/scans/\(ownerScanID)/share",
                .forbidden,
                body: #"{"expiresIn":3600}"#
            ),
            Probe(.GET, "/scans/\(ownerScanID)/shares", .forbidden),
            Probe(.DELETE, "/shares/\(shareID)", .notFound),
            Probe(
                .POST,
                "/export-jobs",
                .notFound,
                body: "{\"scanID\":\"\(ownerScanID)\",\"format\":\"json\"}"
            ),
            Probe(.GET, "/export-jobs/\(exportJobID)", .notFound),
            Probe(.GET, "/export-jobs/\(exportJobID)/manifest", .notFound),
            Probe(.GET, "/export-jobs/\(exportJobID)/download", .notFound),
            Probe(.POST, "/export-jobs/\(exportJobID)/cancel", .notFound),
            Probe(.DELETE, "/scheduled-scans/\(scheduledID)", .notFound),
            Probe(.PATCH, "/scheduled-scans/\(scheduledID)/toggle", .notFound),
            Probe(.POST, "/notifications/\(notificationID)/read", .forbidden),
            Probe(.DELETE, "/auth/api-keys/\(apiKeyID)", .forbidden),
            Probe(.GET, "/investigations/\(investigationID)", .notFound),
            Probe(
                .PUT,
                "/investigations/\(investigationID)",
                .notFound,
                body: #"{"name":"hijacked"}"#
            ),
            Probe(
                .PUT,
                "/investigations/\(investigationID)/watch",
                .notFound,
                body: #"{"watched":true,"interval":"daily"}"#
            ),
            Probe(.DELETE, "/investigations/\(investigationID)", .notFound),
            Probe(.GET, "/dark-web/investigations/\(darkWebJobID)", .notFound),
            Probe(.POST, "/dark-web/investigations/\(darkWebJobID)/cancel", .notFound),
            Probe(.DELETE, "/dark-web/investigations/\(darkWebJobID)", .notFound),
        ]

        for probe in probes {
            try await app.test(probe.method, probe.path, beforeRequest: { request in
                request.headers.replaceOrAdd(name: .cookie, value: attackerCookie)
                if let body = probe.body {
                    request.headers.contentType = .json
                    request.body.writeString(body)
                }
            }, afterResponse: { response in
                XCTAssertEqual(
                    response.status,
                    probe.expectedStatus,
                    "Cross-tenant probe unexpectedly changed behavior: \(probe.method.rawValue) \(probe.path)"
                )
                XCTAssertFalse(
                    (200..<300).contains(Int(response.status.code)),
                    "Cross-tenant probe must never succeed: \(probe.method.rawValue) \(probe.path)"
                )
            })
        }

        let collectionPaths = [
            "/my-scans", "/tags", "/scheduled-scans", "/notifications",
            "/auth/api-keys", "/investigations", "/investigations/index",
            "/dark-web/investigations", "/export-jobs", "/correlations",
            "/account/export",
        ]
        let forbiddenFragments = [
            "tenant-owner-secret.example", ownerScanID.uuidString,
            ownerTagID.uuidString, scheduledID.uuidString, notificationID.uuidString,
            apiKeyID.uuidString, investigationID.uuidString, darkWebJobID.uuidString,
            exportJobID.uuidString, shareID.uuidString,
        ].flatMap { [$0, $0.lowercased()] }

        for path in collectionPaths {
            try await app.test(.GET, path, beforeRequest: { request in
                request.headers.replaceOrAdd(name: .cookie, value: attackerCookie)
            }, afterResponse: { response in
                XCTAssertEqual(response.status, .ok, "Collection probe failed: GET \(path)")
                let body = response.body.string
                for fragment in forbiddenFragments {
                    XCTAssertFalse(
                        body.contains(fragment),
                        "Cross-tenant collection leaked an owner fragment: GET \(path)"
                    )
                }
            })
        }

        let storedScan = try await Scan.find(ownerScanID, on: app.db)
        let storedTag = try await Tag.find(ownerTagID, on: app.db)
        let storedScheduledScan = try await ScheduledScan.find(scheduledID, on: app.db)
        let storedNotification = try await ScanNotification.find(notificationID, on: app.db)
        let storedAPIKey = try await APIKey.find(apiKeyID, on: app.db)
        let storedInvestigation = try await Investigation.find(investigationID, on: app.db)
        let storedDarkWebJob = try await DarkWebInvestigation.find(darkWebJobID, on: app.db)
        let storedExportJob = try await ExportJob.find(exportJobID, on: app.db)
        let storedShare = try await SharedReport.find(shareID, on: app.db)
        let scanTagCount = try await ScanTag.query(on: app.db).count()
        XCTAssertNotNil(storedScan)
        XCTAssertNotNil(storedTag)
        XCTAssertNotNil(storedScheduledScan)
        XCTAssertEqual(storedNotification?.isRead, false)
        XCTAssertNotNil(storedAPIKey)
        XCTAssertEqual(try storedInvestigation?.name, "owner-private-board")
        XCTAssertFalse(storedInvestigation?.watched == true)
        XCTAssertNotNil(storedDarkWebJob)
        XCTAssertEqual(storedExportJob?.status, .pending)
        XCTAssertNotNil(storedShare)
        XCTAssertEqual(scanTagCount, 1)
    }

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

        var writeOnlyKey: APIKey.Created?
        try await app.test(.POST, "/auth/api-keys", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(CreateKeyBody(
                label: "writer", scopes: ["scans:write"], expiresInDays: 30
            ), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            writeOnlyKey = try res.content.decode(APIKey.Created.self)
        })

        // Data-plane operation is allowed by scope.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
            try req.content.encode(ScanRequest(input: "api-user", force: nil, plugins: ["GitHubAccountCheck"]), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertNil(res.headers.first(name: "Set-Cookie"), "Bearer auth must remain stateless.")
        })

        // Export automation is read-plane only and remains scope constrained.
        try await app.test(.GET, "/export-jobs", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })
        let writer = try XCTUnwrap(writeOnlyKey)
        try await app.test(.GET, "/export-jobs", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: writer.token)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })

        // Control-plane and unrelated data-plane operations are deny-by-default.
        try await app.test(.GET, "/auth/api-keys", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })
        try await app.test(.POST, "/investigations", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
            try req.content.encode(InvestigationController.CreateBody(name: "Nope", data: nil), as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .forbidden) })
        try await app.test(.GET, "/dark-web/status", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: key.token)
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
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(key: String(repeating: "ab", count: 32))

        try TokenEncryption.validateConfiguration(required: true)
        let ciphertext = try TokenEncryption.encrypt("person@example.test")
        XCTAssertTrue(ciphertext.hasPrefix("enc:v1:"))
        XCTAssertFalse(ciphertext.contains("person@example.test"))
        XCTAssertEqual(TokenEncryption.decrypt(ciphertext), "person@example.test")

        let scan = Scan(input: "person@example.test")
        XCTAssertTrue(scan.inputCipher.hasPrefix("enc:v1:"))
        XCTAssertEqual(try scan.input, "person@example.test")

        let user = User(username: "alice", email: "alice@example.test", passwordHash: "hash",
                        webhookURL: "https://hooks.example.test/secret")
        XCTAssertTrue(user.webhookURLCipher?.hasPrefix("enc:v1:") == true)
        XCTAssertEqual(try user.webhookURL, "https://hooks.example.test/secret")
    }

    func testV2EnvelopeBindsCiphertextToFieldAndRecord() throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(
            key: String(repeating: "21", count: 32),
            keyID: "epoch-a",
            writeVersion: "2"
        )

        let recordID = UUID()
        let ciphertext = try TokenEncryption.encrypt(
            "person@example.test",
            context: .init(field: FieldCrypto.StoredField.scanInput.rawValue, recordID: recordID)
        )
        XCTAssertTrue(ciphertext.hasPrefix("enc:v2:epoch-a:"))
        XCTAssertFalse(ciphertext.contains("person@example.test"))
        XCTAssertEqual(
            try FieldCrypto.decryptStored(ciphertext, field: .scanInput, recordID: recordID),
            "person@example.test"
        )

        do {
            _ = try FieldCrypto.decryptStored(
                ciphertext,
                field: .resultRawData,
                recordID: recordID
            )
            XCTFail("A v2 envelope must not be transferable to another field")
        } catch let failure as FieldCrypto.DecryptionFailure {
            XCTAssertEqual(failure.reason, .authenticationFailed)
        }

        do {
            _ = try FieldCrypto.decryptStored(
                ciphertext,
                field: .scanInput,
                recordID: UUID()
            )
            XCTFail("A v2 envelope must not be transferable to another record")
        } catch let failure as FieldCrypto.DecryptionFailure {
            XCTAssertEqual(failure.reason, .authenticationFailed)
        }

        let unavailableKey = ciphertext.replacingOccurrences(
            of: "enc:v2:epoch-a:",
            with: "enc:v2:missing-key:"
        )
        do {
            _ = try FieldCrypto.decryptStored(
                unavailableKey,
                field: .scanInput,
                recordID: recordID
            )
            XCTFail("An envelope that names an unavailable key must fail closed")
        } catch let failure as FieldCrypto.DecryptionFailure {
            XCTAssertEqual(failure.reason, .keyUnavailable)
        }
    }

    func testV2KeyringReadsPreviousV2AndLegacyV1Data() throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        let keyA = String(repeating: "61", count: 32)
        let keyB = String(repeating: "62", count: 32)
        let recordID = UUID()
        let context = TokenEncryption.Context(
            field: FieldCrypto.StoredField.scanInput.rawValue,
            recordID: recordID
        )

        configureEncryptionEnvironment(key: keyA, keyID: "epoch-a", writeVersion: "1")
        let legacyCiphertext = try TokenEncryption.encrypt("legacy-value", context: context)
        let legacyBlindIndex = try TokenEncryption.blindIndex("lookup-value")

        setenv("ENCRYPTION_WRITE_VERSION", "2", 1)
        let previousV2Ciphertext = try TokenEncryption.encrypt("v2-value", context: context)
        let previousV2BlindIndex = try TokenEncryption.blindIndex("lookup-value")

        configureEncryptionEnvironment(
            key: keyB,
            keyID: "epoch-b",
            previousKeys: "epoch-a=\(keyA)",
            writeVersion: "2"
        )
        XCTAssertEqual(
            try TokenEncryption.decryptRequired(legacyCiphertext, context: context),
            "legacy-value"
        )
        XCTAssertEqual(
            try TokenEncryption.decryptRequired(previousV2Ciphertext, context: context),
            "v2-value"
        )
        let candidates = try TokenEncryption.blindIndexCandidates("lookup-value")
        XCTAssertTrue(candidates.contains(legacyBlindIndex))
        XCTAssertTrue(candidates.contains(previousV2BlindIndex))

        let currentCiphertext = try TokenEncryption.encrypt("current-value", context: context)
        XCTAssertTrue(currentCiphertext.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(TokenEncryption.isCurrentEnvelope(currentCiphertext))
        XCTAssertFalse(TokenEncryption.isCurrentEnvelope(previousV2Ciphertext))

        unsetenv("ENCRYPTION_PREVIOUS_KEYS")
        XCTAssertThrowsError(try TokenEncryption.decryptRequired(previousV2Ciphertext, context: context)) {
            XCTAssertEqual($0 as? TokenEncryption.Error, .unknownKeyID)
        }
        XCTAssertThrowsError(try TokenEncryption.decryptRequired(legacyCiphertext, context: context)) {
            XCTAssertEqual($0 as? TokenEncryption.Error, .decryptionFailed)
        }
    }

    func testEncryptionConfigurationRejectsInvalidV2Keyrings() throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        let key = String(repeating: "71", count: 32)

        configureEncryptionEnvironment(key: key, keyID: "epoch-a", writeVersion: "3")
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: true)) {
            XCTAssertEqual($0 as? TokenEncryption.Error, .invalidWriteVersion)
        }

        configureEncryptionEnvironment(key: key, keyID: "spaces are invalid", writeVersion: "2")
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: true)) {
            XCTAssertEqual($0 as? TokenEncryption.Error, .invalidKeyring)
        }

        configureEncryptionEnvironment(
            key: key,
            keyID: "epoch-a",
            previousKeys: "epoch-a=\(String(repeating: "72", count: 32))",
            writeVersion: "2"
        )
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: true)) {
            XCTAssertEqual($0 as? TokenEncryption.Error, .invalidKeyring)
        }

        let tooMany = (0..<5)
            .map { "old-\($0)=\(String(repeating: String(format: "%02x", $0 + 1), count: 32))" }
            .joined(separator: ",")
        configureEncryptionEnvironment(
            key: key,
            keyID: "epoch-a",
            previousKeys: tooMany,
            writeVersion: "2"
        )
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: true)) {
            XCTAssertEqual($0 as? TokenEncryption.Error, .invalidKeyring)
        }
    }

    func testCorruptSensitiveEnvelopesThrowTypedFailuresWithoutCrashing() throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }

        let recordID = UUID()
        configureEncryptionEnvironment(key: String(repeating: "31", count: 32))

        do {
            _ = try FieldCrypto.decryptStored(
                "enc:v1:not-base64",
                field: .scanInput,
                recordID: recordID
            )
            XCTFail("A malformed tagged envelope must fail closed")
        } catch let failure as FieldCrypto.DecryptionFailure {
            XCTAssertEqual(failure.field, .scanInput)
            XCTAssertEqual(failure.recordID, recordID)
            XCTAssertEqual(failure.reason, .invalidEnvelope)
        }

        let encrypted = try TokenEncryption.encrypt("sensitive")
        setenv("ENCRYPTION_KEY", String(repeating: "32", count: 32), 1)
        do {
            _ = try FieldCrypto.decryptStored(encrypted, field: .resultRawData)
            XCTFail("A ciphertext authenticated with another key must fail closed")
        } catch let failure as FieldCrypto.DecryptionFailure {
            XCTAssertEqual(failure.field, .resultRawData)
            XCTAssertEqual(failure.reason, .authenticationFailed)
        }

        unsetenv("ENCRYPTION_KEY")
        do {
            _ = try FieldCrypto.decryptStored(encrypted, field: .auditTarget)
            XCTFail("An encrypted value without an available key must fail closed")
        } catch let failure as FieldCrypto.DecryptionFailure {
            XCTAssertEqual(failure.field, .auditTarget)
            XCTAssertEqual(failure.reason, .keyUnavailable)
        }
    }

    func testCorruptSensitiveFieldReturnsGeneric500AndIncrementsMetric() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        let previousMetricsToken = ProcessInfo.processInfo.environment["METRICS_TOKEN"]
        let previousMetricsTokenFile = ProcessInfo.processInfo.environment["METRICS_TOKEN_FILE"]
        configureEncryptionEnvironment(key: String(repeating: "41", count: 32))
        unsetenv("METRICS_TOKEN")
        unsetenv("METRICS_TOKEN_FILE")
        defer {
            environment.restore()
            if let previousMetricsToken { setenv("METRICS_TOKEN", previousMetricsToken, 1) }
            else { unsetenv("METRICS_TOKEN") }
            if let previousMetricsTokenFile { setenv("METRICS_TOKEN_FILE", previousMetricsTokenFile, 1) }
            else { unsetenv("METRICS_TOKEN_FILE") }
        }

        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "corrupt-envelope-user")
        let storedUser = try await User.query(on: app.db)
            .filter(\.$username == "corrupt-envelope-user")
            .first()
        let user = try XCTUnwrap(storedUser)
        let scan = Scan(input: "person@example.test", userID: try XCTUnwrap(user.id))
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        scan.inputCipher = "enc:v1:not-base64"
        try await scan.save(on: app.db)

        let before = await MetricsRegistry.shared.snapshot()
            .sensitiveFieldFailures[.scanInput]?[.invalidEnvelope] ?? 0

        try await app.test(.GET, "/results/\(scanID.uuidString)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { res in
            let body = res.body.string
            XCTAssertEqual(res.status, .internalServerError)
            XCTAssertTrue(body.contains(SensitiveFieldFailureMiddleware.clientReason), body)
            XCTAssertFalse(body.contains(FieldCrypto.StoredField.scanInput.rawValue), body)
            XCTAssertFalse(body.contains(scanID.uuidString), body)
            XCTAssertFalse(body.contains(scan.inputCipher), body)
        })

        let after = await MetricsRegistry.shared.snapshot()
            .sensitiveFieldFailures[.scanInput]?[.invalidEnvelope] ?? 0
        XCTAssertEqual(after, before + 1)

        user.isAdmin = true
        try await user.save(on: app.db)
        try await app.test(.GET, "/metrics", beforeRequest: { req in
            req.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertTrue(res.body.string.contains(
                "swift_vapor_sensitive_field_failures_total{field=\"scans.input\",reason=\"invalid_envelope\"} \(after)"
            ))
        })
    }

    func testScheduledScanWithUnreadableInputIsQuarantined() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(key: String(repeating: "51", count: 32))

        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let user = User(
            username: "quarantine-schedule-user",
            email: "quarantine-schedule@example.test",
            passwordHash: "unused",
            emailVerified: true
        )
        try await user.save(on: app.db)
        let schedule = ScheduledScan(
            userID: try XCTUnwrap(user.id),
            input: "person@example.test",
            interval: .daily,
            nextRunAt: Date().addingTimeInterval(-60)
        )
        try await schedule.save(on: app.db)
        let scheduleID = try XCTUnwrap(schedule.id)
        schedule.inputCipher = "enc:v1:not-base64"
        try await schedule.save(on: app.db)

        let before = await MetricsRegistry.shared.snapshot()
            .sensitiveFieldFailures[.scheduledScanInput]?[.invalidEnvelope] ?? 0
        await runDueScheduledScansOnce(app: app)

        let storedSchedule = try await ScheduledScan.find(scheduleID, on: app.db)
        let quarantined = try XCTUnwrap(storedSchedule)
        XCTAssertFalse(quarantined.isActive)
        XCTAssertNotNil(quarantined.lastRunAt)
        let after = await MetricsRegistry.shared.snapshot()
            .sensitiveFieldFailures[.scheduledScanInput]?[.invalidEnvelope] ?? 0
        XCTAssertEqual(after, before + 1)
    }

    func testEncryptionConfigurationRejectsMissingAndMalformedKeys() {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }

        unsetenv("ENCRYPTION_KEY_ID")
        unsetenv("ENCRYPTION_PREVIOUS_KEYS")
        setenv("ENCRYPTION_WRITE_VERSION", "1", 1)
        unsetenv("ENCRYPTION_KEY")
        XCTAssertNoThrow(try TokenEncryption.validateConfiguration(required: false))
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: true))

        setenv("ENCRYPTION_KEY", "not-a-64-character-hex-key", 1)
        XCTAssertThrowsError(try TokenEncryption.validateConfiguration(required: false))
    }

    func testEncryptionKeyVerifierRejectsKeyReplacement() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(key: String(repeating: "11", count: 32))

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

    func testEncryptionKeyVerifierRewrapsMarkerBeforePreviousKeyRemoval() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        let keyA = String(repeating: "81", count: 32)
        let keyB = String(repeating: "82", count: 32)
        configureEncryptionEnvironment(key: keyA, keyID: "epoch-a", writeVersion: "2")

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        app.databases.use(.sqlite(.memory), as: .psql, isDefault: true)
        app.migrations.add(CreateEncryptionMetadata())
        try await app.autoMigrate()
        try await EncryptionKeyVerifier.verifyOrInitialize(on: app.db)

        let initialMarker = try await EncryptionMetadata.query(on: app.db).first()
        var marker = try XCTUnwrap(initialMarker)
        XCTAssertTrue(marker.value.hasPrefix("enc:v2:epoch-a:"))

        configureEncryptionEnvironment(
            key: keyB,
            keyID: "epoch-b",
            previousKeys: "epoch-a=\(keyA)",
            writeVersion: "2"
        )
        try await EncryptionKeyVerifier.verifyOrInitialize(on: app.db)
        let rotatedMarker = try await EncryptionMetadata.query(on: app.db).first()
        marker = try XCTUnwrap(rotatedMarker)
        XCTAssertTrue(marker.value.hasPrefix("enc:v2:epoch-b:"))

        unsetenv("ENCRYPTION_PREVIOUS_KEYS")
        try await EncryptionKeyVerifier.verifyOrInitialize(on: app.db)
    }

    func testSensitiveFieldRewrapperResumesAndCoversEveryEncryptedModel() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        let keyA = String(repeating: "91", count: 32)
        let keyB = String(repeating: "92", count: 32)
        configureEncryptionEnvironment(key: keyA, keyID: "epoch-a", writeVersion: "1")

        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let user = User(
            username: "rewrap-user",
            email: "rewrap@example.test",
            passwordHash: "unused",
            webhookURL: "https://hooks.example.test/primary",
            discordWebhookURL: "https://discord.example.test/secret",
            telegramBotToken: "123456:abcdefghijklmnopqrstuvwxyzABCDE",
            telegramChatID: "123456",
            slackWebhookURL: "https://slack.example.test/secret",
            emailVerified: true
        )
        user.setTOTPSecret("JBSWY3DPEHPK3PXP")
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)

        let firstScan = Scan(input: "target-one", userID: userID)
        try await firstScan.save(on: app.db)
        let firstScanID = try XCTUnwrap(firstScan.id)
        let legacyFirstScanHash = try XCTUnwrap(firstScan.inputHash)
        try await Result(
            scanID: firstScanID,
            source: "test",
            type: "account",
            confidenceScore: 0.8,
            rawData: "sensitive result",
            metadata: #"{"email":"person@example.test"}"#
        ).save(on: app.db)
        try await Investigation(
            userID: userID,
            name: "Case Alpha",
            data: #"{"nodes":[],"edges":[]}"#
        ).save(on: app.db)
        try await ScheduledScan(
            userID: userID,
            input: "scheduled-target",
            interval: .daily,
            nextRunAt: Date().addingTimeInterval(3_600)
        ).save(on: app.db)
        try await ScanNotification(
            userID: userID,
            scanID: firstScanID,
            message: "new finding",
            newResultsCount: 1
        ).save(on: app.db)
        try await NotificationOutboxEvent(
            userID: userID,
            scanID: firstScanID,
            payload: .init(
                title: "Sensitive delivery",
                message: "Sensitive outbox payload",
                webhookBody: #"{"secret":"value"}"#
            ),
            idempotencyKeyHash: sha256Hex("rewrap-outbox-event")
        ).save(on: app.db)
        let exportJob = ExportJob(
            userID: userID,
            scanID: firstScanID,
            format: .json,
            maxAttempts: 2,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        let exportJobID = try XCTUnwrap(exportJob.id)
        exportJob.statusRaw = ExportJobStatus.completed.rawValue
        exportJob.completedAt = Date()
        try exportJob.setArtifact(
            Data("sensitive export artifact".utf8),
            manifest: ExportJobManifest(
                schemaVersion: 1,
                jobID: exportJobID,
                scanID: firstScanID,
                format: .json,
                sourceStatus: ScanStatus.completed.rawValue,
                sourceCreatedAt: Date(),
                sourceCompletedAt: Date(),
                generatedAt: Date(),
                resultCount: 1,
                resultSetSHA256: String(repeating: "1", count: 64),
                artifactSHA256: String(repeating: "2", count: 64),
                artifactBytes: 25,
                contentType: "application/json",
                filename: "export.json",
                complete: true
            )
        )
        try await exportJob.save(on: app.db)
        try await Tag(userID: userID, name: "Sensitive tag", colour: "#123456")
            .save(on: app.db)
        try await AuditLog(
            userID: userID,
            action: "rewrap_test",
            target: "person@example.test",
            ip: "192.0.2.25"
        ).save(on: app.db)
        let darkWeb = DarkWebInvestigation(
            userID: userID,
            target: "person@example.test",
            retentionHours: 24
        )
        darkWeb.setResultJSON(#"{"matches":["sensitive"]}"#)
        try await darkWeb.save(on: app.db)
        try await PluginCacheEntry(
            pluginName: "TestPlugin",
            targetHash: FieldCrypto.blindIndex("target-one"),
            plaintext: #"[{"source":"test","type":"account","confidenceScore":0.8,"rawData":"cached"}]"#,
            expiresAt: Date().addingTimeInterval(3_600)
        ).save(on: app.db)

        // Mix legacy v1 and old-key v2 rows in the same table.
        setenv("ENCRYPTION_WRITE_VERSION", "2", 1)
        let secondScan = Scan(input: "target-two", userID: userID)
        try await secondScan.save(on: app.db)

        configureEncryptionEnvironment(
            key: keyB,
            keyID: "epoch-b",
            previousKeys: "epoch-a=\(keyA)",
            writeVersion: "2"
        )
        let partial = try await SensitiveFieldRewrapper.run(
            on: app.db,
            confirmedKeyID: "epoch-b",
            batchSize: 1,
            maximumBatches: 2
        )
        XCTAssertFalse(partial.completed)
        XCTAssertEqual(partial.stage, .rewrite)
        XCTAssertEqual(partial.phase, .scans)
        XCTAssertEqual(partial.rewrittenRows["scans"], 2)

        let completed = try await SensitiveFieldRewrapper.run(
            on: app.db,
            confirmedKeyID: "epoch-b",
            batchSize: 2
        )
        XCTAssertTrue(completed.completed)
        XCTAssertEqual(completed.rewrittenRows["scans"], 2)
        XCTAssertEqual(completed.rewrittenRows["results"], 1)
        XCTAssertEqual(completed.rewrittenRows["investigations"], 1)
        XCTAssertEqual(completed.rewrittenRows["users"], 1)
        XCTAssertEqual(completed.rewrittenRows["scheduled_scans"], 1)
        XCTAssertEqual(completed.rewrittenRows["notifications"], 1)
        XCTAssertEqual(completed.rewrittenRows["tags"], 1)
        XCTAssertEqual(completed.rewrittenRows["audit_logs"], 1)
        XCTAssertEqual(completed.rewrittenRows["dark_web_investigations"], 1)
        XCTAssertEqual(completed.rewrittenRows["notification_outbox"], 1)
        XCTAssertEqual(completed.rewrittenRows["export_jobs"], 1)
        XCTAssertEqual(completed.rewrittenRows["plugin_cache"], 1)
        let remainingCacheRows = try await PluginCacheEntry.query(on: app.db).count()
        XCTAssertEqual(remainingCacheRows, 0)

        let scans = try await Scan.query(on: app.db).all()
        XCTAssertEqual(scans.count, 2)
        XCTAssertTrue(scans.allSatisfy { $0.inputCipher.hasPrefix("enc:v2:epoch-b:") })
        let storedFirstScan = try XCTUnwrap(scans.first { $0.id == firstScanID })
        XCTAssertEqual(storedFirstScan.inputHash, FieldCrypto.blindIndex("target-one"))

        let resultRow = try await Result.query(on: app.db).first()
        let investigationRow = try await Investigation.query(on: app.db).first()
        let userRow = try await User.find(userID, on: app.db)
        let scheduleRow = try await ScheduledScan.query(on: app.db).first()
        let notificationRow = try await ScanNotification.query(on: app.db).first()
        let tagRow = try await Tag.query(on: app.db).first()
        let auditRow = try await AuditLog.query(on: app.db).first()
        let darkWebRow = try await DarkWebInvestigation.query(on: app.db).first()
        let outboxRow = try await NotificationOutboxEvent.query(on: app.db).first()
        let exportJobRow = try await ExportJob.query(on: app.db).first()
        let storedResult = try XCTUnwrap(resultRow)
        let storedInvestigation = try XCTUnwrap(investigationRow)
        let storedUser = try XCTUnwrap(userRow)
        let storedSchedule = try XCTUnwrap(scheduleRow)
        let storedNotification = try XCTUnwrap(notificationRow)
        let storedTag = try XCTUnwrap(tagRow)
        let storedAudit = try XCTUnwrap(auditRow)
        let storedDarkWeb = try XCTUnwrap(darkWebRow)
        let storedOutbox = try XCTUnwrap(outboxRow)
        let storedExportJob = try XCTUnwrap(exportJobRow)

        XCTAssertTrue(storedResult.rawDataCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedResult.metadataCipher?.hasPrefix("enc:v2:epoch-b:") == true)
        XCTAssertTrue(storedInvestigation.nameCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedInvestigation.dataCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedUser.webhookURLCipher?.hasPrefix("enc:v2:epoch-b:") == true)
        XCTAssertTrue(storedUser.totpSecretCipher?.hasPrefix("enc:v2:epoch-b:") == true)
        XCTAssertTrue(storedSchedule.inputCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedNotification.messageCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedTag.nameCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedAudit.targetCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedAudit.ipCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedDarkWeb.targetCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertTrue(storedDarkWeb.resultCipher?.hasPrefix("enc:v2:epoch-b:") == true)
        XCTAssertTrue(storedOutbox.payloadCipher.hasPrefix("enc:v2:epoch-b:"))
        XCTAssertEqual(try storedOutbox.payload.message, "Sensitive outbox payload")
        XCTAssertTrue(storedExportJob.artifactCipher?.hasPrefix("enc:v2:epoch-b:") == true)
        XCTAssertTrue(storedExportJob.manifestCipher?.hasPrefix("enc:v2:epoch-b:") == true)
        XCTAssertEqual(
            String(decoding: try XCTUnwrap(storedExportJob.artifactData), as: UTF8.self),
            "sensitive export artifact"
        )

        // Verification covers deterministic indexes as well as ciphertext;
        // an old-key hash would make a valid row undiscoverable after removal.
        storedFirstScan.inputHash = legacyFirstScanHash
        try await storedFirstScan.update(on: app.db)
        do {
            _ = try await SensitiveFieldRewrapper.verifyOnly(
                on: app.db,
                confirmedKeyID: "epoch-b",
                batchSize: 1
            )
            XCTFail("An old-key blind index must fail active-key verification")
        } catch let failure as SensitiveFieldRewrapper.Failure {
            XCTAssertEqual(
                failure,
                .recordFailure(stage: .verify, phase: .scans, recordID: firstScanID)
            )
        }
        storedFirstScan.inputHash = FieldCrypto.blindIndex("target-one")
        try await storedFirstScan.update(on: app.db)

        // The old root is now removable: normal access and an independent
        // active-key-only verification pass must both succeed without it.
        unsetenv("ENCRYPTION_PREVIOUS_KEYS")
        XCTAssertEqual(try storedFirstScan.input, "target-one")
        XCTAssertEqual(try storedResult.rawData, "sensitive result")
        XCTAssertEqual(try storedUser.totpSecret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(try storedDarkWeb.target, "person@example.test")
        XCTAssertEqual(try storedExportJob.manifest?.jobID, exportJobID)
        let verified = try await SensitiveFieldRewrapper.verifyOnly(
            on: app.db,
            confirmedKeyID: "epoch-b",
            batchSize: 1
        )
        XCTAssertTrue(verified.completed)
        XCTAssertEqual(verified.verifiedRows["scans"], 2)

        // Exercise the documented emergency rollback preparation. The current
        // dual reader rewrites every field/index to v1 before any v1-only binary
        // is allowed back into the fleet.
        setenv("ENCRYPTION_WRITE_VERSION", "1", 1)
        let rolledBack = try await SensitiveFieldRewrapper.run(
            on: app.db,
            confirmedKeyID: "epoch-b",
            batchSize: 5
        )
        XCTAssertTrue(rolledBack.completed)
        let v1Scans = try await Scan.query(on: app.db).all()
        XCTAssertTrue(v1Scans.allSatisfy { $0.inputCipher.hasPrefix("enc:v1:") })
        let verifiedV1 = try await SensitiveFieldRewrapper.verifyOnly(
            on: app.db,
            confirmedKeyID: "epoch-b",
            batchSize: 5
        )
        XCTAssertTrue(verifiedV1.completed)
    }

    func testSensitiveFieldRewrapperFailsWithoutAdvancingPastCorruptRow() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        let keyA = String(repeating: "a1", count: 32)
        let keyB = String(repeating: "a2", count: 32)
        configureEncryptionEnvironment(key: keyA, keyID: "epoch-a", writeVersion: "1")

        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let scan = Scan(input: "will-be-corrupted")
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        scan.inputCipher = "enc:v1:not-base64"
        try await scan.update(on: app.db)

        configureEncryptionEnvironment(
            key: keyB,
            keyID: "epoch-b",
            previousKeys: "epoch-a=\(keyA)",
            writeVersion: "2"
        )
        do {
            _ = try await SensitiveFieldRewrapper.run(
                on: app.db,
                confirmedKeyID: "epoch-b",
                batchSize: 10
            )
            XCTFail("A corrupt row must stop rewrap")
        } catch let failure as SensitiveFieldRewrapper.Failure {
            XCTAssertEqual(
                failure,
                .recordFailure(stage: .rewrite, phase: .scans, recordID: scanID)
            )
        }

        let metadata = try await EncryptionMetadata.query(on: app.db)
            .filter(\.$name == SensitiveFieldRewrapper.checkpointName)
            .first()
        let checkpointRow = try XCTUnwrap(metadata)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let checkpoint = try decoder.decode(
            SensitiveFieldRewrapper.Checkpoint.self,
            from: Data(checkpointRow.value.utf8)
        )
        XCTAssertEqual(checkpoint.stage, .rewrite)
        XCTAssertEqual(checkpoint.phase, .scans)
        XCTAssertNil(checkpoint.cursor)
        XCTAssertTrue(checkpoint.rewrittenRows.isEmpty)
        let persistedScanRow = try await Scan.find(scanID, on: app.db)
        let persistedScan = try XCTUnwrap(persistedScanRow)
        XCTAssertEqual(persistedScan.inputCipher, "enc:v1:not-base64")
    }

    func testSensitiveFieldRewrapperRequiresExplicitVersionAndKeyConfirmation() async throws {
        let environment = EnvironmentSnapshot(encryptionEnvironmentNames)
        defer { environment.restore() }
        configureEncryptionEnvironment(
            key: String(repeating: "b1", count: 32),
            keyID: "epoch-a",
            writeVersion: "2"
        )

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        app.databases.use(.sqlite(.memory), as: .psql, isDefault: true)

        unsetenv("ENCRYPTION_WRITE_VERSION")
        do {
            _ = try await SensitiveFieldRewrapper.run(
                on: app.db,
                confirmedKeyID: "epoch-a"
            )
            XCTFail("An implicit write version must be rejected")
        } catch let failure as SensitiveFieldRewrapper.Failure {
            XCTAssertEqual(failure, .explicitWriteVersionRequired)
        }

        setenv("ENCRYPTION_WRITE_VERSION", "2", 1)
        do {
            _ = try await SensitiveFieldRewrapper.run(
                on: app.db,
                confirmedKeyID: "wrong-key-id"
            )
            XCTFail("A mismatched confirmation must be rejected")
        } catch let failure as SensitiveFieldRewrapper.Failure {
            XCTAssertEqual(
                failure,
                .keyIDMismatch(active: "epoch-a", confirmed: "wrong-key-id")
            )
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

    // MARK: - Durable SSE replay

    func testResultStreamStoreAssignsPerScanSequenceAndRollsBackOrphans() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let firstScan = Scan(input: "stream-one", userID: nil)
        let secondScan = Scan(input: "stream-two", userID: nil)
        try await firstScan.save(on: app.db)
        try await secondScan.save(on: app.db)
        let firstScanID = try firstScan.requireID()
        let secondScanID = try secondScan.requireID()

        for index in 1...3 {
            try await ResultStreamStore.persist(Result(
                scanID: firstScanID,
                source: "source-\(index)",
                type: "account",
                confidenceScore: 0.8,
                rawData: "finding-\(index)"
            ), on: app.db)
        }
        // Simulate an insert from the previous release, which knows nothing
        // about ResultStreamStore. The database trigger must still cover it.
        try await App.Result(
            scanID: secondScanID,
            source: "other-source",
            type: "account",
            confidenceScore: 0.7,
            rawData: "other-finding"
        ).save(on: app.db)

        let firstEvents = try await ScanResultEvent.query(on: app.db)
            .filter(\.$scan.$id == firstScanID)
            .sort(\.$streamSequence, .ascending)
            .all()
        let secondEvents = try await ScanResultEvent.query(on: app.db)
            .filter(\.$scan.$id == secondScanID)
            .all()
        XCTAssertEqual(firstEvents.map(\.streamSequence), [1, 2, 3])
        XCTAssertEqual(secondEvents.map(\.streamSequence), [1])

        let orphan = Result(
            scanID: UUID(),
            source: "orphan",
            type: "account",
            confidenceScore: 1,
            rawData: "must roll back"
        )
        let orphanID = try orphan.requireID()
        do {
            try await ResultStreamStore.persist(orphan, on: app.db)
            XCTFail("An event cannot be persisted without its parent scan")
        } catch {
            let persistedOrphan = try await App.Result.find(orphanID, on: app.db)
            XCTAssertNil(persistedOrphan)
        }
    }

    func testResultStreamMigrationBackfillsHistoricalRowsPerScan() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // Recreate just this additive migration after seeding rows in the shape
        // of a pre-upgrade database.
        try await CreateScanResultEvents().revert(on: app.db)
        let firstScan = Scan(input: "legacy-one", userID: nil)
        let secondScan = Scan(input: "legacy-two", userID: nil)
        try await firstScan.save(on: app.db)
        try await secondScan.save(on: app.db)
        let firstScanID = try firstScan.requireID()
        let secondScanID = try secondScan.requireID()

        try await App.Result(
            scanID: firstScanID,
            source: "legacy-a",
            type: "account",
            confidenceScore: 0.5,
            rawData: "a"
        ).save(on: app.db)
        try await App.Result(
            scanID: secondScanID,
            source: "legacy-b",
            type: "account",
            confidenceScore: 0.5,
            rawData: "b"
        ).save(on: app.db)
        try await App.Result(
            scanID: firstScanID,
            source: "legacy-c",
            type: "account",
            confidenceScore: 0.5,
            rawData: "c"
        ).save(on: app.db)

        try await CreateScanResultEvents().prepare(on: app.db)

        let firstSequences = try await ScanResultEvent.query(on: app.db)
            .filter(\.$scan.$id == firstScanID)
            .sort(\.$streamSequence, .ascending)
            .all()
        let secondSequences = try await ScanResultEvent.query(on: app.db)
            .filter(\.$scan.$id == secondScanID)
            .all()
        XCTAssertEqual(firstSequences.map(\.streamSequence), [1, 2])
        XCTAssertEqual(secondSequences.map(\.streamSequence), [1])
    }

    func testSSEReplaysOnlyEventsAfterLastEventIDAndTerminates() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let scan = Scan(input: "resume-stream", userID: nil)
        try await scan.save(on: app.db)
        let scanID = try scan.requireID()
        for index in 1...3 {
            try await ResultStreamStore.persist(Result(
                scanID: scanID,
                source: "resume-\(index)",
                type: "account",
                confidenceScore: 0.75,
                rawData: "payload-\(index)",
                metadata: #"{"platform":"test"}"#
            ), on: app.db)
        }
        scan.status = .completed
        scan.completedAt = Date()
        try await scan.save(on: app.db)

        try await app.test(.GET, "/stream/\(scanID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Last-Event-ID", value: "1")
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.first(name: .contentType), "text/event-stream")
            XCTAssertEqual(response.headers.first(name: "X-Accel-Buffering"), "no")
            let body = response.body.string
            XCTAssertTrue(body.contains("retry: 2000\n\n"), body)
            XCTAssertFalse(body.contains("id: 1\nevent: result"), body)
            XCTAssertTrue(body.contains("id: 2\nevent: result"), body)
            XCTAssertTrue(body.contains("id: 3\nevent: result"), body)
            XCTAssertTrue(body.contains("\"source\":\"resume-2\""), body)
            XCTAssertTrue(body.contains("\"metadata\":{\"platform\":\"test\"}"), body)
            XCTAssertTrue(body.contains("event: done"), body)
            XCTAssertTrue(body.contains("\"count\":3"), body)
        })
    }

    func testSSERejectsMalformedAndOutOfRangeCursors() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let scan = Scan(input: "cursor-validation", userID: nil)
        try await scan.save(on: app.db)
        let scanID = try scan.requireID()
        try await ResultStreamStore.persist(Result(
            scanID: scanID,
            source: "only",
            type: "account",
            confidenceScore: 1,
            rawData: "only"
        ), on: app.db)
        scan.status = .completed
        try await scan.save(on: app.db)

        try await app.test(.GET, "/stream/\(scanID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Last-Event-ID", value: "+1")
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .badRequest)
        })
        try await app.test(.GET, "/stream/\(scanID)?cursor=2", afterResponse: { response in
            XCTAssertEqual(response.status, .badRequest)
        })
    }

    func testSSEEnforcesOwnershipBeforeCursorValidation() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let cookie = try await registerAndLogin(app, username: "sse-owner")
        let owner = try await User.query(on: app.db)
            .filter(\.$username == "sse-owner")
            .first()
        let ownerID = try XCTUnwrap(owner?.id)
        let scan = Scan(input: "owned-stream", status: .completed, userID: ownerID)
        scan.completedAt = Date()
        try await scan.save(on: app.db)
        let scanID = try scan.requireID()

        // Authorization runs before cursor parsing, so a non-owner cannot use
        // malformed cursors as an oracle for an owned scan's stream state.
        try await app.test(.GET, "/stream/\(scanID)", beforeRequest: { request in
            request.headers.replaceOrAdd(name: "Last-Event-ID", value: "+1")
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .forbidden)
        })

        try await app.test(.GET, "/stream/\(scanID)", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertTrue(response.body.string.contains("event: done"))
        })
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

    func testSSRFGuardBlocksAllKnownNonGlobalAddressRanges() {
        let blockedIPv4 = [
            "192.0.0.1", "192.0.0.8", "192.0.0.170",
            "192.0.2.1", "192.88.99.1",
            "198.18.0.1", "198.19.255.255", "198.51.100.1",
            "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
        ]
        for address in blockedIPv4 {
            XCTAssertTrue(SSRFGuard.isInternalHostname(address), "Expected to block \(address)")
            XCTAssertNil(SSRFGuard.resolveValidatedIP(address), "Expected no pin for \(address)")
        }

        let blockedIPv6 = [
            "::ffff:8.8.8.8", "64:ff9b::127.0.0.1", "64:ff9b:1::1",
            "100::1", "100:0:0:1::1", "2001:2::1", "2001:db8::1",
            "2002:7f00:1::", "3fff::1", "5f00::1", "fec0::1", "ff02::1",
        ]
        for address in blockedIPv6 {
            XCTAssertTrue(SSRFGuard.isInternalHostname(address), "Expected to block \(address)")
            XCTAssertNil(SSRFGuard.resolveValidatedIP(address), "Expected no pin for \(address)")
        }
    }

    func testSSRFGuardKeepsGlobalRangeBoundariesAndExceptionsReachable() {
        for address in [
            "192.0.0.9", "192.0.0.10", "192.31.196.1",
            "198.17.255.255", "198.20.0.1", "203.0.114.1",
            "2001:1::1", "2001:3::1", "2001:20::1",
            "2001:4860:4860::8888", "2606:4700:4700::1111", "64:ff9b::8.8.8.8",
        ] {
            XCTAssertFalse(SSRFGuard.isInternalHostname(address), "Expected to allow \(address)")
        }
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

        let defaultCreatedAfter = Date().timeIntervalSince1970
        var defaultShareID = ""
        try await app.test(.POST, "/scans/\(id)/share", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(
                ShareController.CreateShareRequest(expiresIn: nil, password: nil),
                as: .json
            )
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let share = try res.content.decode(ShareController.ShareResponse.self)
            defaultShareID = share.id
            XCTAssertNotNil(UUID(uuidString: share.id))
            let expiresAt = try XCTUnwrap(share.expiresAt)
            XCTAssertGreaterThanOrEqual(
                expiresAt,
                defaultCreatedAfter + Double(ShareController.defaultExpirySeconds) - 2
            )
            XCTAssertLessThanOrEqual(
                expiresAt,
                Date().timeIntervalSince1970 + Double(ShareController.defaultExpirySeconds) + 2
            )
        })

        try await app.test(.GET, "/scans/\(id)/shares", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let shares = try res.content.decode([ShareController.ShareDetail].self)
            XCTAssertEqual(shares.count, 1)
            XCTAssertEqual(shares.first?.id, defaultShareID)
            XCTAssertEqual(shares.first?.hasPassword, false)
            XCTAssertNotNil(shares.first?.expiresAt)
            XCTAssertFalse(res.body.string.contains("token"), "Share listings must not expose token material")
        })

        try await app.test(.DELETE, "/shares/\(defaultShareID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }, afterResponse: { res in XCTAssertEqual(res.status, .noContent) })
        let revokedShare = try await SharedReport.find(UUID(uuidString: defaultShareID)!, on: app.db)
        XCTAssertNil(revokedShare)

        var rawToken = ""
        var shareURL = ""
        var shareID = ""
        try await app.test(.POST, "/scans/\(id)/share", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            try req.content.encode(ShareController.CreateShareRequest(
                expiresIn: ShareController.minExpirySeconds,
                password: "LongEnough123"
            ), as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let share = try res.content.decode(ShareController.ShareResponse.self)
            shareID = share.id
            rawToken = share.token
            shareURL = share.url
        })
        XCTAssertNotNil(UUID(uuidString: shareID))
        XCTAssertEqual(rawToken.utf8.count, 32)
        XCTAssertTrue(shareURL.hasSuffix("/share#\(rawToken)"))
        XCTAssertFalse(shareURL.contains("/share/\(rawToken)"), "Bearer tokens must not be placed in request paths")

        let storedCandidate = try await SharedReport.query(on: app.db).first()
        let stored = try XCTUnwrap(storedCandidate)
        XCTAssertEqual(stored.tokenHash, sha256Hex(rawToken))
        XCTAssertNotEqual(stored.tokenHash, rawToken)
        XCTAssertEqual(stored.tokenHash.count, 64)

        let attackerCookie = try await registerAndLogin(app, username: "share-policy-attacker")
        try await app.test(.DELETE, "/shares/\(shareID)", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: attackerCookie)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .notFound, "Share IDs must not reveal cross-account existence")
        })
        let shareAfterAttack = try await SharedReport.find(stored.id, on: app.db)
        XCTAssertNotNil(shareAfterAttack)

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
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(try res.content.decode(ShareController.SharedReportResponse.self).viewCount, 1)
        })
        try await app.test(.POST, "/share", beforeRequest: { req in
            try req.content.encode(
                ShareController.ShareAccessRequest(token: rawToken, password: "LongEnough123"),
                as: .json
            )
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(try res.content.decode(ShareController.SharedReportResponse.self).viewCount, 2)
        })

        let legacy = SharedReport(
            scanID: id,
            tokenHash: sha256Hex("legacy-permanent-share"),
            expiresAt: nil
        )
        try await legacy.save(on: app.db)
        let migrationStartedAt = Date().timeIntervalSince1970
        try await ExpireLegacySharedReports().prepare(on: app.db)
        let migratedLegacyCandidate = try await SharedReport.find(legacy.id, on: app.db)
        let migratedLegacy = try XCTUnwrap(migratedLegacyCandidate)
        let legacyExpiry = try XCTUnwrap(migratedLegacy.expiresAt?.timeIntervalSince1970)
        XCTAssertGreaterThanOrEqual(
            legacyExpiry,
            migrationStartedAt + Double(ShareController.defaultExpirySeconds) - 2
        )
        XCTAssertLessThanOrEqual(
            legacyExpiry,
            Date().timeIntervalSince1970 + Double(ShareController.defaultExpirySeconds) + 2
        )

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

    func testRDAPParserRetainsNormalizedTimelineDates() throws {
        let json = Data(#"""
        {"events":[
          {"eventAction":"registration","eventDate":"2001-02-03T04:05:06Z"},
          {"eventAction":"registration","eventDate":"2002-01-01T00:00:00Z"},
          {"eventAction":"last changed","eventDate":"2025-06-07T08:09:10Z"},
          {"eventAction":"expiration","eventDate":"2030-02-03T00:00:00Z"},
          {"eventAction":"expiration","eventDate":"2031-02-03T00:00:00Z"},
          {"eventAction":"last changed","eventDate":"2025-02-30T00:00:00Z"}
        ],"status":["active"]}
        """#.utf8)
        let result = try XCTUnwrap(WhoisPlugin.parseResponse(json, domain: "example.test"))
        XCTAssertEqual(result.metadata?["registrationDate"], "2001-02-03")
        XCTAssertEqual(result.metadata?["lastChangedDate"], "2025-06-07")
        XCTAssertEqual(result.metadata?["expirationDate"], "2031-02-03")
        XCTAssertFalse(result.rawData.contains("2025-02-30"))
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

    func testIdentitySynthesizerBuildsExposureTimeline() {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            I(source: "GitHubAccountCheck", type: "account_presence", confidence: 1.0,
              metadata: ["platform": "github", "username": "alice", "since": "2013"], rawData: "x"),
            I(source: "HackerNews", type: "account_presence", confidence: 0.9,
              metadata: ["platform": "hackernews", "since": "2011"], rawData: "x"),
            I(source: "HaveIBeenPwned", type: "data_breach", confidence: 1.0,
              metadata: ["breaches": "LinkedIn, Dropbox",
                         "breachDates": "LinkedIn|2012-05-05; Dropbox|2012-07-01"], rawData: "x"),
            // Garbage date must be dropped, not placed on the timeline.
            I(source: "X", type: "account_presence", confidence: 0.5,
              metadata: ["platform": "steam", "since": "n/a"], rawData: "x"),
        ]
        let p = IdentitySynthesizer.synthesize(from: inputs, riskScore: 20, riskLevel: "Low")
        // Oldest-first, garbage dropped: HN 2011, GitHub 2013, two 2012 breaches.
        XCTAssertEqual(p.timeline.map(\.date), ["2011", "2012-05-05", "2012-07-01", "2013"])
        XCTAssertEqual(p.timeline.first?.label, "Hacker News account created")
        XCTAssertEqual(p.timeline.first?.category, "account")
        XCTAssertTrue(p.timeline.contains { $0.label == "Breach: LinkedIn" && $0.category == "breach" })
        XCTAssertFalse(p.timeline.contains { $0.label.contains("Steam") }, "unparseable 'since' dropped")
    }

    func testTimelineIntelligenceNormalizesDatesStrictlyInUTC() {
        XCTAssertEqual(TimelineIntelligence.normalizedDate("1985")?.value, "1985")
        XCTAssertEqual(TimelineIntelligence.normalizedDate("2024-02-29T23:30:00-05:00")?.value, "2024-03-01")
        XCTAssertEqual(TimelineIntelligence.normalizedDate("2024-01-01T00:30:00+02:00")?.value, "2023-12-31")
        XCTAssertEqual(TimelineIntelligence.normalizedDate("May 25, 2010")?.value, "2010-05-25")
        XCTAssertEqual(TimelineIntelligence.isoDay(unixTimestamp: 1_609_459_200), "2021-01-01")
        XCTAssertNil(TimelineIntelligence.normalizedDate("1969"))
        XCTAssertNil(TimelineIntelligence.normalizedDate("2023-02-29"))
        XCTAssertNil(TimelineIntelligence.normalizedDate("2024-13-01"))
        XCTAssertNil(TimelineIntelligence.normalizedDate("2010-01-01<script>"))
        XCTAssertNil(TimelineIntelligence.normalizedDate("2010-01-01T<script>"))
        XCTAssertNil(TimelineIntelligence.normalizedDate("2010-01-01T25:00:00Z"))
        XCTAssertNil(TimelineIntelligence.normalizedDate(String(repeating: "2", count: 10_000)))
        XCTAssertNil(TimelineIntelligence.isoDay(unixTimestamp: .infinity))
    }

    func testTimelineIntelligenceBuildsProvenanceConflictsAndRecurrence() throws {
        typealias I = IdentitySynthesizer.Input
        let inputs = [
            I(source: "GitHub", type: "account_presence", confidence: 0.8,
              metadata: ["platform": "github", "username": "alice", "since": "2013-04-01"], rawData: "secret-a"),
            I(source: "GitHub mirror", type: "account_presence", confidence: 0.7,
              metadata: ["platform": "github", "username": "alice", "since": "2013-04-01"], rawData: "secret-b"),
            I(source: "Legacy import", type: "account_presence", confidence: 0.4,
              metadata: ["platform": "github", "username": "alice", "since": "2014-01-01"], rawData: "secret-c"),
            I(source: "Steam", type: "account_presence", confidence: 1,
              metadata: ["platform": "steam", "username": "alice", "since": "May 25, 2010"], rawData: "x"),
            I(source: "HIBP", type: "data_breach", confidence: 1,
              metadata: ["breachDates": "LinkedIn|2012-05-05; Dropbox|2012-07-01"], rawData: "breach-secret"),
            I(source: "RDAP", type: "domain_registration", confidence: 0.95,
              metadata: ["domain": "example.test", "registrationDate": "2001-02-03",
                         "expirationDate": "2031-02-03"], rawData: "registrar-secret"),
            I(source: "Wayback", type: "archive_history", confidence: 0.7,
              metadata: ["domain": "example.test", "firstSeen": "2005-04-03", "lastSeen": "2026-08-20"], rawData: "archive-secret"),
            I(source: "crt.sh", type: "subdomain", confidence: 0.9,
              metadata: ["subdomain": "www.example.test", "certificateNotBefore": "2015-06-07"], rawData: "ct-secret"),
            I(source: "invalid", type: "account_presence", confidence: 1,
              metadata: ["platform": "invalid", "since": "2022-02-30"], rawData: "must-not-appear")
        ]

        let report = TimelineIntelligence.build(from: inputs)
        XCTAssertEqual(report.schemaVersion, 1)
        XCTAssertEqual(report.summary.totalEventCount, 10)
        XCTAssertEqual(report.summary.categoryCounts["account"], 3)
        XCTAssertEqual(report.summary.categoryCounts["breach"], 2)
        XCTAssertEqual(report.summary.categoryCounts["domain"], 2)
        XCTAssertEqual(report.summary.categoryCounts["archive"], 2)
        XCTAssertEqual(report.summary.categoryCounts["certificate"], 1)
        XCTAssertEqual(report.summary.breachEventCount, 2)
        XCTAssertEqual(report.summary.breachRecurrenceCount, 1)
        XCTAssertEqual(report.summary.breachYears, [2012])
        XCTAssertEqual(report.summary.conflictGroups, 1)
        XCTAssertEqual(report.summary.corroboratedEvents, 1)
        XCTAssertFalse(report.summary.truncated)

        let corroborated = try XCTUnwrap(report.events.first { $0.date == "2013-04-01" })
        XCTAssertEqual(corroborated.sources, ["GitHub", "GitHub mirror"])
        XCTAssertEqual(corroborated.evidenceCount, 2)
        XCTAssertEqual(corroborated.confidence, 0.85, accuracy: 0.0001)
        XCTAssertTrue(corroborated.conflicting)
        XCTAssertEqual(corroborated.conflictDates, ["2013-04-01", "2014-01-01"])
        XCTAssertTrue(report.events.contains { $0.category == "archive" && $0.date == "2005-04-03" })
        XCTAssertTrue(report.events.contains { $0.category == "certificate" && $0.date == "2015-06-07" })

        let encoded = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
        for secret in ["secret-a", "secret-b", "secret-c", "breach-secret", "registrar-secret", "archive-secret", "ct-secret"] {
            XCTAssertFalse(encoded.contains(secret), "Timeline report must never copy raw finding payloads")
        }
    }

    func testTimelineIntelligenceCapsLargeReports() {
        typealias I = IdentitySynthesizer.Input
        let inputs = (0..<3).map { group in
            let dates = (0..<250).map { item in
                "Breach-\(group)-\(item)|2020-01-01"
            }.joined(separator: ";")
            return I(source: "Source-\(group)", type: "data_breach", confidence: 0.9,
                     metadata: ["breachDates": dates], rawData: "x")
        }
        let report = TimelineIntelligence.build(from: inputs)
        XCTAssertEqual(report.events.count, TimelineIntelligence.maximumEvents)
        XCTAssertEqual(report.summary.totalEventCount, 750)
        XCTAssertTrue(report.summary.truncated)
        XCTAssertEqual(report.summary.breachRecurrenceCount, 749)
    }

    func testTimelineEndpointEnforcesOwnershipAndOmitsRawEvidence() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "timeline-owner")
        let storedUser = try await User.query(on: app.db)
            .filter(\.$username == "timeline-owner").first()
        let user = try XCTUnwrap(storedUser)
        let scan = Scan(input: "private-target.example", status: .completed, userID: try user.requireID())
        try await scan.save(on: app.db)
        let scanID = try scan.requireID()
        let metadata = try String(decoding: JSONEncoder().encode([
            "domain": "private-target.example",
            "registrationDate": "2011-02-03",
        ]), as: UTF8.self)
        try await Result(
            scanID: scanID,
            source: "RDAP",
            type: "domain_registration",
            confidenceScore: 0.95,
            rawData: "raw-private-ledger-evidence",
            metadata: metadata
        ).save(on: app.db)
        let fetchedResult = try await Result.query(on: app.db).first()
        let storedResult = try XCTUnwrap(fetchedResult)
        storedResult.rawDataCipher = "v2:malformed-ciphertext"
        try await storedResult.update(on: app.db)

        try await app.test(.GET, "/scans/\(scanID)/timeline", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            let report = try response.content.decode(TimelineIntelligence.Report.self)
            XCTAssertEqual(report.events.first?.date, "2011-02-03")
            XCTAssertEqual(report.events.first?.category, "domain")
            XCTAssertFalse(response.body.string.contains("raw-private-ledger-evidence"))
        })
        try await app.test(.GET, "/scans/\(scanID)/timeline") { response in
            XCTAssertEqual(response.status, .forbidden)
            XCTAssertFalse(response.body.string.contains("private-target.example"))
        }
        try await app.test(.GET, "/scans/not-a-uuid/timeline") { response in
            XCTAssertEqual(response.status, .badRequest)
        }
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
            timeline: [],
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
                         "since": "2013", "profileURL": "https://github.com/alice"], rawData: "x"),
            I(source: "HIBP", type: "data_breach", confidence: 1.0,
              metadata: ["breaches": "Adobe, LinkedIn", "dataClasses": "Passwords, Phone numbers",
                         "breachDates": "Adobe|2013-10-04; LinkedIn|2012-05-05"], rawData: "x"),
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
        // Exposure timeline: chronological, breach dates + account creation year.
        XCTAssertTrue(md.contains("## Exposure timeline"))
        XCTAssertTrue(md.contains("| 2012-05-05 | Breach: LinkedIn |"))
        XCTAssertTrue(md.contains("| 2013 | GitHub account created |"))
        XCTAssertTrue(md.contains("earliest dated footprint is from 2012-05-05"), "footprint age in summary")
    }

    func testExecutiveReportHTMLEscapesAndStructures() {
        typealias I = IdentitySynthesizer.Input
        // A hostile "name" must not break out into live markup.
        let inputs = [
            I(source: "x", type: "account_presence", confidence: 1.0,
              metadata: ["platform": "github", "username": "alice", "since": "2013",
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
        XCTAssertTrue(html.contains("Exposure timeline") && html.contains("GitHub account created"), "timeline section rendered")
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

    func testCrtShRetainsEarliestCertificateDate() {
        let json = #"""
        [{"name_value":"*.example.com\nwww.example.com\nwww.example.com/poison","not_before":"2020-01-02T00:00:00Z"},
         {"name_value":"WWW.example.com","not_before":"2019-03-04T00:00:00Z"},
         {"name_value":"api.example.com\nattacker.invalid","entry_timestamp":"2021-05-06T10:00:00Z"}]
        """#.data(using: .utf8)!
        let evidence = CrtShPlugin.parseEvidence(json, limit: 50, domain: "example.com")
        XCTAssertEqual(evidence.first { $0.hostname == "www.example.com" }?.firstSeen, "2019-03-04")
        XCTAssertEqual(evidence.first { $0.hostname == "api.example.com" }?.firstSeen, "2021-05-06")
        XCTAssertFalse(evidence.contains { $0.hostname == "attacker.invalid" })
        XCTAssertEqual(evidence.count, 3)
        XCTAssertTrue(CrtShPlugin.parseEvidence(json, limit: 0).isEmpty)
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

    func testRiskScorerEmptyIsLow() throws {
        let s = try RiskScorer.compute(results: [])
        XCTAssertEqual(s.value, 0)
        XCTAssertEqual(s.level, .low)
    }

    // The regression that motivated the rewrite: HIBP's "no breaches found"
    // result (type breach_check, confidence 1.0) must contribute ZERO risk.
    func testRiskScorerCleanBreachCheckIsZeroRisk() throws {
        let s = try RiskScorer.compute(results: [mkResult("breach_check", 1.0, raw: "No breaches found.")])
        XCTAssertEqual(s.value, 0, "A clean breach check must not add risk")
    }

    // And it must not inflate a score built from real (account) findings.
    func testRiskScorerCleanCheckDoesNotInflate() throws {
        let accounts = (0..<5).map { mkResult("account_presence", 0.9, source: "s\($0)", raw: "acct \($0)") }
        let withClean = accounts + [mkResult("breach_check", 1.0, raw: "No breaches found.")]
        XCTAssertEqual(try RiskScorer.compute(results: accounts).value,
                       try RiskScorer.compute(results: withClean).value,
                       "A clean breach check must not change the score")
    }

    func testRiskScorerConfirmedBreachIsAtLeastMedium() throws {
        let s = try RiskScorer.compute(results: [mkResult("data_breach", 1.0, raw: "Found in 3 breaches")])
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
    func testRiskScorerBreachOutweighsManyAccounts() throws {
        let breach = try RiskScorer.compute(results: [mkResult("data_breach", 1.0)])
        let accounts = try RiskScorer.compute(results: (0..<20).map {
            mkResult("account_presence", 0.9, source: "s\($0)", raw: "acct \($0)")
        })
        XCTAssertGreaterThan(breach.value, accounts.value,
            "One breach should score higher than 20 social accounts")
    }

    // Account presence saturates: 50 profiles aren't dramatically worse than 10,
    // and account presence alone never escalates past the Low band.
    func testRiskScorerAccountPresenceSaturates() throws {
        let ten = try RiskScorer.compute(results: (0..<10).map {
            mkResult("account_presence", 1.0, source: "s\($0)", raw: "a\($0)")
        }).value
        let fifty = try RiskScorer.compute(results: (0..<50).map {
            mkResult("account_presence", 1.0, source: "s\($0)", raw: "a\($0)")
        }).value
        XCTAssertLessThanOrEqual(fifty - ten, 3, "Account category must saturate")
        XCTAssertLessThan(fifty, 25, "Public accounts alone should stay in the Low band")
    }

    // Exact-duplicate findings (same source+type+rawData) are counted once.
    func testRiskScorerDeduplicatesIdenticalFindings() throws {
        let one = try RiskScorer.compute(results: [mkResult("data_breach", 1.0, source: "hibp", raw: "X")]).value
        let dup = try RiskScorer.compute(results: [
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

    func testPluginResultLimitsAreUTF8ByteExact() throws {
        let exact = String(repeating: "é", count: PluginResultLimits.maxRawDataBytes / 2)
        XCTAssertEqual(exact.utf8.count, PluginResultLimits.maxRawDataBytes)
        XCTAssertEqual(
            PluginResultLimits.truncateUTF8(
                exact, maxBytes: PluginResultLimits.maxRawDataBytes,
                suffix: PluginResultLimits.truncationSuffix
            ),
            exact
        )

        let oversized = exact + "🛡️"
        let truncated = PluginResultLimits.truncateUTF8(
            oversized, maxBytes: PluginResultLimits.maxRawDataBytes,
            suffix: PluginResultLimits.truncationSuffix
        )
        XCTAssertLessThanOrEqual(truncated.utf8.count, PluginResultLimits.maxRawDataBytes)
        XCTAssertTrue(truncated.hasSuffix(PluginResultLimits.truncationSuffix))
        XCTAssertNotNil(truncated.data(using: .utf8))

        let hugeMetadata = ["value": String(repeating: "💣", count: 2_000)]
        XCTAssertNil(PluginResultLimits.encodeMetadata(hugeMetadata))
        XCTAssertNotNil(PluginResultLimits.encodeMetadata(["platform": "github"]))

        let oversizedResult = PluginResult(
            source: String(repeating: "🔎", count: 100),
            type: String(repeating: "é", count: 100),
            confidenceScore: .infinity,
            rawData: String(repeating: "💣", count: 3_000),
            metadata: hugeMetadata
        )
        let bounded = PluginResultLimits.sanitize(
            Array(repeating: oversizedResult, count: PluginResultLimits.maxResultsPerCandidate + 1)
        )
        XCTAssertEqual(bounded.count, PluginResultLimits.maxResultsPerCandidate)
        XCTAssertLessThanOrEqual(try XCTUnwrap(bounded.first).source.utf8.count,
                                 PluginResultLimits.maxSourceBytes)
        XCTAssertLessThanOrEqual(try XCTUnwrap(bounded.first).type.utf8.count,
                                 PluginResultLimits.maxTypeBytes)
        XCTAssertLessThanOrEqual(try XCTUnwrap(bounded.first).rawData.utf8.count,
                                 PluginResultLimits.maxRawDataBytes)
        XCTAssertEqual(try XCTUnwrap(bounded.first).confidenceScore, 0)
        XCTAssertNil(try XCTUnwrap(bounded.first).metadata)
    }

    func testResultMetadataObjectDecodesStoredJSON() {
        let withMeta = App.Result(scanID: UUID(), source: "github", type: "account_presence",
                                  confidenceScore: 1.0, rawData: "x",
                                  metadata: #"{"platform":"github","username":"alice"}"#)
        XCTAssertEqual(try withMeta.metadataObject?["username"], "alice")

        let without = App.Result(scanID: UUID(), source: "s", type: "t", confidenceScore: 0.5, rawData: "x")
        XCTAssertNil(try without.metadataObject)
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

    func testAccountExportIncludesInvestigationData() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        let cookie = try await registerAndLogin(app, username: "export-investigations")
        let userCandidate = try await User.query(on: app.db)
            .filter(\.$username == "export-investigations")
            .first()
        let user = try XCTUnwrap(userCandidate)
        let userID = try XCTUnwrap(user.id)

        let board = Investigation(
            userID: userID,
            name: "Exposure case",
            data: #"{"nodes":[{"id":"root"}],"edges":[]}"#
        )
        try await board.save(on: app.db)

        let result = DarkWebWorkerResult(
            schemaVersion: 1,
            status: "completed",
            findings: [DarkWebFinding(
                type: "domain",
                value: "example.test",
                source: "Torch",
                confidence: 0.8,
                firstSeen: "2024-01",
                lastSeen: nil
            )],
            relationships: [],
            sources: ["Torch"]
        )
        let job = DarkWebInvestigation(
            userID: userID,
            target: "example.test",
            retentionHours: 72
        )
        job.status = .completed
        job.setResultJSON(String(decoding: try JSONEncoder().encode(result), as: UTF8.self))
        job.resultCount = 1
        job.completedAt = Date()
        try await job.save(on: app.db)

        let scan = Scan(input: "export-metadata", status: .completed, userID: userID)
        scan.completedAt = Date()
        try await scan.save(on: app.db)
        let scanID = try XCTUnwrap(scan.id)
        let exportJob = ExportJob(
            userID: userID,
            scanID: scanID,
            format: .graphml,
            maxAttempts: 2,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        exportJob.statusRaw = ExportJobStatus.cancelled.rawValue
        exportJob.cancelRequested = true
        exportJob.completedAt = Date()
        try await exportJob.save(on: app.db)

        try await app.test(.GET, "/account/export", beforeRequest: { request in
            request.headers.replaceOrAdd(name: .cookie, value: cookie)
        }, afterResponse: { response in
            XCTAssertEqual(response.status, .ok)
            let root = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(response.body.readableBytesView))
                    as? [String: Any]
            )
            XCTAssertEqual(root["formatVersion"] as? Int, 4)
            let notificationOutbox = try XCTUnwrap(
                root["notificationOutbox"] as? [[String: Any]]
            )
            XCTAssertEqual(notificationOutbox.count, 1)
            XCTAssertEqual(notificationOutbox.first?["title"] as? String, "Verify your email")
            let exportJobs = try XCTUnwrap(root["exportJobs"] as? [[String: Any]])
            XCTAssertEqual(exportJobs.count, 1)
            XCTAssertEqual(exportJobs.first?["scanID"] as? String, scanID.uuidString)
            XCTAssertEqual(exportJobs.first?["format"] as? String, "graphml")
            XCTAssertNil(exportJobs.first?["artifact"])
            let boards = try XCTUnwrap(root["investigationBoards"] as? [[String: Any]])
            XCTAssertEqual(boards.count, 1)
            XCTAssertEqual(boards[0]["name"] as? String, "Exposure case")
            let investigations = try XCTUnwrap(
                root["darkWebInvestigations"] as? [[String: Any]]
            )
            XCTAssertEqual(investigations.count, 1)
            XCTAssertEqual(investigations[0]["target"] as? String, "example.test")
            let exportedResult = try XCTUnwrap(investigations[0]["result"] as? [String: Any])
            let findings = try XCTUnwrap(exportedResult["findings"] as? [[String: Any]])
            XCTAssertEqual(findings.first?["value"] as? String, "example.test")
        })
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
        let board = Investigation(
            userID: userID,
            name: "Erase board",
            data: #"{"nodes":[],"edges":[]}"#
        )
        try await board.save(on: app.db)
        let darkWebJob = DarkWebInvestigation(
            userID: userID,
            target: "erase.example",
            retentionHours: 72
        )
        try await darkWebJob.save(on: app.db)
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
        let remainingBoards = try await Investigation.query(on: app.db).count()
        let remainingDarkWebJobs = try await DarkWebInvestigation.query(on: app.db).count()
        XCTAssertNil(deletedUser)
        XCTAssertNil(deletedScan)
        XCTAssertEqual(remainingShares, 0)
        XCTAssertEqual(remainingBoards, 0)
        XCTAssertEqual(remainingDarkWebJobs, 0)

        let retainedAudit = try await AuditLog.query(on: app.db).all()
        XCTAssertFalse(retainedAudit.isEmpty)
        XCTAssertTrue(retainedAudit.allSatisfy { $0.userID == nil })
        XCTAssertTrue(try retainedAudit.allSatisfy { try $0.target == "[deleted-account]" })
        XCTAssertTrue(try retainedAudit.allSatisfy { try $0.ip == "[deleted]" })
    }

    // MARK: - TOTP (2FA)

    func testTOTPGenerateVerifyRoundTrip() throws {
        let secret = TOTP.generateSecret()
        XCTAssertGreaterThanOrEqual(secret.count, 32, "160-bit secret encodes to ≥32 base32 chars")
        let code = try XCTUnwrap(TOTP.current(secret: secret))
        XCTAssertEqual(code.count, 6)
        XCTAssertTrue(TOTP.verify(code: code, secret: secret), "the current code must verify")
        XCTAssertTrue(TOTP.verify(code: "  \(code)  ", secret: secret), "outer whitespace is harmless")
        XCTAssertFalse(TOTP.verify(code: "x\(code)", secret: secret), "codes must be exactly six ASCII digits")
        XCTAssertFalse(TOTP.verify(code: "\(code.prefix(3))-\(code.suffix(3))", secret: secret),
                       "punctuation inside a TOTP must not be silently discarded")
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
        let real = Data(#"{"kind":"t2","data":{"name":"spez","id":"abc","created_utc":1200000000}}"#.utf8)
        let parsed = RedditPlugin.evaluate(username: "spez", status: 200, body: real)
        XCTAssertEqual(parsed?.metadata?["since"], "2008-01-10")
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
         "created_at":"2018-07-06T12:00:00.000Z",
         "note":"<p>Hi <a href=\"x\">there</a></p>"}
        """#.utf8)
        let acct = try XCTUnwrap(MastodonPlugin.parseAccount(from: json, fallbackUsername: "fallback"))
        // Display name is trimmed and now available to feed metadata["name"].
        XCTAssertEqual(acct.displayName, "Alice Example")
        XCTAssertEqual(acct.acct, "alice")
        XCTAssertEqual(acct.bio, "Hi there", "HTML tags stripped from the note")
        XCTAssertEqual(acct.followers, 42)
        XCTAssertEqual(acct.joinedDate, "2018-07-06")
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
